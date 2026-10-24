#!/bin/sh
# Puts this laptop on AGNT, publicly, for as long as this window stays open. Run by a person, not an agent:
# opening a laptop to the internet is that person's decision.
#
# It starts a Cloudflare quick tunnel (a generated public https name), this laptop's AGNT server behind it,
# and the conversation viewer at http://127.0.0.1:8090; it registers the agent on first use and prints its
# server-generated address. Ctrl-C, or closing the window, stops all three. The next start gets a new public
# name, and so a new address.
#
#   sh ~/agnt/repo/examples/two-laptops/start.sh
set -eu

AGNT="$HOME/agnt"
REPO="$AGNT/repo"
PORT=${AGNT_PORT:-8080}
VIEWER_PORT=${AGNT_VIEWER_PORT:-8090}

say() { printf '%s\n' "$*"; }
fail() { say "start.sh: $*" >&2; exit 1; }

[ -s "$HOME/.nvm/nvm.sh" ] && . "$HOME/.nvm/nvm.sh" >/dev/null 2>&1 && nvm use 26 >/dev/null 2>&1 || true
NODE=$(command -v node) || fail "Node is not installed; the setup agent installs it (JOIN-AGNT.md step 1)."
[ "$("$NODE" -p 'process.versions.node.split(".")[0]')" -ge 26 ] || fail "Node 26 or later is needed; $NODE is $("$NODE" --version). Other nodes on the PATH: $(which -a node | tr '\n' ' ')"
PATH="$(dirname "$NODE"):$PATH"   # every node this script and its helpers start is this one
CLOUDFLARED=$(command -v cloudflared || true)
[ -n "$CLOUDFLARED" ] || CLOUDFLARED="$AGNT/bin/cloudflared"
[ -x "$CLOUDFLARED" ] || fail "cloudflared is not installed; the setup agent installs it (JOIN-AGNT.md step 1)."
[ -f "$REPO/server/src/main.ts" ] || fail "the repository is not at $REPO (the setup agent clones it there)."
if lsof -nP -iTCP:$PORT -iTCP:$VIEWER_PORT -sTCP:LISTEN >/dev/null 2>&1; then
  fail "port $PORT or $VIEWER_PORT is in use: $(lsof -nP -iTCP:$PORT -iTCP:$VIEWER_PORT -sTCP:LISTEN | tail -n +2)"
fi

mkdir -p "$AGNT/server" "$AGNT/agent" "$AGNT/workspace" "$AGNT/bin"
chmod 700 "$AGNT/server" "$AGNT/agent"
cd "$AGNT/server"
[ -s keys.env ] || (umask 077; "$REPO/scripts/server-keys.sh" > keys.env.new && mv keys.env.new keys.env) || fail "could not make the server key; see the message above"

PIDS=""
stop() { [ -n "$PIDS" ] && kill $PIDS 2>/dev/null; rm -f "$AGNT/server/name"; say ""; say "Stopped. This laptop is off AGNT."; }
trap stop EXIT INT TERM

say "Opening a public tunnel..."
: > tunnel.log
"$CLOUDFLARED" tunnel --no-autoupdate --url "http://127.0.0.1:$PORT" > tunnel.log 2>&1 &
PIDS="$!"
NAME=""
for _ in $(seq 60); do
  NAME=$(grep -oE '[a-z0-9-]+\.trycloudflare\.com' tunnel.log | head -1 || true)
  [ -n "$NAME" ] && break
  sleep 1
done
[ -n "$NAME" ] || fail "the tunnel gave no name; see $AGNT/server/tunnel.log"
echo "$NAME" > name

say "Starting the server at https://$NAME ..."
(
  . ./keys.env
  export AGNT_ORIGIN="https://$NAME" AGNT_LEASE_DOMAIN="$NAME" AGNT_PORT=$PORT AGNT_LISTEN_HOST=127.0.0.1
  export AGNT_CLIENT_IP_HEADER=cf-connecting-ip AGNT_DB="$AGNT/server/agnt-$NAME.sqlite"
  exec "$NODE" "$REPO/server/src/main.ts" >> server.log 2>&1
) &
PIDS="$PIDS $!"
# The answer must come from this server, not from something else that took the port: it names this origin.
EXPECTED="{\"server\":\"https://$NAME\"}"
for _ in $(seq 60); do
  [ "$(curl -sf --max-time 5 "https://$NAME/.well-known/agnt" 2>/dev/null)" = "$EXPECTED" ] && break
  kill -0 $PIDS 2>/dev/null || fail "the tunnel or the server stopped; see $AGNT/server/server.log and tunnel.log"
  sleep 2
done
[ "$(curl -sf --max-time 5 "https://$NAME/.well-known/agnt")" = "$EXPECTED" ] ||
  fail "https://$NAME does not answer as this server; see $AGNT/server/server.log and tunnel.log"

cat > "$AGNT/bin/agnt-protocol" <<SH
#!/bin/sh
# The AGNT CLI for this laptop's agent, on whatever public name the running start.sh has.
[ -f "\$HOME/agnt/server/name" ] || { echo 'AGNT is not running on this laptop: start ~/agnt/repo/examples/two-laptops/start.sh' >&2; exit 1; }
export AGNT_HOME="\$HOME/agnt/agent" AGNT_SERVER="https://\$(cat "\$HOME/agnt/server/name")"
export AGNT_WORKSPACE="\${AGNT_WORKSPACE:-\$HOME/agnt/workspace}"
exec "$NODE" "\$HOME/agnt/repo/clients/cli/src/cli.ts" "\$@"
SH
chmod 700 "$AGNT/bin/agnt-protocol"

say "Registering the agent..."
# A new public name means a new address: the key stays, the record of the old address goes.
OLD_ADDRESS=""
if [ -f "$AGNT/agent/address.json" ] && ! grep -q "\"https://$NAME\"" "$AGNT/agent/address.json"; then
  OLD_ADDRESS=$(cat "$AGNT/server/address" 2>/dev/null || true)
  rm -f "$AGNT/agent/address.json" "$AGNT/agent/wait.json"
fi
ADDRESS=$(cd "$AGNT/workspace" && "$AGNT/bin/agnt-protocol" register | "$NODE" -e '
let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const r=JSON.parse(s);if(!Array.isArray(r.keys))process.exit(1);console.log(r.address)})') ||
  fail "registration failed; run ~/agnt/bin/agnt-protocol register to see why"
echo "$ADDRESS" > "$AGNT/server/address"

"$NODE" "$REPO/examples/two-laptops/viewer/viewer.ts" --db "$AGNT/server/agnt-$NAME.sqlite" --port $VIEWER_PORT >> viewer.log 2>&1 &
PIDS="$PIDS $!"
sleep 1
open "http://127.0.0.1:$VIEWER_PORT" 2>/dev/null || true

say ""
say "  This laptop is on AGNT."
say "  Its agent's address:  $ADDRESS"
printf '%s' "$ADDRESS" | pbcopy 2>/dev/null && say "  (copied to the clipboard: paste it, don't retype it)"
say "  Watch the conversation:  http://127.0.0.1:$VIEWER_PORT"
if [ -n "$OLD_ADDRESS" ] && [ "$OLD_ADDRESS" != "$ADDRESS" ]; then
  say ""
  say "  THE ADDRESS CHANGED. It was $OLD_ADDRESS."
  say "  Messages sent to the old address will never arrive. Send the new one to the other person,"
  say "  and redo steps 4 and 5 of JOIN-AGNT.md: the agent's CLAUDE.md still names the old address."
fi
say ""
say "  Send the address to the other person. Keep this window open: closing it takes this laptop off AGNT."
wait
