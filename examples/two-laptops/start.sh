#!/bin/sh
# Puts this laptop on SIMON, publicly, for as long as this window stays open. Run by a person, not an agent:
# opening a laptop to the internet is that person's decision.
#
# It starts a Cloudflare quick tunnel (a generated public https name), this laptop's SIMON server behind it,
# and the conversation viewer at http://127.0.0.1:8090; it registers the agent on first use and prints its
# server-generated address. Ctrl-C, or closing the window, stops all three. The next start gets a new public
# name, and so a new address.
#
#   sh ~/simon/repo/examples/two-laptops/start.sh
set -eu

SIMON="$HOME/simon"
REPO="$SIMON/repo"
PORT=${SIMON_PORT:-8080}
VIEWER_PORT=${SIMON_VIEWER_PORT:-8090}

say() { printf '%s\n' "$*"; }
fail() { say "start.sh: $*" >&2; exit 1; }

[ -s "$HOME/.nvm/nvm.sh" ] && . "$HOME/.nvm/nvm.sh" >/dev/null 2>&1 && nvm use 26 >/dev/null 2>&1 || true
NODE=$(command -v node) || fail "Node is not installed; the setup agent installs it (JOIN-SIMON.md step 1)."
[ "$("$NODE" -p 'process.versions.node.split(".")[0]')" -ge 26 ] || fail "Node 26 or later is needed; $NODE is $("$NODE" --version). Other nodes on the PATH: $(which -a node | tr '\n' ' ')"
PATH="$(dirname "$NODE"):$PATH"   # every node this script and its helpers start is this one
CLOUDFLARED=$(command -v cloudflared || true)
[ -n "$CLOUDFLARED" ] || CLOUDFLARED="$SIMON/bin/cloudflared"
[ -x "$CLOUDFLARED" ] || fail "cloudflared is not installed; the setup agent installs it (JOIN-SIMON.md step 1)."
[ -f "$REPO/server/src/main.ts" ] || fail "the repository is not at $REPO (the setup agent clones it there)."
if lsof -nP -iTCP:$PORT -iTCP:$VIEWER_PORT -sTCP:LISTEN >/dev/null 2>&1; then
  fail "port $PORT or $VIEWER_PORT is in use: $(lsof -nP -iTCP:$PORT -iTCP:$VIEWER_PORT -sTCP:LISTEN | tail -n +2)"
fi

mkdir -p "$SIMON/server" "$SIMON/agent" "$SIMON/workspace" "$SIMON/bin"
chmod 700 "$SIMON/server" "$SIMON/agent"
cd "$SIMON/server"
[ -s keys.env ] || (umask 077; "$REPO/scripts/server-keys.sh" > keys.env.new && mv keys.env.new keys.env) || fail "could not make the server key; see the message above"

PIDS=""
stop() { [ -n "$PIDS" ] && kill $PIDS 2>/dev/null; rm -f "$SIMON/server/name"; say ""; say "Stopped. This laptop is off SIMON."; }
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
[ -n "$NAME" ] || fail "the tunnel gave no name; see $SIMON/server/tunnel.log"
echo "$NAME" > name

say "Starting the server at https://$NAME ..."
(
  . ./keys.env
  export SIMON_ORIGIN="https://$NAME" SIMON_LEASE_DOMAIN="$NAME" SIMON_PORT=$PORT SIMON_LISTEN_HOST=127.0.0.1
  export SIMON_CLIENT_IP_HEADER=cf-connecting-ip SIMON_DB="$SIMON/server/simon-$NAME.sqlite"
  exec "$NODE" "$REPO/server/src/main.ts" >> server.log 2>&1
) &
PIDS="$PIDS $!"
# The answer must come from this server, not from something else that took the port: it names this origin.
EXPECTED="{\"server\":\"https://$NAME\"}"
for _ in $(seq 60); do
  [ "$(curl -sf --max-time 5 "https://$NAME/.well-known/simon" 2>/dev/null)" = "$EXPECTED" ] && break
  kill -0 $PIDS 2>/dev/null || fail "the tunnel or the server stopped; see $SIMON/server/server.log and tunnel.log"
  sleep 2
done
[ "$(curl -sf --max-time 5 "https://$NAME/.well-known/simon")" = "$EXPECTED" ] ||
  fail "https://$NAME does not answer as this server; see $SIMON/server/server.log and tunnel.log"

cat > "$SIMON/bin/simon" <<SH
#!/bin/sh
# The SIMON CLI for this laptop's agent, on whatever public name the running start.sh has.
[ -f "\$HOME/simon/server/name" ] || { echo 'SIMON is not running on this laptop: start ~/simon/repo/examples/two-laptops/start.sh' >&2; exit 1; }
export SIMON_HOME="\$HOME/simon/agent" SIMON_SERVER="https://\$(cat "\$HOME/simon/server/name")"
export SIMON_WORKSPACE="\${SIMON_WORKSPACE:-\$HOME/simon/workspace}"
exec "$NODE" "\$HOME/simon/repo/clients/cli/src/cli.ts" "\$@"
SH
chmod 700 "$SIMON/bin/simon"

say "Registering the agent..."
# A new public name means a new address: the key stays, the record of the old address goes.
OLD_ADDRESS=""
if [ -f "$SIMON/agent/address.json" ] && ! grep -q "\"https://$NAME\"" "$SIMON/agent/address.json"; then
  OLD_ADDRESS=$(cat "$SIMON/server/address" 2>/dev/null || true)
  rm -f "$SIMON/agent/address.json" "$SIMON/agent/wait.json"
fi
ADDRESS=$(cd "$SIMON/workspace" && "$SIMON/bin/simon" register | "$NODE" -e '
let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const r=JSON.parse(s);if(!Array.isArray(r.keys))process.exit(1);console.log(r.address)})') ||
  fail "registration failed; run ~/simon/bin/simon register to see why"
echo "$ADDRESS" > "$SIMON/server/address"

"$NODE" "$REPO/examples/two-laptops/viewer/viewer.ts" --db "$SIMON/server/simon-$NAME.sqlite" --port $VIEWER_PORT >> viewer.log 2>&1 &
PIDS="$PIDS $!"
sleep 1
open "http://127.0.0.1:$VIEWER_PORT" 2>/dev/null || true

say ""
say "  This laptop is on SIMON."
say "  Its agent's address:  $ADDRESS"
printf '%s' "$ADDRESS" | pbcopy 2>/dev/null && say "  (copied to the clipboard: paste it, don't retype it)"
say "  Watch the conversation:  http://127.0.0.1:$VIEWER_PORT"
if [ -n "$OLD_ADDRESS" ] && [ "$OLD_ADDRESS" != "$ADDRESS" ]; then
  say ""
  say "  THE ADDRESS CHANGED. It was $OLD_ADDRESS."
  say "  Messages sent to the old address will never arrive. Send the new one to the other person,"
  say "  and redo steps 4 and 5 of JOIN-SIMON.md: the agent's CLAUDE.md still names the old address."
fi
say ""
say "  Send the address to the other person. Keep this window open: closing it takes this laptop off SIMON."
wait
