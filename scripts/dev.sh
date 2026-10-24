#!/usr/bin/env bash
# A development server on this machine, with every setting development needs:
#   scripts/dev.sh        the basic server (server/), its sqlite file in the data directory
#   scripts/dev.sh app    the application template (app/), on a throwaway mongod in the data directory
#
# It serves http://localhost:$PORT (8787 by default) in development mode (AGNT_DEV=1): it hosts
# agents.test, leases addresses on lease.agents.test, resolves both to itself without DNS, and logs
# register codes. The application writes mail to outbox.jsonl in the data directory. Any AGNT_* variable
# already set wins, so a second server can run beside the first:
#   PORT=8788 AGNT_HOSTED_DOMAINS=other.test AGNT_LEASE_DOMAIN=lease.other.test \
#     AGNT_DEV_RESOLVE=other.test=http://localhost:8788,lease.other.test=http://localhost:8788 scripts/dev.sh
# The data directory is .data/ (AGNT_DATA_DIR); MONGO_PORT (27991) moves the application's mongod.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${1:-server}"
case "$MODE" in server | app) ;; *) echo "usage: $0 [server|app]" >&2; exit 2 ;; esac
DATA="${AGNT_DATA_DIR:-$ROOT/.data}"
PORT="${PORT:-8787}"
mkdir -p "$DATA"

export AGNT_DEV=1
export AGNT_PORT="${AGNT_PORT:-$PORT}"
export AGNT_ORIGIN="${AGNT_ORIGIN:-http://localhost:$AGNT_PORT}"
export AGNT_HOSTED_DOMAINS="${AGNT_HOSTED_DOMAINS:-agents.test}"
export AGNT_LEASE_DOMAIN="${AGNT_LEASE_DOMAIN:-lease.agents.test}"
export AGNT_DEV_RESOLVE="${AGNT_DEV_RESOLVE:-agents.test=$AGNT_ORIGIN,lease.agents.test=$AGNT_ORIGIN}"
# Demos register many agents from one address.
export AGNT_RATES="${AGNT_RATES:-register=1000/3600}"

if [ "$MODE" = server ]; then
  export AGNT_DB="${AGNT_DB:-$DATA/server-$AGNT_PORT.sqlite}"
  exec node "$ROOT/server/src/main.ts"
fi

# Whether something accepts connections on a local port (bash's /dev/tcp, so no nc is needed).
listening() { (: <"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
MONGO_PORT="${MONGO_PORT:-27991}"
mkdir -p "$DATA/db"
# A mongod from a run that just stopped may still hold the port while it shuts down: give it a moment.
if listening "$MONGO_PORT"; then sleep 2; fi
if ! listening "$MONGO_PORT"; then
  mongod --dbpath "$DATA/db" --port "$MONGO_PORT" --bind_ip 127.0.0.1 --quiet --logpath "$DATA/mongod.log" &
  MONGO_PID=$!
  trap 'kill $MONGO_PID 2>/dev/null' EXIT
  for _ in $(seq 1 50); do listening "$MONGO_PORT" && break; sleep 0.2; done
fi
export AGNT_MONGO_URI="${AGNT_MONGO_URI:-mongodb://127.0.0.1:$MONGO_PORT}"
export AGNT_DEV_OUTBOX="${AGNT_DEV_OUTBOX:-$DATA/outbox.jsonl}"
node "$ROOT/app/src/main.ts"
