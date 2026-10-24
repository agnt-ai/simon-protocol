#!/usr/bin/env bash
# A development server on this machine, with every setting development needs:
#   scripts/dev.sh        the basic server (server/), its sqlite file in the data directory
#   scripts/dev.sh app    the application template (app/), on a throwaway mongod in the data directory
#
# It serves http://localhost:$PORT (8787 by default) in development mode (SIMON_DEV=1): it hosts
# agents.test, leases addresses on lease.agents.test, resolves both to itself without DNS, and logs
# register codes. The application writes mail to outbox.jsonl in the data directory. Any SIMON_* variable
# already set wins, so a second server can run beside the first:
#   PORT=8788 SIMON_HOSTED_DOMAINS=other.test SIMON_LEASE_DOMAIN=lease.other.test \
#     SIMON_DEV_RESOLVE=other.test=http://localhost:8788,lease.other.test=http://localhost:8788 scripts/dev.sh
# The data directory is .data/ (SIMON_DATA_DIR); MONGO_PORT (27991) moves the application's mongod.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${1:-server}"
case "$MODE" in server | app) ;; *) echo "usage: $0 [server|app]" >&2; exit 2 ;; esac
DATA="${SIMON_DATA_DIR:-$ROOT/.data}"
PORT="${PORT:-8787}"
mkdir -p "$DATA"

export SIMON_DEV=1
export SIMON_PORT="${SIMON_PORT:-$PORT}"
export SIMON_ORIGIN="${SIMON_ORIGIN:-http://localhost:$SIMON_PORT}"
export SIMON_HOSTED_DOMAINS="${SIMON_HOSTED_DOMAINS:-agents.test}"
export SIMON_LEASE_DOMAIN="${SIMON_LEASE_DOMAIN:-lease.agents.test}"
export SIMON_DEV_RESOLVE="${SIMON_DEV_RESOLVE:-agents.test=$SIMON_ORIGIN,lease.agents.test=$SIMON_ORIGIN}"
# Demos register many agents from one address.
export SIMON_RATES="${SIMON_RATES:-register=1000/3600}"

if [ "$MODE" = server ]; then
  export SIMON_DB="${SIMON_DB:-$DATA/server-$SIMON_PORT.sqlite}"
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
export SIMON_MONGO_URI="${SIMON_MONGO_URI:-mongodb://127.0.0.1:$MONGO_PORT}"
export SIMON_DEV_OUTBOX="${SIMON_DEV_OUTBOX:-$DATA/outbox.jsonl}"
node "$ROOT/app/src/main.ts"
