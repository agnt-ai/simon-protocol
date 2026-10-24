#!/usr/bin/env bash
# The basic server's image, run as a deployment behind a load balancer runs it: built from the Dockerfile,
# with the settings such a deployment uses (an https origin, a server key, plain http inside the
# container, trusted proxies, a long keep-alive) and its sqlite file in a volume. The server must answer
# its health check, stop cleanly on SIGTERM, and keep its store across the restart: its server document's
# key keeps the `added` time it was first published with. Needs Docker and Node 26; CI runs it on every push.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME=simon-image-check
PORT="${PORT:-18080}"
URL="http://127.0.0.1:$PORT"
KEYS="$("$ROOT/scripts/server-keys.sh")"
eval "$KEYS"

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker volume rm "$NAME" >/dev/null 2>&1 || true
  docker image rm "$NAME" >/dev/null 2>&1 || true
}
fail() {
  docker logs "$NAME" >&2 || true
  echo "image-check: $1" >&2
  exit 1
}
trap cleanup EXIT
cleanup
docker build -q -t "$NAME" "$ROOT" >/dev/null
docker volume create "$NAME" >/dev/null

# Docker's bridge network stands in for the load balancer's subnets.
start() {
  docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8080" -v "$NAME:/data" \
    -e SIMON_ORIGIN=https://simon.example.com -e SIMON_SERVER_KEY \
    -e SIMON_CLIENT_IP_HEADER=x-forwarded-for -e SIMON_TRUSTED_PROXIES=172.16.0.0/12 -e SIMON_KEEP_ALIVE_TIMEOUT=65 \
    "$NAME" >/dev/null
  for _ in $(seq 50); do
    [ "$(curl -fsS "$URL/health" 2>/dev/null)" = '{"status":"ok"}' ] && return
    sleep 0.2
  done
  fail 'the server never answered its health check'
}
stop() {
  docker stop "$NAME" >/dev/null
  [ "$(docker inspect -f '{{.State.ExitCode}}' "$NAME")" = 0 ] || fail 'the server did not stop cleanly on SIGTERM'
  docker rm "$NAME" >/dev/null
}
added() {
  curl -fsS "$URL/simon/server" | node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(0)).keys[0].added)'
}

start
first="$(added)" || fail 'the server document could not be read'
stop
start
second="$(added)" || fail 'the server document could not be read'
[ "$second" = "$first" ] || fail 'the store did not survive a restart on its volume'
stop
echo "image-check: the image answers its health check, stops cleanly and keeps its store on /data"
