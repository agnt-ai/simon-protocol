#!/usr/bin/env bash
# The SIMON Protocol from a shell (bash or zsh): curl, OpenSSL 3 and jq, nothing else.
#
#   source examples/shell/simon.sh
#   simon_keygen                               # once: writes $SIMON_HOME/key.pem
#   simon_register                             # once: a leased address, written to $SIMON_HOME/address
#   simon_send bob@example.net "Does 3pm work?"
#   simon_sync                                # messages and an opaque token; pass the token unchanged next time
#   simon GET /simon/sent/<id>                  # any signed request
#
# Environment:
#   SIMON_SERVER  the agent's server, as an origin (default http://localhost:8787)
#   SIMON_HOME    where the key and address live (default ~/.config/simon); keep it private (chmod 700)
#
# The key never leaves this machine; it only signs requests and messages.

SIMON_SERVER="${SIMON_SERVER:-http://localhost:8787}"
SIMON_SERVER="${SIMON_SERVER%/}"
SIMON_HOME="${SIMON_HOME:-$HOME/.config/simon}"

_simon_b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
_simon_sha256() { openssl dgst -sha256 -r | cut -d' ' -f1; }

simon_keygen() {
  mkdir -p "$SIMON_HOME" && chmod 700 "$SIMON_HOME"
  [ -f "$SIMON_HOME/key.pem" ] && { echo "key exists: $SIMON_HOME/key.pem" >&2; return 0; }
  (umask 077 && openssl genpkey -algorithm ed25519 -out "$SIMON_HOME/key.pem")
}

# The key token: the algorithm, a colon, and the raw 32-byte public key in base64url.
simon_key() {
  printf 'ed25519:%s' "$(openssl pkey -in "$SIMON_HOME/key.pem" -pubout -outform DER | tail -c 32 | _simon_b64url)"
}

# Signs stdin. Ed25519 signs the whole input at once, which OpenSSL reads reliably from a file, not a pipe.
_simon_sign() {
  local tmp; tmp="$(mktemp)"; cat > "$tmp"
  openssl pkeyutl -sign -inkey "$SIMON_HOME/key.pem" -rawin -in "$tmp" | _simon_b64url
  rm -f "$tmp"
}

# simon METHOD PATH [BODY] [HINTS] [AS]: one signed request; prints the response body.
# HINTS is the simon-hints header, per-recipient JSON such as {"bob@example.net":{"invite":"..."}}.
# AS is the address the request acts as: by default the agent's own, once it has one.
simon() {
  local method="$1" rpath="$2" body="${3:-}" hints="${4:-}" as="${5:-}" ts nonce sig extra=()
  [ -z "$as" ] && [ -f "$SIMON_HOME/address" ] && as="$(cat "$SIMON_HOME/address")"
  ts="$(date +%s)"
  nonce="$(openssl rand -hex 16)"
  # Eight lines: SIMON-REQUEST, the method, the server's origin, who the request acts as, the path as sent,
  # the time, the nonce, and the body's hash. The origin binds the request to this server, and the actor
  # to this agent.
  sig="$(printf 'SIMON-REQUEST\n%s\n%s\n%s\n%s\n%s\n%s\n%s' "$method" "$SIMON_SERVER" "$as" "$rpath" "$ts" "$nonce" \
    "$(printf '%s' "$body" | _simon_sha256)" | _simon_sign)"
  [ -n "$as" ] && extra+=(-H "simon-agent: $as")
  [ -n "$hints" ] && extra+=(-H "simon-hints: $hints")
  [ -n "$body" ] && extra+=(-H "content-type: application/json" --data-binary "$body")
  curl -sS -X "$method" "$SIMON_SERVER$rpath" \
    -H "simon-key: $(simon_key)" -H "simon-timestamp: $ts" -H "simon-nonce: $nonce" -H "simon-signature: $sig" "${extra[@]}"
}

# simon_register [ADDRESS] [CODE]: with no address the server leases one. An address on a domain the
# server does not host gets a code; run again with the code. Writes $SIMON_HOME/address once active.
simon_register() {
  local res address
  # The address is signed as simon-agent exactly as the server compares it: in lower case.
  address="$(tr '[:upper:]' '[:lower:]' <<<"${1:-}")"
  res="$(simon POST /simon/register "$(jq -cn --arg k "$(simon_key)" --arg a "$address" --arg c "${2:-}" \
    '{key: $k} + (if $a == "" then {} else {address: $a} end) + (if $c == "" then {} else {code: $c} end)')" \
    "" "$address")"
  echo "$res"
  if jq -e '(.keys | type) == "array"' <<<"$res" >/dev/null; then
    (umask 077 && jq -r .address <<<"$res" > "$SIMON_HOME/address")
  fi
}

# simon_send TO TEXT [IN_REPLY_TO]: a signed message from a solo agent. It is sent in canonical form (keys
# sorted, no whitespace, integers only: what `jq -S -c` prints for ASCII text), the form its signature covers.
simon_send() {
  local message sig
  message="$(jq -S -c -n --arg from "$(cat "$SIMON_HOME/address")" --arg to "$1" --arg text "$2" --arg re "${3:-}" \
    --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{v: 1, from: $from, to: [$to], inReplyTo: (if $re == "" then null else $re end),
      parts: [{type: "text/plain", data: $text}], headers: {}, sentAt: $at}')"
  sig="$(printf 'SIMON-MESSAGE\n%s' "$message" | _simon_sign)"
  simon POST /simon/send "$(jq -S -c --arg s "$sig" '. + {signature: $s}' <<<"$message")"
}

# simon_sync [TOKEN]: received/sent history since an opaque token; no token starts retained history.
simon_sync() {
  local suffix=""
  if [ -n "${1:-}" ]; then suffix="?since=$(jq -rn --arg t "$1" '$t|@uri')"; fi
  simon GET "/simon/sync${suffix}"
}
