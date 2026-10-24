#!/usr/bin/env bash
# The AGNT Protocol from a shell (bash or zsh): curl, OpenSSL 3 and jq, nothing else.
#
#   source examples/shell/agnt.sh
#   agnt_keygen                               # once: writes $AGNT_HOME/key.pem
#   agnt_register                             # once: a leased address, written to $AGNT_HOME/address
#   agnt_send bob@example.net "Does 3pm work?"
#   agnt_sync                                # messages and an opaque token; pass the token unchanged next time
#   agnt GET /agnt/sent/<id>                  # any signed request
#
# Environment:
#   AGNT_SERVER  the agent's server, as an origin (default http://localhost:8787)
#   AGNT_HOME    where the key and address live (default ~/.config/agnt); keep it private (chmod 700)
#
# The key never leaves this machine; it only signs requests and messages.

AGNT_SERVER="${AGNT_SERVER:-http://localhost:8787}"
AGNT_SERVER="${AGNT_SERVER%/}"
AGNT_HOME="${AGNT_HOME:-$HOME/.config/agnt}"

_agnt_b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
_agnt_sha256() { openssl dgst -sha256 -r | cut -d' ' -f1; }

agnt_keygen() {
  mkdir -p "$AGNT_HOME" && chmod 700 "$AGNT_HOME"
  [ -f "$AGNT_HOME/key.pem" ] && { echo "key exists: $AGNT_HOME/key.pem" >&2; return 0; }
  (umask 077 && openssl genpkey -algorithm ed25519 -out "$AGNT_HOME/key.pem")
}

# The key token: the algorithm, a colon, and the raw 32-byte public key in base64url.
agnt_key() {
  printf 'ed25519:%s' "$(openssl pkey -in "$AGNT_HOME/key.pem" -pubout -outform DER | tail -c 32 | _agnt_b64url)"
}

# Signs stdin. Ed25519 signs the whole input at once, which OpenSSL reads reliably from a file, not a pipe.
_agnt_sign() {
  local tmp; tmp="$(mktemp)"; cat > "$tmp"
  openssl pkeyutl -sign -inkey "$AGNT_HOME/key.pem" -rawin -in "$tmp" | _agnt_b64url
  rm -f "$tmp"
}

# agnt METHOD PATH [BODY] [HINTS] [AS]: one signed request; prints the response body.
# HINTS is the agnt-hints header, per-recipient JSON such as {"bob@example.net":{"invite":"..."}}.
# AS is the address the request acts as: by default the agent's own, once it has one.
agnt() {
  local method="$1" rpath="$2" body="${3:-}" hints="${4:-}" as="${5:-}" ts nonce sig extra=()
  [ -z "$as" ] && [ -f "$AGNT_HOME/address" ] && as="$(cat "$AGNT_HOME/address")"
  ts="$(date +%s)"
  nonce="$(openssl rand -hex 16)"
  # Eight lines: AGNT-REQUEST, the method, the server's origin, who the request acts as, the path as sent,
  # the time, the nonce, and the body's hash. The origin binds the request to this server, and the actor
  # to this agent.
  sig="$(printf 'AGNT-REQUEST\n%s\n%s\n%s\n%s\n%s\n%s\n%s' "$method" "$AGNT_SERVER" "$as" "$rpath" "$ts" "$nonce" \
    "$(printf '%s' "$body" | _agnt_sha256)" | _agnt_sign)"
  [ -n "$as" ] && extra+=(-H "agnt-agent: $as")
  [ -n "$hints" ] && extra+=(-H "agnt-hints: $hints")
  [ -n "$body" ] && extra+=(-H "content-type: application/json" --data-binary "$body")
  curl -sS -X "$method" "$AGNT_SERVER$rpath" \
    -H "agnt-key: $(agnt_key)" -H "agnt-timestamp: $ts" -H "agnt-nonce: $nonce" -H "agnt-signature: $sig" "${extra[@]}"
}

# agnt_register [ADDRESS] [CODE]: with no address the server leases one. An address on a domain the
# server does not host gets a code; run again with the code. Writes $AGNT_HOME/address once active.
agnt_register() {
  local res address
  # The address is signed as agnt-agent exactly as the server compares it: in lower case.
  address="$(tr '[:upper:]' '[:lower:]' <<<"${1:-}")"
  res="$(agnt POST /agnt/register "$(jq -cn --arg k "$(agnt_key)" --arg a "$address" --arg c "${2:-}" \
    '{key: $k} + (if $a == "" then {} else {address: $a} end) + (if $c == "" then {} else {code: $c} end)')" \
    "" "$address")"
  echo "$res"
  if jq -e '(.keys | type) == "array"' <<<"$res" >/dev/null; then
    (umask 077 && jq -r .address <<<"$res" > "$AGNT_HOME/address")
  fi
}

# agnt_send TO TEXT [IN_REPLY_TO]: a signed message from a solo agent. It is sent in canonical form (keys
# sorted, no whitespace, integers only: what `jq -S -c` prints for ASCII text), the form its signature covers.
agnt_send() {
  local message sig
  message="$(jq -S -c -n --arg from "$(cat "$AGNT_HOME/address")" --arg to "$1" --arg text "$2" --arg re "${3:-}" \
    --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{v: 1, from: $from, to: [$to], inReplyTo: (if $re == "" then null else $re end),
      parts: [{type: "text/plain", data: $text}], headers: {}, sentAt: $at}')"
  sig="$(printf 'AGNT-MESSAGE\n%s' "$message" | _agnt_sign)"
  agnt POST /agnt/send "$(jq -S -c --arg s "$sig" '. + {signature: $s}' <<<"$message")"
}

# agnt_sync [TOKEN]: received/sent history since an opaque token; no token starts retained history.
agnt_sync() {
  local suffix=""
  if [ -n "${1:-}" ]; then suffix="?since=$(jq -rn --arg t "$1" '$t|@uri')"; fi
  agnt GET "/agnt/sync${suffix}"
}
