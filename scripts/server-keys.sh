#!/usr/bin/env bash
# Fresh keys for a server, printed as shell `export` lines, so `eval` sets them in this shell or a file
# keeps them:
#   eval "$(scripts/server-keys.sh)"                 AGNT_SERVER_KEY, and AGNT_DATA_KEY for the application
#   eval "$(scripts/server-keys.sh --next)"          AGNT_NEXT_SERVER_KEY, announced before a rotation
#   scripts/server-keys.sh --alg ml-dsa-65           the same with an ML-DSA-65 key
# A server key is `<alg>:<base64url 32-byte seed>`, the form server/src/config.ts reads. A comment line
# gives its public key token, the one the server document lists. Keep the output secret and never commit it.
set -euo pipefail
command -v node >/dev/null || { echo "server-keys.sh: node is not on the PATH" >&2; exit 1; }
[ "$(node -p 'process.versions.node.split(".")[0]')" -ge 26 ] ||
  { echo "server-keys.sh: Node 26 or later is needed; $(command -v node) is $(node --version)" >&2; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME=AGNT_SERVER_KEY
ALG=ed25519
while [ $# -gt 0 ]; do
  case "$1" in
    --next) NAME=AGNT_NEXT_SERVER_KEY ;;
    --alg) ALG="${2:-}"; shift ;;
    *) echo "usage: $0 [--next] [--alg ed25519|ml-dsa-65]" >&2; exit 2 ;;
  esac
  shift
done
NAME="$NAME" ALG="$ALG" PROTOCOL="$ROOT/protocol/src/index.ts" node --input-type=module -e '
const { ALGORITHM_NAMES, keyToken, privateKeyFromSeed } = await import(process.env.PROTOCOL);
const { randomBytes } = await import("node:crypto");
const { NAME: name, ALG: alg } = process.env;
if (!ALGORITHM_NAMES.includes(alg)) {
  console.error(`--alg is one of ${ALGORITHM_NAMES.join(", ")}`);
  process.exit(2);
}
const seed = randomBytes(32);
console.log(`# public key: ${keyToken(privateKeyFromSeed(alg, seed))}`);
console.log(`export ${name}=\x27${alg}:${seed.toString("base64url")}\x27`);
if (name === "AGNT_SERVER_KEY") console.log(`export AGNT_DATA_KEY=\x27${randomBytes(32).toString("base64")}\x27`);
'
