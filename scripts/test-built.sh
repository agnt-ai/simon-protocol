#!/usr/bin/env bash
# The four packed packages (scripts/pack.ts), checked on the Node that runs this script, as a consumer
# gets them: installed from their tarballs into an empty project, the libraries imported by name through
# every export, their declarations read by TypeScript, both algorithms signing and verifying, the `simon`
# and `simon-mcp` binaries run, and every package's own suite, the test vectors among them, run against
# the compiled files.
# The project installs with no @agnt-sdk package reachable from a registry, as clients/js/README.md advises, so
# only the tarballs given can satisfy the packages and their exact-version dependencies on each other.
# CI runs it on Node 24.6.0, the oldest the packages support.
#   scripts/test-built.sh packed/
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PACKED="$(cd "${1:?usage: $0 <directory of packed tarballs>}" && pwd)"
CONSUMER="$(mktemp -d)"
trap 'rm -rf "$CONSUMER"' EXIT
echo "test-built: Node $(node --version)"

cd "$CONSUMER"
echo '{"name":"consumer","private":true,"type":"module"}' >package.json
echo '@agnt-sdk:registry=https://registry.invalid/' >.npmrc
npm install --silent --no-audit --no-fund "$PACKED"/*.tgz
cat >smoke.ts <<'EOF'
import assert from 'node:assert/strict';
import { canonicalize, generateKey, sign, verify } from '@agnt-sdk/simon-protocol';
import { Agent, SimonError } from '@agnt-sdk/simon-client';
import * as credentials from '@agnt-sdk/simon-client/credentials';
import * as provenance from '@agnt-sdk/simon-client/provenance';
import * as wait from '@agnt-sdk/simon-client/wait';
import * as workspace from '@agnt-sdk/simon-client/workspace';

for (const alg of ['ed25519', 'ml-dsa-65'] as const) {
  const { privateKey, key } = generateKey(alg);
  const bytes = canonicalize({ alg, text: 'hello' });
  assert.ok(verify(key, bytes, sign(privateKey, bytes)), `${alg} signs and verifies`);
  assert.ok(!verify(key, `${bytes} `, sign(privateKey, bytes)), `${alg} refuses other bytes`);
}
for (const m of [credentials, provenance, wait, workspace]) assert.ok(Object.keys(m).length);
assert.equal(typeof Agent, 'function');
assert.equal(typeof SimonError, 'function');
console.log('test-built: both packages import by name, and both algorithms sign and verify');
EOF
cat >tsconfig.json <<EOF
{
  "compilerOptions": {
    "module": "nodenext",
    "strict": true,
    "noEmit": true,
    "types": ["node"],
    "typeRoots": ["$ROOT/node_modules/@types"]
  },
  "files": ["smoke.ts"]
}
EOF
node "$ROOT/node_modules/typescript/bin/tsc" -p .
echo 'test-built: the declarations type-check'
node smoke.ts
for file in $(find node_modules/@agnt-sdk -name '*.ts' ! -name '*.d.ts' -not -path '*/node_modules/*/node_modules/*'); do
  echo "test-built: a package ships TypeScript source: $file" >&2
  exit 1
done
node_modules/.bin/simon help >/dev/null
echo 'test-built: the simon binary runs'
INITIALIZED="$(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test-built","version":"0"}}}' |
  SIMON_HOME="$CONSUMER/home" node_modules/.bin/simon-mcp)"
case "$INITIALIZED" in *'"name":"simon"'*) ;; *) echo "test-built: simon-mcp answered $INITIALIZED" >&2; exit 1 ;; esac
echo 'test-built: the simon-mcp binary answers initialize'

cd "$ROOT"
SIMON_BUILT="$CONSUMER" NODE_OPTIONS="--import=$ROOT/scripts/built-hooks.ts" node --test 'protocol/test/**/*.test.ts' 'clients/js/test/**/*.test.ts' \
  'clients/cli/test/**/*.test.ts' 'clients/mcp/test/**/*.test.ts'
