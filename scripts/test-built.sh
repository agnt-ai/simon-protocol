#!/usr/bin/env bash
# The packed protocol library and JavaScript client (scripts/pack.ts), checked on the Node that runs this
# script, as a consumer gets them: installed from their tarballs into an empty project, imported by name
# through every export, their declarations read by TypeScript, both algorithms signing and verifying, and
# the protocol's and the client's own suites, the test vectors among them, run against the compiled files.
# The project installs with no @agnt-protocol package reachable from a registry, as clients/js/README.md advises.
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
echo '@agnt-protocol:registry=https://registry.invalid/' >.npmrc
npm install --silent --no-audit --no-fund "$PACKED"/*.tgz
cat >smoke.ts <<'EOF'
import assert from 'node:assert/strict';
import { canonicalize, generateKey, sign, verify } from '@agnt-protocol/protocol';
import { Agent, SimonError } from '@agnt-protocol/client';
import * as credentials from '@agnt-protocol/client/credentials';
import * as provenance from '@agnt-protocol/client/provenance';
import * as wait from '@agnt-protocol/client/wait';
import * as workspace from '@agnt-protocol/client/workspace';

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

cd "$ROOT"
SIMON_BUILT="$CONSUMER" NODE_OPTIONS="--import=$ROOT/scripts/built-hooks.ts" node --test 'protocol/test/**/*.test.ts' 'clients/js/test/**/*.test.ts'
