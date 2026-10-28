#!/usr/bin/env bash
# The six packed packages (scripts/pack.ts), checked on the Node that runs this script, as a consumer
# gets them: installed from their tarballs into an empty project (with the MongoDB driver and
# mongodb-memory-server at the versions of the lockfile, the store's peers), the libraries imported by name
# through every export, their declarations read by TypeScript, both algorithms signing and verifying, a
# server on MongoDB answering its health check without loading node:sqlite, the `simon-server`, `simon` and
# `simon-mcp` binaries run, and every package's own suite, the test vectors and the Store contract on
# MongoDB among them, run against the compiled files.
# The project installs with no @agnt-sdk package reachable from a registry, as clients/js/readme.md advises, so
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
version() { node -p "require('$ROOT/node_modules/$1/package.json').version"; }
MONGOMS_DISABLE_POSTINSTALL=1 npm install --silent --no-audit --no-fund "$PACKED"/*.tgz \
  "mongodb@$(version mongodb)" "mongodb-memory-server@$(version mongodb-memory-server)"
cat >smoke.ts <<'EOF'
import assert from 'node:assert/strict';
import { canonicalize, generateKey, sign, verify } from '@agnt-sdk/simon-protocol';
import { createServer, defineConfig, loadConfig, SqliteStore, type Store } from '@agnt-sdk/simon-server';
import { retractionCapacityContract, storeContract } from '@agnt-sdk/simon-server/contract';
import { Clock, FakeDns, FakeNet } from '@agnt-sdk/simon-server/testing';
import { connect, insertOnce, isDuplicate, MongoStore, type ConnectOptions } from '@agnt-sdk/simon-store-mongo';
import { freshDb, mongoUri, stopMongo } from '@agnt-sdk/simon-store-mongo/testing';
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
for (const f of [loadConfig, storeContract, retractionCapacityContract, insertOnce, isDuplicate, freshDb, stopMongo])
  assert.equal(typeof f, 'function');
for (const C of [Clock, FakeDns, FakeNet]) assert.equal(typeof C, 'function');
console.log('test-built: the packages import by name, and both algorithms sign and verify');

// A server on MongoDB: node:sqlite is never loaded, until a SqliteStore is made.
const sqliteLoaded = () => (process as unknown as { moduleLoadList: string[] }).moduleLoadList.some(m => /sqlite/.test(m));
const options: ConnectOptions = { maxPoolSize: 2, appName: 'test-built' };
const { client, db } = await connect(await mongoUri(), 'test_built', options);
const store: Store = await new MongoStore(db, () => client.close()).init();
const server = createServer({ config: defineConfig({ origin: 'http://localhost:1', dev: true }), store, worker: false });
const port = await server.listen(0, '127.0.0.1');
const health = await fetch(`http://127.0.0.1:${port}/health`);
assert.deepEqual(await health.json(), { status: 'ok' });
await server.close();
await store.close();
await stopMongo();
assert.ok(!sqliteLoaded(), 'a server on MongoDB loads no node:sqlite');
await new SqliteStore(':memory:').close();
assert.ok(sqliteLoaded(), 'a SqliteStore loads node:sqlite');
console.log('test-built: a server on MongoDB answers its health check, and loads node:sqlite only for a SqliteStore');
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
node_modules/.bin/simon-server help | grep -q SIMON_ORIGIN
echo 'test-built: the simon-server binary runs'
node_modules/.bin/simon help >/dev/null
echo 'test-built: the simon binary runs'
INITIALIZED="$(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test-built","version":"0"}}}' |
  SIMON_HOME="$CONSUMER/home" node_modules/.bin/simon-mcp)"
case "$INITIALIZED" in *'"name":"simon"'*) ;; *) echo "test-built: simon-mcp answered $INITIALIZED" >&2; exit 1 ;; esac
echo 'test-built: the simon-mcp binary answers initialize'

cd "$ROOT"
SIMON_BUILT="$CONSUMER" NODE_OPTIONS="--import=$ROOT/scripts/built-hooks.ts" node --test 'protocol/test/**/*.test.ts' \
  'server/test/**/*.test.ts' 'clients/js/test/**/*.test.ts' 'clients/cli/test/**/*.test.ts' 'clients/mcp/test/**/*.test.ts'
# The Store contract and the store's own suite on MongoDB, one file at a time as in the repository.
SIMON_BUILT="$CONSUMER" NODE_OPTIONS="--import=$ROOT/scripts/built-hooks.ts" node --test --test-concurrency=1 \
  'store-mongo/test/**/*.test.ts'
