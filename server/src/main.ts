#!/usr/bin/env node
/**
 * The server as a process: `node server/src/main.ts`, or `simon-server` installed from npm. Configuration
 * comes from the environment (see config.ts or README.md); storage is the sqlite file SIMON_DB.
 * `simon-server help` prints how to run it and exits.
 */
import { loadConfig } from './config.ts';
import { createServer } from './server.ts';
import { SqliteStore } from './store/sqlite.ts';

const [command] = process.argv.slice(2);
if (command === 'help' || command === '--help' || command === '-h') {
  process.stdout.write(`simon-server: the SIMON reference server, configured by the environment.

  SIMON_ORIGIN=https://simon.example.com SIMON_SERVER_KEY=<alg>:<seed> simon-server

  SIMON_ORIGIN         this server's origin                                   required
  SIMON_SERVER_KEY     the signing key, <alg>:<base64url 32-byte seed>        or SIMON_SERVER_KEY_FILE
  SIMON_DB             the sqlite file (default simon.sqlite)
  SIMON_PORT           the port to listen on (default 8080)
  SIMON_DEV=1          development: http and local hosts, a throwaway key

Every setting: https://github.com/agnt-ai/simon-protocol/tree/main/server#readme
`);
  process.exit(0);
}
if (command !== undefined) {
  console.error(`simon-server: unknown command ${command}; "simon-server help" says how to run it.`);
  process.exit(2);
}

const config = loadConfig();
const store = new SqliteStore(config.database);
const server = createServer({ config, store, retiredAgentDocuments: config.retiredAgentDocuments });
const port = await server.listen();
console.error(JSON.stringify({ level: 'info', message: 'listening', origin: config.origin, port, dev: config.dev }));

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, async () => {
    await server.close();
    await store.close();
    process.exit(0);
  });
}
