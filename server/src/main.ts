#!/usr/bin/env node
/**
 * The server as a process: `node server/src/main.ts`. Configuration comes from the environment (see
 * config.ts or README.md); storage is the sqlite file AGNT_DB.
 */
import { loadConfig } from './config.ts';
import { createServer } from './server.ts';
import { SqliteStore } from './store/sqlite.ts';

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
