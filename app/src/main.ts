/**
 * The application as a process: `node app/src/main.ts`. Configuration comes from the environment (the
 * basic server's variables and this application's, app/README.md); storage is the MongoDB it names.
 */
import { createApp } from './app.ts';
import { loadAppConfig } from './config.ts';
import { connect } from './store/db.ts';

const config = loadAppConfig();
const { client, db } = await connect(config.mongo.uri, config.mongo.db);
const app = createApp({ config, db });
await app.start();
const port = await app.server.listen();
console.error(
  JSON.stringify({ level: 'info', message: 'listening', origin: config.server.origin, port, modules: config.modules }),
);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, async () => {
    await app.close();
    await client.close();
    process.exit(0);
  });
}
