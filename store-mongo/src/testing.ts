/**
 * Databases for tests of a MongoDB store, or of an application on one: one in-memory MongoDB per test
 * process (mongodb-memory-server, an optional peer dependency, loaded only then) and a fresh database for
 * each store a test makes. With SIMON_TEST_MONGO_URI set, a real deployment instead (DocumentDB, say): each
 * database is named simon_contract_<pid>_<n> and dropped when the tests stop. MONGOMS_VERSION picks the
 * in-memory server's version (default 7.0.24).
 *
 *   import { freshDb, stopMongo } from '@agnt-sdk/simon-store-mongo/testing';
 *   after(stopMongo);
 *   storeContract('MongoStore', async () => new MongoStore(await freshDb()).init());
 */
import { MongoClient, type Db } from 'mongodb';

interface Running {
  server: { getUri(): string; stop(): Promise<unknown> } | null;
  client: MongoClient;
}

let started: Promise<Running> | null = null;
let databases = 0;
const made: string[] = [];

export async function freshDb(): Promise<Db> {
  const starting = (started ??= (async () => {
    const uri = process.env.SIMON_TEST_MONGO_URI;
    if (uri) return { server: null, client: await MongoClient.connect(uri, { readPreference: 'primary' }) };
    const { MongoMemoryServer } = await import('mongodb-memory-server');
    const server = await MongoMemoryServer.create({ binary: { version: process.env.MONGOMS_VERSION ?? '7.0.24' } });
    try {
      return { server, client: await MongoClient.connect(server.getUri()) };
    } catch (error) {
      try {
        await server.stop();
      } finally {
        throw error;
      }
    }
  })());
  const { server, client } = await starting.catch(error => {
    if (started === starting) started = null;
    throw error;
  });
  const name = server ? `simon_test_${process.pid}_${++databases}` : `simon_contract_${process.pid}_${++databases}`;
  if (!server) made.push(name);
  return client.db(name);
}

/** The connection string of the database freshDb uses, once it has started: for a test's own clients. */
export async function mongoUri(): Promise<string> {
  await freshDb();
  const { server } = await started!;
  return server ? server.getUri() : process.env.SIMON_TEST_MONGO_URI!;
}

export async function stopMongo() {
  const stopping = started;
  if (!stopping) return;
  started = null;
  const { server, client } = await stopping;
  try {
    for (const name of made.splice(0))
      await client
        .db(name)
        .dropDatabase()
        .catch(e => console.warn(`could not drop test database ${name}: ${e.message}`));
    await client.close();
  } finally {
    await server?.stop();
  }
}
