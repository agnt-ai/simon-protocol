/**
 * One in-memory MongoDB per test process, and a fresh database for each server or store a test makes.
 * With SIMON_TEST_MONGO_URI set, a real deployment instead (DocumentDB, say): each database is named
 * simon_contract_<pid>_<n> and dropped when the tests stop.
 */
import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient, type Db } from 'mongodb';

let started: Promise<{ server: MongoMemoryServer | null; client: MongoClient }> | null = null;
let databases = 0;
const made: string[] = [];

export async function freshDb(): Promise<Db> {
  const starting = (started ??= (async () => {
    const uri = process.env.SIMON_TEST_MONGO_URI;
    if (uri) return { server: null, client: await MongoClient.connect(uri) };
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
