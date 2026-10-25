/**
 * The SIMON reference server's Store on MongoDB and Amazon DocumentDB: `MongoStore`, the `core.*`
 * collections the server keeps, and `connect`, a client that reads from the primary with a bounded pool.
 *
 *   const { client, db } = await connect(process.env.SIMON_MONGO_URI!, 'simon', { appName: 'simon' });
 *   const store = await new MongoStore(db, () => client.close()).init();
 *   createServer({ config: loadConfig(), store }).listen();
 */
export { MongoStore, isIndexBuildConflict, type IndexBuildRetry, type MongoStoreOptions } from './mongo-store.ts';
export { connect, insertOnce, isDuplicate, upsert, DEFAULT_POOL, type ConnectOptions } from './db.ts';
