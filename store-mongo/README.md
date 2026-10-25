# @agnt-sdk/simon-store-mongo

The [SIMON reference server](../server/README.md)'s `Store` on MongoDB and Amazon DocumentDB. It passes
the same Store contract as the server's own SQLite store (`@agnt-sdk/simon-server/contract`).

```sh
npm install @agnt-sdk/simon-server @agnt-sdk/simon-store-mongo mongodb
```

Node 24.6.0 or later. `mongodb` (the driver, 7.6 or a later 7.x) is a peer dependency: the store uses the
copy the application has, so the `Db` an application passes and the errors the store recognises come from
one driver.

## A server on MongoDB

```ts
import { createServer, loadConfig } from '@agnt-sdk/simon-server';
import { connect, MongoStore } from '@agnt-sdk/simon-store-mongo';

const { client, db } = await connect(process.env.SIMON_MONGO_URI!, 'simon', { appName: 'simon' });
const store = await new MongoStore(db, () => client.close()).init();
const config = loadConfig(); // SIMON_ORIGIN, SIMON_SERVER_KEY, ... (the server's README)
const server = createServer({ config, store });
await server.listen();
```

`MongoStore` keeps the server's records in the `core.*` collections of the database it is given, so an
application can keep its own collections beside them under another prefix.

## `connect(uri, database, options?)`

Opens a `MongoClient` and answers `{ client, db }`. Reads are always from the primary, whatever the
connection string says: the store reads what it just wrote. Passing another `readPreference` throws.

| Option          | Default | What it does                                                           |
| --------------- | ------- | ---------------------------------------------------------------------- |
| `maxPoolSize`   | 10      | connections this process opens at most                                 |
| `minPoolSize`   | 0       | connections kept open while idle                                       |
| `maxIdleTimeMS` | 60000   | an idle connection is closed after this long                           |
| `appName`       | none    | the name the database shows for this client's connections and queries |

Any other `MongoClientOptions` may be passed too. With many processes on one DocumentDB instance, size
`maxPoolSize` so that processes times pool stays under the instance's connection limit. DocumentDB needs
`retryWrites=false` in its connection string, and TLS with its CA bundle (`tls=true&tlsCAFile=...`).

## `new MongoStore(db, close?, options?)` and `init()`

`close` is what the store's `close()` runs: the client's own close for a store that owns its client.
`init()` creates the indexes the store's rules rest on and upgrades records an earlier version left; run
it once per process at startup, before serving. Several processes may run it at once against one
database: DocumentDB builds one index on a collection at a time and refuses a second build meanwhile, so a
refused build is tried again after a jittered, doubling wait (`options.indexBuilds`: `attempts` 12,
`delayMs` 250, `maxDelayMs` 5000). An index another process made first is simply found there. Any other
refusal, a conflicting index definition for instance, fails `init()` at once.

`options.retractions` sets the limits on stored listing retractions (the server's `RetractionCapacity`).

## DocumentDB

Every rule is a single-document write with plain update operators (`$set`, `$setOnInsert`, `$inc`,
`$max`, `$unset`, `$currentDate`) or a unique index; the one aggregation is a plain
`$match`/`$sort`/`$group`/`$limit` read. The store uses no update pipelines, `$merge`, `$setWindowFields`,
`$function`, sessions or transactions, and reads only from the primary. A duplicate is recognised by the unique index it hit, from the error's
key pattern or, when a server sends none, from the index's default name (`isDuplicate(error, field)`).

## Several processes on one database

What the server's background work claims through the store is safe to run in several processes at once;
some of it is not claimed yet. See "Running several copies" in
[docs/REFERENCE-SERVER.md](../docs/REFERENCE-SERVER.md) before running more than one worker.

## Exports

- `MongoStore`, `MongoStoreOptions`, `IndexBuildRetry`, `isIndexBuildConflict`
- `connect`, `ConnectOptions`, `DEFAULT_POOL`
- `isDuplicate(error, field?)`, `insertOnce(write, field?)`, `upsert(write)`: duplicate-key handling for
  an application's own collections
- `@agnt-sdk/simon-store-mongo/testing`: `freshDb()`, `stopMongo()` and `mongoUri()`, a fresh database per
  store on an in-memory MongoDB (`mongodb-memory-server`, an optional peer dependency, installed by the
  application that tests with it; `MONGOMS_VERSION` picks its version, default 7.0.24), or on a real
  deployment when `SIMON_TEST_MONGO_URI` is set, each test database named `simon_contract_<pid>_<n>` and
  dropped when the tests stop

```ts
import { after } from 'node:test';
import { storeContract } from '@agnt-sdk/simon-server/contract';
import { MongoStore } from '@agnt-sdk/simon-store-mongo';
import { freshDb, stopMongo } from '@agnt-sdk/simon-store-mongo/testing';

after(stopMongo);
storeContract('MongoStore', async () => new MongoStore(await freshDb()).init());
```

```sh
npm test -w store-mongo                                                    # in-memory MongoDB
SIMON_TEST_MONGO_URI='mongodb://...' node --test store-mongo/test/store.test.ts   # a real deployment
```
