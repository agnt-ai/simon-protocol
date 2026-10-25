/**
 * Startup on a shared database: several processes run MongoStore.init() at once, as a fleet booting
 * together does, and each ends with every index in place; an index build refused because another holds the
 * collection (DocumentDB builds one at a time) is tried again, and any other refusal is not. And `connect`:
 * a bounded pool by default, reads from the primary always.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { MongoServerError, type Db } from 'mongodb';
import { connect, isIndexBuildConflict, MongoStore } from '../src/index.ts';
import { freshDb, mongoUri, stopMongo } from '../src/testing.ts';

after(stopMongo);

/** Every index, by collection, as `name` lists. */
async function indexes(db: Db) {
  const all: Record<string, string[]> = {};
  for (const { name } of await db.listCollections({}, { nameOnly: true }).toArray())
    all[name] = (await db.collection(name).indexes()).map(i => String(i.name)).sort();
  return all;
}

/**
 * `db`, but `core.messages` refuses its first `refusals` index builds with `error`; `builds` counts the tries.
 */
function refusing(db: Db, refusals: number, error: () => Error) {
  const seen = { builds: 0 };
  const proxy = {
    collection(name: string, options?: object) {
      const c = db.collection(name, options);
      if (name !== 'core.messages') return c;
      return new Proxy(c, {
        get(target, prop) {
          if (prop === 'createIndex')
            return async (...args: Parameters<typeof target.createIndex>) => {
              seen.builds++;
              if (refusals-- > 0) throw error();
              return target.createIndex(...args);
            };
          const value = Reflect.get(target, prop, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
    },
  } as unknown as Db;
  return { db: proxy, seen };
}

const quick = { indexBuilds: { delayMs: 1, maxDelayMs: 5 } };
const inProgress = () =>
  new MongoServerError({
    code: 303,
    errmsg:
      'Existing index build in progress on the same collection. Collection is limited to a single index build at a time.',
  });

describe('MongoStore.init on a shared database', () => {
  it('ends with every index in place when several processes run it at once', async () => {
    const db = await freshDb();
    const alone = await freshDb();
    await new MongoStore(alone).init();
    const expected = await indexes(alone);
    await Promise.all([new MongoStore(db).init(), new MongoStore(db).init(), new MongoStore(db).init()]);
    assert.deepEqual(await indexes(db), expected);
    assert.ok(expected['core.messages']!.length > 5, 'the store keeps its indexes on core.messages');
    // Run again, it changes nothing.
    await new MongoStore(db).init();
    assert.deepEqual(await indexes(db), expected);
  });

  it('tries again an index build another build refused, then goes on', async () => {
    const real = await freshDb();
    const { db, seen } = refusing(real, 3, inProgress);
    await new MongoStore(db, async () => {}, quick).init();
    const made = await indexes(real);
    assert.ok(made['core.messages']!.includes('expires_1'));
    assert.equal(seen.builds, 3 + made['core.messages']!.length - 1, 'three refusals, then each index once');
  });

  it('stops trying after its attempts, with the refusal', async () => {
    const { db, seen } = refusing(await freshDb(), 100, inProgress);
    await assert.rejects(
      new MongoStore(db, async () => {}, { indexBuilds: { attempts: 4, delayMs: 1, maxDelayMs: 1 } }).init(),
      /index build in progress/,
    );
    assert.equal(seen.builds, 4);
  });

  it('never tries again an index definition the database refuses', async () => {
    const conflict = () =>
      new MongoServerError({ code: 85, codeName: 'IndexOptionsConflict', errmsg: 'options differ' });
    const { db, seen } = refusing(await freshDb(), 1, conflict);
    await assert.rejects(new MongoStore(db, async () => {}, quick).init(), /options differ/);
    assert.equal(seen.builds, 1);
  });

  it('reads a build conflict by name, number or words, and nothing else', () => {
    const error = (o: object) => new MongoServerError({ errmsg: 'refused', ...o });
    assert.ok(isIndexBuildConflict(error({ codeName: 'IndexBuildAlreadyInProgress' })));
    assert.ok(isIndexBuildConflict(error({ code: 12587 })));
    assert.ok(isIndexBuildConflict(inProgress()));
    assert.ok(!isIndexBuildConflict(error({ code: 85, codeName: 'IndexOptionsConflict' })));
    assert.ok(!isIndexBuildConflict(error({ code: 11000 })));
    assert.ok(!isIndexBuildConflict(new Error('index build in progress')), 'only a server error');
  });
});

describe('connect', () => {
  it('opens a bounded pool by default, and reads from the primary', async () => {
    const { client } = await connect(await mongoUri(), 'simon_connect');
    try {
      assert.equal(client.options.maxPoolSize, 10);
      assert.equal(client.options.minPoolSize, 0);
      assert.equal(client.options.maxIdleTimeMS, 60_000);
      assert.equal(client.readPreference.mode, 'primary');
    } finally {
      await client.close();
    }
  });

  it('takes the pool and name it is given, and keeps primary reads over a connection string', async () => {
    const uri = new URL(await mongoUri());
    uri.searchParams.set('readPreference', 'secondaryPreferred');
    const { client, db } = await connect(uri.href, 'simon_connect', {
      maxPoolSize: 3,
      minPoolSize: 1,
      maxIdleTimeMS: 5000,
      appName: 'simon-test',
    });
    try {
      assert.equal(db.databaseName, 'simon_connect');
      assert.equal(client.options.maxPoolSize, 3);
      assert.equal(client.options.minPoolSize, 1);
      assert.equal(client.options.maxIdleTimeMS, 5000);
      assert.equal(client.options.appName, 'simon-test');
      assert.equal(client.readPreference.mode, 'primary');
    } finally {
      await client.close();
    }
  });

  it('refuses another read preference', async () => {
    await assert.rejects(
      connect(await mongoUri(), 'simon_connect', { readPreference: 'secondary' } as never),
      /primary only/,
    );
  });
});
