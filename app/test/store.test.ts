/**
 * The server's Store contract, against MongoStore: the storage seam holds. And MongoStore's sync stream
 * under writers that stall, with the interleavings forced by holding its own collection calls: a reader
 * never moves its cursor past an entry still being written.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import type { StoredMessage } from 'simon-server';
import { storeContract, retractionCapacityContract } from 'simon-server/store-contract';
import type { Collection, Db, Document } from 'mongodb';
import { MongoStore } from '../src/store/mongo-store.ts';
import { freshDb, stopMongo } from './mongo.ts';

after(stopMongo);
storeContract('MongoStore', async () => new MongoStore(await freshDb()).init());
retractionCapacityContract('MongoStore', async limits =>
  new MongoStore(await freshDb(), async () => {}, { retractions: limits }).init(),
);

const T = '2026-10-15T00:00:00.000Z';

const message = (n: number): StoredMessage => ({
  id: String(n).padStart(64, '0'),
  message: {
    v: 1,
    from: 'ada@a.test',
    to: ['bob@b.test'],
    inReplyTo: null,
    parts: [],
    headers: {},
    sentAt: T,
  } as never,
  carrier: 'https://a.test',
  claims: [],
  signedClaims: null,
  receivedAt: T,
  expiresAt: '2099-01-01T00:00:00.000Z',
});

/** A promise that waits until it is opened. */
function gate() {
  let open!: () => void;
  const closed = new Promise<void>(resolve => (open = resolve));
  return { closed, open };
}

/** Settles once a call `held` holds for `key` (an inserted id, or `read`) has begun to wait. */
function reaching(hold: Hold, key: string): Promise<void> {
  const reached = gate();
  const before = hold.arrived;
  hold.arrived = k => {
    before?.(k);
    if (k === key) reached.open();
  };
  return reached.closed;
}

/** What `held` holds: inserts of some messages, reads while `reads` is set, and who to tell when one waits. */
type Hold = { inserts: Map<string, Promise<void>>; reads: Promise<void> | null; arrived?: (key: string) => void };

/**
 * A database whose `core.inbox` inserts of some messages, and its reads while `reads` is set, wait. Each
 * such call tells `arrived` first: the inserted id, or `read`.
 */
function held(db: Db, hold: Hold): Db {
  const inbox = (c: Collection<Document>) =>
    new Proxy(c, {
      get(target, name: keyof Collection) {
        if (name === 'insertOne') {
          return async (doc: Document, ...rest: []) => {
            hold.arrived?.(doc.id ?? doc._id);
            await hold.inserts.get(doc.id ?? doc._id);
            return target.insertOne(doc, ...rest);
          };
        }
        if (name === 'find') {
          return (...args: Parameters<Collection['find']>) => {
            const cursor = target.find(...args);
            const toArray = cursor.toArray.bind(cursor);
            cursor.toArray = async () => {
              if (hold.reads) hold.arrived?.('read');
              await hold.reads;
              return toArray();
            };
            return cursor;
          };
        }
        const value = target[name];
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
  return new Proxy(db, {
    get(target, name: keyof Db) {
      if (name === 'collection')
        return (n: string) =>
          ['core.inbox', 'core.messages'].includes(n) ? inbox(target.collection(n)) : target.collection(n);
      const value = target[name];
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

describe('MongoStore sync cursors', () => {
  /**
   * An inbox entry is written. A writer takes the next position and stalls before writing it; another
   * writes the one after. A reader after the first reads once while the stalled one is unwritten, then again
   * from where that page ends, once it is: the positions it saw, in order, counted from the first.
   * `readFirst`: the read began before the stalled position was handed out, and its query waited.
   * `aheadMs`: the reader's clock runs this far ahead of the database's.
   */
  async function cursorsSeen(o: { readFirst?: boolean; aheadMs?: number }): Promise<number[]> {
    const hold = { inserts: new Map<string, Promise<void>>(), reads: null as Promise<void> | null };
    const store = await new MongoStore(held(await freshDb(), hold)).init();
    for (const n of [1, 2, 3]) await store.putMessage(message(n), { arrivals: [] });
    await store.addToInbox('bob@b.test', message(1).id, T);
    const base = (await store.sync('bob@b.test', 0, 10, T)).cursor;
    const [reads, slow] = [gate(), gate()];
    hold.inserts.set(message(2).id, slow.closed);
    const realNow = Date.now.bind(Date);
    const read = () => store.sync('bob@b.test', base, 10, T);
    let page: ReturnType<typeof read> | null = null;
    if (o.readFirst) {
      hold.reads = reads.closed;
      const waiting = reaching(hold, 'read');
      page = read();
      await waiting;
    }
    const stalled = reaching(hold, message(2).id);
    const writing = store.addToInbox('bob@b.test', message(2).id, T);
    await stalled;
    await store.addToInbox('bob@b.test', message(3).id, T);
    const RealDate = Date;
    const ahead = o.aheadMs ?? 0;
    // The reader's whole clock runs ahead: Date.now and a new Date alike.
    globalThis.Date = class extends RealDate {
      constructor(...args: [number?]) {
        super(...((args.length ? args : [realNow() + ahead]) as [number]));
      }
      static now = () => realNow() + ahead;
    } as DateConstructor;
    reads.open();
    const first = await (page ?? read()).finally(() => (globalThis.Date = RealDate));
    hold.reads = null;
    slow.open();
    await writing;
    const rest = await store.sync('bob@b.test', first.cursor, 10, T);
    return [...first.messages, ...rest.messages].map(e => e.cursor - base);
  }

  it('never passes a cursor handed out after its read began and written after a later one', async () => {
    assert.deepEqual(await cursorsSeen({ readFirst: true }), [1, 2]);
  });

  it("judges a stalled writer by the database's clock, never by a reader whose clock runs ahead", async () => {
    assert.deepEqual(await cursorsSeen({ aheadMs: 61_000 }), [1, 2]);
  });

  it("passes a cursor whose writer crashed, once the database's clock says a minute has gone", async () => {
    const db = await freshDb();
    const store = await new MongoStore(db).init();
    for (const n of [1, 3]) await store.putMessage(message(n), { arrivals: [] });
    await store.addToInbox('bob@b.test', message(1).id, T);
    // A writer took cursor 2, long ago by the database's clock, and never wrote it.
    await db
      .collection('core.sequences')
      .updateOne({ _id: 'inbox' as never }, { $set: { n: 2, 'pending.2': new Date(0) } });
    await store.addToInbox('bob@b.test', message(3).id, T);
    assert.deepEqual(
      (await store.inbox('bob@b.test', 0, 10)).map(e => e.cursor),
      [1, 3],
    );
    const seq = await db.collection('core.sequences').findOne({ _id: 'inbox' as never });
    assert.deepEqual(Object.keys(seq!.pending), [], 'the abandoned cursor is dropped');
  });

  it('renumbers an entry whose slow writer found its cursor passed, so a reader continuing still finds it', async () => {
    const hold = { inserts: new Map<string, Promise<void>>(), reads: null as Promise<void> | null };
    const db = await freshDb();
    const store = await new MongoStore(held(db, hold)).init();
    for (const n of [1, 2, 3]) await store.putMessage(message(n), { arrivals: [] });
    await store.addToInbox('bob@b.test', message(1).id, T);
    const slow = gate();
    hold.inserts.set(message(2).id, slow.closed);
    const stalled = reaching(hold, message(2).id);
    const writing = store.addToInbox('bob@b.test', message(2).id, T);
    await stalled;
    // The writer of cursor 2 stalls past the minute, by the database's clock: a reader passes its cursor.
    await db.collection('core.sequences').updateOne({ _id: 'inbox' as never }, { $set: { 'pending.2': new Date(0) } });
    await store.addToInbox('bob@b.test', message(3).id, T);
    const first = (await store.inbox('bob@b.test', 1, 10)).map(e => e.cursor);
    assert.deepEqual(first, [3]);
    slow.open();
    assert.equal(await writing, true);
    const rest = await store.inbox('bob@b.test', 3, 10);
    assert.deepEqual(
      rest.map(e => [e.cursor, e.id]),
      [[4, message(2).id]],
      'written late, it appears above the cursor already returned',
    );
    const seq = await db.collection('core.sequences').findOne({ _id: 'inbox' as never });
    assert.deepEqual(Object.keys(seq!.pending), [], 'no cursor is left pending');
  });

  it(
    'repairs a failed renumber on the next reader call without duplicating the inbox entry',
    { timeout: 10_000 },
    async () => {
      const hold = { inserts: new Map<string, Promise<void>>(), reads: null as Promise<void> | null };
      const db = await freshDb();
      let failRenumber = true;
      const failing = new Proxy(held(db, hold), {
        get(target, name: keyof Db) {
          if (name !== 'collection') return Reflect.get(target, name);
          return (n: string) => {
            const c = target.collection(n);
            if (n !== 'core.inbox') return c;
            return new Proxy(c, {
              get(t, m: keyof Collection) {
                if (m === 'updateOne') {
                  return async (filter: Document, update: Document) => {
                    if (failRenumber && update.$set?.cursor !== undefined) {
                      failRenumber = false;
                      throw new Error('the database went away');
                    }
                    return t.updateOne(filter, update);
                  };
                }
                const v = t[m];
                return typeof v === 'function' ? v.bind(t) : v;
              },
            });
          };
        },
      });
      const store = await new MongoStore(failing).init();
      for (const n of [1, 2, 3]) await store.putMessage(message(n), { arrivals: [] });
      await store.addToInbox('bob@b.test', message(1).id, T);
      const slow = gate();
      hold.inserts.set(message(2).id, slow.closed);
      const stalled = reaching(hold, message(2).id);
      const writing = store.addToInbox('bob@b.test', message(2).id, T).catch(e => e);
      try {
        await stalled;
        await db
          .collection('core.sequences')
          .updateOne({ _id: 'inbox' as never }, { $set: { 'pending.2': new Date(0) } });
        await store.addToInbox('bob@b.test', message(3).id, T);
        assert.deepEqual(
          (await store.inbox('bob@b.test', 1, 10)).map(e => e.cursor),
          [3],
        );
        slow.open();
        assert.match(String(await writing), /went away/, 'the renumber failed');
        // Inspect directly: a Store reader would help settle this durable row before returning its page.
        const stranded = await db.collection('core.inbox').findOne({ id: message(2).id });
        const parent = await db.collection('core.messages').findOne({ _id: message(2).id as never });
        assert.equal(stranded!.cursor, 2);
        assert.equal(stranded!.settled, false);
        assert.equal(stranded!.messageGeneration, parent!.generation);
        const recovered = await store.inbox('bob@b.test', 3, 10);
        assert.deepEqual(
          recovered.map(e => e.id),
          [message(2).id],
        );
        assert.ok(recovered[0].cursor > 3, 'reader recovery moves the entry above every cursor already returned');
        // A duplicate arrival is idempotent and cannot move or re-emit the repaired entry.
        assert.equal(await store.addToInbox('bob@b.test', message(2).id, T), false);
        const repaired = await db.collection('core.inbox').findOne({ id: message(2).id });
        assert.equal(repaired!.cursor, recovered[0].cursor);
        assert.equal(repaired!.settled, true);
        assert.equal(repaired!.messageGeneration, parent!.generation);
        assert.deepEqual(await store.inbox('bob@b.test', recovered[0].cursor, 10), []);
        const seq = await db.collection('core.sequences').findOne({ _id: 'inbox' as never });
        assert.deepEqual(seq!.pending ?? {}, {}, 'failed and duplicate reservations are released');
        assert.deepEqual(seq!.committed ?? {}, {}, 'settled entries leave no bridge marker');
      } finally {
        slow.open();
        await writing;
      }
    },
  );

  it('repositions a sent entry and a publication when their writer outlives a passed reservation', async () => {
    for (const published of [false, true]) {
      const db = await freshDb();
      const hold = { inserts: new Map<string, Promise<void>>(), reads: null };
      const store = await new MongoStore(held(db, hold)).init();
      const first = { ...message(8), message: { ...message(8).message, to: published ? [] : ['bob@b.test'] } };
      const second = { ...message(9), message: { ...message(9).message, to: published ? [] : ['bob@b.test'] } };
      const slow = gate();
      hold.inserts.set(first.id, slow.closed);
      const stalled = reaching(hold, first.id);
      const writing = store.putMessage(first);
      await stalled;
      await db
        .collection('core.sequences')
        .updateOne({ _id: 'inbox' as never }, { $set: { 'pending.1': new Date(0) } });
      await store.putMessage(second);
      const page = await store.sync('ada@a.test', 0, 10, T);
      assert.deepEqual(
        page.messages.map(e => e.id),
        [second.id],
      );
      slow.open();
      await writing;
      const rest = await store.sync('ada@a.test', page.cursor, 10, T);
      assert.deepEqual(
        rest.messages.map(e => e.id),
        [first.id],
      );
      if (published) {
        assert.deepEqual(
          (await store.published('ada@a.test', null, 10)).records.map(r => r.message.id),
          [first.id, second.id],
        );
        assert.deepEqual(
          (await store.published('ada@a.test', second.id, 10)).records,
          [],
          'late publication cannot backfill beneath an already exposed publication',
        );
      }
    }
  });

  it('fences two duplicate helpers repairing an entry below a watermark already returned', async () => {
    const db = await freshDb();
    const store = await new MongoStore(db).init();
    await store.putMessage(message(7), { arrivals: [] });
    const heldMessage = await db.collection('core.messages').findOne({ _id: message(7).id as never });
    await db.collection('core.sequences').insertOne({ _id: 'inbox' as never, n: 1, pending: { '1': new Date(0) } });
    const page = await store.sync('bob@b.test', 0, 10, T);
    assert.equal(page.cursor, 1);
    await db.collection('core.inbox').insertOne({
      _id: `bob@b.test\n${message(7).id}\n${heldMessage!.generation}` as never,
      address: 'bob@b.test',
      id: message(7).id,
      messageGeneration: heldMessage!.generation,
      cursor: 1,
      settled: false,
      taken: new Date(T),
      event: true,
    });
    assert.deepEqual(await Promise.all([1, 2].map(() => store.addToInbox('bob@b.test', message(7).id, T))), [
      false,
      false,
    ]);
    const rest = await store.sync('bob@b.test', page.cursor, 10, T);
    assert.deepEqual(
      rest.messages.map(e => e.id),
      [message(7).id],
    );
    assert.ok(rest.messages[0].cursor > page.cursor);
    const seq = await db.collection('core.sequences').findOne({ _id: 'inbox' as never });
    assert.deepEqual(seq!.pending, {});
    assert.deepEqual(seq!.committed ?? {}, {});
  });

  it('recovers the bridge marker after a writer committed but stopped before settling its entry', async () => {
    const db = await freshDb();
    const store = await new MongoStore(db).init();
    await store.putMessage(message(6), { arrivals: [] });
    const m = await db.collection('core.messages').findOne({ _id: message(6).id as never });
    await db
      .collection('core.sequences')
      .insertOne({ _id: 'inbox' as never, n: 1, pending: {}, committed: { '1': true } });
    await db.collection('core.inbox').insertOne({
      _id: `bob@b.test\n${message(6).id}\n${m!.generation}` as never,
      address: 'bob@b.test',
      id: message(6).id,
      messageGeneration: m!.generation,
      cursor: 1,
      settled: false,
      taken: new Date(T),
      event: true,
    });
    const page = await store.sync('bob@b.test', 0, 10, T);
    assert.deepEqual(
      page.messages.map(e => e.id),
      [message(6).id],
    );
    const seq = await db.collection('core.sequences').findOne({ _id: 'inbox' as never });
    assert.deepEqual(seq!.committed ?? {}, {});
  });

  it('adds legacy-message inbox entries without BSON null generations', async () => {
    const db = await freshDb();
    const store = await new MongoStore(db).init();
    await store.putMessage(message(4), { arrivals: [] });
    await db.collection('core.messages').updateOne({ _id: message(4).id as never }, { $unset: { generation: '' } });
    assert.equal(await store.addToInbox('bob@b.test', message(4).id, T, 'legacy'), true);
    const entry = await db.collection('core.inbox').findOne({ id: message(4).id });
    assert.equal(Object.hasOwn(entry!, 'messageGeneration'), false);
    assert.equal(await store.inInbox('bob@b.test', message(4).id), true);
    assert.deepEqual(
      (await store.sync('bob@b.test', 0, 10, T)).messages.map(e => e.id),
      [message(4).id],
    );
  });

  it('reads and writes a counter an older version left, with its pending cursors as an array', async () => {
    const db = await freshDb();
    await db
      .collection('core.sequences')
      .insertOne({ _id: 'inbox' as never, n: 1, pending: [{ seq: 1, at: new Date(0) }] });
    await db.collection('core.inbox').insertOne({
      _id: `bob@b.test\n${message(1).id}` as never,
      cursor: 1,
      address: 'bob@b.test',
      id: message(1).id,
      receivedAt: T,
      event: false,
    });
    const legacy = message(1);
    await db.collection('core.messages').insertOne({
      _id: legacy.id as never,
      json: JSON.stringify(legacy.message),
      from: legacy.message.from,
      to: legacy.message.to,
      public: false,
      inReplyTo: null,
      carrier: legacy.carrier,
      claims: '[]',
      signedClaims: null,
      receivedAt: legacy.receivedAt,
      expires: new Date(legacy.expiresAt),
      parts: [],
      kept: true,
    });
    const store = await new MongoStore(db).init();
    const upgraded = await db.collection('core.sequences').findOne({ _id: 'inbox' as never });
    assert.deepEqual(upgraded!.pending, { '1': new Date(0) }, 'init preserves legacy reservations as a timestamp map');
    for (const n of [1, 2]) await store.putMessage(message(n), { arrivals: [] });
    await store.addToInbox('bob@b.test', message(2).id, T);
    assert.deepEqual(
      (await store.inbox('bob@b.test', 0, 10)).map(e => e.cursor),
      [1, 2],
    );
  });
});

describe('MongoStore key rewrites', () => {
  const at = (s: number) => `2026-10-15T00:00:0${s}.000Z`;
  const ada = {
    address: 'ada@a.test',
    kind: 'solo' as const,
    principal: null,
    keys: [{ key: 'k0', added: at(0), revoked: null }],
    mailbox: false,
    createdAt: at(0),
    retiredAt: null,
  };

  /** A store whose rewrite of ada's keys waits, after reading them, until `go` opens; and a plain one. */
  async function racing() {
    const db = await freshDb();
    const go = gate();
    const reached = gate();
    const agents = (c: Collection<Document>) =>
      new Proxy(c, {
        get(target, name: keyof Collection) {
          if (name === 'updateOne') {
            return async (filter: Document, ...rest: [Document]) => {
              // The slow store makes only the rewrite under test: hold its write, whatever its filter.
              reached.open();
              await go.closed;
              return target.updateOne(filter, ...rest);
            };
          }
          const value = target[name];
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
    const slow = new Proxy(db, {
      get(target, name: keyof Db) {
        if (name === 'collection')
          return (n: string) => (n === 'core.agents' ? agents(target.collection(n)) : target.collection(n));
        const value = target[name];
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const plain = await new MongoStore(db).init();
    await plain.createAgent(structuredClone(ada));
    return { slow: new MongoStore(slow), plain, go, reached: reached.closed };
  }

  it('revokes a key added while a recovery was computing the list, and keeps it', async () => {
    const { slow, plain, go, reached } = await racing();
    const replacing = slow.replaceKeys('ada@a.test', { key: 'k9', added: at(2), revoked: null });
    // The rewrite has read the list and is about to write it.
    await reached;
    assert.equal(await plain.addKey('ada@a.test', { key: 'k1', added: at(1), revoked: null }, 5), 'added');
    go.open();
    assert.equal(await replacing, 'replaced');
    assert.deepEqual(
      (await plain.agentByAddress('ada@a.test'))!.keys.map(k => [k.key, k.revoked]),
      [
        ['k0', at(2)],
        ['k1', at(2)],
        ['k9', null],
      ],
    );
  });

  it('revokes a key added while a retirement was computing the list', async () => {
    const { slow, plain, go, reached } = await racing();
    const retiring = slow.retireAgent('ada@a.test', at(2));
    // The rewrite has read the list and is about to write it.
    await reached;
    assert.equal(await plain.addKey('ada@a.test', { key: 'k1', added: at(1), revoked: null }, 5), 'added');
    go.open();
    await retiring;
    const agent = (await plain.agentByAddress('ada@a.test'))!;
    assert.equal(agent.retiredAt, at(2));
    assert.deepEqual(
      agent.keys.map(k => [k.key, k.revoked]),
      [
        ['k0', at(2)],
        ['k1', at(2)],
      ],
    );
  });

  it('keeps the first retirement time', async () => {
    const { plain } = await racing();
    await plain.retireAgent('ada@a.test', at(1));
    await plain.retireAgent('ada@a.test', at(2));
    assert.equal((await plain.agentByAddress('ada@a.test'))!.retiredAt, at(1));
  });

  it('keeps the first retirement time when another retirement lands while one computes', async () => {
    const { slow, plain, go, reached } = await racing();
    const retiring = slow.retireAgent('ada@a.test', at(2));
    await reached;
    await plain.retireAgent('ada@a.test', at(1));
    go.open();
    await retiring;
    const agent = (await plain.agentByAddress('ada@a.test'))!;
    assert.equal(agent.retiredAt, at(1));
    assert.deepEqual(
      agent.keys.map(k => [k.key, k.revoked]),
      [['k0', at(1)]],
    );
  });
});

describe('MongoStore journal incarnations', () => {
  it('keeps a stale copier invisible after delete/recreate and never recreates its accepted message', async () => {
    const db = await freshDb();
    const go = gate();
    const reached = gate();
    const delayed = new Proxy(db, {
      get(target, name: keyof Db) {
        if (name === 'collection')
          return (collection: string, ...options: []) => {
            const c = target.collection(collection, ...options);
            if (collection !== 'core.deliveries') return c;
            return new Proxy(c, {
              get(t, method: keyof Collection) {
                if (method === 'insertOne')
                  return async (doc: Document) => {
                    reached.open();
                    await go.closed;
                    return t.insertOne(doc);
                  };
                const value = t[method];
                return typeof value === 'function' ? value.bind(t) : value;
              },
            });
          };
        const value = target[name];
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const slow = await new MongoStore(delayed).init();
    const plain = await new MongoStore(db).init();
    const m = message(5);
    const delivery = {
      id: m.id,
      domain: 'b.test',
      recipients: ['bob@b.test'],
      hints: {},
      server: null,
      status: 'pending' as const,
      reason: null,
      attempts: 0,
      nextAttemptAt: T,
      createdAt: T,
      deadline: '2099-01-01T00:00:00.000Z',
    };
    const putting = slow.putMessage(m, { deliveries: [delivery] });
    await reached.closed;
    await plain.deleteMessage(m.id);
    const replacement = { ...m, carrier: 'https://new.test' };
    await plain.putMessage(replacement, { deliveries: [delivery] });
    go.open();
    assert.equal((await putting).carrier, m.carrier, 'the old caller returns its accepted record');
    assert.equal(
      (await plain.message(m.id))!.carrier,
      replacement.carrier,
      'it never restores its deleted incarnation',
    );
    assert.equal((await plain.deliveries(m.id)).length, 1);
    const claimed = await plain.claimDeliveries(T, 10, [], { token: 'current', until: '2098-01-01T00:00:00.000Z' });
    assert.equal(claimed.length, 1, 'a stale physical row never becomes work');
    await plain.sweep(T, T);
    assert.equal(
      await db.collection('core.deliveries').countDocuments({ id: m.id }),
      1,
      'sweep removes stale physical copies',
    );
  });
});

describe('MongoStore private recovery migration', () => {
  const ada = {
    address: 'ada@a.test',
    kind: 'solo' as const,
    principal: null,
    keys: [{ key: 'k0', added: T, revoked: null }],
    mailbox: true,
    createdAt: T,
    retiredAt: null,
  };
  const pending = { key: 'k1', hash: 'legacy-hash', completesAt: T };
  async function legacy() {
    const db = await freshDb();
    const store = await new MongoStore(db).init();
    await store.createAgent(ada);
    await db
      .collection('core.agents')
      .updateOne(
        { _id: ada.address as never },
        { $unset: { recoveryMigrated: '', recovery: '', authorityVersion: '' } },
      );
    await db
      .collection('core.values')
      .insertOne({ _id: `recovery\n${ada.address}` as never, value: JSON.stringify(pending), expires: null });
    return { db, store };
  }
  it('migrates legacy proof without exposing its private state or losing it on rejection', async () => {
    const { db, store } = await legacy();
    assert.deepEqual(await store.value('recovery', ada.address, T), pending);
    const agent = await store.agentByAddress(ada.address);
    assert.equal(Object.hasOwn(agent!, 'recovery'), false);
    assert.equal(Object.hasOwn(agent!, 'recoveryMigrated'), false);
    assert.equal(await db.collection('core.values').findOne({ _id: `recovery\n${ada.address}` as never }), null);
    assert.equal(
      await store.completeRecovery(ada.address, { key: 'k1', added: T, revoked: null }, pending, () => false),
      'too_many_keys',
    );
    assert.deepEqual(await store.value('recovery', ada.address, T), pending);
  });
  it('never imports an old proof after principal recovery completed while the importer was paused', async () => {
    const { db, store } = await legacy();
    const go = gate();
    const reached = gate();
    const delayed = new Proxy(db, {
      get(target, name: keyof Db) {
        if (name === 'collection')
          return (n: string) => {
            const c = target.collection(n);
            if (n !== 'core.values') return c;
            return new Proxy(c, {
              get(t, method: keyof Collection) {
                if (method === 'findOne')
                  return async (filter: Document) => {
                    const value = await t.findOne(filter);
                    reached.open();
                    await go.closed;
                    return value;
                  };
                const v = t[method];
                return typeof v === 'function' ? v.bind(t) : v;
              },
            });
          };
        const v = target[name];
        return typeof v === 'function' ? v.bind(target) : v;
      },
    });
    const slow = new MongoStore(delayed);
    const importing = slow.value('recovery', ada.address, T);
    await reached.closed;
    assert.equal(await store.keepOnlyKey(ada.address, 'k0', T), 'kept');
    go.open();
    assert.equal(await importing, null);
    assert.equal(await store.value('recovery', ada.address, T), null);
    assert.ok(((await store.agentByAddress(ada.address))!.authorityVersion ?? 0) > 0);
  });
});

describe('MongoStore recovery defense activation', () => {
  it(
    'cannot reinstall a proof when principal recovery wins while activation CAS is paused',
    { timeout: 10_000 },
    async t => {
      const db = await freshDb(),
        plain = await new MongoStore(db).init(),
        go = gate(),
        reached = gate();
      const address = 'ada@a.test',
        pending = { key: 'new', hash: 'hash', completesAt: T, defended: false };
      await plain.createAgent({
        address,
        kind: 'solo',
        principal: null,
        keys: [{ key: 'old', added: T, revoked: null }],
        mailbox: true,
        createdAt: T,
        retiredAt: null,
      });
      await plain.beginRecovery(address, pending, null, T);
      const delayed = new Proxy(db, {
        get(target, name: keyof Db) {
          if (name === 'collection')
            return (n: string) => {
              const c = target.collection(n);
              if (n !== 'core.agents') return c;
              return new Proxy(c, {
                get(t, method: keyof Collection) {
                  if (method === 'updateOne')
                    return async (filter: Document, update: Document) => {
                      if (update.$set?.recovery?.value && JSON.parse(update.$set.recovery.value).defended === true) {
                        reached.open();
                        await go.closed;
                      }
                      return t.updateOne(filter, update);
                    };
                  const v = t[method];
                  return typeof v === 'function' ? v.bind(t) : v;
                },
              });
            };
          const v = target[name];
          return typeof v === 'function' ? v.bind(target) : v;
        },
      });
      const activating = new MongoStore(delayed).activateRecovery(address, pending, T);
      const aborted = new Promise<never>((_, reject) =>
        t.signal.addEventListener('abort', () => reject(new Error('activation gate timed out')), { once: true }),
      );
      try {
        await Promise.race([
          reached.closed,
          aborted,
          activating.then(() => {
            throw new Error('activation settled before the forced gate');
          }),
        ]);
        assert.equal(await plain.keepOnlyKey(address, 'old', T), 'kept');
        go.open();
        assert.equal(await activating, false);
        assert.equal(await plain.value('recovery', address, T), null);
        assert.deepEqual((await plain.agentByAddress(address))!.authorizedKeys, ['old']);
      } finally {
        go.open();
        await activating.catch(() => {});
      }
    },
  );
});

describe('MongoStore durable retraction admission', () => {
  const retract = (n: number) => {
    const m = message(n);
    m.message = { ...m.message, inReplyTo: 'a'.repeat(64), headers: { rel: 'retract' } } as never;
    return m;
  };
  function intercept(
    db: Db,
    collection: string,
    method: string,
    run: (target: Collection<Document>, args: unknown[]) => Promise<unknown>,
  ): Db {
    return new Proxy(db, {
      get(target, name: keyof Db) {
        if (name === 'collection')
          return (n: string) => {
            const c = target.collection(n);
            if (n !== collection) return c;
            return new Proxy(c, {
              get(t, m: keyof Collection) {
                if (m === method) return (...args: unknown[]) => run(t, args);
                const v = t[m];
                return typeof v === 'function' ? v.bind(t) : v;
              },
            });
          };
        const v = target[name];
        return typeof v === 'function' ? v.bind(target) : v;
      },
    });
  }
  it('recovers acceptance after a crash before the core copy and preserves suppression immediately', async () => {
    const db = await freshDb(),
      plain = await new MongoStore(db).init();
    const delayed = intercept(db, 'core.messages', 'insertOne', async () => {
      throw new Error('crashed before copy');
    });
    const slow = new MongoStore(delayed),
      m = retract(901);
    await assert.rejects(
      slow.putMessage(m, { arrivals: [{ id: m.id, recipient: 'bob@b.test', hints: {}, attempts: 0, dueAt: T }] }),
      /crashed before copy/,
    );
    assert.equal(await plain.listingRetracted('bob@b.test', 'a'.repeat(64), m.message.from), true);
    assert.deepEqual(await plain.message(m.id), m);
    assert.equal((await plain.arrivals(T, 10)).length, 1);
  });
  it('never restores an accepted retraction deleted while its original copier was paused', async () => {
    const db = await freshDb(),
      plain = await new MongoStore(db).init(),
      go = gate(),
      reached = gate();
    const slow = new MongoStore(
      intercept(db, 'core.messages', 'insertOne', async (c, args) => {
        reached.open();
        await go.closed;
        return c.insertOne(args[0] as Document);
      }),
    );
    const m = retract(902),
      putting = slow.putMessage(m, {
        arrivals: [{ id: m.id, recipient: 'bob@b.test', hints: {}, attempts: 0, dueAt: T }],
      });
    await reached.closed;
    await plain.deleteMessage(m.id);
    go.open();
    await putting;
    assert.equal(await plain.message(m.id), null);
    assert.equal((await plain.arrivals(T, 10)).length, 0);
    assert.equal(await plain.listingRetracted('bob@b.test', 'a'.repeat(64), m.message.from), true);
    await plain.putMessage(m);
    assert.equal(await plain.message(m.id), null);
  });
  it('does not repeat an arrival after a paused journal copier resumes behind settlement', async () => {
    const db = await freshDb(),
      plain = await new MongoStore(db).init(),
      go = gate(),
      reached = gate();
    const slow = new MongoStore(
      intercept(db, 'core.arrivals', 'insertOne', async (c, args) => {
        reached.open();
        await go.closed;
        return c.insertOne(args[0] as Document);
      }),
    );
    const m = retract(903),
      putting = slow.putMessage(m, {
        arrivals: [{ id: m.id, recipient: 'bob@b.test', hints: {}, attempts: 0, dueAt: T }],
      });
    await reached.closed;
    const [pending] = await plain.arrivals(T, 10);
    assert.ok(pending);
    await plain.arrivalDone(m.id, 'bob@b.test', true, pending.generation);
    go.open();
    await putting;
    assert.equal((await plain.arrivals(T, 10)).length, 0);
  });
  it('retains inbox admission while its insertion is paused and the last false arrival settles', async () => {
    const db = await freshDb(),
      plain = await new MongoStore(db).init(),
      go = gate(),
      reached = gate(),
      m = retract(905);
    await plain.putMessage(m, { arrivals: [{ id: m.id, recipient: 'bob@b.test', hints: {}, attempts: 0, dueAt: T }] });
    const slow = new MongoStore(
      intercept(db, 'core.inbox', 'insertOne', async (c, args) => {
        reached.open();
        await go.closed;
        return c.insertOne(args[0] as Document);
      }),
    );
    const admitting = slow.addToInbox('ada@a.test', m.id, T);
    await reached.closed;
    assert.equal(await plain.arrivalDone(m.id, 'bob@b.test', false), null);
    assert.ok(await plain.message(m.id));
    go.open();
    assert.equal(await admitting, true);
    assert.equal(await plain.inInbox('ada@a.test', m.id), true);
  });
  it('does not let a stale last-drop receipt overwrite a concurrent kept arrival', async () => {
    const db = await freshDb(),
      plain = await new MongoStore(db).init(),
      go = gate(),
      reached = gate(),
      m = retract(906);
    await plain.putMessage(m, {
      arrivals: ['bob@b.test', 'cat@c.test'].map(recipient => ({
        id: m.id,
        recipient,
        hints: {},
        attempts: 0,
        dueAt: T,
      })),
    });
    const slow = new MongoStore(
      intercept(db, 'core.retraction_admission', 'updateOne', async (c, args) => {
        const next = JSON.parse((args[1] as { $set: { body: string } }).$set.body)[m.id];
        if (next && !next.kept && !next.outstandingArrivals.includes('bob@b.test')) {
          reached.open();
          await go.closed;
        }
        return c.updateOne(args[0] as Document, args[1] as Document);
      }),
    );
    const dropping = slow.arrivalDone(m.id, 'bob@b.test', false);
    await reached.closed;
    assert.equal(await plain.arrivalDone(m.id, 'cat@c.test', true), 'kept');
    go.open();
    assert.equal(await dropping, null);
    assert.ok(await plain.message(m.id));
    assert.equal((await plain.arrivals(T, 10)).length, 0);
  });
  it('ignores an opposite-result duplicate after that recipient consumed its terminal grant', async () => {
    const db = await freshDb(),
      store = await new MongoStore(db).init(),
      m = retract(909);
    await store.putMessage(m, {
      arrivals: ['bob@b.test', 'cat@c.test'].map(recipient => ({
        id: m.id,
        recipient,
        hints: {},
        attempts: 0,
        dueAt: T,
      })),
    });
    assert.equal(await store.arrivalDone(m.id, 'bob@b.test', false), null);
    assert.equal(
      await store.arrivalDone(m.id, 'bob@b.test', true),
      null,
      'stale opposite settlement cannot mutate core outside ledger authority',
    );
    assert.equal(await store.arrivalDone(m.id, 'cat@c.test', false), 'dropped');
    assert.equal(await store.message(m.id), null);
    assert.equal(await store.listingRetracted('bob@b.test', 'a'.repeat(64), m.message.from), true);
  });
  it('recovers a terminal receipt after crashing between its ledger CAS and core arrival copy', async () => {
    const db = await freshDb(),
      plain = await new MongoStore(db).init(),
      m = retract(907);
    await plain.putMessage(m, { arrivals: [{ id: m.id, recipient: 'bob@b.test', hints: {}, attempts: 0, dueAt: T }] });
    const slow = new MongoStore(
      intercept(db, 'core.arrivals', 'updateOne', async () => {
        throw new Error('crashed after terminal CAS');
      }),
    );
    await assert.rejects(slow.arrivalDone(m.id, 'bob@b.test', true), /crashed after terminal CAS/);
    assert.equal((await plain.arrivals(T, 10)).length, 0);
    assert.ok(await plain.message(m.id));
    await plain.putMessage(m, { arrivals: [{ id: m.id, recipient: 'bob@b.test', hints: {}, attempts: 0, dueAt: T }] });
    assert.equal((await plain.arrivals(T, 10)).length, 0);
  });
  it('fences an expiry scan captured before inbox retention was extended', async () => {
    const db = await freshDb(),
      plain = await new MongoStore(db).init(),
      go = gate(),
      reached = gate(),
      m = { ...retract(908), expiresAt: '2026-10-16T00:00:00.000Z' };
    await plain.putMessage(m, { arrivals: [] });
    const delayed = new Proxy(db, {
      get(target, name: keyof Db) {
        if (name === 'collection')
          return (n: string) => {
            const c = target.collection(n);
            if (n !== 'core.messages') return c;
            return new Proxy(c, {
              get(t, method: keyof Collection) {
                if (method === 'find')
                  return (...args: Parameters<Collection['find']>) => {
                    const cursor = t.find(...args),
                      read = cursor.toArray.bind(cursor);
                    cursor.toArray = async () => {
                      const docs = await read();
                      if ((args[0] as Document)?.expires?.$lte && docs.length) {
                        reached.open();
                        await go.closed;
                      }
                      return docs;
                    };
                    return cursor;
                  };
                const v = t[method];
                return typeof v === 'function' ? v.bind(t) : v;
              },
            });
          };
        const v = target[name];
        return typeof v === 'function' ? v.bind(target) : v;
      },
    });
    const sweep = new MongoStore(delayed).sweep('2026-10-17T00:00:00.000Z', T);
    await reached.closed;
    assert.equal(await plain.addToInbox('bob@b.test', m.id, T, undefined, '2026-10-24T00:00:00.000Z'), true);
    go.open();
    await sweep;
    assert.equal((await plain.message(m.id))!.expiresAt, '2026-10-24T00:00:00.000Z');
    assert.equal(await plain.inInbox('bob@b.test', m.id), true);
  });
  it('returns the atomic fetch enqueue snapshot even if a worker deletes the row immediately', async () => {
    const db = await freshDb();
    await new MongoStore(db).init();
    const store = new MongoStore(
      intercept(db, 'core.fetches', 'findOneAndUpdate', async (c, args) => {
        const row = await c.findOneAndUpdate(args[0] as Document, args[1] as Document, args[2] as never);
        await c.deleteOne(args[0] as Document);
        return row;
      }),
    );
    const f = await store.queueFetch({
      sha256: 'f'.repeat(64),
      carrier: 'https://a.test',
      size: 1,
      attempts: 0,
      dueAt: T,
    });
    assert.equal(f.sha256, 'f'.repeat(64));
    assert.ok(f.generation);
  });
  it('flags ambiguous legacy history permanently and excludes accounts created after the migration checkpoint', async () => {
    const db = await freshDb(),
      m = message(904);
    const ada = {
      _id: 'ada@a.test',
      kind: 'solo',
      principal: null,
      keys: [{ key: 'old', added: T, revoked: null }],
      mailbox: true,
      createdAt: T,
      retiredAt: null,
    };
    await db.collection('core.agents').insertOne(ada as Document);
    await db.collection('core.messages').insertOne({
      _id: m.id,
      json: JSON.stringify(m.message),
      from: m.message.from,
      to: m.message.to,
      public: false,
      inReplyTo: null,
      carrier: m.carrier,
      claims: '[]',
      signedClaims: null,
      receivedAt: T,
      expires: new Date(m.expiresAt),
      parts: [],
      kept: true,
    } as Document);
    const store = await new MongoStore(db).init();
    assert.equal(await store.value('sync-history-gap', ada._id, T), true);
    await store.createAgent({
      address: 'new@a.test',
      kind: 'solo',
      principal: null,
      keys: [{ key: 'new', added: T, revoked: null }],
      mailbox: false,
      createdAt: T,
      retiredAt: null,
    });
    await new MongoStore(db).init();
    assert.equal(await store.value('sync-history-gap', 'new@a.test', T), null);
    assert.equal(await store.value('sync-history-gap', ada._id, T), true);
  });
});

describe('MongoStore reads bounded by what they return', () => {
  it('fills an inbox page past entries whose message is gone, in cursor order', async () => {
    const db = await freshDb();
    const store = await new MongoStore(db).init();
    const ids: string[] = [];
    for (let n = 2000; n < 2040; n++) {
      await store.putMessage(message(n), { arrivals: [] });
      await store.addToInbox('bob@b.test', message(n).id, T);
      ids.push(message(n).id);
    }
    // Every message but each fifth goes, leaving its entry behind, as a paused copier can.
    const live = ids.filter((_, i) => i % 5 === 4);
    await db.collection('core.messages').deleteMany({ _id: { $in: ids.filter(id => !live.includes(id)) as never[] } });
    const seen: string[] = [];
    for (let after = 0, pages = 0; pages < 10; pages++) {
      const page = await store.inbox('bob@b.test', after, 3);
      if (!page.length) break;
      assert.ok(page.length === 3 || seen.length + page.length === live.length, 'a page is full unless it is the last');
      seen.push(...page.map(e => e.id));
      after = page.at(-1)!.cursor;
    }
    assert.deepEqual(seen, live);
  });

  it('finds the parts held for an agent from its own entries, those an older version wrote included', async () => {
    const db = await freshDb();
    const store = await new MongoStore(db).init();
    const sha = 'e'.repeat(64);
    const named = {
      ...message(2100),
      message: { ...message(2100).message, parts: [{ type: 'application/pdf', sha256: sha, size: 3 }] } as never,
      carrier: 'https://c.test',
    };
    await store.putMessage(named, { arrivals: [] });
    await store.addToInbox('bob@b.test', named.id, T);
    assert.deepEqual(await store.heldFor(sha, 'bob@b.test', 'https://a.test'), [
      { carrier: 'https://c.test', size: 3 },
    ]);
    assert.deepEqual(await store.heldFor(sha, 'eve@b.test', 'https://a.test'), []);
    await db.collection('core.inbox').updateMany({}, { $unset: { parts: '' } });
    const again = await new MongoStore(db).init();
    assert.deepEqual(await again.heldFor(sha, 'bob@b.test', 'https://a.test'), [
      { carrier: 'https://c.test', size: 3 },
    ]);
  });

  it('sweeps entries left behind their message, a slice at a time', async () => {
    const db = await freshDb();
    const store = await new MongoStore(db).init();
    await store.putMessage(message(2200), { arrivals: [] });
    await store.addToInbox('bob@b.test', message(2200).id, T);
    await store.putMessage(message(2201), { arrivals: [] });
    await store.addToInbox('bob@b.test', message(2201).id, T);
    await db.collection('core.messages').deleteOne({ _id: message(2200).id as never });
    await store.sweep(T, T);
    assert.deepEqual(
      (await db.collection('core.inbox').find({}).toArray()).map(e => e.id),
      [message(2201).id],
    );
  });
});
