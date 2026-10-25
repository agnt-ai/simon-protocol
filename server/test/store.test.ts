/** The Store contract, against the sqlite store, and what only the sqlite store does: its schema's upgrades. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { describe, it } from 'node:test';
import type { Message } from '@agnt-sdk/simon-protocol';
import { VERSION } from '@agnt-sdk/simon-protocol';
import type { StoredMessage } from '../src/store/store.ts';
import { SqliteStore } from '../src/store/sqlite.ts';
import { retractionCapacityContract, storeContract } from '../src/store/contract.ts';

storeContract('sqlite :memory:', () => new SqliteStore(':memory:'));
retractionCapacityContract('sqlite :memory:', limits => new SqliteStore(':memory:', { retractions: limits }));

// The actual schema-4 layout from incoming 7cad5048, not a current database with its version relabelled.
// Schema 3 differed here only by the agents.unpairing column. Both used an AUTOINCREMENT inbox.
const HISTORICAL_SCHEMA_4 = `
CREATE TABLE agents (address TEXT PRIMARY KEY, kind TEXT NOT NULL, principal TEXT, mailbox INTEGER NOT NULL,
  created_at TEXT NOT NULL, retired_at TEXT, unpairing TEXT);
CREATE TABLE agent_keys (key TEXT PRIMARY KEY, address TEXT NOT NULL, added TEXT NOT NULL, revoked TEXT,
  seq INTEGER NOT NULL);
CREATE INDEX agent_keys_address ON agent_keys (address);
CREATE TABLE messages (id TEXT PRIMARY KEY, json TEXT NOT NULL, from_address TEXT NOT NULL, public INTEGER NOT NULL,
  in_reply_to TEXT, carrier TEXT NOT NULL, claims TEXT NOT NULL, signed_claims TEXT, received_at TEXT NOT NULL,
  expires INTEGER NOT NULL, kept INTEGER NOT NULL);
CREATE INDEX messages_expires ON messages (expires);
CREATE INDEX messages_published ON messages (from_address) WHERE public = 1;
CREATE INDEX messages_in_reply_to ON messages (in_reply_to);
CREATE TABLE message_parts (id TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, PRIMARY KEY (id, sha256));
CREATE INDEX message_parts_sha ON message_parts (sha256);
CREATE TABLE arrivals (id TEXT NOT NULL, recipient TEXT NOT NULL, hints TEXT NOT NULL, attempts INTEGER NOT NULL,
  due INTEGER NOT NULL, PRIMARY KEY (id, recipient));
CREATE INDEX arrivals_due ON arrivals (due);
CREATE TABLE inbox (cursor INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL, id TEXT NOT NULL,
  received_at TEXT NOT NULL, event INTEGER NOT NULL, UNIQUE (address, id));
CREATE INDEX inbox_id ON inbox (id);
CREATE INDEX inbox_events ON inbox (cursor) WHERE event = 1;
CREATE TABLE deliveries (id TEXT NOT NULL, domain TEXT NOT NULL, recipients TEXT NOT NULL, hints TEXT NOT NULL,
  server TEXT, status TEXT NOT NULL, reason TEXT, attempts INTEGER NOT NULL, next_attempt INTEGER NOT NULL,
  created_at TEXT NOT NULL, deadline TEXT NOT NULL, lease TEXT, PRIMARY KEY (id, domain));
CREATE INDEX deliveries_due ON deliveries (status, next_attempt);
CREATE TABLE parts (sha256 TEXT NOT NULL, source TEXT NOT NULL, fetched INTEGER NOT NULL, size INTEGER NOT NULL,
  bytes BLOB NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (sha256, source));
CREATE TABLE fetches (sha256 TEXT NOT NULL, carrier TEXT NOT NULL, size INTEGER NOT NULL, attempts INTEGER NOT NULL,
  due INTEGER NOT NULL, PRIMARY KEY (sha256, carrier));
CREATE INDEX fetches_due ON fetches (due);
CREATE TABLE marks (scope TEXT NOT NULL, id TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY (scope, id));
CREATE TABLE counters (scope TEXT NOT NULL, id TEXT NOT NULL, n INTEGER NOT NULL, expires INTEGER NOT NULL,
  PRIMARY KEY (scope, id));
CREATE TABLE vals (scope TEXT NOT NULL, id TEXT NOT NULL, value TEXT NOT NULL, expires INTEGER,
  PRIMARY KEY (scope, id));
PRAGMA user_version = 4;
`;
const T0 = Date.parse('2026-10-15T12:00:00.000Z');
const at = (offset = 0) => new Date(T0 + offset).toISOString();
const recipient = 'reader@upgrade.test';

function stored(id: string, expiresAt = '2099-01-01T00:00:00.000Z'): StoredMessage & { message: Message } {
  return {
    id: id.repeat(64),
    message: {
      v: VERSION,
      from: 'author@remote.test',
      to: [recipient],
      inReplyTo: null,
      parts: [{ type: 'text/plain', data: id }],
      headers: {},
      sentAt: at(),
      signature: 'AA',
    },
    carrier: 'https://remote.test',
    claims: [],
    signedClaims: null,
    receivedAt: at(),
    expiresAt,
  };
}

function historicalFile(file: string, version: 3 | 4, retainInbox: boolean) {
  const db = new DatabaseSync(file);
  try {
    db.exec(
      version === 4
        ? HISTORICAL_SCHEMA_4
        : HISTORICAL_SCHEMA_4.replace(', unpairing TEXT', '').replace(
            'PRAGMA user_version = 4;',
            'PRAGMA user_version = 3;',
          ),
    );
    db.prepare(
      'INSERT INTO agents(address,kind,principal,mailbox,created_at,retired_at) VALUES(?, ?, NULL, 0, ?, NULL)',
    ).run(recipient, 'solo', at());
    db.prepare('INSERT INTO agent_keys VALUES(?, ?, ?, NULL, 0)').run('historical-key', recipient, at());
    const write = (m: StoredMessage) =>
      db
        .prepare('INSERT INTO messages VALUES(?, ?, ?, 0, NULL, ?, ?, NULL, ?, ?, 1)')
        .run(m.id, JSON.stringify(m.message), m.message.from, m.carrier, '[]', m.receivedAt, Date.parse(m.expiresAt));
    const expired = stored('e', at(-1));
    write(expired);
    db.prepare('INSERT INTO inbox(cursor,address,id,received_at,event) VALUES(9000, ?, ?, ?, 0)').run(
      recipient,
      expired.id,
      at(-1000),
    );
    if (retainInbox) {
      const retained = stored('a');
      write(retained);
      db.prepare('INSERT INTO inbox(cursor,address,id,received_at,event) VALUES(71, ?, ?, ?, 0)').run(
        recipient,
        retained.id,
        at(),
      );
    }
    // A real old retention pass deleted its expired row but AUTOINCREMENT remembered cursor 9000.
    db.prepare('DELETE FROM inbox WHERE id = ?').run(expired.id);
    db.prepare('DELETE FROM messages WHERE id = ?').run(expired.id);
    assert.equal((db.prepare("SELECT seq FROM sqlite_sequence WHERE name='inbox'").get() as { seq: number }).seq, 9000);
  } finally {
    db.close();
  }
}

describe('the sqlite schema', () => {
  for (const version of [3, 4] as const)
    for (const retained of [false, true]) {
      it(`upgrades real schema ${version} with ${retained ? 'a surviving inbox below' : 'no inbox rows below'} its deleted high-water mark, then reopens`, async () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'simon-legacy-highwater-'));
        const file = path.join(dir, 'simon.sqlite');
        let store: SqliteStore | null = null;
        try {
          historicalFile(file, version, retained);
          store = new SqliteStore(file);
          const first = await store.sync(recipient, 0, 10, at());
          assert.equal(first.cursor, 9000, 'deleted positions are never reused during migration');
          assert.deepEqual(
            first.messages.map(e => [e.cursor, e.id, e.receivedAt]),
            retained ? [[71, 'a'.repeat(64), at()]] : [],
            'existing inbox receipt time and position survive conversion',
          );
          assert.equal((await store.agentByAddress(recipient))?.unpairing, null);
          const record = stored('b');
          await store.putMessage(record, {
            arrivals: [{ id: record.id, recipient, hints: {}, attempts: 0, dueAt: at() }],
          });
          assert.equal(await store.addToInbox(recipient, record.id, at()), true);
          await store.arrivalDone(record.id, recipient, true);
          const admitted = await store.sync(recipient, first.cursor, 10, at());
          assert.deepEqual(
            admitted.messages.map(e => e.id),
            [record.id],
            'a checkpoint issued before upgrade sees the first new admission',
          );
          assert.ok(admitted.messages[0].cursor > 9000);
          await store.close();
          store = null;
          const inspector = new DatabaseSync(file);
          try {
            assert.equal((inspector.prepare('PRAGMA user_version').get() as { user_version: number }).user_version, 10);
          } finally {
            inspector.close();
          }
          store = new SqliteStore(file);
          assert.deepEqual(
            (await store.sync(recipient, admitted.cursor, 10, at())).messages,
            [],
            'reopening does not replay settled positions',
          );
          const next = stored('c');
          await store.putMessage(next, {
            arrivals: [{ id: next.id, recipient, hints: {}, attempts: 0, dueAt: at(1) }],
          });
          assert.equal(await store.addToInbox(recipient, next.id, at(1)), true);
          await store.arrivalDone(next.id, recipient, true);
          const reopened = await store.sync(recipient, admitted.cursor, 10, at(1));
          assert.deepEqual(
            reopened.messages.map(e => e.id),
            [next.id],
          );
          assert.ok(reopened.messages[0].cursor > admitted.cursor, 'reopen preserves the new high-water mark too');
        } finally {
          await store?.close();
          fs.rmSync(dir, { recursive: true, force: true });
        }
      });
    }

  it('imports a retained legacy retraction arrival once across upgrade, completion and duplicate replay', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'simon-retraction-upgrade-'));
    const file = path.join(dir, 'simon.sqlite');
    try {
      historicalFile(file, 4, false);
      const record = stored('b');
      record.message = { ...record.message, inReplyTo: 'c'.repeat(64), headers: { rel: 'retract' } };
      const db = new DatabaseSync(file);
      db.prepare(
        'INSERT INTO messages(id,json,from_address,public,in_reply_to,carrier,claims,signed_claims,received_at,expires,kept) VALUES(?,?,?,0,?,?,?,NULL,?,?,0)',
      ).run(
        record.id,
        JSON.stringify(record.message),
        record.message.from,
        'c'.repeat(64),
        record.carrier,
        '[]',
        record.receivedAt,
        Date.parse(record.expiresAt),
      );
      db.prepare('INSERT INTO arrivals VALUES(?,?,?,0,?)').run(record.id, recipient, '{}', T0);
      db.close();
      let store = new SqliteStore(file);
      const [queued] = await store.arrivals(at(), 10);
      assert.equal(queued.arrival.id, record.id);
      assert.equal(await store.arrivalDone(record.id, recipient, true, queued.generation), 'kept');
      await store.close();
      store = new SqliteStore(file);
      try {
        assert.deepEqual(
          await store.putMessage(record, {
            arrivals: [{ id: record.id, recipient, hints: {}, attempts: 0, dueAt: at() }],
          }),
          record,
        );
        assert.deepEqual(
          await store.arrivals(at(), 10),
          [],
          'a duplicate cannot recreate the completed imported arrival',
        );
        assert.equal(await store.listingRetracted(recipient, 'c'.repeat(64), record.message.from), true);
      } finally {
        await store.close();
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('upgrades a file of schema 8, which kept no recovery epoch, in place', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'simon-schema-'));
    const file = path.join(dir, 'simon.sqlite');
    try {
      const made = new SqliteStore(file);
      await made.createAgent({
        address: 'ada@a.test',
        kind: 'solo',
        principal: null,
        keys: [{ key: 'k1', added: '2026-10-15T00:00:00.000Z', revoked: null }],
        mailbox: true,
        createdAt: '2026-10-15T00:00:00.000Z',
        retiredAt: null,
      });
      await made.close();
      const db = new DatabaseSync(file);
      db.exec('ALTER TABLE agents DROP COLUMN recovery_epoch; PRAGMA user_version = 8;');
      db.close();

      const store = new SqliteStore(file);
      assert.equal((await store.agentByAddress('ada@a.test'))?.recoveryEpoch, undefined);
      assert.equal(await store.keepOnlyKey('ada@a.test', 'k1', '2026-10-16T00:00:00.000Z'), 'kept');
      assert.equal((await store.agentByAddress('ada@a.test'))?.recoveryEpoch, 1);
      await store.close();
      const db2 = new DatabaseSync(file);
      assert.equal((db2.prepare('PRAGMA user_version').get() as { user_version: number }).user_version, 10);
      db2.close();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses to open a file of schema 9 that holds a wire version 1 message, and opens one that holds none', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'simon-schema-'));
    const file = path.join(dir, 'simon.sqlite');
    try {
      await new SqliteStore(file).close();
      const db = new DatabaseSync(file);
      db.exec('PRAGMA user_version = 9;');
      db.close();
      await new SqliteStore(file).close();
      const old = new DatabaseSync(file);
      const json =
        '{"from":"ada@a.test","headers":{},"inReplyTo":null,"parts":[],"sentAt":"2026-10-15T00:00:00Z","signature":"AA","to":["bob@b.test"],"v":1}';
      old
        .prepare(
          'INSERT INTO messages(id,json,from_address,public,carrier,claims,received_at,expires,kept,generation) VALUES(?,?,?,?,?,?,?,?,?,?)',
        )
        .run('a'.repeat(64), json, 'ada@a.test', 0, 'https://a.test', '[]', '2026-10-15T00:00:00Z', 0, 1, 'g');
      old.exec('PRAGMA user_version = 9;');
      old.close();
      assert.throws(() => new SqliteStore(file), /wire version 1/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('upgrades a file of schema 3, which kept no unpairing, in place', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'simon-schema-'));
    const file = path.join(dir, 'simon.sqlite');
    try {
      const made = new SqliteStore(file);
      await made.createAgent({
        address: 'ada@a.test',
        kind: 'paired',
        principal: 'simon-key:x',
        keys: [{ key: 'k1', added: '2026-10-15T00:00:00.000Z', revoked: null }],
        mailbox: false,
        createdAt: '2026-10-15T00:00:00.000Z',
        retiredAt: null,
      });
      await made.close();
      const db = new DatabaseSync(file);
      db.exec('ALTER TABLE agents DROP COLUMN unpairing; PRAGMA user_version = 3;');
      db.close();

      const store = new SqliteStore(file);
      assert.equal((await store.agentByAddress('ada@a.test'))?.unpairing, null);
      await store.retireAgent('ada@a.test', '2026-10-16T00:00:00.000Z', 'UNPAIRING');
      assert.equal((await store.agentByAddress('ada@a.test'))?.unpairing, 'UNPAIRING');
      await store.close();
      const db2 = new DatabaseSync(file);
      assert.equal((db2.prepare('PRAGMA user_version').get() as { user_version: number }).user_version, 10);
      // What a second process sees when it read schema 3 just before the first upgraded the file: the column is
      // there, the version it read is 3. It opens the file without upgrading it again.
      db2.exec('PRAGMA user_version = 3;');
      db2.close();
      const second = new SqliteStore(file);
      assert.equal((await second.agentByAddress('ada@a.test'))?.unpairing, 'UNPAIRING');
      await second.close();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
