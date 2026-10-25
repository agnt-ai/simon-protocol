/** Synthetic old-layout files, real signing, and the actual offline copy/CLI; no production data. */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  canonicalBytes,
  generateKey,
  messageId,
  MINIMUM_LIMITS,
  sha256Hex,
  signMessage,
  signRequest,
  verifyMessage,
  type AnyMessage,
  type Message,
  type Part,
  VERSION,
} from '@agnt-sdk/simon-protocol';
import { defineConfig } from '../src/config.ts';
import { createServer } from '../src/server.ts';
import {
  createSqliteV2Candidate,
  SqliteMigrationRefusal,
  SqliteV2CleanupFailure,
} from '../src/store/sqlite-migration.ts';
import { SqliteStore } from '../src/store/sqlite.ts';
import { toRequest } from '../src/testing.ts';

const T = '2026-10-20T12:00:00.000Z';
const DUE = Date.parse('2026-10-20T13:00:00.000Z');
const EXPIRES = Date.parse('2099-01-01T00:00:00.000Z');
const LEGACY_SQL = fs.readFileSync(new URL('./fixtures/sqlite-v2.sql', import.meta.url), 'utf8');
const CLI = fileURLToPath(new URL('../scripts/migrate-sqlite-v2.ts', import.meta.url));
const digest = (value: string) => crypto.createHash('sha256').update(value).digest('hex');
interface FutureMessage extends AnyMessage {
  opaqueFutureInterior: { parts: Part[]; inReplyTo: string };
}

function fixture() {
  const directory = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'simon-v2-synthetic-'));
  const source = path.join(directory, 'simon.sqlite');
  const outbox = path.join(directory, 'app-arrivals.sqlite');
  const core = new DatabaseSync(source);
  core.exec(LEGACY_SQL);
  core.exec('PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;');
  const app = new DatabaseSync(outbox);
  app.exec(`CREATE TABLE arrivals(key TEXT PRIMARY KEY,domain TEXT NOT NULL,body TEXT NOT NULL,since INTEGER NOT NULL);
    CREATE INDEX arrivals_by_domain ON arrivals(domain); PRAGMA user_version=1;
    PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;`);
  const serverKey = generateKey();
  const readerKey = generateKey();
  const foreign = generateKey();
  const address = 'reader@local.example';
  core.prepare('INSERT INTO agents VALUES(?,?,?,?,?,?)').run(address, 'solo', null, 1, T, null);
  core.prepare('INSERT INTO agent_keys VALUES(?,?,?,?,?)').run(readerKey.key, address, T, null, 1);
  const bytes = Buffer.from('WAL-only synthetic attachment');
  const part = { type: 'application/octet-stream', sha256: sha256Hex(bytes), size: bytes.length };
  const carrier = 'https://remote.example';
  function message(parts: Part[], headers: Record<string, string> = {}, inReplyTo: string | null = null) {
    const signed = signMessage<Message>(
      {
        v: VERSION,
        from: 'author@remote.example',
        to: [address],
        sentAt: T,
        inReplyTo,
        parts,
        headers,
      },
      foreign.privateKey,
    );
    assert.ok(verifyMessage(signed, [{ key: foreign.key, added: T, revoked: null }]));
    return signed;
  }
  function keep(m: AnyMessage, rowid: number) {
    const id = messageId(m);
    core
      .prepare(
        'INSERT INTO messages(rowid,id,json,from_address,public,carrier,claims,received_at,expires,kept) VALUES(?,?,?,?,?,?,?,?,?,?)',
      )
      .run(
        rowid,
        id,
        JSON.stringify(m),
        m.from,
        m.to.length === 0 ? 1 : 0,
        carrier,
        '[{"type":"synthetic"}]',
        T,
        EXPIRES,
        1,
      );
    return id;
  }
  const original = message([part, { type: 'text/plain', data: 'WAL-only synthetic message' }]);
  const id = keep(original, 17);
  core.prepare('INSERT INTO message_parts VALUES(?,?,?)').run(id, part.sha256, part.size);
  core
    .prepare('INSERT INTO parts VALUES(?,?,?,?,?,?)')
    .run(part.sha256, carrier, 1, bytes.length, bytes, Date.parse(T));
  core.prepare('INSERT INTO inbox(cursor,address,id,received_at,event) VALUES(?,?,?,?,?)').run(4, address, id, T, 1);
  core.prepare("UPDATE sqlite_sequence SET seq=100 WHERE name='inbox'").run();
  const relation = message(
    [{ type: 'text/plain', data: 'Synthetic listed relation' }],
    { rel: 'comment', listed: 'yes' },
    id,
  );
  const relationId = keep(relation, 33);
  const retract = message([], { rel: 'retract' }, relationId);
  const retractId = keep(retract, 48);
  core
    .prepare('INSERT INTO arrivals(rowid,id,recipient,hints,attempts,due) VALUES(?,?,?,?,?,?)')
    .run(91, id, address, '{}', 3, DUE);
  core
    .prepare('INSERT INTO arrivals(rowid,id,recipient,hints,attempts,due) VALUES(?,?,?,?,?,?)')
    .run(11, retractId, address, '{}', 4, DUE);
  core
    .prepare('INSERT INTO deliveries VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
    .run(
      retractId,
      'elsewhere.example',
      '["recipient@elsewhere.example"]',
      '{}',
      null,
      'pending',
      null,
      3,
      DUE,
      T,
      '2026-10-27T12:00:00.000Z',
      'old-lease-preserved',
    );
  const fetches = [sha256Hex(Buffer.from('a')), sha256Hex(Buffer.from('b'))].sort().reverse();
  for (const [index, sha] of fetches.entries())
    core
      .prepare('INSERT INTO fetches(rowid,sha256,carrier,size,attempts,due) VALUES(?,?,?,?,?,?)')
      .run(index + 8, sha, carrier, 1, 7, DUE);
  core.prepare('INSERT INTO marks VALUES(?,?,?)').run('nonce', `${readerKey.key}\nsynthetic-nonce`, EXPIRES);
  core
    .prepare('INSERT INTO counters VALUES(?,?,?,?)')
    .run('files:give-up-rounds', `${fetches[0]}\n${carrier}`, 29, EXPIRES);
  core.prepare('INSERT INTO counters VALUES(?,?,?,?)').run('code-attempt', 'old-binding', 4, EXPIRES);
  core.prepare('INSERT INTO vals VALUES(?,?,?,?)').run('server-key-added', serverKey.key, JSON.stringify(T), null);
  core.prepare('INSERT INTO vals VALUES(?,?,?,?)').run('app:custom', 'private-id', '{"text":"é","n":7}', null);
  core.prepare('INSERT INTO vals VALUES(?,?,?,?)').run('code', `${address}\n${readerKey.key}`, 'null', null);
  core.prepare('INSERT INTO vals VALUES(?,?,?,?)').run('recovery', address, 'null', null);
  const firstBody = JSON.stringify({ v: 1, address, id, receivedAt: T });
  const secondBody = JSON.stringify({
    v: 2,
    address,
    id: retractId,
    receivedAt: T,
    from: retract.from,
    inReplyTo: relationId,
  });
  app
    .prepare('INSERT INTO arrivals(rowid,key,domain,body,since) VALUES(?,?,?,?,?)')
    .run(47, `${address}\n${id}`, 'local.example', firstBody, Date.parse(T));
  app
    .prepare('INSERT INTO arrivals(rowid,key,domain,body,since) VALUES(?,?,?,?,?)')
    .run(3, `${address}\n${retractId}`, 'local.example', secondBody, Date.parse(T));
  const fenceFile = path.join(directory, 'host-maintenance.fence');
  const fenceToken = crypto.randomBytes(24).toString('base64url');
  fs.writeFileSync(fenceFile, fenceToken, { mode: 0o600 });
  const maintenanceFile = path.join(directory, 'maintenance.json');
  const maintenance = {
    v: 1,
    id: 'synthetic-maintenance-identity',
    origin: 'https://local.example',
    serverKey: serverKey.key,
    serverKeyFingerprint: digest(serverKey.key),
    configDigest: '1'.repeat(64),
    toolCommit: '2'.repeat(40),
    observedAt: T,
    clockProvenance: 'Synthetic trusted fixture clock',
    hostStopped: true,
    callbacksDrained: true,
    appOutboxStopped: true,
    fenceFile,
    fenceToken,
    limits: MINIMUM_LIMITS,
  };
  const writeMaintenance = () => fs.writeFileSync(maintenanceFile, JSON.stringify(maintenance), { mode: 0o600 });
  writeMaintenance();
  const options = { source, directory: path.join(directory, 'bundle'), maintenanceFile };
  return {
    directory,
    source,
    outbox,
    core,
    app,
    serverKey,
    readerKey,
    foreign,
    address,
    id,
    relationId,
    retractId,
    original,
    part,
    bytes,
    fetches,
    carrier,
    message,
    keep,
    options,
    maintenance,
    writeMaintenance,
    close() {
      core.close();
      app.close();
      fs.rmSync(directory, { recursive: true, force: true });
    },
  };
}

const refused = (code: string) => (error: unknown) => error instanceof SqliteMigrationRefusal && error.code === code;

it('copies actual schema2 raw state, WAL cohort, row order, tombstones, null sent history and stable fences', async () => {
  const f = fixture();
  try {
    assert.ok(fs.statSync(f.source + '-wal').size > 0, 'committed rows are still in WAL');
    const before = f.core.prepare('SELECT rowid,* FROM messages ORDER BY rowid').all();
    const outboxBefore = f.app.prepare('SELECT rowid,* FROM arrivals ORDER BY rowid').all();
    const result = await createSqliteV2Candidate(f.options);
    assert.equal(result.status, 'VERIFIED_COPY_HELD');
    assert.equal(result.activationBlocked, true);
    assert.ok(result.holds.includes('historical_suppression_not_proven'));
    assert.ok(result.holds.includes('terminal_policy_history_and_host_adapter_unverified'));
    assert.equal(result.highWatermark, 100);
    assert.equal(result.usableHeadroom, Number.MAX_SAFE_INTEGER - 101);
    assert.equal(result.archivedTombstones.length, 2);
    assert.deepEqual(f.core.prepare('SELECT rowid,* FROM messages ORDER BY rowid').all(), before);
    assert.deepEqual(f.app.prepare('SELECT rowid,* FROM arrivals ORDER BY rowid').all(), outboxBefore);
    assert.equal(f.core.prepare('PRAGMA user_version').get()!.user_version, 2);
    const candidateFile = path.join(f.options.directory, result.candidate.core);
    const destination = new DatabaseSync(candidateFile);
    try {
      assert.equal(destination.prepare('PRAGMA user_version').get()!.user_version, 9);
      const copied = destination
        .prepare(
          'SELECT rowid,id,json,from_address,public,carrier,claims,received_at,expires,kept FROM messages ORDER BY rowid',
        )
        .all();
      assert.deepEqual(copied, before);
      const sent = destination.prepare('SELECT DISTINCT cursor,taken,signed_claims FROM messages').all();
      assert.deepEqual(
        sent.map(row => [row.cursor, row.taken, row.signed_claims]),
        [[null, null, null]],
      );
      const inbox = destination.prepare('SELECT cursor,taken,event FROM inbox').get()!;
      assert.deepEqual([inbox.cursor, inbox.taken, inbox.event], [4, Date.parse(T), 1]);
      assert.equal(destination.prepare('SELECT n FROM positions').get()!.n, 100);
      assert.equal(
        destination.prepare('SELECT value FROM vals WHERE scope=?').get('app:custom')!.value,
        '{"text":"é","n":7}',
      );
      assert.equal(destination.prepare("SELECT count(*) n FROM vals WHERE scope IN ('code','recovery')").get()!.n, 0);
      assert.equal(destination.prepare("SELECT n FROM counters WHERE scope='files:give-up-rounds'").get()!.n, 29);
      assert.equal(destination.prepare('SELECT lease FROM deliveries').get()!.lease, 'old-lease-preserved');
      assert.deepEqual(
        destination.prepare('SELECT rowid,id FROM arrivals ORDER BY due,rowid').all(),
        f.core.prepare('SELECT rowid,id FROM arrivals ORDER BY due,rowid').all(),
      );
      assert.deepEqual(
        destination.prepare('SELECT rowid,sha256,attempts,due FROM fetches ORDER BY due,rowid').all(),
        f.core.prepare('SELECT rowid,sha256,attempts,due FROM fetches ORDER BY due,rowid').all(),
      );
      const fences = destination.prepare('SELECT DISTINCT revision,token,exhausted FROM fetches').all();
      assert.deepEqual(
        fences.map(row => [row.revision, row.token, row.exhausted]),
        [[0, null, null]],
      );
      const generations = destination
        .prepare('SELECT generation FROM messages UNION ALL SELECT generation FROM fetches')
        .all();
      assert.equal(new Set(generations.map(row => row.generation)).size, generations.length);
    } finally {
      destination.close();
    }
    const copiedOutbox = new DatabaseSync(path.join(f.options.directory, result.candidate.outbox));
    try {
      assert.deepEqual(copiedOutbox.prepare('SELECT rowid,* FROM arrivals ORDER BY rowid').all(), outboxBefore);
      assert.equal(copiedOutbox.prepare('PRAGMA user_version').get()!.user_version, 1);
    } finally {
      copiedOutbox.close();
    }
    for (const name of Object.keys(result.hashes))
      assert.equal(fs.statSync(path.join(f.options.directory, name)).mode & 0o777, 0o600);
    const again = await createSqliteV2Candidate(f.options);
    assert.deepEqual(again, result, 'same verified frozen cohort reuses exact generations without duplicate jobs');
    const archive = new DatabaseSync(path.join(f.options.directory, result.snapshots.core));
    try {
      assert.equal(archive.prepare("SELECT count(*) n FROM vals WHERE scope IN ('code','recovery')").get()!.n, 2);
    } finally {
      archive.close();
    }
  } finally {
    f.close();
  }
});

it('keeps schema2 refused by the normal Store and gives every legacy device an explicit history gap', async () => {
  const f = fixture();
  let store: SqliteStore | undefined;
  let server: ReturnType<typeof createServer> | undefined;
  let otherOrigin: ReturnType<typeof createServer> | undefined;
  try {
    assert.throws(() => new SqliteStore(f.source), /schema 2, not 9/);
    const secondDevice = generateKey();
    f.core.prepare('INSERT INTO agent_keys VALUES(?,?,?,?,?)').run(secondDevice.key, f.address, T, null, 2);
    const otherKey = generateKey();
    const otherAddress = 'other@local.example';
    f.core.prepare('INSERT INTO agents VALUES(?,?,?,?,?,?)').run(otherAddress, 'solo', null, 1, T, null);
    f.core.prepare('INSERT INTO agent_keys VALUES(?,?,?,?,?)').run(otherKey.key, otherAddress, T, null, 1);
    const result = await createSqliteV2Candidate(f.options);
    store = new SqliteStore(path.join(f.options.directory, result.candidate.core));
    assert.equal(await store.listingRetracted(f.address, f.relationId, 'author@remote.example'), true);
    const config = defineConfig({
      origin: f.maintenance.origin,
      hostedDomains: ['local.example'],
      serverKey: f.serverKey.privateKey,
      dev: true,
    });
    server = createServer({ config, store, worker: false, now: () => new Date(T), log: () => {} });
    const call = async (
      since?: string,
      key = f.readerKey,
      address = f.address,
      application = server!,
      origin = config.origin,
    ) => {
      const url = new URL('/simon/sync', origin);
      if (since !== undefined) url.searchParams.set('since', since);
      const headers = signRequest(key.privateKey, {
        method: 'GET',
        url: url.href,
        agent: address,
        now: Date.parse(T),
      });
      return application.handle(toRequest('GET', url, headers, Buffer.alloc(0), '192.0.2.8'));
    };
    const first = await call();
    const second = await call(undefined, secondDevice);
    for (const response of [first, second]) {
      assert.equal(response.status, 410);
      const body = response.json as { code: string; details: { reason: string; resumeToken: string } };
      assert.equal(body.code, 'token_expired');
      assert.equal(body.details.reason, 'history_migration');
      assert.equal(typeof body.details.resumeToken, 'string');
    }
    const token = (first.json as { details: { resumeToken: string } }).details.resumeToken;
    assert.equal((await call('4')).status, 410, 'old numeric cursors do not become authenticated tokens');
    assert.equal((await call(token, otherKey, otherAddress)).status, 410, 'a checkpoint is bound to its account');
    const otherConfig = defineConfig({
      origin: 'https://different.example',
      hostedDomains: ['local.example'],
      serverKey: f.serverKey.privateKey,
      dev: true,
    });
    otherOrigin = createServer({ config: otherConfig, store, worker: false, now: () => new Date(T), log: () => {} });
    const moved = await call(token, f.readerKey, f.address, otherOrigin, otherConfig.origin);
    assert.equal(moved.status, 410, 'a checkpoint is bound to its origin');
    const resumed = await call(token);
    assert.equal(resumed.status, 200);
    const body = resumed.json as { messages: { id: string }[] };
    assert.deepEqual(
      body.messages.map(entry => entry.id),
      [f.id],
      'only actually retained received stream rows replay',
    );
    assert.equal(await store.addToInbox(f.address, f.relationId, T), true);
    const db = new DatabaseSync(path.join(f.options.directory, result.candidate.core));
    try {
      assert.equal(db.prepare('SELECT cursor FROM inbox WHERE id=?').get(f.relationId)!.cursor, 101);
    } finally {
      db.close();
    }
    assert.equal((await call()).status, 410, 'one device never clears another device history warning');
  } finally {
    await server?.close();
    await otherOrigin?.close();
    await store?.close();
    f.close();
  }
});

for (const expiry of [Date.parse(T) - 1, Date.parse(T), Date.parse(T) + 1, null])
  for (const scope of ['code', 'recovery'])
    it(`blocks non-null legacy ${scope} regardless expiry=${expiry}`, async () => {
      const f = fixture();
      try {
        const value = JSON.stringify({
          key: f.readerKey.key,
          hash: 'private-code-hash',
          nonce: 'private-code-nonce',
          completesAt: '2026-10-23T12:00:00.000Z',
        });
        f.core.prepare('UPDATE vals SET value=?,expires=? WHERE scope=?').run(value, expiry, scope);
        await assert.rejects(createSqliteV2Candidate(f.options), refused('legacy_challenge_or_recovery'));
        assert.equal(f.core.prepare('SELECT value FROM vals WHERE scope=?').get(scope)!.value, value);
        assert.ok(fs.existsSync(path.join(f.options.directory, 'source-core.sqlite')));
        assert.equal(fs.existsSync(path.join(f.options.directory, '004-VERIFIED.json')), false);
        assert.equal(fs.existsSync(path.join(f.options.directory, 'candidate')), false);
      } finally {
        f.close();
      }
    });

for (const boundary of [Number.MAX_SAFE_INTEGER - 1, Number.MAX_SAFE_INTEGER, 2n ** 53n])
  it(`refuses unusable stream headroom without renumbering: ${boundary}`, async () => {
    const f = fixture();
    try {
      f.core.prepare("UPDATE sqlite_sequence SET seq=? WHERE name='inbox'").run(boundary);
      await assert.rejects(
        createSqliteV2Candidate(f.options),
        (error: unknown) =>
          error instanceof SqliteMigrationRefusal && ['stream_headroom', 'unsafe_integer'].includes(error.code),
      );
      assert.equal(f.core.prepare('SELECT cursor FROM inbox').get()!.cursor, 4);
    } finally {
      f.close();
    }
  });

it('preserves the final usable position and refuses the strict publication rowid sentinel', async () => {
  const f = fixture();
  try {
    f.core.prepare("UPDATE sqlite_sequence SET seq=? WHERE name='inbox'").run(Number.MAX_SAFE_INTEGER - 2);
    const result = await createSqliteV2Candidate(f.options);
    assert.equal(result.usableHeadroom, 1);
    f.core.prepare('UPDATE messages SET rowid=? WHERE id=?').run(Number.MAX_SAFE_INTEGER, f.id);
    await assert.rejects(
      createSqliteV2Candidate({ ...f.options, directory: path.join(f.directory, 'sentinel') }),
      refused('message_rowid_sentinel'),
    );
  } finally {
    f.close();
  }
});

const corruptions: { name: string; mutate: (f: ReturnType<typeof fixture>) => void; code: string }[] = [
  {
    name: 'unknown table',
    mutate: f => f.core.exec('CREATE TABLE surprise(secret TEXT);'),
    code: 'schema_fingerprint',
  },
  {
    name: 'sqlite-prefix lookalike table',
    mutate: f => f.core.exec('CREATE TABLE sqliteXhidden(secret TEXT);'),
    code: 'schema_fingerprint',
  },
  { name: 'unexpected internal statistics', mutate: f => f.core.exec('ANALYZE;'), code: 'schema_fingerprint' },
  {
    name: 'private audience published flag',
    mutate: f => f.core.exec('UPDATE messages SET public=1;'),
    code: 'message_public',
  },
  {
    name: 'invalid paired principal',
    mutate: f => f.core.exec("UPDATE agents SET kind='paired',principal='not-a-principal';"),
    code: 'agent_principal',
  },
  {
    name: 'non-protocol carrier',
    mutate: f => f.core.exec("UPDATE messages SET carrier='ftp://remote.example';"),
    code: 'message_carrier',
  },
  {
    name: 'future received state',
    mutate: f => f.core.prepare('UPDATE messages SET received_at=?').run('2026-10-20T12:00:00.001Z'),
    code: 'future_host_state',
  },
  {
    name: 'unknown trigger',
    mutate: f => f.core.exec('CREATE TRIGGER surprise AFTER INSERT ON agents BEGIN SELECT 1; END;'),
    code: 'schema_fingerprint',
  },
  { name: 'missing index', mutate: f => f.core.exec('DROP INDEX message_parts_sha;'), code: 'schema_fingerprint' },
  { name: 'unsafe version', mutate: f => f.core.exec('PRAGMA user_version=9;'), code: 'schema_version' },
  {
    name: 'orphan inbox',
    mutate: f => f.core.prepare('UPDATE inbox SET id=?').run('e'.repeat(64)),
    code: 'inbox_parent',
  },
  {
    name: 'orphan arrival',
    mutate: f => f.core.prepare('UPDATE arrivals SET id=? WHERE rowid=11').run('e'.repeat(64)),
    code: 'job_parent',
  },
  {
    name: 'invalid inbox time',
    mutate: f => f.core.prepare('UPDATE inbox SET received_at=?').run('bad-time'),
    code: 'inbox_received',
  },
  {
    name: 'missing grant index',
    mutate: f => f.core.exec('DELETE FROM message_parts;'),
    code: 'message_part_projection',
  },
  {
    name: 'conflicting index size',
    mutate: f => f.core.exec('UPDATE message_parts SET size=size+1;'),
    code: 'message_part_projection',
  },
  {
    name: 'corrupt BLOB',
    mutate: f => f.core.prepare('UPDATE parts SET bytes=?').run(Buffer.alloc(f.bytes.length)),
    code: 'blob_hash',
  },
  {
    name: 'corrupt body/id',
    mutate: f =>
      f.core.prepare('UPDATE messages SET json=? WHERE id=?').run(JSON.stringify({ ...f.original, parts: [] }), f.id),
    code: 'message_structure_or_binding',
  },
  {
    name: 'reserved sync scope',
    mutate: f =>
      f.core.prepare('INSERT INTO vals VALUES(?,?,?,?)').run('sync-secret', 'old-origin', '"not-a-new-secret"', null),
    code: 'reserved_value_scope',
  },
  {
    name: 'reserved part-fetch slot collision',
    mutate: f =>
      f.core
        .prepare('INSERT INTO vals VALUES(?,?,?,?)')
        .run('part-fetch-slot', `${f.carrier} 0`, '"never-released"', null),
    code: 'reserved_value_scope',
  },
  {
    name: 'unsupported delivery cutoff',
    mutate: f =>
      f.core
        .prepare('INSERT INTO vals VALUES(?,?,?,?)')
        .run('delivery-move-cutoff', 'old-row', JSON.stringify({ until: T, reason: 'arbitrary', fresh: true }), null),
    code: 'consumed_value_shape',
  },
  {
    name: 'malformed consumed value',
    mutate: f => f.core.prepare("UPDATE vals SET value='{}' WHERE scope='server-key-added'").run(),
    code: 'consumed_value_shape',
  },
  {
    name: 'non-exact null',
    mutate: f => f.core.prepare("UPDATE vals SET value=' null ' WHERE scope='recovery'").run(),
    code: 'legacy_challenge_or_recovery',
  },
];
for (const { name, mutate, code } of corruptions)
  it(`refuses ${name} with source retained`, async () => {
    const f = fixture();
    try {
      mutate(f);
      await assert.rejects(createSqliteV2Candidate(f.options), refused(code));
      assert.equal(fs.existsSync(path.join(f.options.directory, '004-VERIFIED.json')), false);
      assert.equal(fs.existsSync(f.source), true);
    } finally {
      f.close();
    }
  });

it('refuses a legacy store holding a wire version 1 message, which this server cannot read as it was', async () => {
  const f = fixture();
  try {
    const message = signMessage<Message>(
      {
        v: 1,
        from: 'author@remote.example',
        to: [f.address],
        sentAt: T,
        inReplyTo: null,
        parts: [{ type: 'text/plain', data: 'written under wire version 1' }],
        headers: {},
      } as never,
      f.foreign.privateKey,
    );
    f.keep(message, 78);
    await assert.rejects(createSqliteV2Candidate(f.options), refused('legacy_wire_version'));
    assert.equal(fs.existsSync(path.join(f.options.directory, '004-VERIFIED.json')), false);
  } finally {
    f.close();
  }
});

it('refuses a corrupt private flag on a genuinely signed public message', async () => {
  const f = fixture();
  try {
    const message = signMessage<Message>(
      { v: VERSION, from: 'author@remote.example', to: [], sentAt: T, inReplyTo: null, parts: [], headers: {} },
      f.foreign.privateKey,
    );
    assert.ok(verifyMessage(message, [{ key: f.foreign.key, added: T, revoked: null }]));
    const id = f.keep(message, 77);
    f.core.prepare('UPDATE messages SET public=0 WHERE id=?').run(id);
    await assert.rejects(createSqliteV2Candidate(f.options), refused('message_public'));
    assert.equal(f.core.prepare('SELECT public FROM messages WHERE id=?').get(id)!.public, 0);
    assert.equal(fs.existsSync(path.join(f.options.directory, '004-VERIFIED.json')), false);
  } finally {
    f.close();
  }
});

for (const ahead of [299_999, 300_000, 300_001])
  it(`checks key-document future revocation boundary at ${ahead}ms without rewriting source`, async () => {
    const f = fixture();
    try {
      const revoked = new Date(Date.parse(T) + ahead).toISOString();
      f.core.prepare('UPDATE agent_keys SET revoked=?').run(revoked);
      if (ahead > 300_000) {
        await assert.rejects(createSqliteV2Candidate(f.options), refused('key_document_time'));
        assert.equal(fs.existsSync(path.join(f.options.directory, '004-VERIFIED.json')), false);
      } else {
        const result = await createSqliteV2Candidate(f.options);
        const db = new DatabaseSync(path.join(f.options.directory, result.candidate.core));
        try {
          assert.equal(db.prepare('SELECT revoked FROM agent_keys').get()!.revoked, revoked);
        } finally {
          db.close();
        }
      }
      assert.equal(f.core.prepare('SELECT revoked FROM agent_keys').get()!.revoked, revoked);
    } finally {
      f.close();
    }
  });

it('preserves supported trusted/held continuity, serving states and postmaster seed byte-for-byte', async () => {
  const f = fixture();
  try {
    const values = [
      [
        'continuity',
        'remote.example',
        JSON.stringify({
          listed: [f.foreign.key],
          signers: [f.foreign.key],
          held: { server: f.carrier, keys: [f.serverKey.key], until: '2026-10-21T12:00:00.000Z' },
        }),
        null,
      ],
      ['continuity', 'trusted.example', JSON.stringify({ listed: [f.foreign.key], signers: [f.foreign.key] }), null],
      ['serving-since', 'local.example', JSON.stringify({ since: T, checked: T }), EXPIRES],
      ['serving-since', 'legacy.example', JSON.stringify(T), null],
      ['serving-since', 'departed.example', 'null', Date.parse(T)],
      ['postmaster-key', 'postmaster@local.example', JSON.stringify(Buffer.alloc(32, 7).toString('base64url')), null],
    ] as const;
    for (const row of values) f.core.prepare('INSERT INTO vals VALUES(?,?,?,?)').run(...row);
    const before = f.core.prepare('SELECT rowid,* FROM vals ORDER BY rowid').all();
    const result = await createSqliteV2Candidate(f.options);
    const db = new DatabaseSync(path.join(f.options.directory, result.candidate.core));
    try {
      for (const [scope, id, value, expires] of values) {
        const row = db.prepare('SELECT value,expires FROM vals WHERE scope=? AND id=?').get(scope, id)!;
        assert.deepEqual([row.value, row.expires], [value, expires]);
      }
    } finally {
      db.close();
    }
    assert.deepEqual(f.core.prepare('SELECT rowid,* FROM vals ORDER BY rowid').all(), before);
  } finally {
    f.close();
  }
});

for (const [scope, id, value, expires] of [
  ['continuity', 'remote.example', { listed: [], signers: [] }, null],
  ['continuity', 'remote.example', { listed: ['bad'], signers: ['bad'] }, null],
  ['continuity', 'remote.example', { listed: [], signers: [], held: { until: 'bad' } }, null],
  ['serving-since', 'local.example', { since: T }, null],
  ['serving-since', 'local.example', { since: T, checked: 'bad' }, null],
  ['serving-since', 'local.example', null, null],
  ['postmaster-key', 'postmaster@local.example', 'bad', null],
] as const)
  it(`refuses malformed consumed ${scope} state ${JSON.stringify(value)}`, async () => {
    const f = fixture();
    try {
      f.core.prepare('INSERT INTO vals VALUES(?,?,?,?)').run(scope, id, JSON.stringify(value), expires);
      await assert.rejects(createSqliteV2Candidate(f.options), refused('consumed_value_shape'));
      assert.equal(fs.existsSync(path.join(f.options.directory, '004-VERIFIED.json')), false);
    } finally {
      f.close();
    }
  });

for (const bad of ['listed', 'signers', 'server', 'keys', 'until'] as const)
  it(`refuses malformed continuity ${bad} without trusting a replacement`, async () => {
    const f = fixture();
    try {
      const value = {
        listed: [f.foreign.key],
        signers: [f.foreign.key],
        held: { server: f.carrier, keys: [f.serverKey.key], until: '2026-10-21T12:00:00.000Z' },
      };
      const invalid =
        bad === 'listed' || bad === 'signers'
          ? { ...value, [bad]: ['bad-key'] }
          : { ...value, held: { ...value.held, [bad]: bad === 'keys' ? ['bad-key'] : 'bad' } };
      f.core
        .prepare('INSERT INTO vals VALUES(?,?,?,?)')
        .run('continuity', 'remote.example', JSON.stringify(invalid), null);
      await assert.rejects(createSqliteV2Candidate(f.options), refused('consumed_value_shape'));
      assert.equal(fs.existsSync(path.join(f.options.directory, '004-VERIFIED.json')), false);
    } finally {
      f.close();
    }
  });

it('refuses a candidate-directory fsync failure before recording VERIFIED', async t => {
  const f = fixture();
  const realFsync = fs.fsyncSync;
  let attempted = false;
  try {
    await assert.rejects(
      createSqliteV2Candidate({
        ...f.options,
        afterStage(stage) {
          if (stage !== 'COPIED') return;
          const directory = fs.statSync(path.join(f.options.directory, 'candidate'));
          t.mock.method(fs, 'fsyncSync', (fd: number) => {
            const stat = fs.fstatSync(fd);
            if (stat.dev === directory.dev && stat.ino === directory.ino) {
              attempted = true;
              throw new Error('synthetic directory fsync failure');
            }
            realFsync(fd);
          });
        },
      }),
      refused('conversion_failed'),
    );
    assert.equal(attempted, true);
    assert.equal(fs.existsSync(path.join(f.options.directory, '004-VERIFIED.json')), false);
    assert.equal(f.core.prepare('PRAGMA user_version').get()!.user_version, 2);
  } finally {
    t.mock.restoreAll();
    f.close();
  }
});

it('refuses an old flat index that omitted a genuinely signed carried file without creating new grants', async () => {
  const f = fixture();
  try {
    const carried = f.message([f.part]);
    const outer = f.message([{ type: 'application/simon-message', data: canonicalBytes(carried).toString('base64') }]);
    const id = f.keep(outer, 77);
    assert.equal(f.core.prepare('SELECT count(*) n FROM message_parts WHERE id=?').get(id)!.n, 0);
    await assert.rejects(createSqliteV2Candidate(f.options), refused('message_part_projection'));
    assert.equal(f.core.prepare('SELECT count(*) n FROM message_parts WHERE id=?').get(id)!.n, 0);
  } finally {
    f.close();
  }
});

it('keeps unknown-version interiors opaque instead of inventing file grants or reply indexes', async () => {
  const f = fixture();
  try {
    const unknown = signMessage<FutureMessage>(
      {
        v: 9,
        from: 'author@remote.example',
        to: [f.address],
        sentAt: T,
        opaqueFutureInterior: { parts: [f.part], inReplyTo: f.id },
      },
      f.foreign.privateKey,
    );
    const id = f.keep(unknown, 79);
    const result = await createSqliteV2Candidate(f.options);
    const db = new DatabaseSync(path.join(f.options.directory, result.candidate.core));
    try {
      assert.equal(db.prepare('SELECT in_reply_to FROM messages WHERE id=?').get(id)!.in_reply_to, null);
      assert.equal(db.prepare('SELECT count(*) n FROM message_parts WHERE id=?').get(id)!.n, 0);
    } finally {
      db.close();
    }
  } finally {
    f.close();
  }
});

it('refuses unpublishable active-key or retained-retraction capacity without pruning source', async () => {
  const f = fixture();
  try {
    await assert.rejects(
      createSqliteV2Candidate({ ...f.options, retractions: { maxBytes: 1 } }),
      refused('retraction_capacity'),
    );
    assert.equal(fs.existsSync(path.join(f.options.directory, 'candidate')), false);
    for (let i = 2; i <= 33; i++) {
      const key = generateKey();
      f.core.prepare('INSERT INTO agent_keys VALUES(?,?,?,?,?)').run(key.key, f.address, T, null, i);
    }
    await assert.rejects(
      createSqliteV2Candidate({ ...f.options, directory: path.join(f.directory, 'keys') }),
      refused('active_key_capacity'),
    );
    assert.equal(f.core.prepare('SELECT count(*) n FROM agent_keys').get()!.n, 33);
  } finally {
    f.close();
  }
});

it('keeps live callbacks unable to settle new fetch incarnations and preserves due ordering', async () => {
  const f = fixture();
  let store: SqliteStore | undefined;
  try {
    const result = await createSqliteV2Candidate(f.options);
    store = new SqliteStore(path.join(f.options.directory, result.candidate.core));
    assert.equal(await store.fetchDone(f.fetches[0], f.carrier, 'drained-old-token'), false);
    assert.equal(await store.fetchRetry(f.fetches[0], f.carrier, T, 'drained-old-token'), false);
    const due = await store.fetches(new Date(DUE).toISOString(), 10);
    assert.deepEqual(
      due.map(job => job.sha256),
      f.fetches,
      'equal-due original rowid order survives',
    );
    assert.ok(due.every(job => job.attempts === 7));
    const stale = { ...due[0], generation: 'old-incarnation' };
    assert.equal(
      await store.claimFetch(stale, new Date(DUE).toISOString(), {
        token: 'new-owner',
        until: new Date(DUE + 60_000).toISOString(),
      }),
      false,
    );
  } finally {
    await store?.close();
    f.close();
  }
});

it('requires both actual writer exclusions and leaves durable pending outbox entries untouched', async () => {
  for (const target of ['core', 'app'] as const) {
    const f = fixture();
    try {
      const held = f[target];
      held.exec('BEGIN IMMEDIATE;');
      try {
        await assert.rejects(createSqliteV2Candidate(f.options), refused('writer_exclusion_failed'));
      } finally {
        held.exec('ROLLBACK;');
      }
      assert.equal(fs.existsSync(f.options.directory), false);
      assert.equal(f.app.prepare('SELECT count(*) n FROM arrivals').get()!.n, 2);
      const retry = await createSqliteV2Candidate(f.options);
      assert.equal(retry.activationBlocked, true, 'the first writer lock was released after second-file failure');
    } finally {
      f.close();
    }
  }
});

it('requires a trusted non-rollback observation, drained host and unchanged held external fence', async () => {
  for (const change of ['rollback', 'undrained', 'fence'] as const) {
    const f = fixture();
    try {
      if (change === 'rollback') Object.assign(f.maintenance, { previousObservedAt: '2026-10-21T00:00:00.000Z' });
      if (change === 'undrained') Object.assign(f.maintenance, { callbacksDrained: false });
      if (change === 'fence') fs.writeFileSync(f.maintenance.fenceFile, 'replaced');
      f.writeMaintenance();
      const expected =
        change === 'rollback'
          ? 'maintenance_clock_rollback'
          : change === 'undrained'
            ? 'maintenance_drain_attestation'
            : 'maintenance_fence';
      await assert.rejects(createSqliteV2Candidate(f.options), refused(expected));
      assert.equal(fs.existsSync(f.options.directory), false);
    } finally {
      f.close();
    }
  }
});

for (const stage of ['SNAPSHOTTED', 'PREFLIGHT_OK', 'COPIED', 'VERIFIED'] as const)
  it(`preserves the old cohort and refuses incomplete reuse after a synthetic crash at ${stage}`, async () => {
    const f = fixture();
    try {
      await assert.rejects(
        createSqliteV2Candidate({
          ...f.options,
          afterStage: reached => {
            if (reached === stage) throw new Error('synthetic crash');
          },
        }),
        refused('conversion_failed'),
      );
      assert.equal(f.core.prepare('PRAGMA user_version').get()!.user_version, 2);
      assert.equal(f.core.prepare('SELECT count(*) n FROM inbox').get()!.n, 1);
      assert.equal(f.app.prepare('SELECT count(*) n FROM arrivals').get()!.n, 2);
      assert.equal(fs.existsSync(path.join(f.options.directory, 'PROMOTED.json')), false);
      const marker = path.join(f.options.directory, 'REFUSED.json');
      if (stage === 'VERIFIED') {
        // VERIFIED was durable before the crash: the bundle keeps that single meaning, with no refusal marker.
        assert.equal(fs.existsSync(marker), false, 'a durable VERIFIED bundle is never also marked REFUSED');
        const resumed = await createSqliteV2Candidate(f.options);
        assert.equal(resumed.status, 'VERIFIED_COPY_HELD', 'complete matching verified candidate is reusable');
        assert.equal(fs.existsSync(marker), false);
      } else {
        assert.equal(fs.existsSync(path.join(f.options.directory, '004-VERIFIED.json')), false);
        assert.equal(JSON.parse(fs.readFileSync(marker, 'utf8')).code, 'conversion_failed');
        await assert.rejects(createSqliteV2Candidate(f.options), refused('refused_candidate_choose_new_directory'));
        // Without the marker (a crash before it was written), the partial bundle is still refused.
        fs.rmSync(marker);
        await assert.rejects(createSqliteV2Candidate(f.options), refused('incomplete_candidate_choose_new_directory'));
      }
      const fresh = await createSqliteV2Candidate({ ...f.options, directory: path.join(f.directory, 'new-cut') });
      assert.equal(fresh.highWatermark, 100);
    } finally {
      f.close();
    }
  });

it('reports a cleanup failure after VERIFIED as verified, never as a refusal, and keeps the bundle reusable', async () => {
  const f = fixture();
  try {
    let failure: unknown;
    await createSqliteV2Candidate({ ...f.options, faultAt: 'cleanup' }).catch(error => (failure = error));
    assert.ok(failure instanceof SqliteV2CleanupFailure, 'not a refusal');
    assert.ok(!(failure instanceof SqliteMigrationRefusal));
    assert.equal(failure.code, 'cleanup_failed');
    assert.equal(failure.candidate.status, 'VERIFIED_COPY_HELD');
    assert.equal(failure.candidate.activationBlocked, true);
    assert.ok(fs.existsSync(path.join(f.options.directory, '004-VERIFIED.json')));
    assert.equal(fs.existsSync(path.join(f.options.directory, 'REFUSED.json')), false);
    assert.equal(f.core.prepare('PRAGMA user_version').get()!.user_version, 2);
    const resumed = await createSqliteV2Candidate(f.options);
    assert.equal(resumed.bundleId, failure.candidate.bundleId, 'the same verified bundle is reused');
    // A cleanup failure while reusing reports the reused candidate the same way.
    const again = await createSqliteV2Candidate({ ...f.options, faultAt: 'cleanup' }).catch(error => error);
    assert.ok(again instanceof SqliteV2CleanupFailure);
    assert.equal(again.candidate.bundleId, failure.candidate.bundleId);
    assert.equal(fs.existsSync(path.join(f.options.directory, 'REFUSED.json')), false);
  } finally {
    f.close();
  }
});

it('refuses a cleanup failure before VERIFIED as a refusal, and never reuses that bundle', async () => {
  const f = fixture();
  try {
    await assert.rejects(
      createSqliteV2Candidate({
        ...f.options,
        faultAt: 'cleanup',
        afterStage: reached => {
          if (reached === 'COPIED') throw new Error('synthetic crash');
        },
      }),
      refused('cleanup_failed'),
    );
    assert.equal(fs.existsSync(path.join(f.options.directory, '004-VERIFIED.json')), false);
    assert.ok(fs.existsSync(path.join(f.options.directory, 'REFUSED.json')));
    await assert.rejects(createSqliteV2Candidate(f.options), refused('refused_candidate_choose_new_directory'));
  } finally {
    f.close();
  }
});

it('never reuses a VERIFIED bundle that also holds a REFUSED marker', async () => {
  const f = fixture();
  try {
    const first = await createSqliteV2Candidate(f.options);
    const manifest = path.join(f.options.directory, '004-VERIFIED.json');
    const before = fs.readFileSync(manifest);
    const marker = path.join(f.options.directory, 'REFUSED.json');
    fs.writeFileSync(marker, JSON.stringify({ status: 'REFUSED', code: 'conversion_failed' }), { mode: 0o600 });
    await assert.rejects(createSqliteV2Candidate(f.options), refused('refused_candidate_choose_new_directory'));
    assert.deepEqual(fs.readFileSync(manifest), before, 'the refused bundle is left as it was');
    assert.ok(fs.existsSync(marker));
    const fresh = await createSqliteV2Candidate({ ...f.options, directory: path.join(f.directory, 'new-cut') });
    assert.notEqual(fresh.bundleId, first.bundleId);
  } finally {
    f.close();
  }
});

for (const faultAt of ['copy-row', 'bootstrap', 'verify'] as const)
  it(`keeps mid-${faultAt} failure unverified and recoverable`, async () => {
    const f = fixture();
    try {
      await assert.rejects(createSqliteV2Candidate({ ...f.options, faultAt }), SqliteMigrationRefusal);
      assert.equal(fs.existsSync(path.join(f.options.directory, '004-VERIFIED.json')), false);
      assert.equal(f.core.prepare('PRAGMA user_version').get()!.user_version, 2);
      assert.equal(f.app.prepare('SELECT count(*) n FROM arrivals').get()!.n, 2);
      if (faultAt === 'copy-row') {
        const partial = new DatabaseSync(path.join(f.options.directory, 'candidate', 'simon.sqlite'));
        try {
          assert.equal(
            partial.prepare('SELECT count(*) n FROM agents').get()!.n,
            0,
            'candidate copy transaction rolled back',
          );
        } finally {
          partial.close();
        }
      }
    } finally {
      f.close();
    }
  });

it('refuses changed inputs, changed candidates, aliases, symlinks and unrelated destinations instead of overwriting', async () => {
  const f = fixture();
  try {
    const result = await createSqliteV2Candidate(f.options);
    await assert.rejects(
      createSqliteV2Candidate({ ...f.options, retractions: { maxRecords: 1 } }),
      refused('candidate_input_mismatch'),
    );
    f.core.prepare("UPDATE counters SET n=n+1 WHERE scope='code-attempt'").run();
    await assert.rejects(createSqliteV2Candidate(f.options), refused('candidate_input_mismatch'));
    f.core.prepare("UPDATE counters SET n=n-1 WHERE scope='code-attempt'").run();
    const candidate = path.join(f.options.directory, result.candidate.core);
    fs.appendFileSync(candidate, 'corrupt-synthetic-candidate');
    await assert.rejects(createSqliteV2Candidate(f.options), refused('candidate_artifact_mismatch'));
    const unrelated = path.join(f.directory, 'unrelated');
    fs.mkdirSync(unrelated, { mode: 0o700 });
    fs.writeFileSync(path.join(unrelated, 'keep'), 'unchanged');
    await assert.rejects(
      createSqliteV2Candidate({ ...f.options, directory: unrelated }),
      refused('incomplete_candidate_choose_new_directory'),
    );
    assert.equal(fs.readFileSync(path.join(unrelated, 'keep'), 'utf8'), 'unchanged');
    const symlink = path.join(f.directory, 'link.sqlite');
    fs.symlinkSync(f.source, symlink);
    await assert.rejects(createSqliteV2Candidate({ ...f.options, source: symlink }), refused('unsafe_file_type'));
    const hardlink = path.join(f.directory, 'alias.sqlite');
    fs.linkSync(f.source, hardlink);
    await assert.rejects(createSqliteV2Candidate({ ...f.options, source: hardlink }), refused('unsafe_file_type'));
  } finally {
    f.close();
  }
});

it('runs the real CLI on synthetic files with held/refused exits, redacted output and no promotion override', async () => {
  const f = fixture();
  try {
    const help = spawnSync(process.execPath, [CLI, '--help'], { encoding: 'utf8' });
    assert.equal(help.status, 0);
    assert.match(help.stdout, /NEVER selected or promoted/);
    const invalid = spawnSync(process.execPath, [CLI, '--promote'], { encoding: 'utf8' });
    assert.equal(invalid.status, 2);
    const args = [
      CLI,
      '--source',
      f.source,
      '--directory',
      f.options.directory,
      '--maintenance',
      f.options.maintenanceFile,
    ];
    const held = spawnSync(process.execPath, args, { encoding: 'utf8' });
    assert.equal(held.status, 3, held.stderr);
    assert.equal(JSON.parse(held.stdout).activationBlocked, true);
    assert.ok(!held.stdout.includes(f.readerKey.key));
    assert.ok(!held.stdout.includes(f.address));
    const recovery = JSON.stringify({
      key: f.readerKey.key,
      hash: 'private-code-hash',
      nonce: 'private-code-nonce',
      completesAt: T,
    });
    f.core.prepare("UPDATE vals SET value=? WHERE scope='recovery'").run(recovery);
    const blocked = spawnSync(
      process.execPath,
      [
        CLI,
        '--source',
        f.source,
        '--directory',
        path.join(f.directory, 'blocked'),
        '--maintenance',
        f.options.maintenanceFile,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(blocked.status, 1);
    const problem = blocked.stderr.split('\n').find(line => line.startsWith('{'))!;
    assert.equal(JSON.parse(problem).code, 'legacy_challenge_or_recovery');
    for (const secret of [f.address, f.readerKey.key, 'private-code-hash', 'private-code-nonce'])
      assert.equal((blocked.stdout + blocked.stderr).includes(secret), false);
    assert.equal(f.core.prepare('PRAGMA user_version').get()!.user_version, 2);
    assert.equal(f.app.prepare('SELECT count(*) n FROM arrivals').get()!.n, 2);
  } finally {
    f.close();
  }
});
