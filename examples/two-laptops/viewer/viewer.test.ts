/** The viewer's JSON endpoint, against a temp database the server's own store made. */
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { get } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { SqliteStore } from '../../../server/src/store/sqlite.ts';
import { openDb, snapshot, viewer } from './viewer.ts';

const dir = mkdtempSync(join(tmpdir(), 'simon-viewer-'));
after(() => rmSync(dir, { recursive: true, force: true }));

const hex = (c: string) => c.repeat(64);
const msg = (from: string, to: string, text: string, extra: object = {}) => ({
  v: 2,
  from,
  to: [to],
  inReplyTo: null,
  sentAt: '2026-10-15T14:02:11Z',
  signature: 'x',
  parts: [{ type: 'text/plain', data: text }],
  headers: {},
  ...extra,
});

test('messages.json lists sent and received messages, safely', async () => {
  const path = join(dir, 'simon.sqlite');
  const store = new SqliteStore(path);
  await store.createAgent({
    address: 'agent@a.test',
    kind: 'solo',
    principal: null,
    mailbox: false,
    keys: [{ key: 'ed25519:k', added: '2026-10-15T00:00:00Z', revoked: null }],
    createdAt: '2026-10-15T00:00:00Z',
    retiredAt: null,
  });
  const exp = '2027-01-01T00:00:00Z';
  await store.putMessage(
    {
      id: hex('a'),
      message: msg('agent@a.test', 'agent@b.test', 'Hi <b>there</b>') as any,
      carrier: 'http://a',
      claims: [],
      signedClaims: null,
      receivedAt: '2026-10-15T14:02:11Z',
      expiresAt: exp,
    },
    {
      deliveries: [
        {
          id: hex('a'),
          domain: 'b.test',
          recipients: ['agent@b.test'],
          hints: {},
          server: 'http://b',
          status: 'failed',
          reason: 'expired',
          attempts: 3,
          nextAttemptAt: exp,
          createdAt: '2026-10-15T14:02:11Z',
          deadline: exp,
        },
      ],
    },
  );
  const reply = msg('agent@b.test', 'agent@a.test', 'My human says: hi\u{E0041}‮', {
    inReplyTo: hex('a'),
    headers: { 'human-consulted': 'true' },
    parts: [
      { type: 'text/plain', data: 'My human says: hi\u{E0041}‮' },
      { type: 'image/png', sha256: hex('c'), size: 2048 },
    ],
  });
  await store.putMessage({
    id: hex('b'),
    message: reply as any,
    carrier: 'http://b',
    claims: [],
    signedClaims: null,
    receivedAt: '2026-10-15T14:03:00Z',
    expiresAt: exp,
  });
  await store.addToInbox('agent@a.test', hex('b'), '2026-10-15T14:03:00Z');
  await store.close();

  const db = openDb(path);
  const server = viewer(db).listen(0, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const res = await fetch(`${base}/messages.json`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-security-policy')!, /default-src 'none'/);
    const data = await res.json();
    assert.deepEqual(data.agents, ['agent@a.test']);
    const [sent, received] = data.messages;
    assert.equal(sent.direction, 'sent');
    assert.deepEqual(sent.parts, [{ text: 'Hi <b>there</b>' }]);
    assert.deepEqual(sent.deliveries, [{ domain: 'b.test', server: 'http://b', status: 'failed', reason: 'expired' }]);
    assert.equal(received.direction, 'received');
    assert.equal(received.carrier, 'http://b');
    assert.equal(received.human, true);
    assert.equal(received.depth, 1);
    assert.equal(received.parts[0].text, 'My human says: hi⟨U+E0041⟩⟨U+202E⟩');
    assert.equal(received.parts[1].label, '[part: image/png, 2048 bytes]');

    const page = await fetch(base);
    assert.match(page.headers.get('content-security-policy')!, /script-src 'sha256-/);
    assert.doesNotMatch(await page.text(), /innerHTML/);
    assert.equal(snapshot(db, 'agent@c.test').messages.length, 0);
    const port = (server.address() as { port: number }).port;
    const rebound = await new Promise<number>(r =>
      get({ host: '127.0.0.1', port, path: '/messages.json', headers: { host: 'evil.example' } }, res =>
        r(res.statusCode!),
      ),
    );
    assert.equal(rebound, 403);
  } finally {
    server.close();
    db.close();
  }
  assert.throws(() => openDb(join(dir, 'missing.sqlite')), /Cannot open/);
});
