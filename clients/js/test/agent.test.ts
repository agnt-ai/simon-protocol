/** Signed client calls against the in-process fake: signed requests, every register flow, drafts, sync tokens, parts, errors. */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openAgent, saveAddress } from '../src/credentials.ts';
import {
  canonicalize,
  generateKey,
  messageId,
  signMessage,
  signPairing,
  signRecovery,
  timestamp,
} from '@agnt-sdk/simon-protocol';
import { Agent, SimonError, type AgentOptions, type Fetch } from '../src/index.ts';
import { fetchServerDocument } from '../src/read.ts';
import { exchange } from '../src/http.ts';
import { CANCEL_CODE, CODE, RECOVERY_WAIT_MS, fakeServer } from './fake-server.ts';

const T0 = new Date('2026-10-15T12:00:00.000Z');

function setup(opts: Parameters<typeof fakeServer>[0] = {}) {
  const fake = fakeServer(opts);
  const agent = (o: Partial<AgentOptions> = {}) =>
    new Agent({ server: fake.origin, key: generateKey().privateKeyPem, fetch: fake.fetch, now: opts.now, ...o });
  return { fake, agent };
}

async function registered(make: () => Agent) {
  const a = make();
  await a.register();
  return a;
}

/** The SimonError a promise rejects with. */
async function failure(p: Promise<unknown> | (() => unknown)): Promise<SimonError> {
  try {
    await (typeof p === 'function' ? p() : p);
  } catch (e) {
    assert.ok(e instanceof SimonError, String(e));
    return e;
  }
  assert.fail('expected a failure');
}

describe('register', () => {
  it('leases an address for a key alone, and a repeat answers the same', async () => {
    const { agent } = setup();
    const a = agent();
    assert.equal(a.address, null);
    const r = await a.register();
    assert.ok('keys' in r);
    assert.equal(a.address, r.address);
    assert.deepEqual(await a.register(), r);
  });

  it('binds an address on a hosted domain at once, written in lower case', async () => {
    const { agent } = setup();
    const a = agent();
    const r = await a.register({ address: 'Ada@Agents.Test' });
    assert.ok('keys' in r);
    assert.equal(a.address, 'ada@agents.test');
  });

  it('sends a code to any other address, and the code binds it', async () => {
    const { agent } = setup();
    const a = agent();
    assert.deepEqual(await a.register({ address: 'ada@example.com' }), {
      status: 'code_sent',
      address: 'ada@example.com',
    });
    assert.equal(a.address, null);
    const wrong = await failure(a.register({ address: 'ada@example.com', code: '000000' }));
    assert.deepEqual([wrong.status, wrong.code], [422, 'wrong_code']);
    assert.ok('keys' in (await a.register({ address: 'ada@example.com', code: CODE })));
    assert.equal(a.address, 'ada@example.com');
  });

  it('pairs a leased address with a key principal: pairing_required, then the signature', async () => {
    const { agent, fake } = setup();
    const principal = generateKey();
    const id = `simon-key:${principal.key}`;
    const a = agent();
    const first = await a.register({ for: id });
    assert.equal(first.status, 'pairing_required');
    const bad = await failure(a.register({ for: id, pairing: signPairing(principal.privateKey, 'x@agents.test', id) }));
    assert.deepEqual([bad.status, bad.code], [401, 'bad_proof']);
    const pairing = signPairing(principal.privateKey, first.address, id);
    assert.ok('keys' in (await a.register({ for: id, pairing })));
    assert.deepEqual([a.address, a.for, a.pairing], [first.address, id, pairing]);
    assert.equal(fake.agents.get(first.address)?.for, id);
  });

  it('adds a key with a proof the new key signs, and the new key then works alone', async () => {
    const { agent } = setup();
    const a = await registered(agent);
    const second = generateKey();
    const r = await a.addKey(second.privateKeyPem);
    assert.deepEqual('keys' in r && r.keys.map(k => k.key), [a.key, second.key]);
    const b = agent({ key: second.privateKeyPem, address: a.address! });
    assert.deepEqual((await b.sync()).messages, []);
  });

  it('recovers an address with a new key after a code and the wait; the old key is revoked', async () => {
    let now = T0;
    const { agent } = setup({ now: () => now });
    const old = await registered(agent);
    const fresh = agent();
    assert.equal((await fresh.recover({ address: old.address! })).status, 'code_sent');
    const pending = await fresh.recover({ address: old.address!, code: CODE });
    const completesAt = new Date(T0.getTime() + RECOVERY_WAIT_MS).toISOString();
    assert.deepEqual(pending, { status: 'recovery_pending', address: old.address, completesAt });
    assert.equal(fresh.address, null, 'a pending recovery binds nothing');
    assert.deepEqual((await old.sync()).messages, [], 'the old key still works while it waits');
    now = new Date(T0.getTime() + RECOVERY_WAIT_MS);
    assert.ok('keys' in (await fresh.recover({ address: old.address!, code: CODE })));
    assert.equal(fresh.address, old.address);
    const e = await failure(old.sync());
    assert.deepEqual([e.status, e.code], [401, 'key_revoked']);
  });

  it('cancels a pending recovery with any valid key of the agent', async () => {
    let now = T0;
    const { agent } = setup({ now: () => now });
    const old = await registered(agent);
    const thief = agent();
    await thief.recover({ address: old.address! });
    assert.equal((await thief.recover({ address: old.address!, code: CODE })).status, 'recovery_pending');
    const status = await old.recoveryStatus();
    assert.deepEqual(status.recovery, {
      completesAt: new Date(T0.getTime() + RECOVERY_WAIT_MS).toISOString(),
      cancellable: true,
    });
    const cancelled = await old.cancelRecovery();
    assert.deepEqual(cancelled, { status: 'cancelled', address: old.address });
    assert.equal(((await old.recoveryStatus()) as { recovery: unknown }).recovery, null);
    now = new Date(T0.getTime() + RECOVERY_WAIT_MS);
    assert.equal((await thief.recover({ address: old.address!, code: CODE })).status, 'recovery_pending');
    assert.deepEqual((await old.sync()).messages, []);
    const e = await failure(agent().cancelRecovery());
    assert.deepEqual([e.code, e.status], ['not_registered', null]);
  });

  it('cancels a pending recovery with the cancel code sent to the address, signed by any key', async () => {
    const { agent } = setup();
    const old = await registered(agent);
    const thief = agent();
    await thief.recover({ address: old.address! });
    await thief.recover({ address: old.address!, code: CODE });
    const stranger = agent();
    const wrong = await failure(stranger.cancelRecovery({ address: old.address!, cancelCode: 'not-it' }));
    assert.deepEqual([wrong.status, wrong.code], [422, 'wrong_code']);
    const cancelled = await stranger.cancelRecovery({ address: old.address!, cancelCode: CANCEL_CODE });
    assert.deepEqual(cancelled, { status: 'cancelled', address: old.address });
    assert.equal(stranger.address, null, 'a cancel binds nothing');
  });

  it("recovers a paired agent at once with its key principal's signature", async () => {
    const { agent, fake } = setup();
    const principal = generateKey();
    const id = `simon-key:${principal.key}`;
    const old = agent();
    const { address } = await old.register({ for: id });
    await old.register({ for: id, pairing: signPairing(principal.privateKey, address, id) });
    const fresh = agent();
    const at = timestamp(new Date());
    const r = await fresh.recover({
      address,
      at,
      recover: signRecovery(principal.privateKey, address, fresh.key, at),
      for: id,
      pairing: signPairing(principal.privateKey, address, id),
    });
    assert.deepEqual('keys' in r && r.keys.map(k => [k.key, k.revoked !== null]), [
      [old.key, true],
      [fresh.key, false],
    ]);
    assert.equal(fresh.address, address);
    assert.equal(fresh.compose({ to: [], text: 'recovered' }).headers.for, id);
    await fresh.send({ to: [], text: 'recovered', headers: { audience: 'public' } });
    const wire = fake.requests.findLast(r => r.path === '/simon/recovery');
    assert.ok(
      wire &&
        !('for' in JSON.parse(Buffer.from(wire.body).toString())) &&
        !('pairing' in JSON.parse(Buffer.from(wire.body).toString())),
    );
    const forged = await failure(
      agent().recover({
        address,
        at,
        recover: signRecovery(generateKey().privateKey, address, fresh.key, at),
        for: id,
        pairing: signPairing(principal.privateKey, address, id),
      }),
    );
    assert.deepEqual([forged.status, forged.code, forged.details], [null, 'invalid', { field: 'recover' }]);
  });

  it('rejects retained cross-address pairing and a proof from a different principal before network', async () => {
    const { agent, fake } = setup();
    const first = generateKey();
    const other = generateKey();
    const id = `simon-key:${first.key}`;
    const oldAddress = 'old@agents.test';
    const target = 'target@agents.test';
    const retained = agent({ address: oldAddress, for: id, pairing: signPairing(first.privateKey, oldAddress, id) });
    const at = timestamp(new Date());
    const before = fake.requests.length;
    await assert.rejects(
      retained.recover({ address: target, at, recover: signRecovery(first.privateKey, target, retained.key, at) }),
      { code: 'invalid', details: { field: 'for' } },
    );
    const fresh = agent();
    await assert.rejects(
      fresh.recover({
        address: target,
        at,
        recover: signRecovery(other.privateKey, target, fresh.key, at),
        for: id,
        pairing: signPairing(first.privateKey, target, id),
      }),
      { code: 'invalid', details: { field: 'recover' } },
    );
    assert.equal(fake.requests.length, before);
    assert.equal(fresh.address, null);
    assert.equal(retained.address, oldAddress);
  });

  it('requires explicit identity for cross-address recovery with saved email or phone principal', async () => {
    const { agent, fake } = setup();
    for (const principal of ['mailto:alice@example.com', 'tel:+12025550123']) {
      const retained = agent({ address: 'old@agents.test', for: principal });
      const before = fake.requests.length;
      await assert.rejects(retained.recover({ address: 'other@agents.test' }), {
        code: 'invalid',
        details: { field: 'for' },
      });
      assert.equal(fake.requests.length, before);
      assert.equal(retained.for, principal);
      assert.equal(retained.address, 'old@agents.test');
    }
  });

  it('persists local pairing after fresh-home recovery, reloads, and sends with it', async () => {
    const { agent, fake } = setup();
    const principal = generateKey();
    const id = `simon-key:${principal.key}`;
    const original = agent();
    const { address } = await original.register({ for: id });
    const pairing = signPairing(principal.privateKey, address, id);
    await original.register({ for: id, pairing });
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'simon-recovery-'));
    try {
      const fresh = openAgent(home, { server: fake.origin, fetch: fake.fetch });
      const at = timestamp(new Date());
      await fresh.recover({
        address,
        at,
        recover: signRecovery(principal.privateKey, address, fresh.key, at),
        for: id,
        pairing,
      });
      saveAddress(home, fresh);
      const reloaded = openAgent(home, { fetch: fake.fetch });
      assert.deepEqual([reloaded.for, reloaded.pairing], [id, pairing]);
      const message = reloaded.compose({ to: [], text: 'after reload', headers: { audience: 'public' } });
      assert.equal(message.headers.for, id);
      await reloaded.send(message);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it('refuses to add a key before the agent has an address', async () => {
    const { agent } = setup();
    const e = await failure(agent().addKey(generateKey().privateKeyPem));
    assert.deepEqual([e.code, e.status], ['not_registered', null]);
  });
});

describe('send and inbox', () => {
  it('sends a message in canonical form, signed at the injected clock, and the recipient reads it', async () => {
    let now = T0;
    const { agent, fake } = setup({ now: () => now });
    const ada = await registered(agent);
    const bob = await registered(agent);
    const answer = await ada.send({ to: [bob.address!.toUpperCase()], text: 'Does 3pm work?' });
    const request = fake.requests.find(r => r.path === '/simon/send')!;
    const message = JSON.parse(Buffer.from(request.body).toString());
    assert.equal(Buffer.from(request.body).toString(), canonicalize(message));
    assert.equal(request.headers.get('simon-timestamp'), String(T0.getTime() / 1000));
    assert.equal(message.sentAt, '2026-10-15T12:00:00.000Z');
    assert.deepEqual(message.to, [bob.address]);
    assert.equal(answer.id, messageId(message));

    now = new Date(T0.getTime() + 1000);
    const inbox = await bob.sync();
    assert.deepEqual(
      inbox.messages.map(d => [d.id, d.message.parts]),
      [[answer.id, [{ type: 'text/plain', data: 'Does 3pm work?' }]]],
    );
    assert.equal(typeof inbox.token, 'string');
    assert.equal(inbox.more, false);
    assert.deepEqual((await bob.sync({ since: inbox.token })).messages, []);
  });

  it('puts text first, ahead of parts, and keeps both', async () => {
    const { agent } = setup();
    const ada = await registered(agent);
    const m = ada.compose({ to: ['bob@agents.test'], text: 'hi', parts: [{ type: 'text/markdown', data: '*hi*' }] });
    assert.deepEqual(m.parts, [
      { type: 'text/plain', data: 'hi' },
      { type: 'text/markdown', data: '*hi*' },
    ]);
  });

  it("writes a paired agent's for and pairing into every message, and refuses them in a draft", async () => {
    const { agent } = setup();
    const principal = generateKey();
    const id = `simon-key:${principal.key}`;
    const a = agent();
    const { address } = await a.register({ for: id });
    await a.register({ for: id, pairing: signPairing(principal.privateKey, address, id) });
    const m = a.compose({ to: ['bob@agents.test'], text: 'hi' });
    assert.deepEqual(m.headers, { for: id, pairing: a.pairing });
    assert.equal((await a.send(m)).id, messageId(m));
    const e = await failure(() => a.compose({ to: ['bob@agents.test'], headers: { for: 'mailto:x@example.com' } }));
    assert.deepEqual([e.code, e.details], ['invalid', { field: 'headers' }]);
  });

  it('refuses a JSON block whose value canonical JSON cannot carry, saying how to write it', async () => {
    const { agent } = setup();
    const ada = await registered(agent);
    const json = (data: unknown) => ({ to: ['bob@agents.test'], parts: [{ type: 'application/json', data }] });
    for (const data of [{ price: 19.99 }, [1e21], { n: 2 ** 53 }]) {
      const e = await failure(() => ada.compose(json(data) as never));
      assert.deepEqual([e.code, e.details], ['invalid', { field: 'parts' }], JSON.stringify(data));
      assert.match(e.message, /canonical JSON.*"19\.99"/s);
    }
    assert.equal(ada.compose(json({ price: '19.99', cents: 1999 }) as never).parts[0].type, 'application/json');
    assert.equal((ada.compose(json(null) as never).parts[0] as { data: unknown }).data, null, 'null is a JSON value');
  });

  it('sends a composed message again with the same answer', async () => {
    const { agent } = setup();
    const ada = await registered(agent);
    const m = ada.compose({ to: ['nobody@agents.test'], text: 'once' });
    assert.deepEqual(await ada.send(m), await ada.send(m));
  });

  it('passes hints keyed by a recipient in to, and refuses any other key', async () => {
    const { agent, fake } = setup();
    const ada = await registered(agent);
    await ada.send({ to: ['bob@agents.test'], text: 'hi' }, { hints: { 'Bob@Agents.Test': { invite: '7KQ2' } } });
    assert.equal(fake.requests.at(-1)!.headers.get('simon-hints'), '{"bob@agents.test":{"invite":"7KQ2"}}');
    const e = await failure(
      ada.send({ to: ['bob@agents.test'], text: 'hi' }, { hints: { 'eve@agents.test': { invite: 'x' } } }),
    );
    assert.deepEqual([e.code, e.details], ['invalid', { field: 'hints' }]);
  });

  it('sends hints in ASCII, every other character escaped, as an HTTP header carries them', async () => {
    const { agent, fake } = setup();
    const ada = await registered(agent);
    const note = 'price €5 \u{1F600}\u007f';
    await ada.send({ to: ['bob@agents.test'], text: 'hi' }, { hints: { 'bob@agents.test': { note } } });
    const sent = fake.requests.at(-1)!.headers.get('simon-hints')!;
    assert.equal(sent, '{"bob@agents.test":{"note":"price \\u20ac5 \\ud83d\\ude00\\u007f"}}');
    assert.deepEqual(JSON.parse(sent), { 'bob@agents.test': { note } });
  });

  it('refuses bad arguments before sending anything', async () => {
    const { agent, fake } = setup();
    const ada = await registered(agent);
    const before = fake.requests.length;
    const cases: [() => Promise<unknown>, string][] = [
      [() => ada.send({ to: ['not an address'], text: 'hi' }), 'to[0]'],
      [() => ada.sync({ since: '' }), 'since'],
      [() => ada.sync({ wait: 61 }), 'wait'],
      [() => ada.sync({ limit: 201 }), 'limit'],
      [() => ada.sent('abc'), 'id'],
      [() => ada.fetchPart({ sha256: 'ABC' }), 'sha256'],
      [() => ada.call('GET', 'https://elsewhere.example/simon/sync'), 'path'],
      [() => ada.call('GET', '//elsewhere.example/simon/sync'), 'path'],
    ];
    for (const [call, field] of cases) {
      const e = await failure(call());
      assert.deepEqual([e.code, e.status, e.details], ['invalid', null, { field }]);
    }
    assert.equal(fake.requests.length, before);
    // A message needs no text: a draft of nothing at all, or only HTML, is a message.
    assert.deepEqual(ada.compose({ to: ['bob@agents.test'] }).parts, []);
    assert.throws(() => new Agent({ server: 'ftp://x', key: generateKey().privateKeyPem }), { code: 'invalid' });
    await assert.rejects(agent().send({ to: ['bob@agents.test'] }), { code: 'not_registered' });
  });

  it('pages the inbox by cursor with a limit', async () => {
    const { agent, fake } = setup();
    const ada = await registered(agent);
    const bob = await registered(agent);
    for (const text of ['1', '2', '3']) await ada.send({ to: [bob.address!], text });
    const first = await bob.sync({ limit: 2 });
    assert.deepEqual([first.messages.length, typeof first.token, first.more], [2, 'string', true]);
    assert.equal(fake.requests.at(-1)!.path, '/simon/sync?limit=2');
    const rest = await bob.sync({ since: first.token, limit: 2 });
    assert.deepEqual([rest.messages.length, typeof rest.token, rest.more], [1, 'string', false]);
  });
});

describe('lifecycle endpoint boundaries and sync extensions', () => {
  it('rejects implicit recovery through register and keeps dedicated operations separate', async () => {
    const { agent, fake } = setup();
    const old = await registered(agent);
    const fresh = agent();
    await assert.rejects(fresh.register({ address: old.address! }), { code: 'address_in_use' });
    assert.equal(fresh.address, null);
    await fresh.recover({ address: old.address! });
    const pending = await fresh.recover({ address: old.address!, code: CODE });
    assert.equal(pending.status, 'recovery_pending');
    assert.equal(fresh.address, null);
    await old.recoveryStatus();
    assert.ok(fake.requests.some(r => r.method === 'GET' && r.path === '/simon/recovery'));
    await old.cancelRecovery();
    assert.equal((await old.recoveryStatus()).recovery, null);
  });

  it('signs an empty registration identity for a lease even on a saved object', async () => {
    const { agent, fake } = setup();
    const saved = await registered(agent);
    await saved.register();
    assert.equal(fake.requests.at(-1)!.headers.get('simon-agent'), null);
  });

  it('keeps sync tokens opaque and surfaces a rejected token without silently replaying', async () => {
    const { agent, fake } = setup();
    const own = await registered(agent);
    const before = fake.requests.length;
    await assert.rejects(own.sync({ since: 'not-a-known-token' }), { code: 'token_expired', status: 410 });
    assert.equal(fake.requests.length, before + 1);
    assert.equal(fake.requests.at(-1)!.path, '/simon/sync?since=not-a-known-token');
  });

  it('retries an identical signed message without adding another sync entry', async () => {
    let now = T0;
    const { agent } = setup({ now: () => now });
    const ada = await registered(agent);
    const bob = await registered(agent);
    const message = ada.compose({ to: [bob.address!], text: 'once' });
    const first = await ada.send(message);
    now = new Date(T0.getTime() + 1000);
    assert.deepEqual(await ada.send(message), first);
    const page = await bob.sync();
    assert.deepEqual(
      page.messages.map(e => e.id),
      [first.id],
    );
  });

  it('syncs explicitly sent signals and verifies a webhook before deletion', async () => {
    const { agent } = setup();
    const ada = await registered(agent);
    const bob = await registered(agent);
    const sent = await ada.send({ to: [bob.address!], text: 'read when ready' });
    const before = await ada.sync();
    assert.equal((await bob.sendSignal('read', sent.id, [ada.address!])).accepted, true);
    const changes = await ada.sync({ since: before.token });
    assert.deepEqual(
      changes.signals.map(s => [s.type, s.from, s.about]),
      [['read', bob.address, sent.id]],
    );
    const hook = await bob.createWebhook('https://callback.example/wake');
    await assert.rejects(bob.verifyWebhook(hook.id, 'wrong'), { code: 'wrong_code' });
    assert.deepEqual(await bob.verifyWebhook(hook.id, CODE), { id: hook.id, verified: true });
    assert.deepEqual(await bob.deleteWebhook(hook.id), { deleted: true });
  });
});

describe('sent and parts', () => {
  it('reports delivery per server', async () => {
    const { agent, fake } = setup();
    const ada = await registered(agent);
    const bob = await registered(agent);
    const { id } = await ada.send({ to: [bob.address!, 'eve@nowhere.example'], text: 'hi' });
    assert.deepEqual(await ada.sent(id), {
      id,
      servers: [
        { server: fake.origin, recipients: [bob.address], status: 'delivered' },
        { server: null, recipients: ['eve@nowhere.example'], status: 'failed', reason: 'not_found' },
      ],
    });
  });

  it('uploads a part, sends it by hash, and the recipient fetches the same bytes', async () => {
    const { agent } = setup();
    const ada = await registered(agent);
    const bob = await registered(agent);
    const bytes = new TextEncoder().encode('%PDF-1.7 a brief');
    const part = await ada.uploadPart(bytes, 'application/pdf');
    assert.deepEqual(Object.keys(part), ['type', 'sha256', 'size']);
    await ada.send({ to: [bob.address!], text: 'Brief attached.', parts: [part] });
    const [d] = (await bob.sync()).messages;
    const received = d.message.parts[1] as typeof part;
    assert.deepEqual(await bob.fetchPart(received), bytes);
  });

  it('refuses a message naming a part not uploaded, with the hash', async () => {
    const { agent } = setup();
    const ada = await registered(agent);
    const sha256 = 'a'.repeat(64);
    const e = await failure(
      ada.send({ to: ['bob@agents.test'], text: 'The brief.', parts: [{ type: 'application/pdf', sha256, size: 1 }] }),
    );
    assert.deepEqual([e.status, e.code, e.details], [400, 'part_not_uploaded', { sha256 }]);
  });

  it('refuses bytes that do not hash to the part', async () => {
    const { agent } = setup();
    const ada = await registered(agent);
    const part = await ada.uploadPart(new Uint8Array([1, 2, 3]), 'application/octet-stream');
    const e = await failure(ada.fetchPart({ ...part, size: 4 }));
    assert.equal(e.code, 'hash_mismatch');
    const wrong = agent({ address: ada.address!, fetch: async () => new Response('other bytes') });
    assert.equal((await failure(wrong.fetchPart(part))).code, 'hash_mismatch');
  });

  it('carries 503 unavailable as retryable, with Retry-After', async () => {
    const problem = { type: 'about:blank', title: 'Unavailable', status: 503, code: 'unavailable', retryable: true };
    const busy: Fetch = async () =>
      Response.json(
        { ...problem, detail: 'Fetching from the author.' },
        { status: 503, headers: { 'retry-after': '7', 'content-type': 'application/problem+json' } },
      );
    const { agent } = setup();
    const e = await failure(agent({ fetch: busy }).fetchPart({ sha256: 'b'.repeat(64) }));
    assert.deepEqual(
      [e.status, e.code, e.message, e.retryable, e.retryAfter],
      [503, 'unavailable', 'Fetching from the author.', true, 7],
    );
  });

  it('reads problem details by the status: retryable follows it, and a body with no code is bad_response', async () => {
    const answer =
      (status: number, body: unknown): Fetch =>
      async () =>
        Response.json(body, { status, headers: { 'content-type': 'application/problem+json' } });
    const { agent } = setup();
    const get = (f: Fetch) => failure(agent({ fetch: f }).fetchPart({ sha256: 'b'.repeat(64) }));
    const lying = await get(answer(400, { code: 'invalid', retryable: true, detail: 'No.', details: { field: 'x' } }));
    assert.deepEqual([lying.code, lying.retryable, lying.details], ['invalid', false, { field: 'x' }]);
    for (const [status, code] of [
      [403, 'bad_signature'],
      [403, 'unsupported_algorithm'],
      [400, 'unsupported_version'],
    ] as const) {
      const e = await get(
        answer(status, { type: 'about:blank', title: 'T', status, code, retryable: false, detail: 'd' }),
      );
      assert.deepEqual([e.status, e.code, e.retryable], [status, code, false]);
    }
    const old = await get(answer(500, { error: { code: 'unavailable', message: 'old shape' } }));
    assert.deepEqual([old.code, old.retryable], ['bad_response', true]);
  });
});

describe('the revised wire', () => {
  it('refuses a message of a version the server does not implement: 400 unsupported_version', async () => {
    const key = generateKey();
    const { agent } = setup();
    const ada = await registered(() => agent({ key: key.privateKeyPem }));
    const v7 = signMessage(
      { v: 7, from: ada.address!, to: ['bob@agents.test'], sentAt: timestamp(new Date()) },
      key.privateKey,
    );
    const e = await failure(ada.send(v7 as never));
    assert.deepEqual([e.status, e.code, e.retryable, e.details], [400, 'unsupported_version', false, { field: 'v' }]);
  });

  it("reads the server document's algorithms", async () => {
    const { fake } = setup();
    const doc = await fetchServerDocument(fake.origin, { fetch: fake.fetch });
    assert.deepEqual(doc.algorithms, ['ed25519', 'ml-dsa-65']);
  });

  it('reports a delivery whose deadline passed as failed, expired', async () => {
    const { agent, fake } = setup();
    const ada = await registered(agent);
    const bob = await registered(agent);
    const { id } = await ada.send({ to: [bob.address!], text: 'Too late.' });
    fake.expire(id);
    assert.deepEqual(
      (await ada.sent(id)).servers.map(s => [s.status, s.reason]),
      [['failed', 'expired']],
    );
  });

  it("keeps an inbox claim's authoritative judgement as the server sent it", async () => {
    const claim = {
      type: 'acts-for',
      agent: '',
      for: 'mailto:ada@agents.test',
      verifiedAt: '2026-10-01T00:00:00Z',
      scope: ['converse'],
      authoritative: true,
    };
    const { agent } = setup({ claims: m => [{ ...claim, agent: m.from }] });
    const ada = await registered(agent);
    const bob = await registered(agent);
    await ada.send({ to: [bob.address!], text: 'Claimed.' });
    const [entry] = (await bob.sync()).messages;
    assert.deepEqual(entry.claims, [{ ...claim, agent: ada.address }]);
  });
});

describe('call and errors', () => {
  it('signs any request to the server', async () => {
    const { agent, fake } = setup();
    const ada = await registered(agent);
    const inbox = await ada.call<{ messages: unknown[] }>('get', '/simon/sync');
    assert.deepEqual(inbox.messages, []);
    const e = await failure(ada.call('POST', '/simon/nothing', { a: 1 }));
    assert.deepEqual([e.status, e.code], [404, 'not_found']);
    assert.equal(fake.requests.at(-1)!.headers.get('content-type'), 'application/json');
  });

  it("keeps the server's code, message, status, retryable and details, without the code in the message", async () => {
    const { agent } = setup();
    const ada = await registered(agent);
    const e = await failure(ada.send({ to: ['bob@agents.test'], text: 'hi', inReplyTo: 'nope' }));
    assert.equal(e.name, 'SimonError');
    assert.deepEqual([e.status, e.code, e.retryable, e.details], [400, 'invalid', false, { field: 'inReplyTo' }]);
    assert.ok(!e.message.includes('invalid'), e.message);
    assert.deepEqual(Object.keys(e.toJSON().error), [
      'code',
      'message',
      'status',
      'retryable',
      'details',
      'retryAfter',
    ]);
  });

  it('refuses a request signed for another clock as stale, with the server time', async () => {
    const { fake } = setup();
    const a = new Agent({
      server: fake.origin,
      key: generateKey().privateKeyPem,
      fetch: fake.fetch,
      now: () => new Date(Date.now() - 3_600_000),
    });
    const e = await failure(a.register());
    assert.equal(e.code, 'stale_request');
    assert.equal(typeof e.details?.serverTime, 'number');
  });

  it('names the URL when the network fails, and says it may pass', async () => {
    const down: Fetch = async () => {
      throw new TypeError('fetch failed', { cause: { code: 'ECONNREFUSED' } });
    };
    const e = await failure(
      new Agent({ server: 'https://simon.test', key: generateKey().privateKeyPem, fetch: down }).sync(),
    );
    assert.deepEqual([e.code, e.status, e.retryable], ['network_error', null, true]);
    assert.equal(e.message, 'GET https://simon.test/simon/sync failed: ECONNREFUSED.');
    assert.deepEqual(e.details, { url: 'https://simon.test/simon/sync', cause: 'ECONNREFUSED' });
  });

  it('times out a server that never answers', async () => {
    const never: Fetch = (_url, init) =>
      new Promise((_resolve, reject) => init?.signal?.addEventListener('abort', () => reject(init.signal!.reason)));
    const a = new Agent({
      server: 'https://simon.test',
      key: generateKey().privateKeyPem,
      fetch: never,
      timeoutMs: 20,
    });
    const e = await failure(a.sync());
    assert.deepEqual([e.code, e.retryable, e.details?.url], ['timeout', true, 'https://simon.test/simon/sync']);
  });

  it('describes an answer that is not in the protocol shape', async () => {
    const proxy: Fetch = async () => new Response('<html>Bad gateway</html>', { status: 502 });
    const e = await failure(
      new Agent({ server: 'https://simon.test', key: generateKey().privateKeyPem, fetch: proxy }).sync(),
    );
    assert.deepEqual([e.code, e.status, e.retryable], ['bad_response', 502, true]);
  });
});

describe('whole-exchange deadlines and caller cancellation', () => {
  it('preserves caller cancellation reason even when custom fetch ignores the signal', async () => {
    const controller = new AbortController();
    const reason = new Error('caller stopped the job');
    const pending = exchange(
      { fetch: async () => new Promise<Response>(() => {}), timeoutMs: 500 },
      'https://simon.test',
      { signal: controller.signal },
    );
    controller.abort(reason);
    await assert.rejects(pending, e => e === reason);
  });

  it('bounds custom fetch and stalled body reads, including unending cancellation cleanup', async () => {
    await assert.rejects(
      exchange({ fetch: async () => new Promise<Response>(() => {}), timeoutMs: 10 }, 'https://simon.test'),
      { code: 'timeout' },
    );
    const stream = new ReadableStream<Uint8Array>({
      pull: () => new Promise<void>(() => {}),
      cancel: () => new Promise<void>(() => {}),
    });
    await assert.rejects(exchange({ fetch: async () => new Response(stream), timeoutMs: 10 }, 'https://simon.test'), {
      code: 'timeout',
    });
  });

  it('retains only maxBytes+1 decoded bytes and does not await size-limit cancellation', async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new Uint8Array(1_000_000));
      },
      cancel: () => new Promise<void>(() => {}),
    });
    const answer = await exchange(
      { fetch: async () => new Response(stream), timeoutMs: 100 },
      'https://simon.test',
      {},
      8,
    );
    assert.equal(answer.body.byteLength, 9);
  });
});
