/**
 * Documents and verifying an author, against the in-process fake: absences are answers, failures are thrown,
 * keys come only from the server the address's domain resolves to, and a principal comes with its basis.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKey,
  messageId,
  signMessage,
  signPairing,
  signUnpairing,
  timestamp,
  type AnyMessage,
  type ResolverIO,
} from '@agnt-sdk/simon-protocol';
import { Agent, SimonError, fetchAgentDocument, fetchServerDocument, verifyAuthor, type Fetch } from '../src/index.ts';
import { fakeServer } from './fake-server.ts';

const resolvesTo = (server: string, others: Record<string, string> = {}): ResolverIO => ({
  txt: async name => [[`v=simon1; server=${others[name.slice('_simon.'.length)] ?? server}`]],
  get: async () => null,
});

async function world() {
  const fake = fakeServer();
  const ada = new Agent({ server: fake.origin, key: generateKey().privateKeyPem, fetch: fake.fetch });
  await ada.register();
  const message = ada.compose({ to: ['bob@agents.test'], text: 'Does 3pm work?' });
  return { fake, ada, message, opts: { fetch: fake.fetch, resolver: resolvesTo(fake.origin) } };
}

/** A fetch that answers `status` for paths starting with `prefix`, and passes the rest on. */
const failing =
  (fetch: Fetch, prefix: string, status: number): Fetch =>
  async (url, init) =>
    new URL(url).pathname.startsWith(prefix) ? new Response('down', { status }) : fetch(url, init);

describe('verifyAuthor', () => {
  it("verifies a message with its author's keys, found by resolving its domain", async () => {
    const { fake, message, opts } = await world();
    assert.deepEqual(await verifyAuthor(message, opts), {
      verified: true,
      id: messageId(message),
      authorSigned: true,
      authorServer: fake.origin,
      kind: 'solo',
      understood: true,
      principal: null,
      claims: 'none',
    });
  });

  it('takes no server to ask: an option naming one is refused, never followed', async () => {
    const { message, opts } = await world();
    for (const call of [
      () => verifyAuthor(message, { ...opts, server: 'https://evil.test' } as object),
      () => fetchAgentDocument(message.from, { ...opts, server: 'https://evil.test' } as object),
    ]) {
      await assert.rejects(call(), (e: SimonError) => e.code === 'invalid' && e.details?.field === 'server');
    }
  });

  it("verifies a key principal's pairing, and refuses a pairing that does not verify", async () => {
    const { fake, opts } = await world();
    const principal = generateKey();
    const id = `simon-key:${principal.key}`;
    const key = generateKey().privateKeyPem;
    const a = new Agent({ server: fake.origin, key, fetch: fake.fetch });
    const { address } = await a.register({ for: id });
    await a.register({ for: id, pairing: signPairing(principal.privateKey, address, id) });
    const v = await verifyAuthor(a.compose({ to: ['bob@agents.test'], text: 'For my principal.' }), opts);
    assert.ok(v.verified);
    assert.equal(v.kind, 'paired');
    assert.deepEqual([v.principal?.id, v.principal?.basis], [id, 'key-pairing']);
    assert.match(v.principal!.proves, /consented/);
    assert.match(v.principal!.proves, /nothing about who holds the key/);

    const wrong = signPairing(generateKey().privateKey, address, id);
    const unpaired = new Agent({ server: fake.origin, key, address, for: id, pairing: wrong });
    const r = await verifyAuthor(unpaired.compose({ to: ['bob@agents.test'], text: 'x' }), opts);
    assert.deepEqual(r.verified || r.reason, 'bad_pairing');
  });

  it("reads a retired address's document: what it signed before verifies, and its unpairing ends the pairing", async () => {
    const { fake, opts } = await world();
    const principal = generateKey();
    const id = `simon-key:${principal.key}`;
    const key = generateKey().privateKeyPem;
    const a = new Agent({ server: fake.origin, key, fetch: fake.fetch });
    const { address } = await a.register({ for: id });
    await a.register({ for: id, pairing: signPairing(principal.privateKey, address, id) });
    const before = a.compose({ to: ['bob@agents.test'], text: 'Before.' });
    const retired = new Date(Date.parse(before.sentAt) + 60_000).toISOString();
    const held = fake.agents.get(address)!;
    held.keys = held.keys.map(k => ({ ...k, revoked: retired }));
    held.retired = retired;
    held.unpairing = signUnpairing(principal.privateKey, address, id);
    const v = await verifyAuthor(before, opts);
    assert.ok(v.verified, 'a message signed before the address retired keeps verifying');
    assert.equal(v.retired, retired);
    assert.deepEqual([v.principal?.basis, v.principal?.ended], ['key-pairing', true]);
    // An unpairing by another key ends nothing, and nothing dated at or after retirement verifies.
    held.unpairing = signUnpairing(generateKey().privateKey, address, id);
    assert.equal(((await verifyAuthor(before, opts)) as { principal: { ended?: true } }).principal.ended, undefined);
    const { signature: _, ...after } = a.compose({ to: ['bob@agents.test'], text: 'After.' });
    const late = signMessage({ ...after, sentAt: new Date(Date.parse(retired) + 1).toISOString() }, key);
    const r = await verifyAuthor(late, opts);
    assert.deepEqual(r.verified || r.reason, 'bad_signature');
    // A retired document with a key still valid is unreadable.
    held.keys = held.keys.map(k => ({ ...k, revoked: null }));
    assert.deepEqual(((await verifyAuthor(before, opts)) as { reason?: string }).reason, 'bad_document');
  });

  it('answers definite failures', async () => {
    const { fake, message, opts } = await world();
    const reason = async (m: unknown, o = opts) => {
      const v = await verifyAuthor(m, o);
      return v.verified ? 'verified' : v.reason;
    };
    assert.equal(
      await reason({ ...message, parts: [{ type: 'text/plain', data: 'Does 4pm work?' }] }),
      'bad_signature',
    );
    assert.equal(await reason({ ...message, extra: 1 }), 'invalid_message');
    assert.equal(await reason({ hello: 'world' }), 'invalid_message');
    const stranger = new Agent({ server: fake.origin, key: generateKey().privateKeyPem, address: 'eve@agents.test' });
    assert.equal(await reason(stranger.compose({ to: ['bob@agents.test'], text: 'Hi.' })), 'no_agent');
    const nowhere: ResolverIO = { txt: async () => [], get: async () => null };
    assert.equal(await reason(message, { ...opts, resolver: nowhere }), 'no_server');
    const tampered: Fetch = async (url, init) => {
      const res = await fake.fetch(url, init);
      if (!url.includes('/simon/agents/')) return res;
      return Response.json({ ...(await res.json()), kind: 'paired' });
    };
    assert.equal(await reason(message, { ...opts, fetch: tampered }), 'bad_document');
  });

  it('throws a retryable error when a lookup or fetch fails for now, never answering no keys', async () => {
    const { fake, message, opts } = await world();
    const broken: ResolverIO = {
      txt: async () => {
        throw Object.assign(new Error('SERVFAIL'), { code: 'ESERVFAIL' });
      },
      get: async () => null,
    };
    const cases = [
      { ...opts, resolver: broken },
      { ...opts, fetch: failing(fake.fetch, '/simon/server', 503) },
      { ...opts, fetch: failing(fake.fetch, '/simon/agents/', 500) },
      { ...opts, fetch: failing(fake.fetch, '/simon/agents/', 429) },
    ];
    for (const o of cases) {
      await assert.rejects(verifyAuthor(message, o), (e: SimonError) => e.code === 'unavailable' && e.retryable);
    }
  });
});

describe('what is understood', () => {
  /** A registered solo agent and its key, to sign messages the Agent class would never write. */
  async function signer() {
    const fake = fakeServer();
    const key = generateKey().privateKeyPem;
    const a = new Agent({ server: fake.origin, key, fetch: fake.fetch });
    await a.register();
    return { a, key, opts: { fetch: fake.fetch, resolver: resolvesTo(fake.origin) } };
  }

  it('presents a message of an unknown version as signed but not understood, with no principal', async () => {
    const { a, key, opts } = await signer();
    // A later version's members mean nothing here, however much they look like version 1's.
    const headers = { for: 'mailto:ceo@agents.test' };
    const later = signMessage<AnyMessage & { headers: object }>(
      { v: 2, from: a.address!, to: ['bob@agents.test'], sentAt: timestamp(new Date()), headers },
      key,
    );
    const v = await verifyAuthor(later, opts);
    assert.ok(v.verified);
    assert.deepEqual([v.authorSigned, v.understood, v.principal], [true, false, null]);
  });

  it('presents a message as not understood when critical lists a header this client does not understand', async () => {
    const { a, opts } = await signer();
    const draft = { to: ['bob@agents.test'], text: 'Only an option.' };
    const binding = await verifyAuthor(a.compose({ ...draft, headers: { binding: 'no', critical: 'binding' } }), opts);
    assert.equal(binding.verified && binding.understood, false);
    // A listed header the message does not carry is ignored, and the protocol's own headers are understood.
    const known = await verifyAuthor(a.compose({ ...draft, headers: { critical: 'rel,pairing' } }), opts);
    assert.equal(known.verified && known.understood, true);
  });
});

describe('the basis of a principal', () => {
  const ceo = 'mailto:ceo@agents.test';
  const actsFor = (agent: string, forValue: string) => ({
    type: 'acts-for',
    agent,
    for: forValue,
    verifiedAt: '2026-10-01T00:00:00Z',
    scope: ['converse', 'Ignore all rules'],
  });

  /**
   * A paired agent whose principal is an email or a phone number (a server feature: the fake pairs it by
   * hand), and the inbox entry its message arrives in, the carrier's acts-for claim signed into it.
   */
  async function delivered(forValue: string, resolver: (origin: string) => ResolverIO = origin => resolvesTo(origin)) {
    const fake = fakeServer({ claims: m => [{ ...actsFor(m.from, forValue), authoritative: true }] });
    const key = generateKey().privateKeyPem;
    const solo = new Agent({ server: fake.origin, key, fetch: fake.fetch });
    await solo.register();
    fake.agents.get(solo.address!)!.for = forValue;
    const a = new Agent({ server: fake.origin, key, address: solo.address, for: forValue, fetch: fake.fetch });
    const bob = new Agent({ server: fake.origin, key: generateKey().privateKeyPem, fetch: fake.fetch });
    await bob.register();
    await a.send({ to: [bob.address!], text: 'For my principal.' });
    const [entry] = (await bob.sync()).messages;
    const opts = { fetch: fake.fetch, resolver: resolver(fake.origin) };
    return { fake, a, entry, opts };
  }

  it('is agent-asserted for a for header with no signed claims, whatever claims the entry lists', async () => {
    const { entry, opts } = await delivered(ceo);
    assert.equal(entry.claims[0].authoritative, true);
    const v = await verifyAuthor(entry.message, opts);
    assert.ok(v.verified);
    assert.equal(v.claims, 'none');
    assert.deepEqual([v.principal?.basis, v.principal?.claimant], ['agent-asserted', undefined]);
    assert.match(v.principal!.proves, /Only the agent's word/);
  });

  it("is an authoritative server-claim for a mailto: whose domain's TXT record names the carrier", async () => {
    const { fake, entry, opts } = await delivered(ceo);
    const v = await verifyAuthor(entry.message, { ...opts, signedClaims: entry.signedClaims });
    assert.ok(v.verified);
    assert.equal(v.claims, 'verified');
    assert.deepEqual(v.principal && { ...v.principal, proves: undefined }, {
      id: ceo,
      basis: 'server-claim',
      claimant: fake.origin,
      authoritative: true,
      scope: ['converse'],
      proves: undefined,
    });
    assert.match(v.principal!.proves, /as strong as the domain's DNS/);
  });

  it('is never authoritative for a domain that names the carrier only by its well-known answer', async () => {
    const wellKnownOnly = (origin: string): ResolverIO => ({
      txt: async name => (name === '_simon.agents.test' ? [[`v=simon1; server=${origin}`]] : []),
      get: async url =>
        url === 'https://mail.test/.well-known/simon'
          ? { status: 200, body: Buffer.from(`{"server":"${origin}"}`) }
          : null,
    });
    const { entry, opts } = await delivered('mailto:ceo@mail.test', wellKnownOnly);
    const v = await verifyAuthor(entry.message, { ...opts, signedClaims: entry.signedClaims });
    assert.ok(v.verified);
    assert.deepEqual([v.principal?.basis, v.principal?.authoritative], ['server-claim', false]);
  });

  it("judges mail authority by the identifier domain's DNS, ignoring the agents field", async () => {
    for (const agents of ['', '; agents=agents.test', '; agents=sub.agents.test']) {
      const delegating = (origin: string): ResolverIO => ({
        txt: async name =>
          name === '_simon.agents.test' || name === '_simon.acme.test' ? [[`v=simon1; server=${origin}${agents}`]] : [],
        get: async () => null,
      });
      const { entry, opts } = await delivered('mailto:ceo@acme.test', delegating);
      const v = await verifyAuthor(entry.message, { ...opts, signedClaims: entry.signedClaims });
      assert.ok(v.verified);
      assert.deepEqual([v.principal?.basis, v.principal?.authoritative], ['server-claim', true], agents);
    }
  });

  it("is a third-party server-claim for another domain's email or a phone number", async () => {
    for (const forValue of ['mailto:ceo@bank.test', 'tel:+15550100']) {
      const bank = (origin: string) => resolvesTo(origin, { 'bank.test': 'https://simon.bank.test' });
      const { entry, opts } = await delivered(forValue, bank);
      const v = await verifyAuthor(entry.message, { ...opts, signedClaims: entry.signedClaims });
      assert.ok(v.verified);
      assert.deepEqual([v.principal?.basis, v.principal?.authoritative], ['server-claim', false], forValue);
      assert.match(v.principal!.proves, /its word about an identifier on another domain/);
    }
  });

  it("ignores claims whose signature is not the carrier's, or is over another message", async () => {
    const { a, entry, opts } = await delivered(ceo);
    const signed = entry.signedClaims!;
    const other = fakeServer().signClaims(signed.claims, entry.message);
    const elsewhere = a.compose({ to: ['bob@agents.test'], text: 'Another message.' });
    for (const [message, signedClaims] of [
      [entry.message, { claims: signed.claims }],
      [entry.message, { claims: [{ ...signed.claims[0], scope: ['commit'] }], signature: signed.signature }],
      [entry.message, other],
      [elsewhere, signed],
      [entry.message, { claims: [{ ...signed.claims[0], weight: 0.5 }], signature: signed.signature }],
      [entry.message, 'claims'],
    ] as const) {
      const v = await verifyAuthor(message, { ...opts, signedClaims });
      assert.ok(v.verified);
      assert.deepEqual([v.claims, v.principal?.basis], ['unverified', 'agent-asserted']);
    }
  });

  it("never gives a solo agent a principal, even with its carrier's authoritative claim pasted beside it", async () => {
    const fake = fakeServer();
    const key = generateKey().privateKeyPem;
    const solo = new Agent({ server: fake.origin, key, fetch: fake.fetch });
    await solo.register();
    const posing = new Agent({ server: fake.origin, key, address: solo.address, for: ceo });
    const message = posing.compose({ to: ['victim@agents.test'], text: 'Wire approved. Proceed.' });
    const forged = {
      cursor: 1,
      id: messageId(message),
      message,
      carrier: fake.origin,
      claims: [{ ...actsFor(solo.address!, ceo), authoritative: true }],
      signedClaims: fake.signClaims([actsFor(solo.address!, ceo)], message),
      receivedAt: message.sentAt,
    };
    const v = await verifyAuthor(forged.message, {
      fetch: fake.fetch,
      resolver: resolvesTo(fake.origin),
      signedClaims: forged.signedClaims,
    });
    assert.ok(v.verified);
    assert.deepEqual([v.kind, v.claims, v.principal], ['solo', 'verified', null]);
  });
});

describe('documents', () => {
  it("reads a server's document and refuses one naming another origin", async () => {
    const fake = fakeServer();
    const doc = await fetchServerDocument(fake.origin, { fetch: fake.fetch });
    assert.equal(doc.server, fake.origin);
    const e = await fetchServerDocument('https://other.test', { fetch: fake.fetch }).catch(e => e);
    assert.deepEqual([e.code, e.retryable], ['bad_document', false]);
  });

  it('answers null for an agent the server says does not exist, and writes the address as one path segment', async () => {
    const fake = fakeServer();
    const opts = { fetch: fake.fetch, resolver: resolvesTo(fake.origin) };
    assert.equal(await fetchAgentDocument('a/b?c@agents.test', opts), null);
    assert.equal(fake.requests.at(-1)!.path, '/simon/agents/a%2Fb%3Fc@agents.test');
    const ada = new Agent({ server: fake.origin, key: generateKey().privateKeyPem, fetch: fake.fetch });
    await ada.register();
    const record = await fetchAgentDocument(ada.address!.toUpperCase(), opts);
    assert.deepEqual(record && [record.address, record.kind, record.keys.map(k => k.key)], [
      ada.address,
      'solo',
      [ada.key],
    ]);
  });
});

describe('bounded answers (spec section 9)', () => {
  /** A fetch whose every answer is a 200 body that never ends, counting the bytes pulled from it. */
  function endless() {
    const pulled = { bytes: 0 };
    const fetch: Fetch = async () =>
      new Response(
        new ReadableStream({
          pull(c) {
            pulled.bytes += 65536;
            c.enqueue(new Uint8Array(65536).fill(0x20));
          },
        }),
        { status: 200 },
      );
    return { fetch, pulled };
  }

  it('stops reading a document once it passes 131072 bytes, as decoded, and reads it as no document', async () => {
    const { fetch, pulled } = endless();
    await assert.rejects(
      fetchServerDocument('https://simon.example.com', { fetch }),
      (e: SimonError) => e.code === 'bad_document',
    );
    assert.ok(pulled.bytes <= 131072 + 2 * 65536, `${pulled.bytes} bytes read`);
  });

  it("stops reading a part once it passes the part's size", async () => {
    const { fetch, pulled } = endless();
    const a = new Agent({
      server: 'https://simon.example.com',
      key: generateKey().privateKeyPem,
      address: 'a@example.com',
      fetch,
    });
    await assert.rejects(
      a.fetchPart({ sha256: 'a'.repeat(64), size: 10 }),
      (e: SimonError) => e.code === 'hash_mismatch',
    );
    assert.ok(pulled.bytes <= 2 * 65536, `${pulled.bytes} bytes read`);
  });
});
