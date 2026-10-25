/**
 * CLIENT.md `send` and `sent`, and spec section 8 (signed requests) as agents meet it.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import {
  canonicalize,
  generateKey,
  MAX_ENVELOPE_EXTRAS_BYTES,
  sha256Hex,
  signMessage,
  signPairing,
  signSuccession,
  signUnpairing,
  signRequest,
  timestamp,
  type Claim,
  type Message,
  readServerDocument,
  verifyClaims,
} from '@agnt-sdk/simon-protocol';
import { CLOCK_PAIRING_UNTIL, Federation, type TestAgent } from './harness.ts';

const TEXT = { type: 'text/plain', data: 'x' };

describe('send (CLIENT.md)', async () => {
  const fed = new Federation();
  after(() => fed.close());
  const alpha = await fed.server('alpha');
  const beta = await fed.server('beta');
  const ada = await alpha.agent('ada');
  const bob = await beta.agent('bob');

  const code = async (p: Promise<{ status: number; json: any }>) => {
    const res = await p;
    return [res.status, res.json?.code, res.json?.details?.field];
  };

  it('refuses a message not in canonical form, with the canonical form', async () => {
    const m = ada.message([bob.address], 'x');
    const res = await ada.request('POST', '/simon/send', { body: JSON.stringify(m, null, 1) });
    assert.equal(res.status, 400);
    assert.equal(res.json.details.canonical, JSON.stringify(JSON.parse(res.json.details.canonical)));
  });

  it('sends only as the agent itself, on a domain that still names this server', async () => {
    const forged = signMessage<Message>({ ...ada.message([bob.address], 'x'), from: 'eve@alpha.test' }, ada.key);
    assert.deepEqual(await code(ada.send(forged)), [400, 'invalid', 'from']);
    const cat = await alpha.agent('cat');
    fed.dns.point('alpha.test', beta.origin);
    fed.clock.advance(11 * 60_000); // past the resolution cache
    assert.deepEqual(await code(cat.send(cat.message([bob.address], 'x'))), [409, 'address_not_served', undefined]);
    fed.dns.point('alpha.test', alpha.origin);
    fed.clock.advance(11 * 60_000);
  });

  it('holds a solo agent to no for header, and a paired one to its principal and pairing (spec section 2.2)', async () => {
    const solo = ada.message([bob.address], 'x', { headers: { for: 'mailto:ann@example.org' } });
    assert.deepEqual(await code(ada.send(solo)), [400, 'invalid', 'headers']);

    const principal = generateKey();
    const forValue = `simon-key:${principal.key}`;
    const p = alpha.newAgent();
    await p.register({
      address: 'p@alpha.test',
      for: forValue,
      pairing: signPairing(principal.privateKey, 'p@alpha.test', forValue, CLOCK_PAIRING_UNTIL),
    });
    assert.deepEqual(await code(p.send(p.message([bob.address], 'x'))), [400, 'invalid', 'headers']);
    const pairing = signPairing(principal.privateKey, p.address, forValue, CLOCK_PAIRING_UNTIL);
    assert.equal((await p.send(p.message([bob.address], 'x', { headers: { for: forValue, pairing } }))).status, 200);
  });

  it('checks the signature before the paired or solo rule and sentAt', async () => {
    fed.clock.advance(26 * 3600_000); // ada's key must be older than the stale sentAt, or nothing verifies
    const stale = timestamp(fed.clock.t - 25 * 3600_000);
    const both = signMessage<Message>(
      { ...ada.message([bob.address], 'x', { headers: { for: 'mailto:ann@example.org' }, sentAt: stale }) },
      generateKey().privateKey,
    );
    assert.deepEqual(await code(ada.send(both)), [401, 'bad_signature', undefined]);
    const unsigned = ada.message([bob.address], 'x', { headers: { for: 'mailto:ann@example.org' }, sentAt: stale });
    assert.deepEqual(await code(ada.send(unsigned)), [400, 'invalid', 'headers']);
  });

  it('takes a message at most 24 hours old and 5 minutes ahead', async () => {
    const old = ada.message([bob.address], 'x', { sentAt: timestamp(fed.clock.t - 24 * 3600_000 - 1000) });
    assert.deepEqual(await code(ada.send(old)), [400, 'invalid', 'sentAt']);
    const ahead = ada.message([bob.address], 'x', { sentAt: timestamp(fed.clock.t + 6 * 60_000) });
    assert.deepEqual(await code(ada.send(ahead)), [400, 'invalid', 'sentAt']);
  });

  it("refuses a message its author's keys do not verify", async () => {
    const m = { ...ada.message([bob.address], 'x'), signature: ada.message([bob.address], 'y').signature };
    assert.deepEqual(await code(ada.send(m)), [401, 'bad_signature', undefined]);
  });

  it('needs every content-addressed part uploaded by this agent first', async () => {
    const bytes = Buffer.from('%PDF-1.7 a contract');
    const part = { type: 'application/pdf', sha256: sha256Hex(bytes), size: bytes.length };
    const m = ada.message([bob.address], 'x', { parts: [TEXT, part] });
    const res = await ada.send(m);
    assert.deepEqual([res.status, res.json.code, res.json.details.sha256], [400, 'part_not_uploaded', part.sha256]);
    await ada.upload(bytes);
    assert.equal((await ada.send(m)).status, 200);
  });

  it('refuses to carry whole a message for an audience narrower than public, at any depth (spec section 5.4)', async () => {
    const carry = (m: object) => ({
      type: 'application/simon-message',
      data: Buffer.from(canonicalize(m as never)).toString('base64'),
    });
    const post = bob.message([], 'for followers', { headers: { audience: 'followers' } });
    const open = bob.message([], 'for anyone');
    assert.deepEqual(await code(ada.send(ada.message([bob.address], 'fwd', { parts: [TEXT, carry(post)] }))), [
      400,
      'invalid',
      'parts',
    ]);
    const wrapped = ada.message([bob.address], 'inner', { parts: [TEXT, carry(post)] });
    assert.deepEqual(await code(ada.send(ada.message([bob.address], 'fwd', { parts: [TEXT, carry(wrapped)] }))), [
      400,
      'invalid',
      'parts',
    ]);
    assert.equal((await ada.send(ada.message([bob.address], 'fwd', { parts: [TEXT, carry(open)] }))).status, 200);
    // A message to no one with no audience is its author's alone; a first-draft post's narrow audience still binds.
    const unsaid = { ...bob.message([], 'unsaid'), headers: {} };
    const draft1 = { ...bob.message([], 'first draft', { headers: { audience: 'followers' } }), v: 1 };
    for (const inner of [unsaid, draft1])
      assert.deepEqual(await code(ada.send(ada.message([bob.address], 'fwd', { parts: [TEXT, carry(inner)] }))), [
        400,
        'invalid',
        'parts',
      ]);
  });

  it('answers a repeat with the same id and receivedAt', async () => {
    const m = ada.message([bob.address], 'once');
    const first = await ada.send(m);
    fed.clock.advance(1000);
    assert.deepEqual((await ada.send(m)).json, first.json);
  });

  it('checks simon-hints as part of the envelope it will travel in', async () => {
    const m = ada.message([bob.address], 'x');
    assert.deepEqual(await code(ada.send(m, { 'eve@beta.test': { invite: 'x' } })), [400, 'invalid', 'hints']);
    assert.deepEqual(await code(ada.send(m, { [bob.address]: { invite: 'x'.repeat(17000) } })), [
      400,
      'invalid',
      'claims',
    ]);
    assert.equal((await ada.send(m, { [bob.address]: { invite: 'x' } })).status, 200);
    const raw = await ada.send(m, { [bob.address]: { note: 'café' } });
    assert.deepEqual([raw.status, raw.json.details.field], [400, 'simon-hints'], 'ASCII only, never read as Latin-1');
  });

  it('checks hints on a repeat against the claims that travel, as the first send did', async () => {
    const gamma = await fed.server('gamma', {
      extensions: [{ name: 'claims', claimsFor: m => [identifier(m.from)] }],
    });
    // An identifier claim is one this server judges, so the one it stores carries `authoritative`; the one sent
    // does not.
    const identifier = (agent: string) =>
      ({
        type: 'identifier',
        agent,
        of: 'agent',
        identifier: 'mailto:cat@example.org',
        verifiedAt: '2026-10-01T00:00:00Z',
      }) as Claim;
    const cat = await gamma.agent('cat');
    const claim = identifier(cat.address);
    const m = cat.message([bob.address], 'near the bound');
    const extras = (pad: string) => canonicalize({ claims: [claim], hints: { [bob.address]: { pad } } });
    const hints = { [bob.address]: { pad: 'x'.repeat(MAX_ENVELOPE_EXTRAS_BYTES - extras('').length) } };
    const first = await cat.send(m, hints);
    assert.equal(first.status, 200, JSON.stringify(first.json));
    const again = await cat.send(m, hints);
    assert.deepEqual([again.status, again.json], [200, first.json], 'the retry answers as the first call did');
  });

  it('signs the claims of a message written here, so a local recipient gets signedClaims whenever claims', async () => {
    const delta = await fed.server('delta', {
      extensions: [
        {
          name: 'claims',
          claimsFor: m => [
            {
              type: 'identifier',
              agent: m.from,
              of: 'agent',
              identifier: 'mailto:dee@delta.test',
              verifiedAt: '2026-10-01T00:00:00Z',
            },
          ],
        },
      ],
    });
    const [dee, dan] = [await delta.agent('dee'), await delta.agent('dan')];
    const m = dee.message([dan.address], 'here');
    assert.equal((await dee.send(m)).status, 200);
    await fed.work();
    const [entry] = (await dan.sync()).json.messages;
    assert.equal(entry.claims.length, 1);
    assert.ok(entry.signedClaims, 'signedClaims beside claims');
    const doc = readServerDocument(
      (await dan.request('GET', '/simon/server', { sign: false })).bytes,
      delta.origin,
      fed.clock.now(),
    )!;
    assert.equal(verifyClaims(entry.signedClaims, m, doc.keys), true, 'signed by this server, as a carrier signs');
  });

  it('counts distinct destination domains against the sender, not just messages', async () => {
    const gamma = await fed.server('gamma', { config: { rates: { destinations: { limit: 2, seconds: 3600 } } } });
    const g = await gamma.agent('g');
    assert.equal((await g.send(g.message(['a@one.example', 'b@two.example'], '1'))).status, 200);
    assert.equal((await g.send(g.message(['c@one.example'], '2'))).status, 200, 'a domain already counted is free');
    const res = await g.send(g.message(['d@three.example'], '3'));
    assert.equal(res.status, 429);
    assert.ok(Number(res.headers['retry-after']) > 0);
  });
});

describe('a pairing that lapses (spec section 2.2)', async () => {
  const fed = new Federation();
  after(() => fed.close());
  const alpha = await fed.server('alpha');
  const bob = await alpha.agent('bob');

  it('judges the pairing at sentAt, refuses one lapsed by then, and takes a renewed one with no call to the server', async () => {
    const principal = generateKey();
    const forValue = `simon-key:${principal.key}`;
    const p = alpha.newAgent();
    const pairing = signPairing(principal.privateKey, 'lapse@alpha.test', forValue, CLOCK_PAIRING_UNTIL);
    assert.equal((await p.register({ address: 'lapse@alpha.test', for: forValue, pairing })).status, 200);
    const send = (pairing: string) => p.send(p.message([bob.address], 'x', { headers: { for: forValue, pairing } }));

    // Judged at sentAt, not the server's now: an hour old, it was sent while the pairing counted.
    fed.clock.t = Date.parse(CLOCK_PAIRING_UNTIL) + 1000;
    const hourOld = p.message([bob.address], 'x', {
      headers: { for: forValue, pairing },
      sentAt: timestamp(fed.clock.t - 3_600_000),
    });
    assert.equal((await p.send(hourOld)).status, 200);
    const lapsed = await send(pairing);
    assert.deepEqual([lapsed.status, lapsed.json.code, lapsed.json.details.field], [400, 'invalid', 'headers']);
    const renewed = signPairing(principal.privateKey, p.address, forValue, timestamp(fed.clock.t + 90 * 86_400_000));
    assert.equal((await send(renewed)).status, 200);
  });
});

describe('a principal that moves to a new key (spec section 2.2)', async () => {
  const fed = new Federation();
  after(() => fed.close());
  const alpha = await fed.server('alpha');
  const bob = await alpha.agent('bob');

  it('moves the record along a succession both keys signed, and then holds the agent to the new key', async () => {
    const [old, fresh, stranger] = [generateKey(), generateKey(), generateKey()];
    const [oldFor, newFor] = [`simon-key:${old.key}`, `simon-key:${fresh.key}`];
    const p = alpha.newAgent();
    const address = 'moving@alpha.test';
    const oldPairing = signPairing(old.privateKey, address, oldFor, CLOCK_PAIRING_UNTIL);
    assert.equal((await p.register({ address, for: oldFor, pairing: oldPairing })).status, 200);
    const newPairing = signPairing(fresh.privateKey, address, newFor, CLOCK_PAIRING_UNTIL);
    const send = (headers: Record<string, string>) => p.send(p.message([bob.address], 'x', { headers }));
    const code = async (headers: Record<string, string>) => {
      const res = await send(headers);
      return [res.status, res.json?.code];
    };

    assert.deepEqual(await code({ for: newFor, pairing: newPairing }), [400, 'invalid'], 'no succession');
    const forged = signSuccession(stranger.privateKey, fresh.privateKey);
    assert.deepEqual(
      await code({ for: newFor, pairing: newPairing, succession: forged }),
      [400, 'invalid'],
      "a succession from someone else's key",
    );
    const succession = signSuccession(old.privateKey, fresh.privateKey);
    assert.equal((await send({ for: newFor, pairing: newPairing, succession })).status, 200);
    assert.equal((await alpha.store.agentByAddress(address))?.principal, newFor);
    assert.equal((await send({ for: newFor, pairing: newPairing })).status, 200, 'the chain is history now');
    assert.deepEqual(await code({ for: oldFor, pairing: oldPairing }), [400, 'invalid'], 'the old key is left');
    const post = (body: object) => alpha.newAgent().request('POST', '/simon/unpair', { body: JSON.stringify(body) });
    const unpair = (k: typeof old) => ({
      address,
      unpairing: signUnpairing(k.privateKey, address, `simon-key:${k.key}`),
    });
    assert.equal((await post(unpair(old))).status, 401, 'the key it left unpairs it no more');
    assert.equal((await post(unpair(fresh))).status, 200, 'the key it moved to does');
  });

  it('moves the record only for a message it accepts, and once for concurrent sends of the same move', async () => {
    const [old, fresh] = [generateKey(), generateKey()];
    const [oldFor, newFor] = [`simon-key:${old.key}`, `simon-key:${fresh.key}`];
    const p = alpha.newAgent();
    const address = 'racing@alpha.test';
    const pairing = signPairing(old.privateKey, address, oldFor, CLOCK_PAIRING_UNTIL);
    assert.equal((await p.register({ address, for: oldFor, pairing })).status, 200);
    const headers = {
      for: newFor,
      pairing: signPairing(fresh.privateKey, address, newFor, CLOCK_PAIRING_UNTIL),
      succession: signSuccession(old.privateKey, fresh.privateKey),
    };
    // Refused for a file never uploaded: a check after the principal's.
    const missing = p.message([bob.address], 'x', {
      headers,
      parts: [{ type: 'application/pdf', sha256: '0'.repeat(64), size: 10 }],
    });
    assert.equal((await p.send(missing)).json.code, 'part_not_uploaded');
    assert.equal((await alpha.store.agentByAddress(address))?.principal, oldFor, 'a refused message moves nothing');
    const [one, two] = await Promise.all([
      p.send(p.message([bob.address], 'one', { headers })),
      p.send(p.message([bob.address], 'two', { headers })),
    ]);
    assert.deepEqual([one.status, two.status], [200, 200]);
    assert.equal((await alpha.store.agentByAddress(address))?.principal, newFor);
  });
});

describe('sent (CLIENT.md)', async () => {
  const fed = new Federation();
  after(() => fed.close());
  const alpha = await fed.server('alpha');
  const ada = await alpha.agent('ada');
  const bob = await alpha.agent('bob');

  it("reports delivery per server, and 404 for another agent's message", async () => {
    const m = ada.message([bob.address, 'x@nowhere.example'], 'to two');
    const { json } = await ada.send(m);
    assert.deepEqual(
      (await ada.sent(json.id)).json.servers.map((s: { status: string }) => s.status),
      ['pending', 'pending'],
    );
    await fed.work();
    assert.deepEqual((await ada.sent(json.id)).json.servers, [
      { server: alpha.origin, recipients: [bob.address], status: 'delivered' },
      { server: null, recipients: ['x@nowhere.example'], status: 'failed', reason: 'not_found' },
    ]);
    const theirs = await bob.sent(json.id);
    const unknown = await bob.sent('0'.repeat(64));
    assert.equal(theirs.status, 404);
    assert.deepEqual(theirs.bytes, unknown.bytes, 'the same bytes as for a message this server does not know');
  });
});

describe('signed requests (spec section 8)', async () => {
  const fed = new Federation();
  after(() => fed.close());
  const alpha = await fed.server('alpha');
  const ada: TestAgent = await alpha.agent('ada');
  const inbox = (headers: Record<string, string>) => ada.request('GET', '/simon/sync', { sign: false, headers });
  const signed = (nonce: string, now = fed.clock.t) =>
    ada.request('GET', '/simon/sync', { sign: false, headers: sig(ada, '/simon/sync', nonce, now) });

  it('refuses a missing or malformed header with signature_required and the server time', async () => {
    const res = await inbox({});
    assert.deepEqual([res.status, res.json.code], [401, 'signature_required']);
    assert.equal(res.json.details.serverTime, Math.floor(fed.clock.t / 1000));
    assert.equal(
      (await inbox({ ...sig(ada, '/simon/sync', 'short'), 'simon-nonce': 'short' })).json.code,
      'signature_required',
    );
  });

  it('refuses a timestamp outside 300 seconds', async () => {
    assert.equal((await signed('nonce-stale-1', fed.clock.t - 301_000)).json.code, 'stale_request');
    assert.equal((await signed('nonce-stale-2', fed.clock.t - 299_000)).status, 200);
  });

  it('refuses an unknown key, and a bad signature with the signing string expected', async () => {
    const stranger = generateKey();
    const res = await ada.request('GET', '/simon/sync', { key: stranger.privateKey });
    assert.equal(res.json.code, 'unknown_key');
    const bad = await inbox({
      ...sig(ada, '/simon/sync', 'nonce-bad-1'),
      'simon-signature': sig(ada, '/simon/other', 'nonce-bad-1')['simon-signature'],
    });
    assert.equal(bad.json.code, 'bad_signature');
    assert.match(
      bad.json.details.signingString,
      /^SIMON-REQUEST\nGET\nhttps:\/\/simon\.alpha\.test\nada@alpha\.test\n\/simon\/sync\n/,
    );
  });

  it('records a nonce only once a signature verified, and refuses its reuse', async () => {
    const forged = {
      ...sig(ada, '/simon/sync', 'nonce-once'),
      'simon-signature': sig(ada, '/x', 'nonce-once')['simon-signature'],
    };
    assert.equal((await inbox(forged)).json.code, 'bad_signature');
    assert.equal((await signed('nonce-once')).status, 200, 'the forged request did not use the nonce up');
    assert.equal((await signed('nonce-once')).json.code, 'replayed_request');
    fed.clock.advance(601_000);
    assert.equal((await signed('nonce-once')).status, 200, 'a nonce is kept 600 seconds');
  });
});

function sig(a: TestAgent, target: string, nonce: string, now = a.fed.clock.t) {
  return signRequest(a.key, { method: 'GET', url: a.home.origin + target, now, nonce, agent: a.address });
}
