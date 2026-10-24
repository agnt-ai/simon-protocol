/**
 * Spec section 6.3: the checks of a delivery, each in its place in the order, and the answers. A peer
 * played by the test sends what a well-behaved server never would.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import {
  canonicalBytes,
  canonicalize,
  generateKey,
  keyToken,
  MAX_ENVELOPE_EXTRAS_BYTES,
  signEnvelope,
  signMessage,
  signPairing,
  timestamp,
  verifyClaims,
  type Message,
} from '@agnt-protocol/protocol';
import { Federation, Peer, toRequest } from './harness.ts';

const HOUR = 3_600_000;

describe('deliver (spec section 6.3)', async () => {
  const fed = new Federation();
  after(() => fed.close());
  const alpha = await fed.server('alpha', { config: { trustedClaimServers: ['https://simon.trusted.test'] } });
  const bob = await alpha.agent('bob');
  const peer = new Peer(fed, 'peer');
  const zed = peer.agent('zed');
  const post = (body: object | Buffer) => peer.post(alpha, body);
  const answer = async (body: object | Buffer) => {
    const res = await post(body);
    return [res.status, res.json?.code ?? res.json, res.json?.details?.field];
  };

  it('1. refuses a body over requestBodyBytes before parsing it, and one that is not JSON', async () => {
    assert.deepEqual(await answer(Buffer.alloc(1_048_577, 0x20)), [413, 'body_too_large', undefined]);
    assert.deepEqual(await answer(Buffer.from('{"message":')), [400, 'invalid', undefined]);
  });

  it('2. refuses an envelope of the wrong shape, naming the field', async () => {
    const m = peer.message(zed, [bob.address], 'x');
    assert.deepEqual(await answer({ message: m }), [400, 'invalid', 'signature']);
    assert.deepEqual(await answer(peer.envelope(m, { hints: { 'eve@alpha.test': { invite: 'x' } } })), [
      400,
      'invalid',
      'hints',
    ]);
    assert.deepEqual(await answer(peer.envelope(m, { claims: [{ type: '' }] })), [400, 'invalid', 'claims']);
  });

  it('3. refuses a message that is not canonical, with its canonical form', async () => {
    const m = peer.message(zed, [bob.address], 'x');
    const env = peer.envelope(m);
    const text = canonicalize(env).replace(canonicalize(m), JSON.stringify(m, null, 1));
    const res = await post(Buffer.from(text));
    assert.deepEqual([res.status, res.json.details.canonical], [400, canonicalize(m)]);
  });

  it('4. refuses a message that breaks its version rules or the limits', async () => {
    const m = signMessage(
      { ...peer.message(zed, [bob.address], 'x'), extra: 1 } as unknown as Message,
      generateKey().privateKey,
    );
    assert.deepEqual(await answer(peer.envelope(m)), [400, 'invalid', 'extra']);
    const many = peer.message(
      zed,
      Array.from({ length: 101 }, (_, i) => `r${i}@alpha.test`),
      'x',
    );
    assert.deepEqual(await answer(peer.envelope(many)), [400, 'invalid', 'to']);
  });

  it('5. refuses an envelope for another server, or for recipients not in to or not served here', async () => {
    const m = peer.message(zed, [bob.address], 'x');
    assert.deepEqual(await answer(peer.envelope(m, { server: 'https://simon.beta.test' })), [400, 'invalid', 'server']);
    assert.deepEqual(await answer(peer.envelope(m, { recipients: ['cat@alpha.test'] })), [
      400,
      'invalid',
      'recipients',
    ]);
    const elsewhere = peer.message(zed, [bob.address, 'x@peer.test'], 'x');
    assert.deepEqual(await answer(peer.envelope(elsewhere, { recipients: [bob.address, 'x@peer.test'] })), [
      400,
      'invalid',
      'recipients',
    ]);
  });

  it('6. answers 503 when the from domain cannot be resolved now, 403 when it names no server or this one', async () => {
    const m = peer.message(zed, [bob.address], 'x');
    fed.dns.failing.add('_simon.peer.test');
    fed.clock.advance(11 * 60_000); // past the resolution cache
    assert.deepEqual(await answer(peer.envelope(m)), [503, 'unavailable', undefined]);
    fed.dns.failing.delete('_simon.peer.test');
    fed.clock.advance(61_000); // past the one minute a temporary outcome is remembered

    const lost = new Peer(fed, 'lost');
    const l = lost.agent('l');
    fed.dns.records.delete('_simon.lost.test');
    assert.deepEqual(await answer(lost.envelope(lost.message(l, [bob.address], 'x'))), [
      403,
      'bad_signature',
      undefined,
    ]);

    const posing = new Peer(fed, 'posing');
    const p = posing.agent('p');
    fed.dns.point('posing.test', alpha.origin);
    assert.deepEqual(await answer(posing.envelope(posing.message(p, [bob.address], 'x'))), [
      403,
      'bad_signature',
      undefined,
    ]);
  });

  it('7. refuses an envelope its server did not sign, with 403', async () => {
    const m = peer.message(zed, [bob.address], 'x');
    const forged = { ...peer.envelope(m), signature: peer.envelope(peer.message(zed, [bob.address], 'y')).signature };
    const res = await post(forged);
    assert.deepEqual([res.status, res.json.code], [403, 'bad_signature']);
    assert.equal(res.headers['content-type'], 'application/problem+json');
    assert.equal(res.headers['www-authenticate'], undefined, 'no request failed');
  });

  it('7 before 9: an unsigned stale envelope is a signature failure', async () => {
    const stale = peer.message(zed, [bob.address], 'x', { sentAt: timestamp(fed.clock.t - 200 * HOUR) });
    assert.deepEqual(await answer({ ...peer.envelope(stale), signature: 'AAAA' }), [403, 'bad_signature', undefined]);
  });

  it('8. answers 202 to a repeat within 168 hours, even past the 144-hour freshness window', async () => {
    const m = peer.message(zed, [bob.address], 'repeat me');
    assert.deepEqual(await answer(peer.envelope(m)), [202, { accepted: true }, undefined]);
    fed.clock.advance(150 * HOUR);
    assert.deepEqual(await answer(peer.envelope(m)), [202, { accepted: true }, undefined]);
    fed.clock.advance(-150 * HOUR);
  });

  it('9. refuses a sentAt more than 144 hours old or 5 minutes ahead', async () => {
    const old = peer.message(zed, [bob.address], 'x', { sentAt: timestamp(fed.clock.t - 145 * HOUR) });
    assert.deepEqual(await answer(peer.envelope(old)), [400, 'invalid', 'sentAt']);
    const ahead = peer.message(zed, [bob.address], 'x', { sentAt: timestamp(fed.clock.t + 6 * 60_000) });
    assert.deepEqual(await answer(peer.envelope(ahead)), [400, 'invalid', 'sentAt']);
  });

  it("10. needs the author's document (503 when it cannot be read now) and a message it verifies", async () => {
    const unknown = `ghost@${peer.domain}`;
    peer.agents.set(unknown, generateKey().privateKey);
    const m = peer.message(unknown, [bob.address], 'x');
    peer.agents.delete(unknown);
    assert.deepEqual(await answer(peer.envelope(m)), [403, 'bad_signature', undefined]);

    peer.agentStatus = 503;
    const zed2 = peer.agent('zed2');
    assert.deepEqual(await answer(peer.envelope(peer.message(zed2, [bob.address], 'x'))), [
      503,
      'unavailable',
      undefined,
    ]);
    peer.agentStatus = null;

    const wrong = {
      ...peer.message(zed, [bob.address], 'x'),
      signature: peer.message(zed, [bob.address], 'y').signature,
    };
    assert.deepEqual(await answer(peer.envelope(wrong)), [403, 'bad_signature', undefined]);
  });

  it('11. accepts, and the recipient finds the message with its carrier', async () => {
    const m = peer.message(zed, [bob.address], 'hello from a peer');
    assert.deepEqual(await answer(peer.envelope(m)), [202, { accepted: true }, undefined]);
    await fed.work();
    const entry = (await bob.received()).find(
      (e: { message: Message }) =>
        e.message.parts[0].type === 'text/plain' &&
        'data' in e.message.parts[0] &&
        e.message.parts[0].data === 'hello from a peer',
    );
    assert.equal(entry.carrier, peer.origin);
  });

  it('routes a message of a version it does not know, on its invariants alone (spec section 1)', async () => {
    const m = signMessage(
      { v: 2, from: zed, to: [bob.address], sentAt: timestamp(fed.clock.t), body: { anything: 'new' } } as never,
      peer.agents.get(zed)!,
    );
    assert.deepEqual(await answer(peer.envelope(m)), [202, { accepted: true }, undefined]);
    await fed.work();
    const box = await bob.received();
    assert.deepEqual(box.at(-1).message, m);
  });

  it('accepts opaque claim types even when their names are Object prototype properties', async () => {
    for (const type of ['custom', 'toString', 'constructor', '__proto__', 'hasOwnProperty']) {
      const m = peer.message(zed, [bob.address], `opaque claim ${type}`);
      assert.equal((await post(peer.envelope(m, { claims: [{ type }] }))).status, 202);
    }
  });

  it('shows authoritative claims always, and others only from carriers it trusts (spec section 6.2)', async () => {
    const claim = (agent: string, forValue: string) => ({
      type: 'acts-for',
      agent,
      for: forValue,
      scope: ['converse'],
      verifiedAt: '2026-10-01T00:00:00Z',
    });
    const other = { type: 'x-note', note: 'opaque' };

    // A carrier speaking for its own domain's address: authoritative, shown though it is not trusted.
    const own = peer.agent('own', 'paired');
    const ownFor = `mailto:own@${peer.domain}`;
    await post(
      peer.envelope(peer.message(own, [bob.address], 'own', { headers: { for: ownFor } }), {
        claims: [claim(own, ownFor), other],
      }),
    );
    // The same carrier about someone else's address: its word only, not shown.
    const u = peer.agent('u', 'paired');
    await post(
      peer.envelope(peer.message(u, [bob.address], 'untrusted', { headers: { for: 'mailto:u@else.test' } }), {
        claims: [claim(u, 'mailto:u@else.test')],
      }),
    );
    // A trusted carrier: every claim about the author, judged.
    const trusted = new Peer(fed, 'trusted');
    const t = trusted.agent('t', 'paired');
    const tFor = 'mailto:tia@example.org';
    const aboutSomeoneElse = claim(`x@${trusted.domain}`, tFor);
    await trusted.post(
      alpha,
      trusted.envelope(trusted.message(t, [bob.address], 'claimed', { headers: { for: tFor } }), {
        claims: [claim(t, tFor), aboutSomeoneElse, other],
      }),
    );
    await fed.work();

    const box = await bob.received();
    assert.deepEqual(box.at(-3).claims, [{ ...claim(own, ownFor), authoritative: true }]);
    assert.deepEqual(box.at(-3).signedClaims.claims, [claim(own, ownFor), other], 'as the carrier signed them');
    assert.deepEqual(box.at(-2).claims, []);
    assert.deepEqual(box.at(-1).claims, [{ ...claim(t, tFor), authoritative: false }, other]);
  });

  it("carries the carrier's signed claims into the inbox, checkable there, and never a principal for a solo agent", async () => {
    const solo = peer.agent('solo');
    const forValue = `mailto:solo@${peer.domain}`;
    const actsFor = {
      type: 'acts-for',
      agent: solo,
      for: forValue,
      scope: ['commit'],
      verifiedAt: '2026-10-01T00:00:00Z',
    };
    const m = peer.message(solo, [bob.address], 'wire the invoice', { headers: { for: forValue } });
    await post(peer.envelope(m, { claims: [actsFor] }));
    await fed.work();
    const entry = (await bob.received()).at(-1);
    assert.deepEqual(entry.message, m);
    assert.deepEqual(entry.claims, [], 'a solo agent speaks for no one, whatever its carrier claims');
    const carrierKeys = [{ key: keyToken(peer.key), added: '2026-01-01T00:00:00Z', revoked: null }];
    assert.equal(verifyClaims(entry.signedClaims, m, carrierKeys), true);
    assert.equal(
      verifyClaims({ ...entry.signedClaims, claims: [{ ...actsFor, scope: ['converse'] }] }, m, carrierKeys),
      false,
      'changed in the entry, it no longer verifies',
    );
  });

  it("judges identifier claims as acts-for claims: an email on the carrier's own domain is shown, any other is not", async () => {
    const identifier = (agent: string, of: string, value: string) => ({
      type: 'identifier',
      agent,
      of,
      identifier: value,
      verifiedAt: '2026-10-01T00:00:00Z',
    });
    // An agent with its own email, whose principal is named by an email address.
    const ivy = peer.agent('ivy', 'paired');
    const own = identifier(ivy, 'agent', `mailto:ivy.mail@${peer.domain}`);
    await post(
      peer.envelope(peer.message(ivy, [bob.address], 'known by', { headers: { for: `mailto:ivy@${peer.domain}` } }), {
        claims: [
          own,
          identifier(ivy, 'agent', 'mailto:ivy@else.test'),
          identifier(ivy, 'agent', 'tel:+14155550100'),
          identifier(`x@${peer.domain}`, 'agent', `mailto:x@${peer.domain}`),
          // The principal is the for header's email: a claim naming another one would contradict it.
          identifier(ivy, 'principal', `mailto:boss@${peer.domain}`),
        ],
      }),
    );
    // An agent whose principal is a key: the principal's current email, on the carrier's domain or not.
    const kai = peer.agent('kai', 'paired');
    const principal = generateKey();
    const forValue = `simon-key:${principal.key}`;
    const known = identifier(kai, 'principal', `mailto:kim@${peer.domain}`);
    const pairing = signPairing(principal.privateKey, kai, forValue);
    await post(
      peer.envelope(peer.message(kai, [bob.address], 'for a key', { headers: { for: forValue, pairing } }), {
        claims: [known, identifier(kai, 'principal', 'mailto:kim@else.test')],
      }),
    );
    await fed.work();

    const box = await bob.received();
    assert.deepEqual(box.at(-2).claims, [{ ...own, authoritative: true }]);
    assert.deepEqual(box.at(-1).claims, [{ ...known, authoritative: true }]);
  });

  it("drops a carrier's own authoritative member from the claims it judges, and keeps it in signedClaims", async () => {
    const own = peer.agent('sayer', 'paired');
    const ownFor = `mailto:sayer@${peer.domain}`;
    const sent = {
      type: 'acts-for',
      agent: own,
      for: ownFor,
      scope: ['converse'],
      verifiedAt: '2026-10-01T00:00:00Z',
      authoritative: false,
    };
    const m = peer.message(own, [bob.address], 'self-judged', { headers: { for: ownFor } });
    assert.equal((await post(peer.envelope(m, { claims: [sent] }))).status, 202);
    await fed.work();
    const entry = (await bob.sync()).json.messages.at(-1);
    const { authoritative: _, ...rest } = sent;
    assert.deepEqual(entry.claims, [{ ...rest, authoritative: true }], 'judged here');
    assert.deepEqual(entry.signedClaims.claims, [sent], 'as signed, byte for byte');
    const keys = [{ key: keyToken(peer.key), added: '2026-01-01T00:00:00Z', revoked: null }];
    assert.equal(verifyClaims(entry.signedClaims, m, keys), true);
  });

  it('fans out only to the recipients the envelope names, and accepts each (id, recipient) once', async () => {
    const seen: string[] = [];
    const gamma = await fed.server('gamma', {
      config: { hostedDomains: ['gamma.test', 'delta.test'] },
      extensions: [{ name: 'watch', admit: a => void seen.push(`${a.recipient} ${JSON.stringify(a.hints)}`) }],
    });
    fed.dns.point('delta.test', gamma.origin);
    const cat = await gamma.agent('cat');
    const dan = gamma.newAgent();
    await dan.register({ address: 'dan@delta.test' });
    const eve = await gamma.agent('eve');
    const m = peer.message(zed, [cat.address, dan.address, eve.address], 'x');
    const to = (recipients: string[], hints = {}) => peer.post(gamma, peer.envelope(m, { recipients, hints }));

    assert.equal((await to([cat.address])).status, 202);
    assert.equal((await to([cat.address, dan.address], { [dan.address]: { invite: 'D' } })).status, 202);
    assert.equal((await to([cat.address])).status, 202, 'a repeat');
    await fed.work();
    assert.deepEqual(seen, ['cat@gamma.test {}', 'dan@delta.test {"invite":"D"}'], 'eve is never offered it');
    assert.equal((await eve.received()).length, 0);
  });
});

describe("the server's bound beside the message", () => {
  it('accepts a maximal spec-valid envelope: longest recipients, extras at their bound, ML-DSA-65 signatures', async () => {
    const fed = new Federation();
    const domain = ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(56), 'test'].join('.');
    const alpha = await fed.server('alpha', { config: { hostedDomains: ['alpha.test', domain] } });
    const peer = new Peer(fed, 'peer');
    peer.key = generateKey('ml-dsa-65').privateKey;
    const zed = peer.agent('zed');
    const to = Array.from({ length: 100 }, (_, i) => `${String(i).padStart(64, 'r')}@${domain}`);
    const m = peer.message(zed, to, 'to a hundred');
    const claims = [{ type: 'x-note' }];
    const extras = (pad: string) => ({ claims, hints: { [to[0]]: { pad } } });
    const pad = 'x'.repeat(MAX_ENVELOPE_EXTRAS_BYTES - canonicalize(extras('')).length);
    assert.equal(canonicalize(extras(pad)).length, MAX_ENVELOPE_EXTRAS_BYTES);
    const envelope = signEnvelope({ message: m, server: alpha.origin, recipients: to, ...extras(pad) }, peer.key);
    const { message: _, ...beside } = envelope;
    assert.ok(canonicalize(beside).length > 32_768, 'more than the old default beside the message');
    const res = await peer.post(alpha, envelope);
    assert.equal(res.status, 202, JSON.stringify(res.json));
    await fed.close();
  });
});

describe("a domain's move loses no mail (spec section 6.3)", async () => {
  /** A count of TXT lookups of `_simon.<domain>`. */
  const counting = (fed: Federation) => {
    const counts = new Map<string, number>();
    const txt = fed.dns.txt.bind(fed.dns);
    fed.dns.txt = async (name: string) => {
      counts.set(name, (counts.get(name) ?? 0) + 1);
      return txt(name);
    };
    return (domain: string) => counts.get(`_simon.${domain}`) ?? 0;
  };

  it('refreshes cached self-routes and absences before refusing a carrier that moved', async () => {
    for (const prior of ['self', 'absent']) {
      const fed = new Federation();
      try {
        const alpha = await fed.server('alpha', { config: { keyChangeHoldSeconds: 0 } });
        const bob = await alpha.agent('bob');
        const peer = new Peer(fed, 'moving');
        const x = peer.agent('x');
        if (prior === 'self') fed.dns.point('moving.test', alpha.origin);
        else fed.dns.records.delete('_simon.moving.test');
        const first = await peer.post(alpha, peer.envelope(peer.message(x, [bob.address], 'cache old route')));
        assert.equal(first.status, 403);
        fed.dns.point('moving.test', peer.origin);
        const fresh = await peer.post(alpha, peer.envelope(peer.message(x, [bob.address], 'new route')));
        assert.equal(fresh.status, 202, JSON.stringify(fresh.json));
      } finally {
        await fed.close();
      }
    }
  });

  it('finds a carrier at its new server before answering 403, at most once a minute, and 503 when that fails for now', async () => {
    const fed = new Federation();
    const lookups = counting(fed);
    // No hold on a domain whose server keys changed, so the move itself is what is tested.
    const alpha = await fed.server('alpha', { config: { keyChangeHoldSeconds: 0 } });
    const bob = await alpha.agent('bob');
    const old = new Peer(fed, 'mover');
    const x = old.agent('x');
    assert.equal((await old.post(alpha, old.envelope(old.message(x, [bob.address], 'before')))).status, 202);
    // mover.test moves to a new server, with keys of its own; alpha's cache still names the old one.
    const next = new Peer(fed, 'newhome');
    next.agents.set(x, generateKey().privateKey);
    fed.dns.point('mover.test', next.origin);
    const before = lookups('mover.test');
    const after = next.envelope(next.message(x, [bob.address], 'after the move'));
    // Found at the new server, whose keys key continuity holds until it confirms them (section 11.1): 503, then 202.
    const held = await next.post(alpha, after);
    assert.deepEqual([held.status, held.json.code], [503, 'unavailable'], JSON.stringify(held.json));
    assert.equal(lookups('mover.test'), before + 1, 'resolved again without the cache');
    const moved = await next.post(alpha, after);
    assert.equal(moved.status, 202, JSON.stringify(moved.json));
    // A forged envelope within the minute is refused from the fresh answer, without another lookup.
    const forger = new Peer(fed, 'forger');
    forger.agents.set(x, generateKey().privateKey);
    const forged = () => forger.post(alpha, forger.envelope(forger.message(x, [bob.address], 'forged')));
    const settled = lookups('mover.test');
    assert.equal((await forged()).json.code, 'bad_signature');
    assert.equal(lookups('mover.test'), settled, 'within the minute, no lookup');
    fed.clock.advance(61_000);
    assert.equal((await forged()).json.code, 'bad_signature');
    assert.equal(lookups('mover.test'), settled + 1, 'a minute later, once more');
    fed.clock.advance(61_000);
    fed.dns.failing.add('_simon.mover.test');
    const failing = await forged();
    assert.deepEqual([failing.status, failing.json.code], [503, 'unavailable'], 'a re-resolution that fails for now');
    await fed.close();
  });

  it("gives back the minute's re-resolution when a forger out of lookups is refused it (step 7)", async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha', {
      config: { keyChangeHoldSeconds: 0, rates: { lookup: { limit: 2, seconds: 3600 } } },
    });
    const bob = await alpha.agent('bob');
    const old = new Peer(fed, 'mover');
    const x = old.agent('x');
    const deliver = async (p: Peer, m: Message, ip: string) => {
      const body = canonicalBytes(p.envelope(m));
      const res = await alpha.server.handle(
        toRequest('POST', new URL(`${alpha.origin}/simon/deliver`), { 'content-type': 'application/json' }, body, ip),
      );
      return { status: res.status, code: (res.json as { code?: string })?.code };
    };
    assert.equal((await deliver(old, old.message(x, [bob.address], 'before'), '203.0.113.1')).status, 202);
    const next = new Peer(fed, 'newhome');
    next.agents.set(x, generateKey().privateKey);
    fed.dns.point('mover.test', next.origin);
    // A forger whose network has spent its lookups: two on domains of its own, then one naming mover.test.
    const forger = new Peer(fed, 'forger');
    for (const d of ['own1', 'own2']) {
      const p = new Peer(fed, d);
      await deliver(forger, p.message(p.agent('z'), [bob.address], 'spend'), '198.51.100.66');
    }
    forger.agents.set(x, generateKey().privateKey);
    const forged = await deliver(forger, forger.message(x, [bob.address], 'forged'), '198.51.100.66');
    assert.deepEqual([forged.status, forged.code], [429, 'rate_limited'], 'refused the fresh lookup');
    // The honest new server still has the minute's re-resolution: found (held by key continuity, then 202).
    const honest = await deliver(next, next.message(x, [bob.address], 'after the move'), '203.0.113.2');
    assert.deepEqual([honest.status, honest.code], [503, 'unavailable'], 'found at the new server, not 403');
    await fed.close();
  });

  it("gives back the minute's re-resolution when a carrier out of lookups is refused it (step 8)", async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha', { config: { rates: { carrierLookup: { limit: 1, seconds: 3600 } } } });
    const spent = new Peer(fed, 'spent');
    const honest = new Peer(fed, 'honest');
    const [s, h] = [spent.agent('s'), honest.agent('h')];
    const to = (p: Peer, m: Message) => signEnvelope({ message: m, server: alpha.origin, recipients: m.to }, p.key);
    fed.dns.point('moving.test', 'https://simon.elsewhere.test');
    // The spent carrier's one lookup caches moving.test as elsewhere.
    assert.equal((await spent.post(alpha, to(spent, spent.message(s, ['bob@moving.test'], '1')))).status, 400);
    fed.dns.point('moving.test', alpha.origin);
    // Its re-resolution is refused for its rate, and gives the minute back...
    assert.equal((await spent.post(alpha, to(spent, spent.message(s, ['bob@moving.test'], '2')))).status, 429);
    // ...so the honest carrier's delivery re-resolves, and moving.test is served here.
    const res = await honest.post(alpha, to(honest, honest.message(h, ['bob@moving.test'], '3')));
    assert.equal(res.status, 202, JSON.stringify(res.json));
    await fed.close();
  });

  it('resolves a recipient domain again before answering 400, so one that just moved here is served', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const peer = new Peer(fed, 'peer');
    const zed = peer.agent('zed');
    fed.dns.point('moving.test', 'https://simon.elsewhere.test');
    const first = peer.message(zed, ['bob@moving.test'], 'first');
    const to = (m: Message) => signEnvelope({ message: m, server: alpha.origin, recipients: m.to }, peer.key);
    const refused = await peer.post(alpha, to(first));
    assert.deepEqual([refused.status, refused.json.details?.field], [400, 'recipients']);
    fed.dns.point('moving.test', alpha.origin);
    const second = await peer.post(alpha, to(peer.message(zed, ['bob@moving.test'], 'second')));
    assert.equal(second.status, 202, JSON.stringify(second.json));
    await fed.close();
  });

  it("re-resolves cached recipient domains only within step 8's deadline, then answers 503", async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const peer = new Peer(fed, 'peer');
    const zed = peer.agent('zed');
    // Two domains named by their well-known answers, elsewhere; the second lookup of each takes 21 s.
    const asked = new Map<string, number>();
    for (const d of ['far1.test', 'far2.test']) {
      fed.net.hosts.set(`https://${d}`, async () => {
        asked.set(d, (asked.get(d) ?? 0) + 1);
        if (asked.get(d)! > 1) fed.clock.advance(21_000);
        return { status: 200, json: { server: 'https://simon.elsewhere.test' } };
      });
    }
    const to = (m: Message) => signEnvelope({ message: m, server: alpha.origin, recipients: m.to }, peer.key);
    const first = await peer.post(alpha, to(peer.message(zed, ['a@far1.test', 'b@far2.test'], 'first')));
    assert.deepEqual([first.status, first.json.details?.field], [400, 'recipients'], 'both cached now');
    const second = await peer.post(alpha, to(peer.message(zed, ['a@far1.test', 'b@far2.test'], 'second')));
    assert.deepEqual([second.status, second.json.code], [503, 'unavailable']);
    assert.equal(
      [...asked.values()].reduce((a, b) => a + b),
      3,
      'one re-resolution, then the deadline',
    );
    await fed.close();
  });

  const problem = (status: number, code: string, details?: object) => ({
    status,
    json: {
      type: 'about:blank',
      title: code,
      status,
      code,
      retryable: false,
      detail: code,
      ...(details && { details }),
    },
  });

  it('retries a 400 on recipients for an hour, resolving their domain afresh before each attempt', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha', { config: { keyChangeHoldSeconds: 0 } });
    const ada = await alpha.agent('ada');
    const old = new Peer(fed, 'olddest');
    old.refuse = problem(400, 'invalid', { field: 'recipients' });
    fed.dns.point('dest.test', old.origin);
    const { json } = await ada.send(ada.message(['bob@dest.test'], 'to a domain about to move'));
    await fed.work();
    const status = async () => (await ada.request('GET', `/simon/sent/${json.id}`)).json.servers[0];
    assert.equal((await status()).status, 'pending', 'retried, not failed');
    const next = new Peer(fed, 'newdest');
    fed.dns.point('dest.test', next.origin);
    // Twice: key continuity holds the new server's keys once before it confirms them (section 11.1).
    for (let i = 0; i < 2; i++) {
      fed.clock.advance(5 * 60_000);
      await fed.work();
    }
    assert.deepEqual([(await status()).status, next.delivered], ['delivered', 1], 'found afresh at the new server');

    // A domain that keeps refusing its recipients fails once the hour is over.
    const stuck = new Peer(fed, 'stuck');
    stuck.refuse = problem(400, 'invalid', { field: 'recipients' });
    const sent = await ada.send(ada.message([stuck.agent('bo')], 'refused for good'));
    for (
      let i = 0;
      i < 12 && (await ada.request('GET', `/simon/sent/${sent.json.id}`)).json.servers[0].status === 'pending';
      i++
    ) {
      await fed.work();
      fed.clock.advance(10 * 60_000);
    }
    const last = (await ada.request('GET', `/simon/sent/${sent.json.id}`)).json.servers[0];
    assert.deepEqual([last.status, last.reason], ['failed', 'invalid']);
    assert.ok(stuck.delivered > 2, `${stuck.delivered} attempts`);
    // Any other 400 is final at once.
    const other = new Peer(fed, 'other');
    other.refuse = problem(400, 'invalid', { field: 'message' });
    const plain = await ada.send(ada.message([other.agent('oz')], 'refused at once'));
    await fed.work();
    assert.equal((await ada.request('GET', `/simon/sent/${plain.json.id}`)).json.servers[0].status, 'failed');
    await fed.close();
  });

  it('retries a 403 for an hour after this server began serving its domain, and not after', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const ada = await alpha.agent('ada');
    const strict = new Peer(fed, 'strict');
    strict.refuse = problem(403, 'bad_signature');
    const status = async (id: string) => (await ada.request('GET', `/simon/sent/${id}`)).json.servers[0];
    const early = await ada.send(ada.message([strict.agent('sam')], 'just after a move'));
    await fed.work();
    assert.equal((await status(early.json.id)).status, 'pending', 'serving the domain for less than an hour');
    // A send half an hour on finds the domain still naming this server, so it has served it all along.
    fed.clock.advance(31 * 60_000);
    assert.equal((await ada.send(ada.message([ada.address], 'still here'))).status, 200);
    fed.clock.advance(30 * 60_000);
    const late = await ada.send(ada.message([strict.agent('sue')], 'long after'));
    await fed.work();
    assert.deepEqual(
      [(await status(late.json.id)).status, (await status(late.json.id)).reason],
      ['failed', 'bad_signature'],
    );
    await fed.work();
    assert.equal((await status(early.json.id)).status, 'failed', 'the early one stops once the hour is over');
    // The domain moves away and back with no send in between: this server begins serving it again.
    fed.dns.point('alpha.test', 'https://simon.elsewhere.test');
    fed.clock.advance(2 * 3600_000);
    fed.dns.point('alpha.test', alpha.origin);
    fed.clock.advance(11 * 60_000); // past the cached answer naming elsewhere
    const back = await ada.send(ada.message([strict.agent('sid')], 'back again'));
    await fed.work();
    assert.equal((await status(back.json.id)).status, 'pending', 'retried: serving the domain anew');
  });

  it('continues retrying transient HTTP failures even when their problem code is invalid', async () => {
    const fed = new Federation();
    try {
      const alpha = await fed.server('alpha');
      const ada = await alpha.agent('ada');
      const peer = new Peer(fed, 'temporary-invalid');
      peer.refuse = problem(500, 'invalid');
      const sent = await ada.send(ada.message([peer.agent('bob')], 'transient code is not migration state'));
      await fed.work();
      assert.equal((await ada.request('GET', `/simon/sent/${sent.json.id}`)).json.servers[0].status, 'pending');
      peer.refuse = null;
      fed.clock.advance(2 * 60_000);
      await fed.work();
      assert.equal((await ada.request('GET', `/simon/sent/${sent.json.id}`)).json.servers[0].status, 'delivered');
    } finally {
      await fed.close();
    }
  });

  it('requires fresh destination routing after a 403 changes to a recipients mismatch, without extending the cutoff', async () => {
    const fed = new Federation();
    try {
      const alpha = await fed.server('alpha', { config: { keyChangeHoldSeconds: 0 } });
      const ada = await alpha.agent('ada');
      const old = new Peer(fed, 'mixed-move');
      old.refuse = problem(403, 'bad_signature');
      const began = fed.clock.t;
      const sent = await ada.send(ada.message([old.agent('bob')], 'two migration signals'));
      await fed.work();
      old.refuse = problem(400, 'invalid', { field: 'recipients' });
      fed.clock.advance(5 * 60_000);
      await fed.work();
      const next = new Peer(fed, 'mixed-new');
      fed.dns.point('mixed-move.test', next.origin);
      for (let i = 0; i < 2; i++) {
        fed.clock.advance(5 * 60_000);
        await fed.work();
      }
      assert.equal((await ada.request('GET', `/simon/sent/${sent.json.id}`)).json.servers[0].status, 'delivered');
      assert.ok(next.delivered > 0);
      const cutoff = await alpha.store.value<{ until: string }>(
        'delivery-move-cutoff',
        `${sent.json.id} mixed-move.test`,
        fed.clock.now().toISOString(),
      );
      assert.ok(cutoff && Date.parse(cutoff.until) <= began + 3600_000);
    } finally {
      await fed.close();
    }
  });

  it('does not reopen a recipient-move retry window after a worker is offline for hours', async () => {
    const fed = new Federation();
    try {
      const alpha = await fed.server('alpha');
      const ada = await alpha.agent('ada');
      const peer = new Peer(fed, 'still-old');
      peer.refuse = problem(400, 'invalid', { field: 'recipients' });
      const sent = await ada.send(ada.message([peer.agent('bob')], 'do not restart the move clock'));
      await fed.work();
      const attempts = peer.delivered;
      fed.clock.advance(3 * 3600_000);
      await fed.work();
      const row = (await ada.request('GET', `/simon/sent/${sent.json.id}`)).json.servers[0];
      assert.deepEqual([row.status, row.reason, peer.delivered], ['failed', 'invalid', attempts]);
    } finally {
      await fed.close();
    }
  });

  it('keeps different recipient rows migration cutoffs independent at one destination', async () => {
    const fed = new Federation();
    try {
      const alpha = await fed.server('alpha');
      const ada = await alpha.agent('ada');
      const peer = new Peer(fed, 'shared-dest');
      peer.refuse = problem(400, 'invalid', { field: 'recipients' });
      fed.dns.point('old-row.test', peer.origin);
      fed.dns.point('new-row.test', peer.origin);
      const sent = await ada.send(ada.message(['bob@old-row.test', 'bob@new-row.test'], 'separate row history'));
      await alpha.store.setValue(
        'recipients-refused',
        `${sent.json.id} old-row.test`,
        new Date(fed.clock.t - 61 * 60_000).toISOString(),
        new Date(fed.clock.t + 86_400_000).toISOString(),
      );
      await fed.work();
      const rows = await alpha.store.deliveries(sent.json.id);
      assert.equal(rows.find(row => row.domain === 'old-row.test')!.status, 'failed');
      assert.equal(rows.find(row => row.domain === 'new-row.test')!.status, 'pending');
    } finally {
      await fed.close();
    }
  });

  it('reads a bare serving-since an earlier version noted as lapsed, and begins the note anew', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const ada = await alpha.agent('ada');
    const strict = new Peer(fed, 'strict');
    strict.refuse = problem(403, 'bad_signature');
    // Noted by an earlier version, as a bare time with no expiry, the last time the domain came here.
    await alpha.store.setValue('serving-since', 'alpha.test', new Date(fed.clock.t - 86_400_000).toISOString(), null);
    const sent = await ada.send(ada.message([strict.agent('sam')], 'after the upgrade'));
    await fed.work();
    const row = (await ada.request('GET', `/simon/sent/${sent.json.id}`)).json.servers[0];
    assert.equal(row.status, 'pending', 'retried: the note began with this send');
    await fed.close();
  });
});
