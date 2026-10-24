/**
 * Hardening learned from email (spec sections 11.1 and 11.2): what a hostile or broken peer, network or
 * resolver cannot do to this server.
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { describe, it } from 'node:test';
import {
  canonicalBytes,
  canonicalize,
  generateKey,
  keyToken,
  serverDocument,
  sha256Hex,
  signEnvelope,
  signMessage,
  signRequest,
  type Message,
} from '@agnt-protocol/protocol';
import { systemDns, DnsFailure, type Lookups } from '../src/net/dns.ts';
import { guardedHttp, Unreachable } from '../src/net/fetch.ts';
import { clientKey, inNetworks, isBlockedAddress, parseNetwork, type Network } from '../src/net/ip.ts';
import { PER_DESTINATION } from '../src/outbox.ts';
import { PREFETCH_JITTER_MS } from '../src/parts.ts';
import { RECIPIENT_LOOKUPS_MS } from '../src/deliver.ts';
import { MAX_LOOKUPS_PER_AGENT, MAX_LOOKUPS_PER_CARRIER, MAX_LOOKUPS_PER_NETWORK, Resolver } from '../src/resolver.ts';
import { toRequest } from '../src/testing.ts';
import type { Store } from '../src/store/store.ts';
import { Federation, Peer, TARPIT_MS, type TestServer } from './harness.ts';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

describe('the outbox', () => {
  it('delivers to others while a tarpit holds its connections, then treats the tarpit as dead', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const beta = await fed.server('beta');
    const slow = new Peer(fed, 'slow');
    slow.hang = true;
    const ada = await alpha.agent('ada');
    const bob = await beta.agent('bob');

    await ada.send(ada.message(['zed@slow.test'], 'into the tarpit'));
    const { json } = await ada.send(ada.message([bob.address], 'meanwhile'));
    const started = Date.now();
    const working = alpha.server.work();
    while ((await ada.sent(json.id)).json.servers[0].status !== 'delivered') await new Promise(r => setTimeout(r, 5));
    assert.ok(Date.now() - started < TARPIT_MS, 'delivered before the tarpit gave up');
    await working;

    const before = slow.delivered;
    await ada.send(ada.message(['zed@slow.test'], 'again'));
    fed.clock.advance(2 * 60_000);
    await alpha.server.work();
    assert.equal(slow.delivered, before, 'a dead destination is not tried again for a while');
    fed.clock.advance(5 * 60_000);
    await alpha.server.work();
    assert.ok(slow.delivered > before, 'and is tried once it may be alive');
    await fed.close();
  });

  it(`posts at most ${PER_DESTINATION} envelopes to one server at once`, async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const slow = new Peer(fed, 'slow');
    slow.hang = true;
    const ada = await alpha.agent('ada');
    for (let i = 0; i < 10; i++) await ada.send(ada.message([`z${i}@slow.test`], `m${i}`));
    await alpha.server.work();
    assert.equal(slow.delivered, PER_DESTINATION);
    await fed.close();
  });

  it('posts nothing to a server without a valid server document, and keeps retrying', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const broken = new Peer(fed, 'broken');
    broken.serverDocument = 404;
    const ada = await alpha.agent('ada');
    const { json } = await ada.send(ada.message(['x@broken.test'], 'x'));
    await alpha.server.work();
    assert.equal(broken.delivered, 0);
    const [row] = await alpha.store.deliveries(json.id);
    assert.deepEqual([row.status, row.reason], ['pending', 'no_server_document']);
    await fed.close();
  });

  it('backs off exponentially, and fails as expired at the deadline', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const ada = await alpha.agent('ada');
    new Peer(fed, 'gone');
    fed.net.hosts.set('https://agnt.gone.test', 'down');
    const { json } = await ada.send(ada.message(['x@gone.test'], 'x'));
    const gaps: number[] = [];
    for (let i = 0; i < 40; i++) {
      await alpha.server.work();
      const [row] = await alpha.store.deliveries(json.id);
      if (row.status === 'failed') break;
      gaps.push(Date.parse(row.nextAttemptAt) - fed.clock.t);
      fed.clock.t = Date.parse(row.nextAttemptAt);
    }
    const [row] = await alpha.store.deliveries(json.id);
    assert.deepEqual([row.status, row.reason], ['failed', 'expired']);
    assert.equal(row.deadline, new Date(Date.parse(row.createdAt) + 5 * DAY).toISOString());
    assert.ok(fed.clock.t < Date.parse(row.deadline), 'the last attempt came before the deadline');
    assert.ok(fed.clock.t >= Date.parse(row.deadline) - 4 * HOUR, 'and as late as backoff allowed');
    assert.deepEqual(gaps.slice(0, 3), [60_000, 120_000, 240_000]);
    assert.equal(Math.max(...gaps), 4 * HOUR);
    assert.deepEqual((await ada.sent(json.id)).json.servers[0].status, 'failed');
    await fed.close();
  });
});

describe('documents from other servers', () => {
  it('refuses a server document listing more than 32 keys, or larger than 131072 bytes (spec section 4)', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const bob = await alpha.agent('bob');
    const peer = new Peer(fed, 'peer');
    const zed = peer.agent('zed');
    const keys = [peer.key, ...Array.from({ length: 32 }, () => generateKey().privateKey)];
    peer.serverDocument = Buffer.from(
      canonicalize(
        serverDocument(
          peer.origin,
          keys.map(k => ({ key: keyToken(k), added: '2026-01-01T00:00:00Z', revoked: null })),
        ),
      ),
    );
    const env = peer.envelope(peer.message(zed, [bob.address], 'x'));
    assert.equal((await peer.post(alpha, env)).json.code, 'bad_signature');

    const peer2 = new Peer(fed, 'peer2');
    const z2 = peer2.agent('z2');
    const doc = serverDocument(peer2.origin, [
      { key: keyToken(peer2.key), added: '2026-01-01T00:00:00Z', revoked: null },
    ]);
    peer2.serverDocument = Buffer.from(canonicalize({ ...doc, padding: 'x'.repeat(131_072) }));
    assert.equal(
      (await peer2.post(alpha, peer2.envelope(peer2.message(z2, [bob.address], 'x')))).json.code,
      'bad_signature',
    );
    await fed.close();
  });
});

describe('lookup pools', () => {
  /** 16 domains whose well-known answer never comes: each lookup of one holds its slot until the deadline. */
  const tarpits = (fed: Federation, n = 16) =>
    Array.from({ length: n }, (_, i) => {
      fed.net.hosts.set(`https://slow${i}.test`, () => new Promise(() => {}));
      return `slow${i}.test`;
    });

  /** An envelope `peer` signs for every recipient of `m`, posted to `to` in-process, past the network's deadline. */
  const post = (peer: Peer, to: TestServer, m: Message, ip = '192.0.2.9') => {
    const body = canonicalBytes(signEnvelope({ message: m, server: to.origin, recipients: m.to }, peer.key));
    const url = new URL(`${to.origin}/agnt/deliver`);
    return to.server.handle(toRequest('POST', url, { 'content-type': 'application/json' }, body, ip));
  };

  /** Start `attacks` together, let them reach their lookups, then send as an agent here: the send's answer. */
  async function sendDuring(fed: Federation, attacks: (() => Promise<unknown>)[]) {
    const alpha = fed.servers[0];
    const ada = await alpha.agent('ada');
    const held = attacks.map(a => a().catch(() => null));
    await new Promise(r => setTimeout(r, TARPIT_MS / 3));
    const res = await ada.send(ada.message(['bob@beta.test'], 'mine'));
    await Promise.all(held);
    return res;
  }

  it("keeps the server's own lookups from deliveries naming slow recipient domains", async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    // Four carriers on four networks, each within its own share, together as many as the server's own pool holds.
    const carriers = ['evil1', 'evil2', 'evil3', 'evil4'].map(name => {
      const peer = new Peer(fed, name);
      return { peer, from: peer.agent('mallory') };
    });
    const posts = tarpits(fed).map((d, i) => () => {
      const { peer, from } = carriers[i % carriers.length];
      return post(peer, alpha, peer.message(from, ['ada@alpha.test', `x@${d}`], d), `198.51.${i % carriers.length}.9`);
    });
    const res = await sendDuring(fed, posts);
    assert.equal(res.status, 200, JSON.stringify(res.json));
    await fed.close();
  });

  it(`keeps one agent's deliveries to slow domains, ${MAX_LOOKUPS_PER_AGENT} lookups at once, from another agent's send`, async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const mallory = await alpha.agent('mallory');
    const ada = await alpha.agent('ada');
    // As many messages as the server's own pool holds lookups, each to a domain whose answer never comes.
    for (const d of tarpits(fed)) {
      const sent = await mallory.send(mallory.message([`x@${d}`], 'slow'));
      assert.equal(sent.status, 200, JSON.stringify(sent.json));
    }
    // The server's resolution of its own domain lapses, so ada's send looks it up again.
    fed.clock.advance(11 * 60_000);
    const work = alpha.server.work();
    await new Promise(r => setTimeout(r, TARPIT_MS / 3));
    const res = await ada.send(ada.message(['bob@beta.test'], 'mine'));
    await work;
    assert.equal(res.status, 200, JSON.stringify(res.json));
    await fed.close();
  });

  it(`resolves an envelope's domains side by side, ${MAX_LOOKUPS_PER_CARRIER} at once, and starts none past its deadline`, async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const evil = new Peer(fed, 'evil');
    const mallory = evil.agent('mallory');
    // Domains whose well-known answer comes after a while, naming another server.
    const counts = { now: 0, peak: 0, started: 0 };
    const slow = (prefix: string) =>
      Array.from({ length: 2 * MAX_LOOKUPS_PER_CARRIER + 1 }, (_, i) => {
        fed.net.hosts.set(`https://${prefix}${i}.test`, async () => {
          counts.started++;
          counts.peak = Math.max(counts.peak, ++counts.now);
          await new Promise(r => setTimeout(r, 20));
          counts.now--;
          return { status: 200, json: { server: 'https://agnt.elsewhere.test' } };
        });
        return `x@${prefix}${i}.test`;
      });
    const wide = (to: string[]) => post(evil, alpha, evil.message(mallory, ['ada@alpha.test', ...to], to[0]));

    const res = await wide(slow('wide'));
    assert.deepEqual([res.status, counts.started], [400, 2 * MAX_LOOKUPS_PER_CARRIER + 1], 'every domain looked up');
    assert.equal(counts.peak, MAX_LOOKUPS_PER_CARRIER, "side by side, never more than the carrier's share");

    Object.assign(counts, { now: 0, peak: 0, started: 0 });
    const late = wide(slow('late'));
    await new Promise(r => setTimeout(r, 5));
    fed.clock.advance(RECIPIENT_LOOKUPS_MS + 1);
    assert.equal((await late).status, 503);
    assert.equal(counts.started, MAX_LOOKUPS_PER_CARRIER, 'none started past the deadline');
    await fed.close();
  });

  it(`gives one carrier at most ${MAX_LOOKUPS_PER_CARRIER} lookups at once, across its envelopes`, async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const evil = new Peer(fed, 'evil');
    const mallory = evil.agent('mallory');
    const started = Date.now();
    const answers = tarpits(fed, MAX_LOOKUPS_PER_CARRIER + 1).map(async d => {
      const res = await post(evil, alpha, evil.message(mallory, ['ada@alpha.test', `x@${d}`], d));
      return { status: res.status, ms: Date.now() - started };
    });
    const refused = await Promise.race(answers);
    assert.equal(refused.status, 503);
    assert.ok(refused.ms < TARPIT_MS / 2, `one past its share is refused at once (${refused.ms} ms)`);
    await Promise.all(answers);
    await fed.close();
  });

  it("sizes an envelope's lookups to its carrier's free share, rather than refusing its own", async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const carrier = new Peer(fed, 'busy');
    const from = carrier.agent('bea');
    // Six of its deliveries hold lookups of domains that never answer...
    const held = tarpits(fed, 6).map(d =>
      post(carrier, alpha, carrier.message(from, ['ada@alpha.test', `x@${d}`], d)).catch(() => null),
    );
    await new Promise(r => setTimeout(r, TARPIT_MS / 6));
    // ...when it delivers to four custom domains that this server serves, each answering after a while.
    const to = Array.from({ length: 4 }, (_, i) => {
      fed.net.hosts.set(`https://own${i}.test`, async () => {
        await new Promise(r => setTimeout(r, 20));
        return { status: 200, json: { server: alpha.origin } };
      });
      return `bea${i}@own${i}.test`;
    });
    const res = await post(carrier, alpha, carrier.message(from, to, 'to four domains here'));
    assert.equal(res.status, 202, JSON.stringify(res.json));
    await Promise.all(held);
    await fed.close();
  });

  it('keeps carriers made up on one network from starving other carriers of lookups', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    // Four carriers on free domains, from one network, each within its own share: 32 tarpitted lookups.
    const sybils = ['sybil1', 'sybil2', 'sybil3', 'sybil4'].map(name => {
      const peer = new Peer(fed, name);
      return { peer, from: peer.agent('mallory') };
    });
    const slow = tarpits(fed, 4 * MAX_LOOKUPS_PER_CARRIER);
    const held = slow.map((d, i) => {
      const { peer, from } = sybils[i % sybils.length];
      return post(peer, alpha, peer.message(from, ['ada@alpha.test', `x@${d}`], d)).catch(() => null);
    });
    await new Promise(r => setTimeout(r, TARPIT_MS / 3));
    const honest = new Peer(fed, 'honest');
    const bea = honest.agent('bea');
    const res = await post(honest, alpha, honest.message(bea, ['ada@alpha.test'], 'hello'), '203.0.113.20');
    assert.equal(res.status, 202, 'its author document is fetched');
    await Promise.all(held);
    await fed.close();
  });

  it(`gives carriers behind one network ${MAX_LOOKUPS_PER_NETWORK} lookups at once, each its own ${MAX_LOOKUPS_PER_CARRIER}`, async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    // Two tenants of one host, behind one NAT: each fills its own share of tarpitted lookups...
    const tenants = ['tenant1', 'tenant2', 'tenant3'].map(name => {
      const peer = new Peer(fed, name);
      return { peer, from: peer.agent('ten') };
    });
    const slow = tarpits(fed, 2 * MAX_LOOKUPS_PER_CARRIER);
    const held = slow.map((d, i) => {
      const { peer, from } = tenants[i % 2];
      return post(peer, alpha, peer.message(from, ['ada@alpha.test', `x@${d}`], d), '198.51.100.7').catch(() => null);
    });
    await new Promise(r => setTimeout(r, TARPIT_MS / 3));
    const started = slow.filter(d => fed.net.sent.some(r => r.url === `https://${d}/.well-known/agnt`));
    assert.equal(started.length, 2 * MAX_LOOKUPS_PER_CARRIER, "neither tenant's lookups were refused for the other's");
    // ...which together hold the network's share: a third carrier there is refused for now, not one elsewhere.
    const extra = tarpits(fed, 2 * MAX_LOOKUPS_PER_CARRIER + 1).at(-1)!;
    const { peer, from } = tenants[2];
    const third = await post(
      peer,
      alpha,
      peer.message(from, ['ada@alpha.test', `x@${extra}`], 'third'),
      '198.51.100.7',
    );
    assert.equal(third.status, 503, 'the network holds no more than its share');
    const honest = new Peer(fed, 'honest');
    const bea = honest.agent('bea');
    const res = await post(honest, alpha, honest.message(bea, ['ada@alpha.test'], 'hello'), '203.0.113.20');
    assert.equal(res.status, 202);
    await Promise.all(held);
    await fed.close();
  });

  it("keeps the server's own lookups from part fetches signed for slow origins", async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const key = generateKey().privateKey;
    const gets = tarpits(fed).map(d => () => {
      const url = new URL(`${alpha.origin}/agnt/parts/${'a'.repeat(64)}`);
      const headers = signRequest(key, { method: 'GET', url: url.href, now: fed.clock.t, server: `https://${d}` });
      return alpha.server.handle(toRequest('GET', url, headers, Buffer.alloc(0), '192.0.2.9'));
    });
    const res = await sendDuring(fed, gets);
    assert.equal(res.status, 200, JSON.stringify(res.json));
    await fed.close();
  });

  it("keeps the server's own lookups from signed reads by agents whose server document never comes", async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const reads = Array.from({ length: 16 }, (_, i) => {
      const origin = `https://agnt.rd${i}.test`;
      fed.dns.point(`rd${i}.test`, origin);
      // The agent document comes at once; the server document that would check it never does.
      fed.net.hosts.set(origin, req =>
        req.path === '/agnt/server' ? new Promise(() => {}) : Promise.resolve({ status: 200, json: {} }),
      );
      return () => {
        const url = new URL(`${alpha.origin}/agnt/messages/${'0'.repeat(64)}`);
        const agent = `r@rd${i}.test`;
        const headers = signRequest(generateKey().privateKey, {
          method: 'GET',
          url: url.href,
          now: fed.clock.t,
          agent,
        });
        return alpha.server.handle(toRequest('GET', url, headers, Buffer.alloc(0), '192.0.2.9'));
      };
    });
    const res = await sendDuring(fed, reads);
    assert.equal(res.status, 200, JSON.stringify(res.json));
    await fed.close();
  });

  it('charges no lookup the pool refused', async () => {
    const fed = new Federation();
    // Each client may cause two lookups an hour: a reader's domain, then its agent document.
    const alpha = await fed.server('alpha', { config: { rates: { lookup: { limit: 2, seconds: 3600 } } } });
    const reader = (name: string, hang: boolean) => {
      const origin = `https://agnt.${name}.test`;
      fed.dns.point(`${name}.test`, origin);
      fed.net.hosts.set(origin, () => (hang ? new Promise(() => {}) : Promise.resolve({ status: 404, json: {} })));
      return (ip: string) => {
        const url = new URL(`${alpha.origin}/agnt/messages/${'0'.repeat(64)}`);
        const headers = signRequest(generateKey().privateKey, {
          method: 'GET',
          url: url.href,
          now: fed.clock.t,
          agent: `r@${name}.test`,
        });
        return alpha.server.handle(toRequest('GET', url, headers, Buffer.alloc(0), ip));
      };
    };
    // 24 clients' agent documents that never come fill the pool for unauthenticated callers...
    const held = Array.from({ length: 24 }, (_, i) => reader(`hold${i}`, true)(`198.51.100.${i + 1}`));
    await new Promise(r => setTimeout(r, TARPIT_MS / 3));
    // ...so this reader's lookup is refused, and then made once there is room: its budget was not spent.
    const read = reader('late', false);
    await read('203.0.113.7');
    await Promise.all(held);
    const before = fed.net.sent.length;
    await read('203.0.113.7');
    const fetched = fed.net.sent.slice(before).filter(r => r.url.startsWith('https://agnt.late.test/agnt/agents/'));
    assert.equal(fetched.length, 1, "the reader's document is fetched");
    await fed.close();
  });

  it("keeps the server's own lookups from registrations of addresses on slow domains", async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const registers = tarpits(fed).map(d => () => alpha.newAgent().register({ address: `x@${d}` }));
    const res = await sendDuring(fed, registers);
    assert.equal(res.status, 200, JSON.stringify(res.json));
    await fed.close();
  });
});

describe('the bound on lookups before a signature verifies (spec section 11.2)', () => {
  /** An envelope claiming to come from `from`, signed by a key nobody publishes, posted from `ip`. */
  const forged = (to: TestServer, from: string, ip: string) => {
    const key = generateKey().privateKey;
    const m = signMessage<Message>(
      {
        v: 1,
        from,
        to: ['ada@alpha.test'],
        inReplyTo: null,
        parts: [],
        headers: {},
        sentAt: new Date(to.fed.clock.t).toISOString(),
      },
      key,
    );
    const body = canonicalBytes(signEnvelope({ message: m, server: to.origin, recipients: m.to }, key));
    const url = new URL(`${to.origin}/agnt/deliver`);
    return to.server.handle(toRequest('POST', url, { 'content-type': 'application/json' }, body, ip));
  };

  it('bounds lookups per registrable domain, counts only those made, and holds across processes on one store', async () => {
    const fed = new Federation();
    const rates = { lookupDomain: { limit: 3, seconds: 3600 } };
    const alpha = await fed.server('alpha', { config: { rates } });
    const second = await fed.server('alpha2', { config: { rates }, wrapStore: () => alpha.store });
    const looked = (name: string) => fed.net.sent.filter(r => r.url === `https://${name}/.well-known/agnt`).length;
    // Random subdomains of one victim domain, each from a network of its own, so no per-client bound applies.
    const statuses = [];
    for (let i = 1; i <= 4; i++) statuses.push((await forged(alpha, `x@r${i}.victim.test`, `198.51.100.${i}`)).status);
    assert.deepEqual(statuses, [403, 403, 403, 429], 'three lookups, then the domain is out of them');
    assert.equal(looked('r4.victim.test'), 0, 'a refused lookup is never made');
    // Delivery refreshes cached absence for migration; that fresh lookup must still respect the budget.
    const refresh = await forged(alpha, 'x@r1.victim.test', '198.51.100.9');
    assert.deepEqual([refresh.status, (refresh.json as { code: string }).code], [429, 'rate_limited']);
    assert.equal(looked('r1.victim.test'), 1);
    // Another registrable domain has a bound of its own; another process on the same store shares this one.
    assert.equal((await forged(alpha, 'x@other.test', '198.51.100.10')).status, 403);
    const refused = await forged(second, 'x@r5.victim.test', '198.51.100.11');
    assert.deepEqual([refused.status, (refused.json as { code: string }).code], [429, 'rate_limited']);
    assert.ok(Number(refused.headers?.['retry-after']) > 0, 'with Retry-After');
    // A signed read past the bound asks as nobody in particular, and looks nothing up.
    const reader = generateKey().privateKey;
    const url = new URL(`${alpha.origin}/agnt/feeds/ada@alpha.test/posts`);
    const signed = signRequest(reader, { method: 'GET', url: url.href, now: fed.clock.t, agent: 'eve@r6.victim.test' });
    const read = await alpha.server.handle(toRequest('GET', url, signed, Buffer.alloc(0), '198.51.100.12'));
    assert.equal(read.status, 200);
    assert.equal(looked('r6.victim.test'), 0);
    // The next hour, lookups are made again.
    fed.clock.advance(HOUR);
    assert.equal((await forged(alpha, 'x@r7.victim.test', '198.51.100.13')).status, 403);
    assert.equal(looked('r7.victim.test'), 1);
    await fed.close();
  });

  it('serves an ordinary cached resolution for free while refusing fresh work past the domain budget', async () => {
    const fed = new Federation();
    try {
      const alpha = await fed.server('alpha', { config: { rates: { lookupDomain: { limit: 1, seconds: 3600 } } } });
      const resolver = new Resolver({
        config: alpha.server.api.config,
        store: alpha.store,
        http: fed.net,
        dns: fed.dns,
        now: fed.clock.now,
        log: () => {},
        ownDocument: async () => serverDocument(alpha.origin, []),
        localAgent: async () => null,
      });
      let charges = 0;
      const charge = () => {
        charges++;
      };
      assert.equal((await resolver.resolve('one.victim.test', { charge })).outcome, 'not_found');
      const requests = fed.net.sent.length;
      assert.equal(charges, 1);
      assert.equal((await resolver.resolve('one.victim.test', { charge })).outcome, 'not_found');
      assert.equal(charges, 1, 'the ordinary cache hit spends no caller or domain budget');
      await assert.rejects(resolver.resolve('two.victim.test', { charge }), { status: 429 });
      await assert.rejects(resolver.resolve('one.victim.test', { charge, fresh: true }), { status: 429 });
      assert.equal(charges, 1, 'domain admission refuses before charging the caller');
      assert.equal(fed.net.sent.length, requests, 'neither refused lookup reaches the network');
    } finally {
      await fed.close();
    }
  });

  it('does not debit the caller when the domain budget refuses a lookup before network work', async () => {
    const fed = new Federation();
    try {
      const alpha = await fed.server('alpha', {
        config: {
          rates: {
            lookup: { limit: 1, seconds: 3600 },
            lookupDomain: { limit: 1, seconds: 3600 },
          },
        },
      });
      assert.equal((await forged(alpha, 'x@one.victim.test', '198.51.100.1')).status, 403);
      assert.equal((await forged(alpha, 'x@two.victim.test', '198.51.100.2')).status, 429);
      assert.equal(
        (await forged(alpha, 'x@unrelated.test', '198.51.100.2')).status,
        403,
        "the domain refusal did not spend this caller's sole lookup",
      );
    } finally {
      await fed.close();
    }
  });

  it("keeps an agent document's absence cached against a signed reader's refetch", async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const peer = new Peer(fed, 'peer');
    const asked = () => fed.net.sent.filter(r => r.url.includes('/agnt/agents/ghost@peer.test')).length;
    const read = async () => {
      const url = new URL(`${alpha.origin}/agnt/feeds/ada@alpha.test/posts`);
      const signed = signRequest(generateKey().privateKey, {
        method: 'GET',
        url: url.href,
        now: fed.clock.t,
        agent: 'ghost@peer.test',
      });
      return alpha.server.handle(toRequest('GET', url, signed, Buffer.alloc(0), '198.51.100.20'));
    };
    for (let i = 0; i < 3; i++) assert.equal((await read()).status, 200);
    assert.equal(asked(), 1, 'one fetch, its 404 kept for the ten minutes section 4 allows');
    fed.clock.advance(10 * 60_000 + 1);
    await read();
    assert.equal(asked(), 2);
    assert.ok(peer);
    await fed.close();
  });
});

describe('key continuity (spec section 11.1)', () => {
  it("charges a held key change's confirmation to the carrier's carrierLookup rate", async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha', {
      config: { keyChangeHoldSeconds: 0, rates: { carrierLookup: { limit: 1, seconds: 3600 } } },
    });
    const peer = new Peer(fed, 'turner');
    const from = peer.agent('tess');
    const deliver = (text: string) => peer.post(alpha, peer.envelope(peer.message(from, ['ada@alpha.test'], text)));
    await alpha.agent('ada');
    assert.equal((await deliver('before')).status, 202);
    peer.key = generateKey().privateKey;
    fed.clock.advance(61_000); // a server document is fetched again at most once a minute
    assert.equal((await deliver('held')).status, 503, 'held');
    // Confirming takes a fresh resolution and document, two of the carrier's lookups: past its one, refused.
    const confirm = await deliver('confirm');
    assert.deepEqual([confirm.status, confirm.json.code], [429, 'rate_limited']);
    await fed.close();
  });

  it('holds a domain whose server keys changed wholesale, then trusts them once confirmed', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha', { config: { keyChangeHoldSeconds: 3600 } });
    const bob = await alpha.agent('bob');
    const peer = new Peer(fed, 'peer');
    const zed = peer.agent('zed');
    const send = async (text: string) =>
      (await peer.post(alpha, peer.envelope(peer.message(zed, [bob.address], text)))).status;

    assert.equal(await send('first contact'), 202);

    // An honest rotation overlaps: the new key is listed beside the old one first.
    const next = generateKey().privateKey;
    peer.extraKeys = [next];
    fed.clock.advance(11 * 60_000);
    assert.equal(await send('overlap'), 202);
    [peer.key, peer.extraKeys] = [next, []];
    fed.clock.advance(11 * 60_000);
    assert.equal(await send('rotated'), 202, 'an overlapping rotation is never held');

    // A wholesale change, as a hijacked domain would show.
    peer.key = generateKey().privateKey;
    fed.clock.advance(11 * 60_000);
    const held = await peer.post(alpha, peer.envelope(peer.message(zed, [bob.address], 'hijacked?')));
    assert.deepEqual([held.status, held.json.code], [503, 'unavailable']);
    fed.clock.advance(30 * 60_000);
    assert.equal(await send('still held'), 503);
    fed.clock.advance(31 * 60_000);
    assert.equal(await send('confirmed'), 202, 'confirmed again after the hold');
    await fed.close();
  });
});

describe('rate limits', () => {
  it('keys IPv6 clients by /64, and IPv4-mapped clients by their IPv4', () => {
    assert.equal(clientKey('2001:db8:1:2:3:4:5:6'), clientKey('2001:db8:1:2:ffff::1'));
    assert.notEqual(clientKey('2001:db8:1:2::1'), clientKey('2001:db8:1:3::1'));
    assert.equal(clientKey('::ffff:192.0.2.1'), '192.0.2.1');
    assert.equal(clientKey('192.0.2.1'), '192.0.2.1');
  });

  it('counts requests from one /64 together', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha', { config: { rates: { request: { limit: 2, seconds: 60 } } } });
    const ada = alpha.newAgent();
    const get = (ip: string) => ada.request('GET', '/agnt/server', { sign: false, ip });
    assert.equal((await get('2001:db8:5:6::1')).status, 200);
    assert.equal((await get('2001:db8:5:6::2')).status, 200);
    assert.equal((await get('2001:db8:5:6:a:b:c:d')).status, 429);
    assert.equal((await get('2001:db8:5:7::1')).status, 200);
    await fed.close();
  });

  it('makes probing for addresses cost: a miss counts, a hit does not, and past the budget every address is refused alike', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha', { config: { rates: { agentMiss: { limit: 3, seconds: 3600 } } } });
    const bob = await alpha.agent('bob');
    const prober = alpha.newAgent();
    const doc = (address: string, ip = '203.0.113.7') =>
      prober.request('GET', `/agnt/agents/${address}`, { sign: false, ip });
    for (let i = 0; i < 10; i++) assert.equal((await doc(bob.address)).status, 200, 'verifying a real agent is free');
    for (let i = 0; i < 3; i++) assert.equal((await doc(`nobody${i}@alpha.test`)).status, 404);
    const [known, unknown] = [await doc(bob.address), await doc('nobody9@alpha.test')];
    assert.deepEqual([known.status, unknown.status], [429, 429]);
    assert.deepEqual(known.json, unknown.json, 'the refusal says nothing about either address');
    assert.equal(known.headers['retry-after'], unknown.headers['retry-after']);
    assert.equal((await doc(bob.address, '198.51.100.8')).status, 200, 'another client is not held back');
    fed.clock.advance(3600_000);
    assert.equal((await doc(bob.address)).status, 200, 'the window ends');
    await fed.close();
  });

  it('serves a retired agent its retired document, no miss, and lookups in flight together never exceed the budget', async () => {
    const fed = new Federation();
    // A store that waits on every lookup, as a database across a network does.
    const slow = (store: Store) =>
      new Proxy(store, {
        get(target, name) {
          const value = Reflect.get(target, name);
          if (typeof value !== 'function') return value;
          if (name !== 'agentByAddress') return value.bind(target);
          return async (address: string) => (await new Promise(r => setTimeout(r, 5)), value.call(target, address));
        },
      });
    const alpha = await fed.server('alpha', {
      // The public retired document is an explicit opt-in; a private one is charged as a miss.
      config: { rates: { agentMiss: { limit: 3, seconds: 3600 } }, retiredAgentDocuments: 'public' },
      wrapStore: slow,
    });
    const bob = await alpha.agent('bob');
    await alpha.server.api.retire(bob.address);
    const prober = alpha.newAgent();
    const doc = (address: string) =>
      prober.request('GET', `/agnt/agents/${address}`, { sign: false, ip: '203.0.113.7' });
    assert.equal((await doc(bob.address)).status, 200, 'a retired document (spec section 4)');
    const answers = await Promise.all(Array.from({ length: 20 }, (_, i) => doc(`nobody${i}@alpha.test`)));
    assert.deepEqual(
      answers.map(a => a.status).sort(),
      [...Array(3).fill(404), ...Array(17).fill(429)],
      'the retired agent took none of three',
    );
    await fed.close();
  });

  it("spares a hosting service's own networks the probing budget", async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha', {
      config: { rates: { agentMiss: { limit: 1, seconds: 3600 } }, rateExemptNetworks: ['203.0.113.0/24'] },
    });
    const backend = alpha.newAgent();
    for (let i = 0; i < 5; i++) {
      const res = await backend.request('GET', `/agnt/agents/nobody${i}@alpha.test`, {
        sign: false,
        ip: '203.0.113.7',
      });
      assert.equal(res.status, 404);
    }
    await fed.close();
  });

  it('counts failed envelope signatures against (client, server) before verifying again', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha', { config: { rates: { badSignature: { limit: 3, seconds: 3600 } } } });
    const bob = await alpha.agent('bob');
    const peer = new Peer(fed, 'peer');
    const zed = peer.agent('zed');
    const forged = () => ({ ...peer.envelope(peer.message(zed, [bob.address], 'x')), signature: 'AAAA' });
    for (let i = 0; i < 3; i++) assert.equal((await peer.post(alpha, forged())).status, 403);
    assert.equal((await peer.post(alpha, peer.envelope(peer.message(zed, [bob.address], 'valid')))).status, 429);
    fed.net.ip = '198.51.100.99';
    assert.equal((await peer.post(alpha, peer.envelope(peer.message(zed, [bob.address], 'valid')))).status, 202);
    await fed.close();
  });
});

describe('policy is silent (spec section 6.3)', () => {
  it('does the same work and gives the same answer for an unknown recipient as for a known one', async () => {
    const calls: string[] = [];
    const watch = (store: Store) =>
      new Proxy(store, {
        get(target, name) {
          const value = Reflect.get(target, name);
          return typeof value === 'function'
            ? (...args: unknown[]) => (calls.push(String(name)), value.apply(target, args))
            : value;
        },
      });
    const fed = new Federation();
    const alpha = await fed.server('alpha', { wrapStore: watch });
    const bob = await alpha.agent('bob');
    const peer = new Peer(fed, 'peer');
    const zed = peer.agent('zed');
    await peer.post(alpha, peer.envelope(peer.message(zed, [bob.address], 'warm the caches')));

    const deliverTo = async (recipient: string) => {
      calls.length = 0;
      const res = await peer.post(alpha, peer.envelope(peer.message(zed, [recipient], `to ${recipient}`)));
      return { status: res.status, body: res.bytes.toString(), calls: [...calls] };
    };
    const known = await deliverTo(bob.address);
    const unknown = await deliverTo('nobody@alpha.test');
    assert.deepEqual(unknown, known);
    assert.ok(!known.calls.includes('agentByAddress'), 'no recipient is looked up before the answer');
    await fed.close();
  });
});

describe('fetched parts', () => {
  it('are collected with the messages that name them, and budgeted per carrier by bytes fetched', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const beta = await fed.server('beta', { config: { fetchBytesPerHour: 30 } });
    const ada = await alpha.agent('ada');
    const bob = await beta.agent('bob');
    const send = async (bytes: Buffer) => {
      await ada.upload(bytes);
      await ada.send(
        ada.message([bob.address], 'x', {
          parts: [
            { type: 'text/plain', data: 'x' },
            { type: 'application/octet-stream', sha256: sha256Hex(bytes), size: bytes.length },
          ],
        }),
      );
      await fed.work();
      fed.clock.advance(PREFETCH_JITTER_MS);
      await fed.work();
      return bob.part(sha256Hex(bytes));
    };
    const first = Buffer.alloc(20, 1);
    assert.equal((await send(first)).status, 200);
    const second = Buffer.alloc(20, 2);
    const over = await send(second);
    assert.deepEqual([over.status, over.json.code], [503, 'unavailable'], 'over the hour: it waits, never skipped');
    fed.clock.advance(HOUR);
    await fed.work();
    assert.equal((await bob.part(sha256Hex(second))).status, 200, 'and is fetched in the next hour');

    fed.clock.advance(31 * DAY);
    await beta.server.sweep();
    assert.equal(await beta.store.part(sha256Hex(first), { carrier: alpha.origin }), null);
    await fed.close();
  });
});

describe('the SSRF guard', () => {
  it('refuses private, loopback, link-local, NAT64, 6to4 and mapped addresses', () => {
    const blocked = [
      '127.0.0.1',
      '10.1.2.3',
      '172.16.0.1',
      '192.168.1.1',
      '169.254.169.254',
      '100.64.0.1',
      '0.0.0.0',
      '::1',
      '::',
      'fe80::1',
      'fc00::1',
      'fd12::1',
      '::ffff:127.0.0.1',
      '::ffff:7f00:1',
      '::127.0.0.1',
      '64:ff9b::808:808',
      '2002:808:808::1',
      '2001::1',
      '2001:db8::1',
      'ff02::1',
      '224.0.0.1',
      'not an ip',
    ];
    for (const ip of blocked) assert.equal(isBlockedAddress(ip), true, ip);
    for (const ip of ['8.8.8.8', '203.0.112.1', '2606:4700::1111', '::ffff:8.8.8.8'])
      assert.equal(isBlockedAddress(ip), false, ip);
  });

  it('refuses http, credentials, and hosts that resolve to private addresses, before connecting', async () => {
    const dns = { txt: async () => [], addresses: async (h: string) => (h === 'inside.example' ? ['10.0.0.5'] : []) };
    const http = guardedHttp({ dns });
    const kind = (url: string) =>
      http.request({ method: 'GET', url, maxBytes: 10 }).then(
        () => 'answered',
        (e: Unreachable) => e.kind,
      );
    assert.equal(await kind('http://example.com/'), 'forbidden');
    assert.equal(await kind('https://user:pw@example.com/'), 'forbidden');
    assert.equal(await kind('https://inside.example/'), 'forbidden');
    assert.equal(await kind('https://[::1]/'), 'forbidden');
    assert.equal(await kind('https://nxdomain.example/'), 'absent');
  });

  it('reads trusted networks as CIDR, /8 or narrower, with no bits after the prefix', () => {
    const ok = (text: string) => (parseNetwork(text) as Network).cidr;
    assert.equal(ok('100.64.0.0/10'), '100.64.0.0/10');
    assert.equal(ok('10.0.0.0/8'), '10.0.0.0/8');
    assert.equal(ok('192.168.1.7/32'), '192.168.1.7/32');
    assert.equal(ok('fd7a:115c:a1e0::/48'), 'fd7a:115c:a1e0:0:0:0:0:0/48');
    for (const bad of [
      '0.0.0.0/0',
      '::/0',
      '8.0.0.0/7',
      '::/7',
      '100.64.0.1/10',
      '10.0.0.0',
      '10.0.0.0/33',
      'fd00::/129',
      'x/8',
    ])
      assert.equal(typeof parseNetwork(bad), 'string', bad);
  });

  it('places an address in a trusted network, an IPv4-mapped IPv6 address as its IPv4', () => {
    const nets = ['100.64.0.0/10', 'fd7a:115c:a1e0::/48'].map(n => parseNetwork(n) as Network);
    for (const ip of ['100.64.0.1', '100.127.255.254', '::ffff:100.100.1.2', 'fd7a:115c:a1e0:ab12::1'])
      assert.equal(inNetworks(ip, nets), true, ip);
    for (const ip of ['100.128.0.1', '100.63.255.255', '10.0.0.1', 'fd7a:115c:a1e1::1', '::1', 'not an ip'])
      assert.equal(inNetworks(ip, nets), false, ip);
    assert.equal(inNetworks('100.64.0.1', []), false);
  });

  it('calls a private address only inside a trusted network, still over https only', async () => {
    const at: Record<string, string[]> = {
      'laptop.tail.ts.net': ['100.101.102.103', 'fd7a:115c:a1e0::1'],
      'printer.lan': ['192.168.1.20'],
      'half.example': ['100.101.102.104', '10.0.0.9'],
    };
    const dns = { txt: async () => [], addresses: async (h: string) => at[h] ?? [] };
    const trustedNetworks = ['100.64.0.0/10', 'fd7a:115c:a1e0::/48'].map(n => parseNetwork(n) as Network);
    const kind = (http: ReturnType<typeof guardedHttp>, url: string) =>
      http.request({ method: 'GET', url, maxBytes: 10, timeoutMs: 200 }).then(
        () => 'answered',
        (e: Unreachable) => e.kind,
      );
    const off = guardedHttp({ dns });
    const on = guardedHttp({ dns, trustedNetworks, connectTimeoutMs: 50 });
    assert.equal(await kind(off, 'https://laptop.tail.ts.net/'), 'forbidden', 'off by default');
    assert.notEqual(await kind(on, 'https://laptop.tail.ts.net/'), 'forbidden', 'reached the connection');
    assert.equal(await kind(on, 'https://printer.lan/'), 'forbidden', 'outside the trusted networks');
    assert.equal(await kind(on, 'https://half.example/'), 'forbidden', 'every address must be allowed');
    assert.equal(await kind(on, 'http://laptop.tail.ts.net/'), 'forbidden', 'http stays development only');
  });
});

/** A self-signed certificate for localhost, for TLS tests only. */
const LOCALHOST_TLS = {
  key: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglXHENsQE5edyMb+y
eXP+TJIYx51NL6LqytgWEH1mRMKhRANCAAR94BLDTGSrvFmmXW6O7hGEAlhoDSm+
W9SClYEQqMxXhyLUeF/QQIGZcSguQg6wbkjKceJQQfOMW/tzpGxnxZrJ
-----END PRIVATE KEY-----`,
  cert: `-----BEGIN CERTIFICATE-----
MIIBlDCCATugAwIBAgIUZ+tRlEWB5ZPtGWqZar93gHKgNwQwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTAxNTIwMTAyNFoYDzIxMjYwOTIx
MjAxMDI0WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAR94BLDTGSrvFmmXW6O7hGEAlhoDSm+W9SClYEQqMxXhyLUeF/QQIGZ
cSguQg6wbkjKceJQQfOMW/tzpGxnxZrJo2kwZzAdBgNVHQ4EFgQUJkq2nl9AqzjQ
NkLhs4b+p+FvtdYwHwYDVR0jBBgwFoAUJkq2nl9AqzjQNkLhs4b+p+FvtdYwDwYD
VR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwID
RwAwRAIfT4wvq+pu2Ocri1XcWwdEeD6gbEU3uKmMQ+1vcmQBnQIhAIB85gPkYKBL
QbIs331G1aMKJDCCEICFCwDQgZlhUbex
-----END CERTIFICATE-----`,
};

describe('outbound TLS and redirects (spec section 9)', () => {
  /** A local https or http server answering every request with `answer`, for the duration of `use`. */
  async function serving<T>(
    options: { tls?: https.ServerOptions },
    answer: http.RequestListener,
    use: (origin: string) => Promise<T>,
  ): Promise<T> {
    const server = options.tls ? https.createServer(options.tls, answer) : http.createServer(answer);
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    try {
      return await use(`${options.tls ? 'https' : 'http'}://localhost:${port}`);
    } finally {
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
  }
  const dns = { txt: async () => [], addresses: async () => ['127.0.0.1'] };
  const outbound = guardedHttp({ dns, dev: true });
  const failure = (url: string) =>
    outbound.request({ method: 'GET', url, maxBytes: 100, timeoutMs: 2000 }).then(
      () => null,
      (e: Unreachable) => e,
    );

  it('refuses a server that offers nothing newer than TLS 1.2', async () => {
    const e = await serving({ tls: { ...LOCALHOST_TLS, maxVersion: 'TLSv1.2' } }, (_, res) => res.end('hi'), failure);
    assert.equal(e?.kind, 'failed');
    assert.match(e.message, /protocol version|unsupported protocol|wrong version/i);
  });

  it('refuses a certificate that does not authenticate the host, as not a failure that may pass', async () => {
    const e = await serving({ tls: { ...LOCALHOST_TLS, minVersion: 'TLSv1.3' } }, (_, res) => res.end('hi'), failure);
    assert.equal(e?.kind, 'certificate');
  });

  it('never follows a redirect', async () => {
    let followed = false;
    const answer: http.RequestListener = (req, res) => {
      if (req.url === '/elsewhere') followed = true;
      res.writeHead(302, { location: '/elsewhere' }).end();
    };
    const res = await serving({}, answer, origin =>
      outbound.request({ method: 'GET', url: `${origin}/x`, maxBytes: 100 }),
    );
    assert.equal(res.status, 302);
    assert.equal(followed, false);
  });
});

describe('DNS', () => {
  const resolver = (records: string[][]): Lookups =>
    ({ resolveTxt: async () => records, resolve4: async () => [], resolve6: async () => [] }) as unknown as Lookups;
  const doh = (answers: Record<string, unknown>) =>
    (async (url: string | URL | Request) => {
      const body = answers[new URL(String(url)).origin];
      return new Response(JSON.stringify(body), { status: 200 });
    }) as typeof fetch;
  const txt = (data: string) => ({ Status: 0, Answer: [{ type: 16, data }] });
  const record = [['v=agnt1; server=https://agnt.example.com']];

  it('confirms TXT answers with every DNS-over-HTTPS resolver', async () => {
    const dns = systemDns({
      resolver: resolver(record),
      doh: ['https://one.example/dns', 'https://two.example/dns'],
      fetch: doh({
        'https://one.example': txt('"v=agnt1; server=https://agnt.example.com"'),
        'https://two.example': txt('"v=agnt1; " "server=https://agnt.example.com"'),
      }),
    });
    assert.deepEqual(await dns.txt('_agnt.example.com'), record);
  });

  it('treats disagreement, and a SERVFAIL such as a DNSSEC failure, as temporary', async () => {
    const disagree = systemDns({
      resolver: resolver(record),
      doh: ['https://one.example/dns', 'https://two.example/dns'],
      fetch: doh({
        'https://one.example': txt('"v=agnt1; server=https://agnt.example.com"'),
        'https://two.example': txt('"v=agnt1; server=https://evil.example"'),
      }),
    });
    await assert.rejects(disagree.txt('_agnt.example.com'), DnsFailure);
    const servfail = systemDns({
      resolver: resolver(record),
      doh: ['https://one.example/dns', 'https://two.example/dns'],
      fetch: doh({
        'https://one.example': { Status: 2 },
        'https://two.example': txt('"v=agnt1; server=https://agnt.example.com"'),
      }),
    });
    await assert.rejects(servfail.txt('_agnt.example.com'), DnsFailure);
  });

  it('reads an absence as none and a server failure as temporary from c-ares', async () => {
    const fail = (code: string) =>
      ({ resolveTxt: async () => Promise.reject(Object.assign(new Error(code), { code })) }) as unknown as Lookups;
    assert.deepEqual(await systemDns({ resolver: fail('ENOTFOUND') }).txt('x'), []);
    assert.deepEqual(await systemDns({ resolver: fail('ENODATA') }).txt('x'), []);
    await assert.rejects(systemDns({ resolver: fail('ESERVFAIL') }).txt('x'), DnsFailure);
    await assert.rejects(systemDns({ resolver: fail('ETIMEOUT') }).txt('x'), DnsFailure);
  });
});
