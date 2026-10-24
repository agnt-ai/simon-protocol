/**
 * Regression tests for faults found in review, each written to fail on the server before its fix: crash
 * windows and races in delivery (dist), deliver as an outbound-fetch primitive (offsec), key continuity by
 * mention (crypto), and signed-request boundaries.
 * Part confidentiality (privacy) is in parts.test.ts.
 */
import assert from 'node:assert/strict';
import net from 'node:net';
import { describe, it } from 'node:test';
import {
  canonicalBytes,
  generateKey,
  keyToken,
  serverDocument,
  signMessage,
  signRequest,
  timestamp,
  type Message,
} from '@agnt-sdk/simon-protocol';
import { createServer } from '../src/server.ts';
import type { HttpRequest, HttpResponse } from '../src/net/fetch.ts';
import { CONCURRENCY } from '../src/outbox.ts';
import { SqliteStore } from '../src/store/sqlite.ts';
import type { Store } from '../src/store/store.ts';
import { defineConfig } from '../src/config.ts';
import { Federation, Peer, TARPIT_MS, toRequest } from './harness.ts';

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const LEASE_MS = 2 * MIN;

/** A store whose methods `over` replaces, as a crash at a chosen point leaves it. */
const wrap = (store: Store, over: Partial<Record<keyof Store, Function>>): Store =>
  new Proxy(store, {
    get(target, name) {
      const replaced = (over as Record<PropertyKey, Function>)[name];
      if (replaced) return replaced;
      const value = Reflect.get(target, name);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });

const tick = () => new Promise(r => setImmediate(r));
const posts = (fed: Federation) => fed.net.sent.filter(r => r.url.endsWith('/simon/deliver')).length;

/** Hold every POST to /simon/deliver until the test answers it. */
function gateDeliveries(fed: Federation) {
  const real = fed.net.request.bind(fed.net);
  const gates: { answer: (r: HttpResponse) => void; req: HttpRequest }[] = [];
  fed.net.request = async (r: HttpRequest) => {
    if (!r.url.endsWith('/simon/deliver')) return real(r);
    fed.net.sent.push({ method: r.method, url: r.url });
    return new Promise<HttpResponse>(answer => gates.push({ answer, req: r }));
  };
  const until = async (n: number) => {
    for (let i = 0; i < 100 && gates.length < n; i++) await tick();
  };
  return { gates, until, real };
}

describe('crash windows', () => {
  it('completes a send whose delivery rows were lost, when the client repeats it', async () => {
    const fed = new Federation();
    let crash = true;
    const alpha = await fed.server('alpha', {
      wrapStore: s =>
        wrap(s, {
          putMessage: async (m: never, rows: never) => {
            if (!crash) return s.putMessage(m, rows);
            crash = false;
            await s.putMessage(m); // the message alone, as a store that is not atomic could leave it
            throw new Error('killed before the rows were written');
          },
        }),
    });
    const beta = await fed.server('beta');
    const ada = await alpha.agent('ada');
    const bob = await beta.agent('bob');
    const m = ada.message([bob.address], 'hello');
    assert.equal((await ada.send(m)).status, 500);
    const retry = await ada.send(m);
    assert.equal(retry.status, 200);
    await fed.work();
    assert.deepEqual(await bob.texts(), ['hello']);
    assert.equal((await ada.sent(retry.json.id)).json.servers[0].status, 'delivered');
    await fed.close();
  });

  it('delivers once more, and is recognised as a repeat, when it crashed between the 202 and its record', async () => {
    const fed = new Federation();
    let crash = true;
    const alpha = await fed.server('alpha', {
      wrapStore: s =>
        wrap(s, {
          settleDelivery: async (d: { status: string }, token: string) => {
            if (crash && d.status === 'delivered') {
              crash = false;
              throw new Error('killed after the 202');
            }
            return s.settleDelivery(d as never, token);
          },
        }),
    });
    const beta = await fed.server('beta');
    const ada = await alpha.agent('ada');
    const bob = await beta.agent('bob');
    const { json } = await ada.send(ada.message([bob.address], 'once'));
    await fed.work();
    assert.equal((await alpha.store.deliveries(json.id))[0].status, 'pending');
    fed.clock.advance(LEASE_MS);
    await fed.work();
    assert.equal(posts(fed), 2);
    assert.equal((await alpha.store.deliveries(json.id))[0].status, 'delivered');
    assert.deepEqual(await bob.texts(), ['once']);
    await fed.close();
  });

  it('isolates a poison arrival: the others are offered, and the outbox still runs', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const beta = await fed.server('beta', {
      extensions: [
        {
          name: 'flaky-policy',
          admit: a => {
            if ((a.message as Message).parts[0].type === 'text/plain' && JSON.stringify(a.message).includes('poison')) {
              throw new Error('policy lookup failed for this sender');
            }
            return undefined;
          },
        },
      ],
    });
    const ada = await alpha.agent('ada');
    const bob = await beta.agent('bob');
    const cat = await beta.agent('cat');
    await ada.send(ada.message([bob.address], 'poison'));
    await ada.send(ada.message([cat.address], 'innocent'));
    await alpha.server.work();
    const out = await bob.send(bob.message([ada.address], 'outbound'));
    await beta.server.work();
    assert.deepEqual(await cat.texts(), ['innocent']);
    assert.equal((await bob.sent(out.json.id)).json.servers[0].status, 'delivered');
    const [waiting] = await beta.store.arrivals(new Date(fed.clock.t + HOUR).toISOString(), 10);
    assert.deepEqual([waiting.arrival.recipient, waiting.arrival.attempts], [bob.address, 1], 'retried later');
    await fed.close();
  });

  it('tells an inbox event at least once, though the process died between the entry and the event', async () => {
    const fed = new Federation();
    const events: string[] = [];
    let crash = true;
    const alpha = await fed.server('alpha');
    const beta = await fed.server('beta', {
      extensions: [{ name: 'watch', on: { inbox: e => void events.push(e.address) } }],
      wrapStore: s =>
        wrap(s, {
          addToInbox: async (a: string, id: string, at: string) => {
            const added = await s.addToInbox(a, id, at);
            if (crash && a.startsWith('bob')) {
              crash = false;
              throw new Error('killed after the inbox entry was written');
            }
            return added;
          },
        }),
    });
    const ada = await alpha.agent('ada');
    const bob = await beta.agent('bob');
    const cat = await beta.agent('cat');
    await ada.send(ada.message([bob.address, cat.address], 'fan'));
    await fed.work();
    fed.clock.advance(HOUR);
    await fed.work();
    assert.deepEqual(await bob.texts(), ['fan']);
    assert.deepEqual(events.sort(), [bob.address, cat.address]);
    await fed.close();
  });
});

describe('outbox claims', () => {
  it('never lets an attempt that outlived its lease overwrite a delivery', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const beta = await fed.server('beta');
    const ada = await alpha.agent('ada');
    const bob = await beta.agent('bob');
    const { gates, until, real } = gateDeliveries(fed);
    const { json } = await ada.send(ada.message([bob.address], 'slow exchange'));
    const first = alpha.server.work();
    await until(1);
    fed.clock.advance(LEASE_MS + 1);
    const second = alpha.server.work();
    await until(2);
    assert.equal(gates.length, 2, 'the lease ran out, so the row was claimed again');
    gates[1].answer(await real(gates[1].req));
    for (let i = 0; i < 50; i++) await tick();
    gates[0].answer({ status: 503, headers: { 'retry-after': '3600' }, body: Buffer.from('{}') });
    await Promise.all([first, second]);
    const [row] = await alpha.store.deliveries(json.id);
    assert.deepEqual([row.status, row.reason], ['delivered', null]);
    await fed.close();
  });

  it('lets two workers on one store take each row once', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const beta = await fed.server('beta');
    const ada = await alpha.agent('ada');
    const bobs = await Promise.all([0, 1, 2, 3, 4, 5, 6, 7].map(i => beta.agent(`bob${i}`)));
    const second = createServer({
      config: alpha.server.api.config,
      store: alpha.store,
      dns: fed.dns,
      http: fed.net,
      now: fed.clock.now,
      log: () => {},
      worker: false,
    });
    for (const b of bobs) await ada.send(ada.message([b.address], `to ${b.address}`));
    await Promise.all([alpha.server.work(), second.work()]);
    fed.clock.advance(10_000); // rows that found their server busy wait a moment
    await Promise.all([alpha.server.work(), second.work()]);
    assert.equal(posts(fed), 8, 'one POST per message');
    await beta.server.work();
    for (const b of bobs) assert.equal((await b.texts()).length, 1);
    await second.close();
    await fed.close();
  });

  it(`counts POSTs against the cap: at most ${CONCURRENCY} at once, however many domains a message names`, async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const ada = await alpha.agent('ada');
    const to = Array.from({ length: 100 }, (_, i) => {
      new Peer(fed, `p${i}`);
      return `x@p${i}.test`;
    });
    const real = fed.net.request.bind(fed.net);
    let inFlight = 0;
    let peak = 0;
    fed.net.request = async (r: HttpRequest) => {
      if (!r.url.endsWith('/simon/deliver')) return real(r);
      peak = Math.max(peak, ++inFlight);
      await new Promise(res => setTimeout(res, 5));
      return real(r).finally(() => inFlight--);
    };
    for (let k = 0; k < 3; k++) await ada.send(ada.message(to, `fan ${k}`));
    await alpha.server.work();
    assert.ok(peak <= CONCURRENCY, `peak ${peak}`);
    await fed.close();
  });

  it('treats every name for a dead address as dead, so a wildcard tarpit costs one timeout', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const ada = await alpha.agent('ada');
    const tarpits = ['tar1', 'tar2'].map(name => {
      const p = new Peer(fed, name);
      p.hang = true;
      fed.net.addresses.set(`simon.${name}.test`, '203.0.113.66');
      return p;
    });
    await ada.send(ada.message(['x@tar1.test'], 'one'));
    await alpha.server.work();
    assert.equal(tarpits[0].delivered, 1);
    const { json } = await ada.send(ada.message(['x@tar2.test'], 'two'));
    const started = Date.now();
    await alpha.server.work();
    assert.ok(Date.now() - started < TARPIT_MS, 'no second timeout');
    assert.equal(tarpits[1].delivered, 0);
    assert.equal((await alpha.store.deliveries(json.id))[0].reason, 'refused');
    await fed.close();
  });

  it('throttles a destination that answered 429 until its Retry-After', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const busy = new Peer(fed, 'busy');
    const serve = fed.net.hosts.get(busy.origin);
    assert.ok(typeof serve === 'function');
    fed.net.hosts.set(busy.origin, async req =>
      req.path === '/simon/deliver'
        ? { status: 429, json: { code: 'rate_limited' }, headers: { 'retry-after': '600' } }
        : serve(req),
    );
    const ada = await alpha.agent('ada');
    await ada.send(ada.message(['a@busy.test'], 'one'));
    await alpha.server.work();
    await ada.send(ada.message(['b@busy.test'], 'two'));
    fed.clock.advance(5 * MIN);
    await alpha.server.work();
    assert.equal(posts(fed), 1, 'nothing more while throttled');
    fed.clock.advance(5 * MIN);
    await alpha.server.work();
    assert.equal(posts(fed), 3);
    await fed.close();
  });
});

describe('delivery timing', () => {
  it('attempts nothing before sentAt', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const beta = await fed.server('beta');
    const ada = await alpha.agent('ada');
    const bob = await beta.agent('bob');
    const { json } = await ada.send(ada.message([bob.address], 'ahead', { sentAt: timestamp(fed.clock.t + 4 * MIN) }));
    await fed.work();
    assert.equal(posts(fed), 0);
    fed.clock.advance(4 * MIN);
    await fed.work();
    assert.equal((await ada.sent(json.id)).json.servers[0].status, 'delivered');
    await fed.close();
  });

  it('caps backoff to make a last attempt before the deadline, 143 hours after sentAt', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const beta = await fed.server('beta');
    const ada = await alpha.agent('ada');
    const bob = await beta.agent('bob');
    const serve = fed.net.hosts.get(beta.origin)!;
    fed.clock.advance(DAY);
    const sentAt = fed.clock.t - 23 * HOUR - 50 * MIN;
    const { json } = await ada.send(ada.message([bob.address], 'queued', { sentAt: timestamp(sentAt) }));
    fed.net.hosts.set(beta.origin, 'down');
    const back = sentAt + 141 * HOUR;
    for (let i = 0; i < 80; i++) {
      if (fed.clock.t >= back) fed.net.hosts.set(beta.origin, serve);
      await fed.work();
      const [row] = await alpha.store.deliveries(json.id);
      if (row.status !== 'pending') break;
      fed.clock.t = Math.max(fed.clock.t + 1, Date.parse(row.nextAttemptAt));
    }
    const [row] = await alpha.store.deliveries(json.id);
    assert.equal(row.status, 'delivered');
    assert.ok(fed.clock.t < sentAt + 143 * HOUR);
    assert.deepEqual(await bob.texts(), ['queued']);
    await fed.close();
  });
});

describe('deliver as an outbound-fetch primitive', () => {
  /** An envelope naming a `from` on any domain, unsigned: what costs an attacker nothing to send. */
  const junk = (fromDomain: string, to = 'y@alpha.test') => {
    const message = {
      v: 1,
      from: `x@${fromDomain}`,
      to: [to],
      inReplyTo: null,
      parts: [{ type: 'text/plain', data: '' }],
      headers: {},
      sentAt: '2026-10-15T12:00:00Z',
      signature: 'AAAA',
    };
    return { message, server: 'https://simon.alpha.test', recipients: [to], signature: 'AAAA' };
  };
  const post = (fed: Federation, body: object, ip = '198.51.100.9') =>
    fed.servers[0].server.handle(
      toRequest('POST', new URL('https://simon.alpha.test/simon/deliver'), {}, canonicalBytes(body), ip),
    );

  it('remembers a temporary outcome for a minute, so a failing host is not fetched on every request', async () => {
    const fed = new Federation();
    await fed.server('alpha');
    fed.net.hosts.set('https://attacker.test', async () => ({ status: 503, json: {} }));
    for (let i = 0; i < 5; i++) assert.equal((await post(fed, junk('attacker.test'))).status, 503);
    assert.equal(fed.net.sent.filter(r => r.url.includes('/.well-known/simon')).length, 1);
    await fed.close();
  });

  it('counts each lookup against the client network before making it, and every delivery against its carrier', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha', {
      config: { rates: { lookup: { limit: 3, seconds: 3600 }, deliver: { limit: 3, seconds: 3600 } } },
    });
    for (let i = 0; i < 3; i++) assert.equal((await post(fed, junk(`d${i}.test`))).status, 403);
    const refused = await post(fed, junk('d3.test'));
    assert.deepEqual([refused.status, (refused.json as { code: string }).code], [429, 'rate_limited']);
    assert.equal(fed.net.sent.filter(r => r.url === 'https://d3.test/.well-known/simon').length, 0, 'not made');
    assert.equal((await post(fed, junk('d3.test'), '2001:db8:9::1')).status, 403, 'another network has its own');

    const peer = new Peer(fed, 'peer');
    const zed = peer.agent('zed');
    const bob = await alpha.agent('bob');
    const env = peer.envelope(peer.message(zed, [bob.address], 'once'));
    for (let i = 0; i < 3; i++) assert.equal((await peer.post(alpha, env)).status, 202);
    assert.equal((await peer.post(alpha, env)).status, 429, 'a repeat counts like any delivery (spec section 11.2)');
    assert.equal((await peer.post(alpha, peer.envelope(peer.message(zed, [bob.address], 'twice')))).status, 429);
    await fed.close();
  });

  it('runs a bounded number of lookups at once, and refuses the rest for now', async () => {
    const fed = new Federation();
    await fed.server('alpha');
    let inFlight = 0;
    let peak = 0;
    for (let i = 0; i < 40; i++) {
      fed.net.hosts.set(`https://h${i}.test`, async () => {
        peak = Math.max(peak, ++inFlight);
        await new Promise(r => setTimeout(r, 20));
        inFlight--;
        return { status: 404, json: {} };
      });
    }
    const answers = await Promise.all(
      Array.from({ length: 40 }, (_, i) => post(fed, junk(`h${i}.test`), `198.51.100.${i}`)),
    );
    assert.ok(peak <= 32, `peak ${peak}`);
    assert.ok(
      answers.some(a => a.status === 503),
      'the rest were told to come back',
    );
    await fed.close();
  });
});

describe('connections', () => {
  it('serves at most maxConnections at once', async () => {
    const config = defineConfig({ origin: 'http://127.0.0.1', dev: true, maxConnections: 2 });
    const store = new SqliteStore();
    const server = createServer({ config, store, worker: false, log: () => {} });
    const port = await server.listen(0, '127.0.0.1');
    const open = () =>
      new Promise<net.Socket>(resolve => {
        const s = net.connect(port, '127.0.0.1', () => resolve(s));
      });
    const sockets = [await open(), await open(), await open()];
    const closed = await Promise.race([
      new Promise(resolve => sockets[2].once('close', () => resolve(true))),
      new Promise(resolve => setTimeout(() => resolve(false), 500)),
    ]);
    assert.equal(closed, true, 'the third connection is closed');
    for (const s of sockets) s.destroy();
    await server.close();
    await store.close();
  });
});

describe('key continuity by possession', () => {
  async function takeover() {
    const fed = new Federation();
    const alpha = await fed.server('alpha', { config: { keyChangeHoldSeconds: 3600 } });
    const bob = await alpha.agent('bob');
    const peer = new Peer(fed, 'peer');
    const zed = peer.agent('zed');
    const first = peer.envelope(peer.message(zed, [bob.address], 'first'));
    assert.equal((await peer.post(alpha, first)).status, 202, 'first contact');
    const victim = peer.key;
    peer.key = generateKey().privateKey;
    // The hijacker lists the victim's public key beside its own: mention, not possession.
    peer.serverDocument = canonicalBytes(
      serverDocument(
        peer.origin,
        [victim, peer.key].map(k => ({ key: keyToken(k), added: '2026-01-01T00:00:00Z', revoked: null })),
      ),
    );
    fed.clock.advance(11 * MIN);
    return { fed, alpha, bob, peer, zed, first };
  }

  it('holds a domain whose server lists a trusted key but signs with another', async () => {
    const { fed, alpha, bob, peer, zed } = await takeover();
    const held = await peer.post(alpha, peer.envelope(peer.message(zed, [bob.address], 'after takeover')));
    assert.deepEqual([held.status, held.json.code], [503, 'unavailable']);
    fed.clock.advance(30 * MIN);
    assert.equal((await peer.post(alpha, peer.envelope(peer.message(zed, [bob.address], 'still')))).status, 503);
    fed.clock.advance(31 * MIN);
    const confirmed = await peer.post(alpha, peer.envelope(peer.message(zed, [bob.address], 'confirmed')));
    assert.equal(confirmed.status, 202, 'trusted once confirmed after the hold');
    await fed.close();
  });

  it('is not vouched for by a replayed envelope the trusted key once signed', async () => {
    const { fed, alpha, bob, peer, zed, first } = await takeover();
    // A copy of what the honest server sent: it verifies, but is a repeat here, so it vouches for nothing.
    assert.equal((await peer.post(alpha, first)).status, 202);
    const held = await peer.post(alpha, peer.envelope(peer.message(zed, [bob.address], 'now trusted?')));
    assert.equal(held.status, 503);
    await fed.close();
  });
});

describe('signed requests (spec section 8)', () => {
  it('keeps a nonce until its timestamp leaves the window, so no replay fits at the boundary', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const ada = await alpha.agent('ada');
    const ts = fed.clock.t;
    const headers = signRequest(ada.key, {
      method: 'GET',
      url: `${alpha.origin}/simon/sync`,
      now: ts,
      agent: ada.address,
    });
    const ask = () =>
      alpha.server.handle(
        toRequest('GET', new URL(`${alpha.origin}/simon/sync`), { ...headers }, Buffer.alloc(0), '192.0.2.1'),
      );
    fed.clock.t = ts - 300_000;
    assert.equal((await ask()).status, 200);
    fed.clock.t = ts + 300_999;
    const replay = await ask();
    assert.deepEqual([replay.status, (replay.json as { code: string }).code], [401, 'replayed_request']);
    assert.equal(replay.headers?.['www-authenticate'], 'SIMON');
    await fed.close();
  });

  it('refuses a message version it does not implement on send', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    const ada = await alpha.agent('ada');
    const v7 = signMessage(
      { v: 7, from: ada.address, to: ['b@beta.test'], sentAt: timestamp(fed.clock.t) } as never,
      ada.key,
    );
    const res = await ada.send(v7);
    assert.deepEqual(
      [res.status, res.json.code, res.headers['content-type']],
      [400, 'unsupported_version', 'application/problem+json'],
    );
    await fed.close();
  });
});
