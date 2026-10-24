/**
 * Spec section 3: resolution's six outcomes as this server meets them, and what it caches.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateKey, serverDocument } from '@agnt-sdk/simon-protocol';
import { defineConfig } from '../src/config.ts';
import { Unreachable, type Http } from '../src/net/fetch.ts';
import type { Context } from '../src/context.ts';
import { reresolve } from '../src/deliver.ts';
import { rateLimited } from '../src/errors.ts';
import { Resolver } from '../src/resolver.ts';
import { SqliteStore } from '../src/store/sqlite.ts';
import { Clock, FakeDns, FakeNet } from './harness.ts';

/** A resolver on a fake network; `wrap` stands in front of the network, to make it fail as a real one does. */
function setup(wrap: (net: FakeNet) => Http = net => net) {
  const clock = new Clock();
  const dns = new FakeDns();
  const net = new FakeNet();
  const config = defineConfig({ origin: 'https://simon.self.test', serverKey: generateKey().privateKey });
  const store = new SqliteStore();
  const resolver = new Resolver({
    config,
    store,
    http: wrap(net),
    dns,
    now: clock.now,
    log: () => {},
    ownDocument: async () => serverDocument(config.origin, [], config.limits),
    localAgent: async () => null,
  });
  const wellKnown = (domain: string, status: number, body: unknown) =>
    net.hosts.set(`https://${domain}`, async () => ({ status, json: body }));
  return { clock, dns, net, resolver, wellKnown, store };
}

describe('resolution (spec section 3)', () => {
  it('ends in each of its six outcomes', async () => {
    const { dns, resolver, wellKnown } = setup();
    dns.records.set('_simon.bad.example', [['v=simon1; server=ftp://x']]);
    dns.records.set('_simon.two.example', [
      ['v=simon1; server=https://a.example'],
      ['v=simon1; server=https://b.example'],
    ]);
    dns.point('txt.example', 'https://simon.txt.example');
    wellKnown('web.example', 200, { server: 'https://simon.web.example' });
    wellKnown('busy.example', 503, {});
    dns.failing.add('_simon.down.example');

    const outcome = async (d: string) => (await resolver.resolve(d)).outcome;
    assert.equal(await outcome('not a domain'), 'invalid_domain');
    assert.equal(await outcome('bad.example'), 'invalid_record');
    assert.equal(await outcome('two.example'), 'conflict');
    assert.deepEqual(await resolver.resolve('txt.example'), {
      outcome: 'server',
      server: 'https://simon.txt.example',
      via: 'dns',
    });
    assert.deepEqual(await resolver.resolve('web.example'), {
      outcome: 'server',
      server: 'https://simon.web.example',
      via: 'well-known',
    });
    assert.equal(await outcome('nowhere.example'), 'not_found');
    assert.equal(await outcome('down.example'), 'temporary');
    assert.equal(await outcome('busy.example'), 'temporary');
  });

  it('caches a server and not_found for ten minutes, and temporary for one minute only', async () => {
    const { clock, dns, resolver } = setup();
    dns.failing.add('_simon.flaky.example');
    assert.equal((await resolver.resolve('flaky.example')).outcome, 'temporary');
    dns.failing.delete('_simon.flaky.example');
    dns.point('flaky.example', 'https://simon.flaky.example');
    assert.equal((await resolver.resolve('flaky.example')).outcome, 'temporary', 'remembered for a minute');
    clock.advance(60_000);
    assert.equal((await resolver.resolve('flaky.example')).outcome, 'server');

    assert.equal((await resolver.resolve('later.example')).outcome, 'not_found');
    dns.point('later.example', 'https://simon.later.example');
    assert.equal((await resolver.resolve('later.example')).outcome, 'not_found', 'cached');
    clock.advance(10 * 60_000);
    assert.equal((await resolver.resolve('later.example')).outcome, 'server');
  });

  it('reads a refused connection, a bad certificate and a redirect from the well-known host as not_found', async () => {
    const badCertificate = (net: FakeNet): Http => ({
      request: async r => {
        if (new URL(r.url).hostname === 'badcert.example') throw new Unreachable('certificate', 'not valid');
        return net.request(r);
      },
    });
    const { net, resolver, wellKnown } = setup(badCertificate);
    net.hosts.set('https://refused.example', 'down');
    wellKnown('moved.example', 301, {});
    wellKnown('badcert.example', 200, { server: 'https://simon.badcert.example' });
    assert.equal((await resolver.resolve('refused.example')).outcome, 'not_found');
    assert.equal((await resolver.resolve('moved.example')).outcome, 'not_found', 'a redirect is never followed');
    assert.equal((await resolver.resolve('badcert.example')).outcome, 'not_found');
  });
  it("gives a re-resolution's minute back only when the whole call made no lookup", async () => {
    const { clock, dns, resolver, store } = setup();
    dns.point('mover.example', 'https://simon.mover.example');
    const ctx = { store, now: clock.now, resolver } as unknown as Context;
    const taken = () => store.value('reresolve', 'mover.example', clock.now().toISOString());
    // The domain's resolution is made and paid; the server document's lookup is then refused by the payer.
    let charges = 0;
    const payer = () => {
      if (++charges > 1) throw rateLimited(60);
    };
    const lookup = () => resolver.peer('mover.example', payer, { fresh: true });
    await assert.rejects(reresolve(ctx, 'mover.example', lookup), { status: 429 });
    assert.equal(charges, 2);
    assert.notEqual(await taken(), null, 'a lookup was made, so the minute is spent');
    // Refused before any lookup: the minute is given back.
    clock.advance(61_000);
    charges = 1;
    await assert.rejects(reresolve(ctx, 'mover.example', lookup), { status: 429 });
    assert.equal(await taken(), null);
  });
});
