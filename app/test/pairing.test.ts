/**
 * Pairing an agent with an email or phone principal through the core's verifyPrincipal hook, the acts-for
 * claim it earns, what a key recovery and the end of a pair do, and a person's several pairs together.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { CLOCK_PAIRING_UNTIL } from '@agnt-sdk/simon-server/testing';
import { generateKey, signPairing, signRecovery } from '@agnt-sdk/simon-protocol';
import { Agent, type Delivered } from '@agnt-sdk/simon-client';
import { AppAgent, pair } from '../src/client.ts';
import { received, World } from './harness.ts';

describe('pairing', async () => {
  const world = new World();
  after(() => world.close());
  const alpha = await world.app('alpha');
  const trusting = await world.basic('beta', { trustedClaimServers: [alpha.origin] });
  const wary = await world.basic('gamma');
  const bob = await trusting.agent('bob');
  const cy = await wary.agent('cy');

  it('sends a code naming the agent, its key and its scope, and pairs only with that code', async () => {
    const key = generateKey().privateKey;
    const agent = new Agent({ server: alpha.origin, key, fetch: world.fetch, now: world.clock.now });
    const sent = await pair(agent, { for: 'mailto:ada@mail.test', address: 'ada@alpha.test', scope: ['converse'] });
    assert.deepEqual(sent, {
      status: 'pairing_code_sent',
      address: 'ada@alpha.test',
      for: 'mailto:ada@mail.test',
      sentTo: 'mailto:a**@mail.test',
    });
    const mail = world.outbox.last('ada@mail.test')!;
    assert.match(mail.text, /Agent: ada@alpha\.test/);
    assert.match(mail.text, /It asks to: converse/);
    await assert.rejects(
      pair(agent, { for: 'mailto:ada@mail.test', address: 'ada@alpha.test', pairingCode: '000000' }),
      { code: 'wrong_code' },
    );
    const done = await pair(agent, {
      for: 'mailto:ada@mail.test',
      address: 'ada@alpha.test',
      pairingCode: world.outbox.code('ada@mail.test'),
    });
    assert.equal(done.address, 'ada@alpha.test');
    const me = await new AppAgent(
      new Agent({ server: alpha.origin, key, address: 'ada@alpha.test', fetch: world.fetch, now: world.clock.now }),
    ).me();
    assert.deepEqual([me.kind, me.principal], ['paired', 'mailto:ada@mail.test']);
  });

  it('accepts namespaced app pairing fields and ignores unprefixed extension fields', async () => {
    const blank = new Agent({
      server: alpha.origin,
      key: generateKey().privateKey,
      fetch: world.fetch,
      now: world.clock.now,
    });
    const body = { key: blank.key, address: 'prefixed@alpha.test', for: 'mailto:prefix@mail.test' };
    const pending = await blank.call<{ status: string }>('POST', '/simon/register', {
      ...body,
      pairingCode: 'ignored',
      scope: ['not-a-scope'],
    });
    assert.equal(pending.status, 'pairing_code_sent');
    assert.match(world.outbox.last('prefix@mail.test')!.text, /It asks to: converse, schedule/);
    await assert.rejects(blank.call('POST', '/simon/register', { ...body, 'agnt.ai:pairingCode': 5 }), {
      code: 'invalid',
      details: { field: 'agnt.ai:pairingCode' },
    });
    const done = await blank.call<{ address: string }>('POST', '/simon/register', {
      ...body,
      'agnt.ai:pairingCode': world.outbox.code('prefix@mail.test'),
    });
    assert.equal(done.address, body.address);
  });

  it('carries an acts-for claim to a server that trusts this one, and only there; replies come back', async () => {
    const ada = await alpha.paired('ann@mail.test', { scope: ['converse', 'schedule'] });
    const { id } = await ada.agent.send({ to: [bob.address!, cy.address!], text: 'lunch?' });
    await world.work();
    const [atBob] = (await received(bob)).messages;
    assert.equal(atBob.id, id);
    assert.deepEqual(atBob.claims, [
      {
        type: 'acts-for',
        agent: ada.agent.address,
        for: 'mailto:ann@mail.test',
        scope: ['converse', 'schedule'],
        verifiedAt: atBob.claims[0].verifiedAt,
        authoritative: false,
      },
    ]);
    assert.deepEqual((await received(cy)).messages[0].claims, [], 'a server that does not trust alpha shows no claim');

    await bob.send({ to: [ada.agent.address!], text: 'yes', inReplyTo: id });
    await world.work();
    const replies = (await received(ada.agent)).messages.filter((m: Delivered) => m.message.inReplyTo === id);
    assert.deepEqual(
      replies.map(r => r.message.parts[0]),
      [{ type: 'text/plain', data: 'yes' }],
    );
  });

  it('pairs a phone number by text message', async () => {
    const tel = await alpha.paired('tel:+15550101234');
    assert.equal((await tel.api.me()).principal, 'tel:+15550101234');
    assert.match(world.outbox.last('+15550101234')!.text, /^SIMON code \d{8} for agent/);
  });

  it('records a key principal as a person the first time it matters, with no code', async () => {
    const principal = generateKey();
    const forValue = `simon-key:${principal.key}`;
    const key = generateKey().privateKey;
    const agent = new Agent({ server: alpha.origin, key, fetch: world.fetch, now: world.clock.now });
    await agent.register({
      address: 'keyed@alpha.test',
      for: forValue,
      pairing: signPairing(principal.privateKey, 'keyed@alpha.test', forValue, CLOCK_PAIRING_UNTIL),
    });
    const home = await new AppAgent(agent).home();
    assert.equal(home.pair?.identifier, forValue);
  });

  it('leaves the pair whole when a key principal recovers its agent, its own act', async () => {
    const principal = generateKey();
    const forValue = `simon-key:${principal.key}`;
    const address = 'rooted@alpha.test';
    const agent = new Agent({
      server: alpha.origin,
      key: generateKey().privateKey,
      fetch: world.fetch,
      now: world.clock.now,
    });
    await agent.register({
      address,
      for: forValue,
      pairing: signPairing(principal.privateKey, address, forValue, CLOCK_PAIRING_UNTIL),
    });
    const key = generateKey().privateKey;
    const at = world.clock.now().toISOString();
    const fresh = new Agent({ server: alpha.origin, key, fetch: world.fetch, now: world.clock.now });
    const recover = signRecovery(principal.privateKey, address, fresh.key, at);
    await fresh.call('POST', '/simon/recovery', { key: fresh.key, address, at, recover });
    const recovered = new Agent({
      server: alpha.origin,
      key,
      address,
      for: forValue,
      fetch: world.fetch,
      now: world.clock.now,
    });
    const home = await new AppAgent(recovered).home();
    assert.equal(home.pair?.identifier, forValue);
    assert.equal((await new AppAgent(recovered).listing()).listed, false, 'not narrowed to conversing');
  });

  it('narrows a recovered agent to conversing until its person confirms by the link sent to them', async () => {
    world.dns.point('mail.alpha.test', alpha.origin);
    const box = 'box@mail.alpha.test';
    const agent = new Agent({
      server: alpha.origin,
      key: generateKey().privateKey,
      fetch: world.fetch,
      now: world.clock.now,
    });
    await pair(agent, { for: 'mailto:rex@mail.test', address: box });
    await pair(agent, { for: 'mailto:rex@mail.test', address: box, code: world.outbox.code(box) });
    await pair(agent, {
      for: 'mailto:rex@mail.test',
      address: box,
      code: world.outbox.code(box),
      pairingCode: world.outbox.code('rex@mail.test'),
    });

    // Whoever holds the mailbox takes the address with a new key; the person never approved them.
    const key = generateKey().privateKey;
    const holder = new Agent({ server: alpha.origin, key, fetch: world.fetch, now: world.clock.now });
    await holder.recover({ address: box });
    const code = world.outbox.code(box);
    await holder.recover({ address: box, code });
    assert.match(world.outbox.last(box)!.text, /cancel it with POST \/simon\/recovery\/cancel/);
    // The server waits before a mailbox takes an agent that still holds a key, then completes on a repeat.
    world.clock.advance(72 * 3600_000);
    await holder.recover({ address: box, code });
    const recovered = new Agent({
      server: alpha.origin,
      key,
      address: box,
      for: 'mailto:rex@mail.test',
      fetch: world.fetch,
      now: world.clock.now,
    });
    await assert.rejects(new AppAgent(recovered).listing(), { code: 'recovery_pending' });
    await recovered.send({ to: [bob.address!], text: 'it is me' });
    await world.work();
    const narrowed = (await received(bob)).messages.at(-1)!.claims[0];
    assert.deepEqual([narrowed.scope, typeof narrowed.recoveredAt], [['converse'], 'string']);

    const notice = world.outbox.last('rex@mail.test')!;
    assert.match(notice.text, /replaced its keys/);
    const link = /https:\/\/\S+\/api\/recovery\/\S+/.exec(notice.text)![0];
    assert.match(await (await world.fetch(link)).text(), /Yes, this is my agent/);
    assert.match(await (await world.fetch(`${link}/confirm`, { method: 'POST' })).text(), /Confirmed/);
    assert.equal((await world.fetch(link)).status, 404, 'the link works once');
    assert.equal((await new AppAgent(recovered).listing()).listed, false);
  });

  it('shows a person their several pairs together, and ending one retires its address', async () => {
    const work = await alpha.paired('pat@work.test');
    const home = await alpha.paired('pat@home.test');
    const owner = await alpha.owner('pat@work.test');
    assert.deepEqual(
      (await owner.agents()).items.map(a => a.pair.address),
      [work.agent.address],
    );
    await owner.addIdentifier('mailto:pat@home.test');
    await assert.rejects(owner.verifyIdentifier('mailto:pat@home.test', world.outbox.code('pat@home.test')), {
      code: 'merge_required',
    });
    await owner.mergeIdentifier('mailto:pat@home.test');
    const both = (await owner.agents()).items.map(a => a.pair.address).sort();
    assert.deepEqual(both, [work.agent.address, home.agent.address].sort());

    await owner.endAgent(home.agent.address!);
    assert.deepEqual(
      (await owner.agents()).items.map(a => a.pair.address),
      [work.agent.address],
    );
    await assert.rejects(received(home.agent), { status: 401 });
    const again = new Agent({
      server: alpha.origin,
      key: generateKey().privateKey,
      fetch: world.fetch,
      now: world.clock.now,
    });
    const mailed = world.outbox.sent.length;
    await assert.rejects(pair(again, { for: 'mailto:pat@home.test', address: home.agent.address! }), {
      code: 'address_taken',
    });
    assert.equal(world.outbox.sent.length, mailed, 'no code is sent for a retired address');
  });

  it('sends no pairing code for an address another agent holds', async () => {
    const held = await alpha.paired('hal@mail.test');
    const mailed = world.outbox.sent.length;
    const agent = new Agent({
      server: alpha.origin,
      key: generateKey().privateKey,
      fetch: world.fetch,
      now: world.clock.now,
    });
    await assert.rejects(pair(agent, { for: 'mailto:ivy@mail.test', address: held.agent.address! }), {
      code: 'address_taken',
    });
    assert.equal(world.outbox.sent.length, mailed, 'no code reached ivy');
  });
});
