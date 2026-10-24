/**
 * Recipient policy: who an agent here takes messages from. A refusal is always silent: the sender's
 * answer is the same, and so is what it can observe afterwards.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { generateKey, signPairing } from '@agnt-sdk/simon-protocol';
import { Agent } from '@agnt-sdk/simon-client';
import { texts, World } from './harness.ts';

describe('recipient policy', async () => {
  const world = new World();
  after(() => world.close());
  const alpha = await world.app('alpha');
  const peer = await world.basic('beta');

  it('takes a first message from a stock server with no setting changed', async () => {
    const [bob, eve] = [await alpha.solo(), await peer.agent('eve')];
    await eve.send({ to: [bob.agent.address!], text: 'hello from elsewhere' });
    await world.work();
    assert.deepEqual(await texts(bob.agent), ['hello from elsewhere']);
    assert.deepEqual(await bob.api.policy(), { accept: 'anyone', requireVerifiedHuman: false });
  });

  it('refuses everyone else on accept known; an invite lets one message in; a block beats the invite', async () => {
    const [bob, ada, mal] = [await alpha.solo(), await alpha.solo(), await alpha.solo()];
    await bob.api.setPolicy({ accept: 'known' });
    await ada.agent.send({ to: [bob.agent.address!], text: 'refused' });
    const invited = { [bob.agent.address!]: { invite: (await bob.approved.invite()).code } };
    await ada.agent.send({ to: [bob.agent.address!], text: 'invited' }, { hints: invited });
    await world.work(); // in order: the second message comes after the code is used
    await ada.agent.send({ to: [bob.agent.address!], text: 'used up' }, { hints: invited });
    const second = await bob.approved.invite();
    await bob.api.addContacts('block', [{ kind: 'address', value: mal.agent.address! }]);
    await mal.agent.send(
      { to: [bob.agent.address!], text: 'blocked' },
      { hints: { [bob.agent.address!]: { invite: second.code } } },
    );
    await world.work();
    assert.deepEqual(await texts(bob.agent), ['invited']);
  });

  it('takes allowed addresses, domains with their subdomains, and servers; and removes an entry by its path', async () => {
    const [bob, ada, eve] = [await alpha.solo(), await alpha.solo(), await peer.agent('eve2')];
    await bob.api.setPolicy({ accept: 'known' });
    await bob.api.addContacts('allow', [
      { kind: 'address', value: ada.agent.address! },
      { kind: 'domain', value: 'beta.test' },
    ]);
    await ada.agent.send({ to: [bob.agent.address!], text: 'listed' });
    await eve.send({ to: [bob.agent.address!], text: 'domain listed' });
    await world.work();
    assert.deepEqual((await texts(bob.agent)).sort(), ['domain listed', 'listed']);
    await bob.api.removeContact('allow', 'domain', 'beta.test');
    assert.deepEqual(
      (await bob.api.contacts('allow')).items.map(e => e.value),
      [ada.agent.address],
    );
    await assert.rejects(bob.api.addContacts('allow', [{ kind: 'domain', value: 'not a domain' }]), {
      code: 'invalid',
    });
    await assert.rejects(bob.api.removeContact('allow', 'domain', 'beta.test'), {
      code: 'not_found',
      details: { what: 'entry' },
    });
  });

  it('takes replies from anyone the recipient wrote to, whatever its rule', async () => {
    const [bob, ada] = [await alpha.solo(), await alpha.solo()];
    await bob.api.setPolicy({ accept: 'known', requireVerifiedHuman: true });
    await ada.agent.send({ to: [bob.agent.address!], text: 'cold' });
    await world.work();
    const q = await bob.agent.send({ to: [ada.agent.address!], text: 'the deck?' });
    await world.work();
    await ada.agent.send({ to: [bob.agent.address!], text: 'here it is', inReplyTo: q.id });
    await world.work();
    assert.deepEqual(await texts(bob.agent), ['here it is']);
  });

  it('asks for a verified human only when told to: a trusted claim or a key pairing counts, a solo agent does not', async () => {
    const bob = await alpha.solo();
    await bob.api.setPolicy({ requireVerifiedHuman: true });
    const solo = await alpha.solo();
    const paired = await alpha.paired('vera@mail.test');
    const principal = generateKey();
    const forValue = `simon-key:${principal.key}`;
    const keyed = new Agent({
      server: alpha.origin,
      key: generateKey().privateKey,
      fetch: world.fetch,
      now: world.clock.now,
    });
    const pairing = signPairing(principal.privateKey, 'keyed@alpha.test', forValue);
    await keyed.register({ address: 'keyed@alpha.test', for: forValue, pairing });
    await solo.agent.send({ to: [bob.agent.address!], text: 'solo' });
    await paired.agent.send({ to: [bob.agent.address!], text: 'claimed' });
    await keyed.send({ to: [bob.agent.address!], text: 'keyed' });
    await world.work();
    assert.deepEqual((await texts(bob.agent)).sort(), ['claimed', 'keyed']);
  });

  it('counts held messages per sender, once each, and tells the sender nothing', async () => {
    const [bob, ada] = [await alpha.solo(), await alpha.solo()];
    await bob.api.setPolicy({ accept: 'known' });
    const one = await ada.agent.send({ to: [bob.agent.address!], text: 'one' });
    await ada.agent.send({ to: [bob.agent.address!], text: 'two' });
    await world.work();
    assert.equal((await ada.agent.sent(one.id)).servers[0].status, 'delivered');
    assert.deepEqual(
      (await bob.api.held()).items.map(h => [h.sender, h.count]),
      [[ada.agent.address, 2]],
    );
  });

  it("applies a person's own blocks on every agent that speaks for them, now and later", async () => {
    const first = await alpha.paired('owen@mail.test');
    const owner = await alpha.owner('owen@mail.test');
    const mal = await alpha.solo();
    await owner.block([{ kind: 'address', value: mal.agent.address! }]);
    const later = await alpha.paired('owen@mail.test');
    await mal.agent.send({ to: [first.agent.address!, later.agent.address!], text: 'blocked' });
    await world.work();
    assert.deepEqual([await texts(first.agent), await texts(later.agent)], [[], []]);
    assert.deepEqual(
      (await owner.held()).items.map(h => h.agent).sort(),
      [first.agent.address, later.agent.address].sort(),
    );
    await owner.unblock('address', mal.agent.address!);
    assert.deepEqual((await owner.blocks()).items, []);
  });

  it('holds first contacts past the daily limit, never counts correspondents, and offers the held ones the next day', async () => {
    const limited = await world.app('limits', { env: { SIMON_INBOUND_FIRST_CONTACTS: '2' } });
    const [bob, ada, o1, o2] = [await limited.solo(), await limited.solo(), await limited.solo(), await limited.solo()];
    await ada.agent.send({ to: [bob.agent.address!], text: '1' });
    await world.work();
    await o1.agent.send({ to: [bob.agent.address!], text: 'a' });
    await world.work();
    await o2.agent.send({ to: [bob.agent.address!], text: 'b' });
    await world.work();
    assert.deepEqual(await texts(bob.agent), ['1', 'a'], 'the third first contact of the day waits');
    await bob.agent.send({ to: [ada.agent.address!], text: 'more?' });
    await world.work();
    await ada.agent.send({ to: [bob.agent.address!], text: '2' });
    await world.work();
    assert.deepEqual(await texts(bob.agent), ['1', 'a', '2'], 'a correspondent is not a first contact');
    world.clock.advance(86_400_000);
    await world.work();
    assert.deepEqual(await texts(bob.agent), ['1', 'a', '2', 'b'], 'the next day, what waited is offered again');
  });

  it('runs every rule again on what waited: a block made meanwhile refuses it, and a spent limit holds it again', async () => {
    const limited = await world.app('limits-again', { env: { SIMON_INBOUND_FIRST_CONTACTS: '1' } });
    const [bob, o1, o2, o3, mal] = [
      await limited.solo(),
      await limited.solo(),
      await limited.solo(),
      await limited.solo(),
      await limited.solo(),
    ];
    for (const [from, text] of [
      [o1, 'a'],
      [mal, 'from mal'],
      [o2, 'b'],
      [o3, 'c'],
    ] as const) {
      await from.agent.send({ to: [bob.agent.address!], text });
      await world.work();
    }
    assert.deepEqual(await texts(bob.agent), ['a'], 'one first contact a day');
    await bob.api.addContacts('block', [{ kind: 'address', value: mal.agent.address! }]);
    world.clock.advance(86_400_000);
    await world.work();
    assert.deepEqual(await texts(bob.agent), ['a', 'b'], 'the block holds; of the rest, the limit takes one');
    world.clock.advance(86_400_000);
    await world.work();
    assert.deepEqual(await texts(bob.agent), ['a', 'b', 'c'], 'held again, not lost');
  });
});
