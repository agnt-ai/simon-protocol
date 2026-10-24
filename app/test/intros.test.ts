/** Introductions: double opt-in, sealed routing in waves, and nothing told to whoever should not know. */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { notices, strong, texts, World, type TestApp } from './harness.ts';

describe('introductions', async () => {
  const world = new World();
  after(() => world.close());
  const alpha: TestApp = await world.app('alpha');
  const route = async () => {
    world.clock.advance(2 * 60_000 + 5_000);
    await world.work();
  };

  /** Dana knows Bob; Bob, who carries for others, knows Alice and Dana; Alice takes introductions only. */
  async function triangle(tag: string) {
    const dana = await alpha.joined(`dana@${tag}.test`);
    const bob = await alpha.joined(`bob@${tag}.test`);
    const alice = await alpha.joined(`alice@${tag}.test`);
    await dana.approved.attest({ person: dana.person }, [{ field: 'name', value: 'Dana' }]);
    await alice.approved.updateListing({ contact: 'introduced_only' });
    await bob.approved.updateListing({ secondDegreeOptIn: true });
    await dana.approved.submitEdges([strong(`bob@${tag}.test`)]);
    await bob.approved.submitEdges([strong(`alice@${tag}.test`), strong(`dana@${tag}.test`)]);
    return { dana, bob, alice };
  }

  it('runs the double opt-in, then lets each write to the other; the carrier is not told the outcome', async () => {
    const { dana, bob, alice } = await triangle('i1');
    await dana.agent.send({ to: [alice.agent.address!], text: 'cold' });
    const req = await dana.api.requestIntro({
      target: 'mailto:alice@i1.test',
      brief: 'Dana builds agent protocols and would value 20 minutes.',
    });
    assert.equal(req.state, 'submitted');
    await route();
    assert.deepEqual(await texts(alice.agent), [], 'introductions only');
    const [ask] = await notices(bob.agent, 'intro-carry-request');
    assert.equal(ask.data.quoted.requesterName.text, 'Dana');
    assert.equal((await bob.api.home()).introsToAnswer?.length, 1);
    await bob.approved.carry(req.id, 'carry');
    await world.work();
    const [incoming] = (await alice.api.home()).introsToAnswer!;
    assert.deepEqual([incoming.role, (incoming as { introducedBy: string }).introducedBy], ['target', bob.person]);
    assert.equal(
      ((await dana.api.intro(req.id)) as { state: string }).state,
      'submitted',
      'the requester still sees nothing',
    );
    assert.equal((await alice.approved.respond(req.id, 'accept')).introducedTo, dana.agent.address);
    await world.work();
    const [made] = await notices(dana.agent, 'intro-made');
    assert.equal(made.data.to, alice.agent.address);
    assert.deepEqual(await notices(bob.agent, 'intro-made'), []);
    await dana.agent.send({ to: [alice.agent.address!], text: 'thanks for making time' });
    await world.work();
    assert.deepEqual(await texts(alice.agent), ['thanks for making time']);
    assert.equal(((await dana.api.intro(req.id)) as { state: string }).state, 'introduced');
  });

  it('never reaches a target who blocks the requester, whether the block came before routing or before carrying', async () => {
    const before = await triangle('i9');
    await before.alice.approved.addContacts('block', [{ kind: 'address', value: before.dana.agent.address! }]);
    await before.dana.api.requestIntro({ target: 'mailto:alice@i9.test', brief: 'I know where you live.' });
    await route();
    assert.deepEqual(await notices(before.bob.agent, 'intro-carry-request'), [], 'no carrier sees the brief');

    const during = await triangle('i10');
    const req = await during.dana.api.requestIntro({ target: 'mailto:alice@i10.test', brief: 'Hello again.' });
    await route();
    await during.alice.approved.addContacts('block', [{ kind: 'address', value: during.dana.agent.address! }]);
    await during.bob.approved.carry(req.id, 'carry');
    await world.work();
    assert.deepEqual((await during.alice.api.home()).introsToAnswer ?? [], [], 'the target is never asked');
    assert.deepEqual(await notices(during.alice.agent, 'intro-request'), []);
  });

  it("carries only through people whose own edge says they know the requester, never on the requester's word", async () => {
    const dana = await alpha.joined('dana@i11.test');
    const bob = await alpha.joined('bob@i11.test');
    const alice = await alpha.joined('alice@i11.test');
    await alice.approved.updateListing({ contact: 'introduced_only' });
    await bob.approved.updateListing({ secondDegreeOptIn: true });
    await dana.approved.submitEdges([strong('bob@i11.test')]);
    await bob.approved.submitEdges([strong('alice@i11.test')]);
    await dana.api.requestIntro({ target: 'mailto:alice@i11.test', brief: 'Bob knows me, honestly.' });
    await route();
    assert.deepEqual(await notices(bob.agent, 'intro-carry-request'), [], 'Bob never said he knows Dana');
  });

  it('looks the same to the requester whether declined, unroutable or never carried, until it expires', async () => {
    const { dana, bob, alice } = await triangle('i2');
    const reqs = [
      await dana.api.requestIntro({ target: 'mailto:alice@i2.test', brief: 'one' }),
      await dana.api.requestIntro({ target: 'mailto:nobody@i2.test', brief: 'two' }),
      await dana.api.requestIntro({ target: 'mailto:alice@i2.test', brief: 'three' }),
    ];
    await route();
    await bob.approved.carry(reqs[0].id, 'decline');
    await bob.approved.carry(reqs[2].id, 'carry');
    await alice.approved.respond(reqs[2].id, 'decline');
    for (const r of reqs) assert.deepEqual(await dana.api.intro(r.id), { ...r, state: 'submitted' });
    world.clock.advance(15 * 86_400_000);
    await world.work();
    for (const r of reqs) assert.equal(((await dana.api.intro(r.id)) as { state: string }).state, 'expired');
  });

  it("carries automatically when the carrier's person chose auto, and never through one who carries nothing", async () => {
    const auto = await triangle('i3');
    await auto.bob.approved.updateListing({ introCarrying: 'auto', introAutoMinGrade: 'strong' });
    await auto.dana.api.requestIntro({ target: 'mailto:alice@i3.test', brief: 'auto please' });
    const off = await triangle('i4');
    await off.bob.approved.updateListing({ introCarrying: 'never' });
    await off.dana.api.requestIntro({ target: 'mailto:alice@i4.test', brief: 'no route' });
    await route();
    assert.deepEqual(
      [(await auto.bob.api.home()).introsToAnswer, (await auto.alice.api.home()).introsToAnswer?.length],
      [[], 1],
    );
    assert.deepEqual(
      [(await off.bob.api.home()).introsToAnswer, (await off.alice.api.home()).introsToAnswer],
      [[], []],
    );
  });

  /** Dana knows five people who know Alice, at strengths 5, 4, 4, 3, 3. */
  async function fan(tag: string) {
    const dana = await alpha.joined(`dana@${tag}.test`);
    const alice = await alpha.joined(`alice@${tag}.test`);
    const carriers = [];
    for (const [n, strength] of [5, 4, 4, 3, 3].entries()) {
      const c = await alpha.joined(`c${n}@${tag}.test`);
      await c.approved.updateListing({ secondDegreeOptIn: true });
      await c.approved.submitEdges([{ identifier: `mailto:alice@${tag}.test`, strength }, strong(`dana@${tag}.test`)]);
      carriers.push(c);
    }
    await dana.approved.submitEdges(carriers.map((_, n) => strong(`c${n}@${tag}.test`)));
    const req = await dana.api.requestIntro({ target: `mailto:alice@${tag}.test`, brief: 'compare notes' });
    await route();
    return { dana, alice, carriers, req };
  }
  const asked = async (c: { api: { home(): Promise<{ introsToAnswer?: unknown[] }> } }) =>
    (await c.api.home()).introsToAnswer!.length;

  it('asks the strongest three first, the next wave when they decline, and the first yes withdraws the rest', async () => {
    const { alice, carriers, req } = await fan('w1');
    assert.deepEqual(await Promise.all(carriers.map(asked)), [1, 1, 1, 0, 0]);
    for (const c of carriers.slice(0, 3)) await c.approved.carry(req.id, 'decline');
    assert.deepEqual(await Promise.all(carriers.map(asked)), [0, 0, 0, 1, 1]);
    await carriers[3].approved.carry(req.id, 'carry');
    await world.work();
    assert.equal((await notices(carriers[4].agent, 'intro-withdrawn')).length, 1);
    await assert.rejects(carriers[4].approved.carry(req.id, 'carry'), { code: 'intro_decided' });
    assert.equal(
      ((await alice.api.home()).introsToAnswer![0] as { introducedBy: string }).introducedBy,
      carriers[3].person,
    );
  });

  it('opens the next wave after a quiet spell, and never tells carriers in a wave that did not open', async () => {
    const quiet = await fan('w2');
    world.clock.advance(24 * 3_600_000 + 1_000);
    await world.work();
    assert.deepEqual(await Promise.all(quiet.carriers.map(asked)), [1, 1, 1, 1, 1]);
    const early = await fan('w3');
    await early.carriers[0].approved.carry(early.req.id, 'carry');
    for (const c of early.carriers.slice(3)) {
      assert.deepEqual(await notices(c.agent, 'intro-carry-request'), []);
      await assert.rejects(c.approved.carry(early.req.id, 'carry'), { code: 'not_found' });
    }
  });

  it('lands a decline and a carry made at the same moment consistently', async () => {
    const { dana, bob } = await triangle('i5');
    const carol = await alpha.joined('carol@i5.test');
    await carol.approved.updateListing({ secondDegreeOptIn: true });
    await dana.approved.submitEdges([strong('carol@i5.test')]);
    await carol.approved.submitEdges([strong('alice@i5.test'), strong('dana@i5.test')]);
    const req = await dana.api.requestIntro({ target: 'mailto:alice@i5.test', brief: 'hello' });
    await route();
    const [carried, declined] = await Promise.allSettled([
      bob.approved.carry(req.id, 'carry'),
      carol.approved.carry(req.id, 'decline'),
    ]);
    assert.equal(carried.status, 'fulfilled');
    assert.equal(
      ((await carol.api.intro(req.id)) as { state: string }).state,
      declined.status === 'fulfilled' ? 'declined' : 'withdrawn',
    );
  });
});
