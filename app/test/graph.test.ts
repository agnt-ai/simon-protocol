/**
 * Visibility and the graph: only edges an asker cannot write itself widen what it sees; an edge is its
 * person's, one per identifier; a private note goes back to its owner and nobody else.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { strong, texts, World } from './harness.ts';

describe('visibility and the graph', async () => {
  const world = new World();
  after(() => world.close());
  const alpha = await world.app('alpha');
  const at = async (
    m: { api: { search: (q: { company: string[] }) => Promise<{ results: { person: string }[] }> } },
    company: string,
  ) => (await m.api.search({ company: [company] })).results.map(r => r.person);

  it("connections tier: the asker's own edge never widens; the target's does", async () => {
    const dana = await alpha.joined('dana@v1.test');
    const alice = await alpha.joined('alice@v1.test');
    await alice.approved.attest({ person: alice.person }, [
      { field: 'affiliation', affiliation: { domain: 'acme-v1.com', title: 'PM' } },
    ]);
    await alice.approved.updateListing({ discoverability: 'connections' });
    await dana.approved.submitEdges([strong('alice@v1.test')]);
    assert.deepEqual(await at(dana, 'acme-v1.com'), [], "the asker's edge does not widen anything");
    await alice.approved.submitEdges([strong('dana@v1.test')]);
    assert.deepEqual(await at(dana, 'acme-v1.com'), [alice.person]);
  });

  it('second degree needs an opted-in intermediary with its own edges on both legs, unhidden', async () => {
    const dana = await alpha.joined('dana@v2.test');
    const alice = await alpha.joined('alice@v2.test');
    const bob = await alpha.joined('bob@v2.test');
    await alice.approved.attest({ person: alice.person }, [
      { field: 'affiliation', affiliation: { domain: 'acme-v2.com' } },
    ]);
    await alice.approved.updateListing({ discoverability: 'second_degree' });
    await bob.approved.submitEdges([strong('alice@v2.test')]);
    await dana.approved.submitEdges([strong('bob@v2.test')]);
    assert.deepEqual(await at(dana, 'acme-v2.com'), []);
    await bob.approved.submitEdges([strong('dana@v2.test')]);
    assert.deepEqual(await at(dana, 'acme-v2.com'), [], 'not opted in');
    await bob.approved.updateListing({ secondDegreeOptIn: true });
    assert.deepEqual(await at(dana, 'acme-v2.com'), [alice.person]);
    const owner = await alpha.owner('bob@v2.test');
    const toAlice = (await owner.edges()).items.find(e => e.identifier === 'mailto:alice@v2.test')!;
    await owner.updateEdge(toAlice.id, { hidden: true });
    assert.deepEqual(await at(dana, 'acme-v2.com'), [], 'a hidden edge counts for nothing');
  });

  it('shows what was said about someone only to its author, until they join and confirm it', async () => {
    const dana = await alpha.joined('dana@v3.test');
    const mallory = await alpha.joined('mallory@v3.test');
    await dana.approved.attest({ identifier: 'mailto:carol@v3.test' }, [
      { field: 'name', value: 'Carol' },
      { field: 'affiliation', affiliation: { domain: 'netflix-v3.com', title: 'PM' } },
    ]);
    await dana.approved.submitEdges([strong('carol@v3.test')]);
    assert.deepEqual(await at(mallory, 'netflix-v3.com'), []);
    assert.deepEqual(await mallory.api.resolve('mailto:carol@v3.test'), { found: false });
    const [carol] = (await dana.api.graph()).connections;
    assert.deepEqual([carol.name, carol.person], ['Carol', null]);
    await mallory.approved.attest({ identifier: 'mailto:carol@v3.test' }, [
      { field: 'title', value: 'Mallory says hi' },
    ]);
    assert.ok((await dana.api.graph()).connections[0].facts.every(f => f.value !== 'Mallory says hi'));
    const joined = await alpha.joined('carol@v3.test');
    assert.deepEqual(await at(mallory, 'netflix-v3.com'), [], 'until she confirms it');
    const owner = await alpha.ownerOf('mailto:carol@v3.test');
    const said = (await owner.attestations('about')).items.find(a => a.field === 'affiliation')!;
    await owner.dispose(said.id, 'confirmed');
    assert.deepEqual(await at(mallory, 'netflix-v3.com'), [joined.person]);
  });

  it('resolves a person the asker may not see exactly like nobody', async () => {
    const dana = await alpha.joined('dana@v4.test');
    const hidden = await alpha.joined('hidden@v4.test');
    await hidden.approved.updateListing({ discoverability: 'private', contact: 'introduced_only' });
    assert.deepEqual(await dana.api.resolve('mailto:hidden@v4.test'), await dana.api.resolve('mailto:nobody@v4.test'));
    assert.deepEqual(await dana.api.reach('mailto:hidden@v4.test'), await dana.api.reach('mailto:nobody@v4.test'));
  });

  it("gates who may write by the recipient's person's contact tier, one recipient at a time", async () => {
    const dana = await alpha.joined('dana@v5.test');
    const alice = await alpha.joined('alice@v5.test');
    const mallory = await alpha.joined('mallory@v5.test');
    await alice.approved.updateListing({ contact: 'connections' });
    await alice.approved.submitEdges([strong('dana@v5.test')]);
    await mallory.agent.send({ to: [alice.agent.address!], text: 'from a stranger' });
    await dana.agent.send({ to: [alice.agent.address!], text: 'from a connection' });
    await mallory.agent.send({ to: [dana.agent.address!, alice.agent.address!], text: 'to both' });
    await world.work();
    assert.deepEqual(await texts(alice.agent), ['from a connection']);
    assert.deepEqual(await texts(dana.agent), ['to both']);
  });

  it('says nothing in reach of whether an introduction could reach someone, nor through whom', async () => {
    const dana = await alpha.joined('dana@v6.test');
    await alpha.joined('alice@v6.test').then(a => a.approved.updateListing({ contact: 'introduced_only' }));
    const bob = await alpha.joined('bob@v6.test');
    await bob.approved.updateListing({ secondDegreeOptIn: true });
    await dana.approved.submitEdges([strong('bob@v6.test'), strong('alice@v6.test')]);
    const reach = () => dana.api.reach('mailto:alice@v6.test');
    const alone = await reach();
    await bob.approved.submitEdges([strong('alice@v6.test'), strong('dana@v6.test')]);
    assert.deepEqual(await reach(), alone);
    assert.deepEqual(alone, { reachable: false, degree: 1, yourNote: { strength: 4, summary: null } });
  });

  it("keeps one edge per person and identifier, whichever agent wrote it; keeps the owner's hide; clears stale marks", async () => {
    const work = await alpha.joined('p@e1.test');
    const second = await alpha.paired('p@e1.test');
    await work.approved.submitEdges([
      { identifier: 'mailto:x@e1.test', strength: 4, summary: 'Worked together at Initech', introduceOk: false },
    ]);
    await second.approved.submitEdges([
      { identifier: 'mailto:x@e1.test', strength: 2 },
      { identifier: 'mailto:x-work@e1.test', strength: 3 },
    ]);
    const owner = await alpha.owner('p@e1.test');
    const edges = (await owner.edges()).items;
    const x = edges.find(e => e.identifier === 'mailto:x@e1.test')!;
    assert.equal(edges.length, 2, 'two identifiers stay two edges');
    assert.deepEqual(
      [x.strength, x.writtenBy, x.summary, x.introduceOk],
      [2, second.agent.address, 'Worked together at Initech', false],
    );
    await owner.updateEdge(x.id, { hidden: true });
    await work.approved.submitEdges([{ identifier: 'mailto:x@e1.test', strength: 5 }]);
    assert.equal((await owner.edges()).items.find(e => e.id === x.id)!.hidden, true);
    await assert.rejects(owner.clearEdges({}), { code: 'invalid' });
    assert.equal((await owner.clearEdges({ writtenBy: second.agent.address! })).removed, 1);
    assert.deepEqual(
      (await owner.edges()).items.map(e => e.identifier),
      ['mailto:x@e1.test'],
    );
  });

  it('caps what was not observed, refuses links, addresses and numbers in notes, and shows a note to its owner only', async () => {
    const a = await alpha.joined('a@n1.test');
    const b = await alpha.joined('b@n1.test');
    const c = await alpha.joined('c@n1.test');
    assert.equal(
      (await a.approved.submitEdges([{ identifier: 'mailto:b@n1.test', strength: 5, provenance: 'imported' }]))
        .results[0].strength,
      3,
    );
    for (const summary of ['see example.com', 'mail jane@example', 'call +1 415 555 0100', 'https://x']) {
      await assert.rejects(
        a.approved.submitEdges([{ identifier: 'mailto:b@n1.test', strength: 3, summary }]),
        { code: 'invalid' },
        summary,
      );
    }
    await b.approved.attest({ person: b.person }, [
      { field: 'affiliation', affiliation: { domain: 'initrode-n1.com' } },
    ]);
    const note = { strength: 4, summary: 'Used to work together at Initrode' };
    await a.approved.submitEdges([{ identifier: 'mailto:b@n1.test', ...note }]);
    assert.deepEqual((await a.api.search({ company: ['initrode-n1.com'] })).results[0].yourNote, note);
    assert.deepEqual((await a.api.reach('mailto:b@n1.test')).yourNote, note);
    for (const seen of [
      await c.api.search({ company: ['initrode-n1.com'] }),
      await c.api.profile(b.person),
      await (await alpha.owner('b@n1.test')).attestations(),
    ]) {
      assert.ok(!JSON.stringify(seen).includes(note.summary));
    }
  });
});
