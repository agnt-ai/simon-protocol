/**
 * Privacy: what the directory, the graph and the owner window reveal, and to whom, and what is kept and
 * for how long. Each test is a demonstration of a leak, turned around. The tests that move the
 * clock come last.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { sha256Hex } from '@agnt-protocol/protocol';
import type { Db, Filter } from 'mongodb';
import { AppOwner } from '../src/client.ts';
import { received, notices, strong, texts, World } from './harness.ts';

const DAY = 86_400_000;

type Doc = { _id: string } & Record<string, unknown>;

/** The collections of `db` holding a document that matches, among those named. */
async function holding(db: Db, where: Record<string, Filter<Doc>>): Promise<string[]> {
  const found = await Promise.all(
    Object.entries(where).map(async ([name, filter]) =>
      (await db.collection<Doc>(name).countDocuments(filter)) ? name : null,
    ),
  );
  return found.filter(n => n !== null);
}

/** The collections outside the server's own `core.*`, and the person's own log, that mention `text`. */
async function mentioning(db: Db, text: string): Promise<string[]> {
  const names = (await db.listCollections().toArray())
    .map(c => c.name)
    .filter(n => !n.startsWith('core.') && n !== 'owner.activity');
  const found = await Promise.all(
    names.map(async n =>
      (await db.collection(n).find().toArray()).some(d => JSON.stringify(d).includes(text)) ? n : null,
    ),
  );
  return found.filter(n => n !== null);
}

describe('privacy', async () => {
  const world = new World();
  after(() => world.close());
  const alpha = await world.app('alpha');

  it('never resolves an unlisted person for anyone but their connections, nor shows a card before it is published', async () => {
    const quiet = await alpha.joined('quiet@p1.test', { list: false });
    await quiet.api.updateMe({ name: 'Quiet Q', description: 'private assistant' });
    const stranger = await alpha.solo();
    assert.deepEqual(await stranger.api.resolve('mailto:quiet@p1.test'), { found: false });
    assert.deepEqual(
      await stranger.api.reach('mailto:quiet@p1.test'),
      await stranger.api.reach('mailto:nobody@p1.test'),
    );
    assert.equal((await quiet.api.listing()).contact, 'connections', 'until listed, only connections may write');
    await stranger.agent.send({ to: [quiet.agent.address!], text: 'hello stranger' });
    await world.work();
    assert.deepEqual(await texts(quiet.agent), []);

    const friend = await alpha.joined('friend@p1.test');
    await quiet.approved.submitEdges([strong('friend@p1.test')]);
    const found = await friend.api.resolve('mailto:quiet@p1.test');
    assert.deepEqual(
      [found.found, found.profile, found.agents],
      [true, null, [{ address: quiet.agent.address, card: null }]],
    );
    await quiet.approved.publishCard(true);
    const [shown] = (await friend.api.resolve('mailto:quiet@p1.test')).agents!;
    assert.deepEqual(Object.keys(shown).sort(), ['address', 'card'], 'no keys, no creation date');
    assert.equal(shown.card?.name, 'Quiet Q');
  });

  it("tells an asker nothing from the target's own edges: no mutuality, and a degree from the asker's edges", async () => {
    const asker = await alpha.joined('asker@p2.test');
    await alpha.joined('t@p2.test').then(t => t.approved.submitEdges([strong('asker@p2.test')]));
    assert.deepEqual((await asker.api.resolve('mailto:t@p2.test')).relationship, { grade: 'none', degree: null });
    await asker.approved.submitEdges([strong('t@p2.test')]);
    assert.deepEqual((await asker.api.resolve('mailto:t@p2.test')).relationship, { grade: 'strong', degree: 1 });

    const x = await alpha.joined('x@p2.test');
    await x.approved.submitEdges([strong('far@p2.test')]);
    await alpha.joined('far@p2.test');
    await asker.approved.submitEdges([strong('x@p2.test')]);
    assert.equal((await asker.api.resolve('mailto:far@p2.test')).relationship!.degree, null, 'x never opted in');
    assert.equal((await x.api.listing()).secondDegreeOptIn, false, 'listing does not opt anyone in');
    await (await alpha.ownerOf('mailto:x@p2.test')).updateListing({ secondDegreeOptIn: true });
    assert.equal((await asker.api.resolve('mailto:far@p2.test')).relationship!.degree, 2);
  });

  it('lets others say only a name, title or affiliation, shown once its subject confirms it, who is told on claiming', async () => {
    const gossip = await alpha.joined('gossip@p3.test');
    for (const field of ['location', 'bio'] as const) {
      await assert.rejects(
        gossip.approved.attest({ identifier: 'mailto:newbie@p3.test' }, [{ field, value: '12 Elm St, in rehab' }]),
        { code: 'invalid' },
      );
    }
    await gossip.approved.attest({ identifier: 'mailto:newbie@p3.test' }, [
      { field: 'title', value: 'Rehab counsellor' },
    ]);
    const newbie = await alpha.joined('newbie@p3.test');
    const reader = await alpha.solo();
    assert.deepEqual((await reader.api.profile(newbie.person)).facts, []);
    assert.deepEqual((await reader.api.search({ title: 'rehab' })).results, []);

    const owner = await alpha.ownerOf('mailto:newbie@p3.test');
    assert.ok((await owner.activity()).items.some(e => e.kind === 'attestations_to_review' && e.data?.count === 1));
    assert.ok((await newbie.api.home()).attention.some(a => a.kind === 'attestations_to_review'));
    const [said] = (await owner.attestations('about')).items;
    assert.equal(said.disposition, 'pending');
    await owner.dispose(said.id, 'confirmed');
    assert.deepEqual(
      (await reader.api.profile(newbie.person)).facts.map(f => f.value),
      ['Rehab counsellor'],
    );
  });

  it('shows an owner session only what belongs to the identifiers proven in it', async () => {
    const work = await alpha.joined('work@p4.test');
    await work.approved.submitEdges([
      { identifier: 'mailto:doctor@p4.test', strength: 4, summary: 'Oncologist, weekly' },
    ]);
    const owner = await alpha.ownerOf('mailto:work@p4.test');
    await owner.addIdentifier('mailto:old-shared@p4.test');
    await owner.verifyIdentifier('mailto:old-shared@p4.test', world.outbox.code('old-shared@p4.test'));
    assert.equal((await owner.edges()).items.length, 1);

    // Later, whoever holds the shared inbox signs in by it.
    const other = await alpha.owner('old-shared@p4.test');
    assert.deepEqual((await other.edges()).items, []);
    assert.deepEqual((await other.agents()).items, []);
    assert.deepEqual(
      (await other.me()).identifiers.map(i => i.identifier),
      ['mailto:old-shared@p4.test'],
    );
    const log = JSON.stringify((await other.activity({ limit: 200 })).items);
    assert.ok(!log.includes(work.agent.address!) && !log.includes('work@p4.test'));
    await assert.rejects(other.erase(), { code: 'prove_every_identifier' });
  });

  it('gives a recycled inbox, proven again after a year, a person of its own: never the whole person it left', async () => {
    const vic = await alpha.joined('vic@work11.test');
    const vicOwner = await alpha.ownerOf('mailto:vic@work11.test');
    await vicOwner.addIdentifier('mailto:vic.old@mail11.test');
    await vicOwner.verifyIdentifier('mailto:vic.old@mail11.test', world.outbox.code('vic.old@mail11.test'));
    await vicOwner.updateListing({ contact: 'introduced_only' });
    await vicOwner.block([{ kind: 'address', value: 'stalker@evil11.test' }]);

    // Over a year later the old inbox has a new holder, who proves it by the code it receives.
    world.clock.advance(400 * DAY);
    const intruder = await alpha.owner('vic.old@mail11.test');
    assert.deepEqual((await intruder.blocks()).items, [], "the new holder sees none of Vic's blocks");
    await intruder.updateListing({ contact: 'anyone' });
    const agent = await alpha.paired('vic.old@mail11.test');
    assert.notEqual((await agent.api.home()).pair!.person, vic.person, 'an agent it pairs speaks for its own person');
    await assert.rejects(
      agent.api.requestIntro({ target: 'mailto:x@p11.test', brief: 'hi', presentAs: 'mailto:vic@work11.test' }),
      { code: 'invalid' },
    );

    // Vic, signing in by work email, still has the listing and the block, and is told what was released.
    const back = await alpha.owner('vic@work11.test');
    assert.equal((await back.listing()).contact, 'introduced_only');
    assert.deepEqual(
      (await back.blocks()).items.map(e => e.value),
      ['stalker@evil11.test'],
    );
    const log = JSON.stringify((await back.activity({ limit: 200 })).items);
    assert.ok(log.includes('identifier_released'));
  });

  it("never joins a recycled inbox, proven in another person's session, to the whole person it left", async () => {
    const vic = await alpha.joined('vic@work14.test');
    const vicOwner = await alpha.ownerOf('mailto:vic@work14.test');
    await vicOwner.addIdentifier('mailto:vic.old@mail14.test');
    await vicOwner.verifyIdentifier('mailto:vic.old@mail14.test', world.outbox.code('vic.old@mail14.test'));
    await vicOwner.block([{ kind: 'address', value: 'stalker@evil14.test' }]);

    world.clock.advance(400 * DAY);
    // The new holder of the old inbox, signed in as someone else, proves it and confirms the join.
    const intruder = await alpha.owner('mallory@own14.test');
    await intruder.addIdentifier('mailto:vic.old@mail14.test');
    await assert.rejects(
      intruder.verifyIdentifier('mailto:vic.old@mail14.test', world.outbox.code('vic.old@mail14.test')),
      { code: 'merge_required' },
    );
    await intruder.mergeIdentifier('mailto:vic.old@mail14.test');
    assert.ok(!(await intruder.agents()).items.some(i => i.pair.address === vic.agent.address));
    assert.deepEqual((await intruder.blocks()).items, [], "none of Vic's blocks join the intruder");

    // Vic still has his agent and his block.
    const back = await alpha.owner('vic@work14.test');
    assert.ok((await back.agents()).items.some(i => i.pair.address === vic.agent.address));
    assert.deepEqual(
      (await back.blocks()).items.map(e => e.value),
      ['stalker@evil14.test'],
    );
  });

  it('keeps a stale identifier with its person when a session of that person proves it again', async () => {
    await alpha.joined('wes@work15.test');
    const wes = await alpha.ownerOf('mailto:wes@work15.test');
    await wes.addIdentifier('mailto:wes.old@mail15.test');
    await wes.verifyIdentifier('mailto:wes.old@mail15.test', world.outbox.code('wes.old@mail15.test'));
    world.clock.advance(200 * DAY);
    await alpha.owner('wes@work15.test');
    world.clock.advance(200 * DAY);
    const again = await alpha.owner('wes@work15.test');
    await again.addIdentifier('mailto:wes.old@mail15.test');
    const me = await again.verifyIdentifier('mailto:wes.old@mail15.test', world.outbox.code('wes.old@mail15.test'));
    assert.ok(me.identifiers.some(i => i.identifier === 'mailto:wes.old@mail15.test'));
  });

  it('joins two people only when a session signed in as one proves the other and confirms', async () => {
    const a = await alpha.joined('a@p5.test');
    const b = await alpha.joined('b@p5.test');
    const owner = await alpha.owner('a@p5.test');
    const agents = async () => (await owner.agents()).items.map(i => i.pair.address).sort();
    await owner.addIdentifier('mailto:b@p5.test');
    await assert.rejects(owner.verifyIdentifier('mailto:b@p5.test', world.outbox.code('b@p5.test')), {
      code: 'merge_required',
    });
    assert.deepEqual(await agents(), [a.agent.address]);
    await owner.mergeIdentifier('mailto:b@p5.test');
    assert.deepEqual(await agents(), [a.agent.address, b.agent.address].sort());
    await assert.rejects(owner.mergeIdentifier('mailto:b@p5.test'), { code: 'proof_required' });
  });

  it('signs a key principal in to the owner window by its signature over a challenge', async () => {
    const keyed = await alpha.keyed();
    const owner = await alpha.ownerOf(keyed.principal);
    assert.deepEqual(
      (await owner.agents()).items.map(i => i.pair.address),
      [keyed.agent.address],
    );
    const login = await world.fetch(`${alpha.origin}/api/oauth/authorize?${await authorizeQuery()}`);
    const page = login.headers.get('location')!;
    const form = (body: Record<string, string>) => ({
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body).toString(),
    });
    const asked = await world.fetch(`${alpha.origin}${page}/identifier`, form({ identifier: keyed.principal }));
    assert.match(await asked.text(), /SIMON-APP-SIGN-IN/);
    const forged = await world.fetch(`${alpha.origin}${page}/signature`, form({ signature: 'AAAA' }));
    assert.equal(forged.status, 400);
    assert.match(await forged.text(), /does not verify/);
  });

  /** An authorization request from a freshly registered client. */
  async function authorizeQuery() {
    const client = await (
      await world.fetch(`${alpha.origin}/api/oauth/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ redirect_uris: ['https://portal.example.com/cb'] }),
      })
    ).json();
    return new URLSearchParams({
      response_type: 'code',
      client_id: client.client_id,
      redirect_uri: 'https://portal.example.com/cb',
      code_challenge: 'x'.repeat(43),
      code_challenge_method: 'S256',
    });
  }

  it('routes an introduction only to someone who joined and listed themselves, and never says whether one could', async () => {
    const dana = await alpha.joined('dana@p6.test');
    const bob = await alpha.joined('bob@p6.test');
    const quiet = await alpha.joined('quiet@p6.test', { list: false });
    await (await alpha.ownerOf('mailto:bob@p6.test')).updateListing({ secondDegreeOptIn: true });
    await dana.approved.submitEdges([strong('bob@p6.test')]);
    await bob.approved.submitEdges([strong('quiet@p6.test'), strong('dana@p6.test')]);
    assert.ok(!('introRoute' in (await dana.api.reach('mailto:quiet@p6.test'))));
    await dana.api.requestIntro({ target: 'mailto:quiet@p6.test', brief: 'Would like to meet.' });
    world.clock.advance(2 * 60_000 + 5_000);
    await world.work();
    assert.deepEqual(await notices(bob.agent, 'intro-carry-request'), [], 'nobody is asked about the unlisted');
    await (await alpha.ownerOf('mailto:quiet@p6.test')).updateListing({ listed: true });
    await dana.api.requestIntro({ target: 'mailto:quiet@p6.test', brief: 'Would like to meet.' });
    world.clock.advance(2 * 60_000 + 5_000);
    await world.work();
    assert.equal((await notices(bob.agent, 'intro-carry-request')).length, 1);
    assert.deepEqual(await texts(quiet.agent), []);
  });

  it('erases a person: identifiers, agents, the graph to and from them, what was said by and about them, introductions, their log', async () => {
    const gone = await alpha.joined('gone@p7.test');
    const friend = await alpha.joined('friend@p7.test');
    await gone.approved.submitEdges([strong('friend@p7.test')]);
    await friend.approved.submitEdges([strong('gone@p7.test')]);
    await friend.approved.attest({ person: gone.person }, [{ field: 'name', value: 'Gone G' }]);
    await gone.approved.attest({ person: friend.person }, [{ field: 'name', value: 'Friend F' }]);
    await gone.api.requestIntro({ target: 'mailto:friend@p7.test', brief: 'hello' });
    await (await alpha.owner('gone@p7.test')).erase();

    await assert.rejects(received(gone.agent), { status: 401 });
    const person = gone.person;
    assert.deepEqual(
      await holding(alpha.db, {
        'directory.people': { _id: person },
        'directory.identifiers': { $or: [{ person }, { _id: 'mailto:gone@p7.test' }] },
        'directory.pairings': { person },
        'directory.edges': { $or: [{ from: person }, { to: person }] },
        'directory.attestations': { $or: [{ subject: person }, { authorPrincipal: person }] },
        'intros.requests': { requesterPerson: person },
        'owner.activity': { person },
        'owner.tokens': { person },
        'owner.requests': { agent: gone.agent.address! },
        'agents.cards': { _id: gone.agent.address! },
      }),
      [],
    );
    assert.deepEqual((await friend.api.graph()).connections, []);
  });

  it('keeps only a hash of a retired agent where its records outlive it', async () => {
    const leaving = await alpha.joined('leaving@p8.test');
    const address = leaving.agent.address!;
    await leaving.approved.submitEdges([strong('someone@p8.test')]);
    await leaving.approved.setPolicy({ accept: 'known' });
    await leaving.api.updateMe({ name: 'Leaving' });
    await leaving.approved.end();
    assert.deepEqual(await mentioning(alpha.db, address), []);
    const [edge] = (await (await alpha.ownerOf('mailto:leaving@p8.test')).edges()).items;
    assert.equal(edge.writtenBy, `retired:${sha256Hex(address)}`);
  });

  it('leaves no raw address of a retired agent once the work it set off has settled, introductions included', async () => {
    const dana = await alpha.joined('dana@p12.test');
    const bob = await alpha.joined('bob@p12.test');
    const alice = await alpha.joined('alice@p12.test');
    await alice.approved.updateListing({ contact: 'introduced_only' });
    await bob.approved.updateListing({ secondDegreeOptIn: true });
    await dana.approved.submitEdges([strong('bob@p12.test')]);
    await bob.approved.submitEdges([strong('alice@p12.test'), strong('dana@p12.test')]);
    const req = await dana.api.requestIntro({ target: 'mailto:alice@p12.test', brief: 'hello' });
    world.clock.advance(2 * 60_000 + 5_000);
    await world.work();
    await bob.approved.carry(req.id, 'carry');
    await world.work();
    await alice.approved.respond(req.id, 'accept');
    await world.work();
    const address = dana.agent.address!;
    await dana.approved.end();
    await world.work();
    assert.deepEqual(await mentioning(alpha.db, address), []);
  });

  it("forgets an erased person's sign-ins with the rest", async () => {
    const gone = await alpha.joined('gone@p13.test');
    await (await alpha.owner('gone@p13.test')).erase();
    await world.work();
    assert.equal(await alpha.db.collection('owner.logins').countDocuments({ person: gone.person }), 0);
  });

  it('forgets bridge replies after 30 days, unconfirmed attestations and unclaimed people after 90, edges after a year', async () => {
    const ann = await alpha.paired('ann@p9.test');
    await ann.agent.send({ to: ['carl@mail.example'], text: 'Lunch?' });
    const keeper = await alpha.joined('keeper@p9.test');
    await keeper.approved.submitEdges([strong('member@p9.test')]);
    await alpha.joined('member@p9.test');
    await keeper.approved.attest({ identifier: 'mailto:shadow@p9.test' }, [{ field: 'name', value: 'Shadow' }]);
    await world.work();
    const replies = () => alpha.db.collection('bridge.replies').countDocuments({ author: ann.agent.address! });
    const shadow = () =>
      alpha.db.collection<Doc>('directory.identifiers').countDocuments({ _id: 'mailto:shadow@p9.test' });
    const edges = async () => (await (await alpha.ownerOf('mailto:keeper@p9.test')).edges()).items.length;
    assert.deepEqual([await replies(), await shadow(), await edges()], [1, 1, 1]);

    world.clock.advance(31 * DAY);
    await world.work();
    assert.deepEqual([await replies(), await shadow()], [0, 1]);
    world.clock.advance(60 * DAY);
    await world.work();
    assert.deepEqual([await shadow(), await edges()], [0, 1]);
    assert.deepEqual(
      await holding(alpha.db, { 'directory.attestations': { authorPrincipal: keeper.person } }),
      [],
      'what nobody confirmed is gone',
    );
    world.clock.advance(275 * DAY);
    await world.work();
    assert.equal(await edges(), 0, 'an edge nobody rewrote in a year is gone');
  });

  it('asks an identifier proven more than a year ago to be proven again before it grants anything', async () => {
    await alpha.joined('stale@p10.test');
    const { key } = await (await alpha.owner('stale@p10.test')).createApiKey('nightly');
    const script = new AppOwner({ server: alpha.origin, token: key, fetch: world.fetch });
    assert.equal((await script.me()).identifiers.length, 1);
    world.clock.advance(366 * DAY);
    await assert.rejects(script.me(), { code: 'reverify_required' });
    await alpha.owner('stale@p10.test');
    assert.equal((await script.me()).identifiers.length, 1, 'signing in proved it again');
  });
});
