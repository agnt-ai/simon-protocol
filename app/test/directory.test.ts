/** The directory: search and provenance, entities, the rubric, and its limits. */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { grade } from '../../skill/grade.js';
import { World } from './harness.ts';

describe('the directory', async () => {
  const world = new World();
  after(() => world.close());
  const alpha = await world.app('alpha');

  it('publishes one rubric agents run themselves: 1 to 5, decaying with recency, capping what was not observed', () => {
    assert.equal(grade({}), 0);
    assert.equal(grade({ threads: '10-49', lastTouch: '90d' }), 4);
    assert.equal(grade({ threads: '10-49', lastTouch: 'older' }), 2);
    assert.equal(grade({ threads: '50+', lastTouch: '30d', provenance: 'imported' }), 3);
  });

  it("tells a stranger nothing about the subject's verified domains through the stranger's own pending fact", async () => {
    const ada = await alpha.joined('ada@acme-d9.com');
    const stranger = await alpha.joined('stranger@else-d9.test');
    await stranger.approved.attest({ person: ada.person }, [
      { field: 'affiliation', affiliation: { domain: 'acme-d9.com', title: 'Engineer' } },
    ]);
    const mine = (await stranger.api.profile(ada.person)).facts.find(f => f.field === 'affiliation');
    assert.ok(mine, 'the writer sees its own pending fact');
    assert.notEqual(mine.provenance, 'domain_verified');
  });

  it('searches by facet and reports provenance: domain verified, and corroborated at three domains', async () => {
    const asker = await alpha.joined('asker@d1.test');
    const ada = await alpha.joined('ada@acme-d1.com');
    await ada.approved.attest({ person: ada.person }, [
      { field: 'name', value: 'Ada' },
      { field: 'title', value: 'Head of Product' },
      { field: 'location', value: 'Lisbon' },
      { field: 'affiliation', affiliation: { domain: 'acme-d1.com', title: 'Head of Product' } },
      { field: 'interest', value: 'agent protocols' },
    ]);
    const [hit] = (await asker.api.search({ company: ['acme-d1.com'] })).results;
    assert.equal(hit.matched.find(m => m.field === 'affiliation')!.provenance, 'domain_verified');
    assert.equal((await asker.api.search({ title: 'product', location: 'lisbon' })).results.length, 1);
    assert.equal((await asker.api.search({ title: 'product', location: 'porto' })).results.length, 0);
    assert.equal((await asker.api.search({ text: 'agent protocols' })).results[0].name, 'Ada');
    for (const w of ['w1', 'w2', 'w3']) {
      const writer = await alpha.joined(`writer@${w}-d1.com`);
      await writer.approved.attest({ person: ada.person }, [{ field: 'title', value: 'Pricing lead' }]);
    }
    const owner = await alpha.ownerOf('mailto:ada@acme-d1.com');
    for (const a of (await owner.attestations('about')).items.filter(x => x.disposition === 'pending'))
      await owner.dispose(a.id, 'confirmed');
    assert.equal(
      (await asker.api.profile(ada.person)).facts.find(f => f.value === 'Pricing lead')?.provenance,
      'corroborated',
    );
    await assert.rejects(
      asker.api.attest({ person: ada.person }, [{ field: 'skill', value: 'All', provenance: 'corroborated' as never }]),
      {
        code: 'invalid',
      },
    );
  });

  it('never lists unlisted people, and an agent speaking for no one writes as itself', async () => {
    const asker = await alpha.joined('asker@d2.test');
    const quiet = await alpha.joined('quiet@d2.test', { list: false });
    await quiet.approved.attest({ person: quiet.person }, [
      { field: 'affiliation', affiliation: { domain: 'quiet-d2.com' } },
    ]);
    assert.equal((await asker.api.search({ company: ['quiet-d2.com'] })).results.length, 0);
    const solo = await alpha.solo();
    await assert.rejects(solo.api.listing(), { code: 'not_paired' });
    assert.equal(
      (await solo.approved.submitEdges([{ identifier: 'mailto:x@d2.test', strength: 2 }])).results[0].status,
      'stored',
    );
  });

  it('finds companies by domain, never from consumer mail', async () => {
    const a = await alpha.joined('a@d3.test');
    const e1 = await a.api.resolveEntity({ domain: 'https://www.Initech-D3.com/about' });
    assert.equal((await a.api.resolveEntity({ domain: 'initech-d3.com' })).id, e1.id);
    assert.equal(e1.name, 'Initech-d3');
    await assert.rejects(a.api.resolveEntity({ domain: 'gmail.com' }), { code: 'freemail_domain' });
    assert.equal((await a.api.resolveEntity({ domain: 'state-d3.edu' })).kind, 'school');
    await assert.rejects(a.api.entity('ent_01J9ZQ3W5Y8K2M4N6P8R0T2V4X'), {
      code: 'not_found',
      details: { what: 'entity' },
    });
  });

  it('lets an organisation claim its entity by DNS, name it, and attest its roster, which each member confirms', async () => {
    const admin = await alpha.joined('admin@globex-d4.com');
    const member = await alpha.joined('member@globex-d4.com');
    const outside = await alpha.joined('contractor@d4.test');
    const asker = await alpha.joined('asker@d4.test');
    const entity = await admin.api.resolveEntity({ domain: 'globex-d4.com' });
    const challenge = await admin.api.startEntityClaim(entity.id, 'globex-d4.com');
    await assert.rejects(admin.api.completeEntityClaim(entity.id), { code: 'challenge_not_found' });
    world.dns.records.set(challenge.record, [[challenge.value]]);
    assert.equal((await admin.api.completeEntityClaim(entity.id)).claimed, true);
    await admin.approved.attestRoster(entity.id, [
      { identifier: 'mailto:member@globex-d4.com', title: 'Engineer' },
      { identifier: 'mailto:contractor@d4.test', title: 'Contractor' },
    ]);
    assert.deepEqual((await asker.api.search({ company: ['globex-d4.com'] })).results, [], 'until each confirms');
    for (const who of ['member@globex-d4.com', 'contractor@d4.test']) {
      const owner = await alpha.ownerOf(`mailto:${who}`);
      for (const a of (await owner.attestations('about')).items) await owner.dispose(a.id, 'confirmed');
    }
    const results = (await asker.api.search({ company: ['globex-d4.com'] })).results;
    assert.ok(results.find(r => r.person === member.person)!.matched.some(m => m.provenance !== 'imported'));
    assert.ok(results.find(r => r.person === outside.person)!.matched.every(m => m.provenance === 'imported'));
    await admin.api.renameEntity(entity.id, { name: 'Globex Corporation', aliases: ['Globex'] });
    assert.ok((await asker.api.search({ company: ['globex'] })).results.some(r => r.person === member.person));
    await assert.rejects(asker.api.renameEntity(entity.id, { name: 'Hijacked' }), { code: 'not_entity_owner' });
    await assert.rejects(admin.api.renameEntity(entity.id, { name: 'globex.com' }), { code: 'invalid' });
  });

  it('answers "who do I know at X" from the asker\'s own edges, with its own note', async () => {
    const me = await alpha.joined('me@d5.test');
    const co = await alpha.joined('co@hooli-d5.com');
    await co.approved.attest({ person: co.person }, [
      { field: 'affiliation', affiliation: { domain: 'hooli-d5.com', title: 'Designer' } },
    ]);
    await me.approved.submitEdges([
      { identifier: 'mailto:co@hooli-d5.com', strength: 3, summary: 'Worked together at Hooli, still in touch' },
    ]);
    const [c] = (await me.api.graph({ company: ['hooli-d5.com'] })).connections;
    assert.deepEqual(
      [c.grade, c.yourNote, c.identifiers],
      ['working', { strength: 3, summary: 'Worked together at Hooli, still in touch' }, ['mailto:co@hooli-d5.com']],
    );
  });

  it('limits discovery per agent, and says when to retry', async () => {
    const limited = await world.app('limits', { env: { AGNT_APP_RATES: 'discovery=3/3600' } });
    const a = await limited.joined('limit@r1.test');
    for (let i = 0; i < 3; i++) await a.api.resolve(`mailto:x${i}@r1.test`);
    await assert.rejects(
      a.api.resolve('mailto:x9@r1.test'),
      (e: { code: string; retryAfter?: number }) => e.code === 'rate_limited' && e.retryAfter! > 0,
    );
  });
});
