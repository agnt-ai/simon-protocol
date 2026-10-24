/**
 * The email bridge: a recipient whose domain names no AGNT server, taken through the core's unroutable
 * event. Mail goes out with a reply address; replies come back from `bridge@`.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { received, notices, texts, World } from './harness.ts';

describe('the email bridge', async () => {
  const world = new World();
  after(() => world.close());
  const alpha = await world.app('alpha');
  const inbound = (body: Record<string, unknown>, secret = 'bridge-secret') =>
    world.fetch(`${alpha.origin}/api/bridge/inbound`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${secret}` },
      body: JSON.stringify(body),
    });
  const replyTo = (to: string) => world.outbox.last(to)!.replyTo!;

  it("emails someone with no agent, as the sender's agent, and brings their reply back from bridge@", async () => {
    const ann = await alpha.paired('ann@b1.test');
    const { id } = await ann.agent.send({
      to: ['carl@mail.example'],
      text: 'Lunch on Friday?',
      headers: { subject: 'Lunch' },
    });
    await world.work();
    const mail = world.outbox.last('carl@mail.example')!;
    assert.equal(mail.from, `"${ann.agent.address} via AGNT" <no-reply@alpha.test>`);
    assert.deepEqual(
      [mail.subject, mail.text, mail.headers!['AGNT-Agent']],
      ['Lunch', 'Lunch on Friday?', ann.agent.address],
    );
    assert.deepEqual((await ann.agent.sent(id)).servers, [
      { server: null, recipients: ['carl@mail.example'], status: 'delivered' },
    ]);

    assert.equal((await inbound({ to: mail.replyTo, from: 'carl@mail.example', text: 'Yes!' }, 'wrong')).status, 401);
    const taken = await (
      await inbound({
        to: mail.replyTo,
        from: 'Carl@Mail.example',
        text: 'Yes!\n\nOn Friday Ann wrote:\n> Lunch?',
        messageId: '<m1@mail.example>',
      })
    ).json();
    assert.match(taken.id, /^[0-9a-f]{64}$/);
    await world.work();
    const [reply] = (await received(ann.agent)).messages;
    assert.deepEqual(
      [reply.message.from, reply.message.inReplyTo, reply.message.headers['email-from'], reply.message.headers.subject],
      ['bridge@alpha.test', id, 'carl@mail.example', 'Re: Lunch'],
    );
    assert.deepEqual(await texts(ann.agent), ['Yes!']);
  });

  it('takes a reply only from the address the mail went to, once, and not after 30 days', async () => {
    const ann = await alpha.paired('ann@b2.test');
    await ann.agent.send({ to: ['dee@mail.example'], text: 'hello' });
    await world.work();
    const to = replyTo('dee@mail.example');
    assert.equal((await inbound({ to, from: 'mallory@mail.example', text: 'hi' })).status, 404);
    const take = async (messageId: string) =>
      (await (await inbound({ to, from: 'dee@mail.example', text: 'hi', messageId })).json()).id;
    assert.match(await take('<a@x>'), /^[0-9a-f]{64}$/);
    assert.equal(await take('<a@x>'), null, "a provider's retry is taken once");
    assert.match(await take('<b@x>'), /^[0-9a-f]{64}$/, 'the same words in a new mail are a new reply');
    world.clock.advance(31 * 86_400_000);
    assert.equal((await inbound({ to, from: 'dee@mail.example', text: 'late', messageId: '<c@x>' })).status, 404);
  });

  it('never sends anonymous mail: an agent speaking for no one is not bridged', async () => {
    const solo = await alpha.solo();
    const { id } = await solo.agent.send({ to: ['eve@mail.example'], text: 'hi' });
    await world.work();
    assert.equal(world.outbox.last('eve@mail.example'), undefined);
    assert.equal((await solo.agent.sent(id)).servers[0].reason, 'not_found');
  });

  it('never bridges for a key principal alone, since anyone can make a key: the person must have proved an email or a phone', async () => {
    const keyed = await alpha.keyed();
    const { id } = await keyed.agent.send({ to: ['ceo@bigcorp.example'], text: 'Your invoice is overdue.' });
    await world.work();
    assert.equal(world.outbox.last('ceo@bigcorp.example'), undefined);
    assert.equal((await keyed.agent.sent(id)).servers[0].reason, 'not_found');
  });

  it("delivers to a person's agent for that very address instead of emailing them, through its policy", async () => {
    const ann = await alpha.paired('ann@b3.test');
    const fay = await alpha.joined('fay@mail.example');
    await ann.agent.send({ to: ['fay@mail.example'], text: 'to your agent' });
    await world.work();
    assert.deepEqual(await texts(fay.agent), ['to your agent']);
    assert.equal(
      world.outbox.sent.filter(m => m.to === 'fay@mail.example' && 'replyTo' in m).length,
      0,
      'a person here is never emailed',
    );
    await fay.approved.setPolicy({ accept: 'known' });
    const held = await ann.agent.send({ to: ['fay@mail.example'], text: 'held by policy' });
    await world.work();
    assert.deepEqual(await texts(fay.agent), ['to your agent']);
    assert.equal(
      (await ann.agent.sent(held.id)).servers[0].status,
      'delivered',
      'the sender sees what any bridged message looks like',
    );
    assert.deepEqual(await notices(ann.agent, 'agent-only-run'), []);
  });
});
