/** An agent's own place: its card, its check-in and read cursor, webhooks, the nudge, upload checks, ending it. */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { after, describe, it } from 'node:test';
import { checkMessage, checkSupportedVersion, sha256Hex } from '@agnt-protocol/protocol';
import type { Request } from '@agnt-protocol/server';
import { received, notices, texts, World } from './harness.ts';

describe('agents', async () => {
  const world = new World();
  after(() => world.close());
  const alpha = await world.app('alpha', { env: { SIMON_NUDGE_TURNS: '4', SIMON_UPLOAD_BYTES_PER_DAY: '1000' } });

  it('keeps a card the agent writes, readable by others only once it is published', async () => {
    const [ada, bob] = [await alpha.solo('ada'), await alpha.solo('bob')];
    const me = await ada.api.updateMe({
      name: 'Ada',
      description: 'Schedules things',
      capabilities: { attachments: true },
    });
    assert.deepEqual([me.name, me.capabilities.attachments, me.kind, me.keys.length], ['Ada', true, 'solo', 1]);
    await assert.rejects(ada.api.updateMe({ name: 'Ada at ada.example' }), { code: 'invalid' });
    await assert.rejects(bob.api.card(ada.agent.address!), { code: 'not_found', details: { what: 'agent' } });
    await ada.approved.publishCard(true);
    assert.equal((await bob.api.card(ada.agent.address!)).name, 'Ada');
  });

  it('takes only an https: homepage, since anyone may open a card', async () => {
    const ada = await alpha.solo();
    for (const homepage of ['javascript:alert(document.cookie)', 'http://ada.example', 'data:text/html,hi']) {
      await assert.rejects(ada.api.updateMe({ capabilities: { homepage } }), { code: 'invalid' }, homepage);
    }
    const me = await ada.api.updateMe({ capabilities: { homepage: 'https://ada.example/about' } });
    assert.equal(me.capabilities.homepage, 'https://ada.example/about');
  });

  it('shows what is unread until the agent marks it read', async () => {
    const [ada, bob] = [await alpha.solo(), await alpha.solo()];
    await bob.agent.send({ to: [ada.agent.address!], text: 'one' });
    await bob.agent.send({ to: [ada.agent.address!], text: 'two' });
    await world.work();
    const home = await ada.api.home();
    assert.equal(home.unread.messages.length, 2);
    assert.equal(home.agent.address, ada.agent.address);
    assert.ok(home.attention.length === 0 && home.nextCheckInSeconds > 0);
    await ada.api.ack(home.unread.messages[0].cursor);
    assert.equal((await ada.api.home()).unread.messages.length, 1);
    await ada.api.ack(0);
    assert.equal((await ada.api.home()).unread.messages.length, 1, 'the read cursor never goes back');
  });

  it('keeps outbound history out of unread and includes messages addressed to itself', async () => {
    const [ada, bob] = [await alpha.solo(), await alpha.solo()];
    const own = await ada.agent.send({ to: [ada.agent.address!], text: 'a note to myself' });
    // Establish inbox arrival order before the other sender's independently queued delivery.
    await world.work();
    const self = (await ada.api.home()).unread.messages;
    assert.deepEqual(
      self.map(e => e.id),
      [own.id],
    );
    await ada.agent.send({ to: [bob.agent.address!], text: 'outbound only' });
    await bob.agent.send({ to: [ada.agent.address!], text: 'inbound only' });
    await world.work();
    const home = await ada.api.home();
    assert.deepEqual(
      home.unread.messages.map(e => {
        const message = checkMessage(e.message);
        checkSupportedVersion(message);
        return message.parts[0];
      }),
      [
        { type: 'text/plain', data: 'a note to myself' },
        { type: 'text/plain', data: 'inbound only' },
      ],
    );
    assert.ok(home.unread.messages[0].cursor < home.unread.messages[1].cursor);
    assert.equal(home.unread.messages.filter(e => e.id === own.id).length, 1);
    assert.equal(home.unread.more, false, 'outbound entries do not report another unread page');
    await ada.api.ack(home.unread.messages.at(-1)!.cursor);
    assert.deepEqual((await ada.api.home()).unread.messages, []);
  });

  it('wakes a webhook on each new message, signed, and retries one that failed', async () => {
    const ada = await alpha.solo();
    const posts: { body: string; headers: Request['headers'] }[] = [];
    let answer = 500;
    world.net.hosts.set('https://hooks.example', async req => {
      posts.push({ body: req.body.toString(), headers: req.headers });
      return { status: answer };
    });
    await assert.rejects(ada.approved.createWebhook('ftp://hooks.example/x'), { code: 'invalid' });
    const hook = await ada.approved.createWebhook('https://hooks.example/simon');
    const bob = await alpha.solo();
    await bob.agent.send({ to: [ada.agent.address!], text: 'ping' });
    await world.work();
    assert.equal(posts.length, 1);
    answer = 200;
    world.clock.advance(11_000);
    await world.work();
    assert.equal(posts.length, 2, 'retried after it failed');
    const { body, headers } = posts[1];
    assert.equal(JSON.parse(body).type, 'inbox.changed');
    const expected = crypto
      .createHmac('sha256', hook.secret)
      .update(`${headers['simon-webhook-timestamp']}.${body}`)
      .digest('hex');
    assert.equal(headers['simon-webhook-signature'], `v1=${expected}`);
    assert.equal((await ada.api.webhooks()).items[0].lastSuccessAt !== null, true);
  });

  it("posts each webhook apart, so one agent's slow endpoint never holds up another's", async () => {
    const [mal, ada, bob] = [await alpha.solo(), await alpha.solo(), await alpha.solo()];
    let tarpitted = 0;
    let tarpittedWhenAdaHeard = -1;
    world.net.hosts.set('https://tarpit.example', () => {
      tarpitted++;
      return new Promise(() => {});
    });
    world.net.hosts.set('https://ada-hooks.example', async () => {
      tarpittedWhenAdaHeard = tarpitted;
      return { status: 200 };
    });
    await mal.approved.createWebhook('https://tarpit.example/simon');
    for (let n = 0; n < 12; n++) await bob.agent.send({ to: [mal.agent.address!], text: `slow ${n}` });
    await world.work();
    await ada.approved.createWebhook('https://ada-hooks.example/simon');
    for (let n = 0; n < 12; n++) await bob.agent.send({ to: [mal.agent.address!], text: `slower ${n}` });
    await bob.agent.send({ to: [ada.agent.address!], text: 'ping' });
    await world.work();
    assert.ok(tarpittedWhenAdaHeard >= 0, "ada's webhook was posted");
    assert.ok(tarpittedWhenAdaHeard <= 13, `posted beside the tarpit, not behind it (${tarpittedWhenAdaHeard})`);
  });

  it('nudges each agent here in a thread after a run of messages with no person consulted, and never stops it', async () => {
    const [ada, bob] = [await alpha.solo(), await alpha.solo()];
    let last: string | null = null;
    for (let turn = 0; turn < 4; turn++) {
      const [from, to] = turn % 2 ? [bob, ada] : [ada, bob];
      last = (await from.agent.send({ to: [to.agent.address!], text: `turn ${turn}`, inReplyTo: last })).id;
      await world.work();
    }
    const [toAda, toBob] = [await notices(ada.agent, 'agent-only-run'), await notices(bob.agent, 'agent-only-run')];
    assert.deepEqual([toAda.length, toBob.length], [1, 1]);
    assert.equal(toAda[0].data.turns, 4);
    assert.ok(!toAda[0].text.includes(bob.agent.address!), 'a notice names nobody else');
    for (let turn = 0; turn < 3; turn++) {
      const [from, to] = turn % 2 ? [bob, ada] : [ada, bob];
      last = (await from.agent.send({ to: [to.agent.address!], text: `again ${turn}`, inReplyTo: last })).id;
      await world.work();
    }
    assert.ok((await texts(bob.agent)).includes('again 2'), 'delivery never stops');
  });

  it('refuses an upload that fails its scan, and uploads past the daily volume', async () => {
    const ada = await alpha.solo();
    const eicar = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
    await assert.rejects(ada.agent.uploadPart(eicar, 'application/octet-stream'), { code: 'infected', status: 422 });
    const part = await ada.agent.uploadPart(Buffer.alloc(600, 1), 'application/octet-stream');
    assert.equal(part.sha256, sha256Hex(Buffer.alloc(600, 1)));
    await assert.rejects(ada.agent.uploadPart(Buffer.alloc(600, 2), 'application/octet-stream'), {
      code: 'rate_limited',
    });
  });

  it('ends an agent: its address retires and never takes a key again', async () => {
    const ada = await alpha.solo('leaving');
    await ada.approved.end();
    await assert.rejects(received(ada.agent), { status: 401 });
    await assert.rejects(world.agent(alpha.origin, 'leaving@alpha.test'), { code: 'address_taken' });
  });
});
