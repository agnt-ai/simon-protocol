/** Cold foreign-reader authentication must charge every fetch before it starts. */
import assert from 'node:assert/strict';
import { it } from 'node:test';
import { signRequest } from '@agnt-sdk/simon-protocol';
import { Federation, toRequest } from './harness.ts';

it('charges a cold reader chain, stops before its signing document, and reuses verified caches', async () => {
  const fed = new Federation();
  try {
    const home = await fed.server('home', {
      config: { rates: { lookup: { limit: 2, seconds: 3600 } } },
      extensions: [
        { name: 'readers', admitsReader: ({ reader }) => (reader === 'bob@peer.test' ? 'admit' : 'refuse') },
      ],
    });
    const peer = await fed.server('peer');
    const author = await home.agent('author');
    const reader = await peer.agent('bob');
    const sent = await author.send(author.message([], 'members only', { headers: { audience: 'members' } }));
    assert.equal(sent.status, 200);
    const url = new URL(`${home.origin}/simon/messages/${sent.json.id}`);
    const ask = (ip: string) =>
      home.server.handle(
        toRequest(
          'GET',
          url,
          signRequest(reader.key, { method: 'GET', url: url.href, now: fed.clock.t, agent: reader.address }),
          Buffer.alloc(0),
          ip,
        ),
      );
    const start = fed.net.sent.length;
    assert.equal(
      (await ask('203.0.113.10')).status,
      404,
      'two charges cover DNS and the agent document; a third fetch is refused',
    );
    assert.deepEqual(
      fed.net.sent.slice(start).map(r => r.url),
      [`${peer.origin}/simon/agents/${reader.address}`],
      'the signing-server document never leaves the process after the budget is spent',
    );
    assert.equal((await ask('203.0.113.10')).status, 404);
    assert.equal(fed.net.sent.length, start + 1, 'retrying cannot spend the protected own-work pool');
    assert.equal(
      (await ask('203.0.113.11')).status,
      200,
      'a fresh network has room for the remaining two uncached documents',
    );
    assert.deepEqual(
      fed.net.sent.slice(start).map(r => r.url),
      [
        `${peer.origin}/simon/agents/${reader.address}`,
        `${peer.origin}/simon/agents/${reader.address}`,
        `${peer.origin}/simon/server`,
      ],
    );
    assert.equal((await ask('203.0.113.10')).status, 200, 'verified cached documents require no new lookup charge');
    assert.equal(fed.net.sent.length, start + 3);
  } finally {
    await fed.close();
  }
});
