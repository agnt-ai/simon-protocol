/**
 * Spec section 7.2 and CLIENT.md parts: uploads, the three ways bytes may be read, and the recipient's
 * server fetching bytes for its agents.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { canonicalBytes, generateKey, messageId, sha256Hex, signRequest } from '@agnt-protocol/protocol';
import { replyBody } from '../src/testing.ts';
import { defineConfig } from '../src/config.ts';
import {
  Fetcher,
  MAX_FETCH_BYTES,
  MAX_FETCHES,
  MAX_FETCHES_PER_CARRIER,
  MAX_PENDING_FETCHES_PER_CARRIER,
  PREFETCH_JITTER_MS,
  queuePrefetch,
} from '../src/parts.ts';
import { audienceOf } from '../src/readers.ts';
import type { Store } from '../src/store/store.ts';
import { Federation, Peer, toRequest, type Answer } from './harness.ts';

const TEXT = { type: 'text/plain', data: 'x' };

describe('parts (spec section 7.2)', async () => {
  const fed = new Federation();
  after(() => fed.close());
  const alpha = await fed.server('alpha');
  const beta = await fed.server('beta');
  const gamma = await fed.server('gamma');
  const ada = await alpha.agent('ada');
  const bob = await beta.agent('bob');
  const eve = await alpha.agent('eve');

  const bytes = Buffer.from('%PDF-1.7 the contract');
  const part = { type: 'application/pdf', sha256: sha256Hex(bytes), size: bytes.length };

  /** A part fetch signed by a server, as one server asks another. */
  const asServer = async (from: typeof beta, to: typeof alpha, sha256: string) => {
    const url = new URL(`${to.origin}/simon/parts/${sha256}`);
    const headers = signRequest(from.server.api.config.serverKey, {
      method: 'GET',
      url: url.href,
      now: fed.clock.t,
      server: from.origin,
    });
    return to.server.handle(toRequest('GET', url, { ...headers }, Buffer.alloc(0), '203.0.113.20'));
  };

  it('takes an upload whose hash is its path, and refuses any other', async () => {
    const res = await ada.upload(bytes);
    assert.deepEqual([res.status, res.json], [200, { sha256: part.sha256, size: part.size }]);
    const wrong = await ada.request('PUT', `/simon/parts/${'0'.repeat(64)}`, { body: bytes });
    assert.deepEqual([wrong.status, wrong.json.code], [400, 'invalid']);
    const huge = await ada.request('PUT', `/simon/parts/${'0'.repeat(64)}`, { body: Buffer.alloc(26_214_401) });
    assert.equal(huge.status, 413);
  });

  it("serves an agent's own upload to it, and to nobody else", async () => {
    assert.deepEqual((await ada.part(part.sha256)).bytes, bytes);
    assert.equal((await eve.part(part.sha256)).status, 404);
    assert.equal((await ada.request('GET', `/simon/parts/${part.sha256}`, { sign: false })).status, 404);
  });

  it('fetches a received part from its carrier soon after it arrives: 503 until then, never sooner', async () => {
    await ada.send(
      ada.message([bob.address], 'see attached', { parts: [{ type: 'text/plain', data: 'see attached' }, part] }),
    );
    await fed.work();
    const fetches = () => fed.net.sent.filter(r => r.url === `${alpha.origin}/simon/parts/${part.sha256}`).length;
    const first = await bob.part(part.sha256);
    assert.deepEqual([first.status, first.json.code], [503, 'unavailable']);
    assert.ok(Number(first.headers['retry-after']) <= PREFETCH_JITTER_MS / 1000);
    await fed.work();
    assert.equal(fetches(), 0, 'asking does not bring the fetch forward');
    fed.clock.advance(PREFETCH_JITTER_MS);
    await fed.work();
    assert.equal(fetches(), 1);
    const second = await bob.part(part.sha256);
    assert.deepEqual([second.status, second.bytes], [200, bytes]);
  });

  it('serves a server only the parts of messages delivered to it', async () => {
    assert.equal((await asServer(beta, alpha, part.sha256)).status, 200);
    const refused = await asServer(gamma, alpha, part.sha256);
    assert.deepEqual([refused.status, (refused.json as { code: string }).code], [404, 'not_found']);
  });

  it('serves the parts of a public message to anyone', async () => {
    const pub = Buffer.from('a public image');
    await ada.upload(pub);
    await ada.send(
      ada.message([], 'look', { parts: [TEXT, { type: 'image/png', sha256: sha256Hex(pub), size: pub.length }] }),
    );
    const res = await eve.request('GET', `/simon/parts/${sha256Hex(pub)}`, { sign: false });
    assert.deepEqual([res.status, res.bytes], [200, pub]);
    const signed = await eve.part(sha256Hex(pub));
    assert.deepEqual([signed.status, signed.bytes], [200, pub], 'and to an agent here that signs, as clients do');
    // A server request whose signature fails asks as nobody in particular, and nobody may read a public post.
    const url = new URL(`${alpha.origin}/simon/parts/${sha256Hex(pub)}`);
    const forged = signRequest(generateKey().privateKey, {
      method: 'GET',
      url: url.href,
      now: fed.clock.t,
      server: beta.origin,
    });
    const asNobody = await alpha.server.handle(toRequest('GET', url, forged, Buffer.alloc(0), '203.0.113.21'));
    assert.deepEqual([asNobody.status, replyBody(asNobody)], [200, pub]);
  });

  it("answers an agent here as the client API does: a signature that fails is 401, not the parts path's 404", async () => {
    // Eve's own key, over another target than the one sent: the client API's 401.
    const url = new URL(`${alpha.origin}/simon/parts/${part.sha256}`);
    const other = new URL(`${alpha.origin}/simon/parts/${'f'.repeat(64)}`);
    const signed = signRequest(eve.key, { method: 'GET', url: other.href, now: fed.clock.t, agent: eve.address });
    const res = await alpha.server.handle(toRequest('GET', url, signed, Buffer.alloc(0), '203.0.113.30'));
    assert.deepEqual(
      [res.status, (res.json as { code: string }).code, res.headers?.['www-authenticate']],
      [401, 'bad_signature', 'SIMON'],
    );
    // Dispatch follows the publicly served domain, never the presence of a hidden account/key record.
    const stranger = await eve.request('GET', `/simon/parts/${part.sha256}`, { key: generateKey().privateKey });
    const nobody = await eve.request('GET', `/simon/parts/${part.sha256}`, { agent: 'nobody@alpha.test' });
    assert.deepEqual([stranger.status, stranger.json], [res.status, res.json]);
    assert.deepEqual([nobody.status, nobody.bytes], [stranger.status, stranger.bytes]);
    const unsigned = await eve.request('GET', `/simon/parts/${part.sha256}`, { sign: false });
    assert.equal(unsigned.status, 404);
  });
});

describe('parts are kept per source', async () => {
  const fed = new Federation();
  after(() => fed.close());
  const refused: string[] = [];
  const alpha = await fed.server('alpha');
  const beta = await fed.server('beta', {
    extensions: [
      { name: 'quiet', admit: a => (a.message.from.startsWith('spam') ? (refused.push(a.id), 'refuse') : undefined) },
    ],
  });
  const evil = new Peer(fed, 'evil');
  const mallory = evil.agent('mallory');
  const ada = await alpha.agent('ada');
  const bob = await beta.agent('bob');

  it('never serves bytes because a message merely names their hash', async () => {
    const secret = Buffer.from('%PDF-1.7 salary: 183,000');
    const x = sha256Hex(secret);
    await ada.upload(secret);
    await ada.send(
      ada.message([bob.address], 'private', {
        parts: [TEXT, { type: 'application/pdf', sha256: x, size: secret.length }],
      }),
    );
    await fed.work();
    // The attack: an agent on alpha, sent a message by the attacker's own server that names the hash.
    const eve = alpha.newAgent();
    assert.equal((await eve.register()).status, 200);
    const env = evil.envelope(
      evil.message(mallory, [eve.address], 'hi', {
        parts: [TEXT, { type: 'application/pdf', sha256: x, size: secret.length }],
      }),
    );
    assert.equal((await evil.post(alpha, env)).status, 202);
    await fed.work();
    const held = await eve.part(x);
    assert.equal(held.status, 503, "alpha fetches from the message's carrier, not from ada's upload");
    const nothing = sha256Hex(Buffer.from('nothing anyone holds'));
    await evil.post(
      alpha,
      evil.envelope(
        evil.message(mallory, [eve.address], 'hi2', {
          parts: [TEXT, { type: 'application/pdf', sha256: nothing, size: 20 }],
        }),
      ),
    );
    await fed.work();
    assert.equal((await eve.part(nothing)).status, 503, 'a hash held here and one held nowhere look the same');
    fed.clock.advance(PREFETCH_JITTER_MS);
    await fed.work();
    assert.notEqual((await eve.part(x)).status, 200, 'the carrier cannot serve what it never had');
    assert.deepEqual((await ada.part(x)).bytes, secret, "ada's own bytes are still hers");
  });

  it('prefetches the parts of a message for an agent here whatever policy decides', async () => {
    const spammer = await alpha.agent('spammer');
    const bytes = Buffer.from('a tracking pixel');
    const sha256 = sha256Hex(bytes);
    await spammer.upload(bytes);
    await spammer.send(
      spammer.message([bob.address], 'open me', { parts: [TEXT, { type: 'image/png', sha256, size: bytes.length }] }),
    );
    await fed.work();
    fed.clock.advance(PREFETCH_JITTER_MS);
    await fed.work();
    assert.equal(refused.length, 1, 'policy refused it');
    assert.equal(
      fed.net.sent.filter(r => r.url === `${alpha.origin}/simon/parts/${sha256}`).length,
      1,
      'and the carrier saw the fetch all the same',
    );
  });

  it('prefetches the parts of every accepted message, even one for no agent here', async () => {
    const bytes = Buffer.from('a probe for who is there');
    const sha256 = sha256Hex(bytes);
    await ada.upload(bytes);
    await ada.send(
      ada.message(['nobody@beta.test'], 'is anyone there?', {
        parts: [TEXT, { type: 'image/png', sha256, size: bytes.length }],
      }),
    );
    await fed.work();
    fed.clock.advance(PREFETCH_JITTER_MS);
    await fed.work();
    const fetched = fed.net.sent.filter(r => r.url === `${alpha.origin}/simon/parts/${sha256}`);
    assert.equal(fetched.length, 1, 'the carrier learns nothing about who is there');
  });

  it('never fetches because an agent asked, and answers 404 once a fetch was given up', async () => {
    const zed = evil.agent('zed');
    const lost = sha256Hex(Buffer.from('bytes the carrier will never serve'));
    const env = evil.envelope(
      evil.message(zed, [bob.address], 'lost', { parts: [TEXT, { type: 'application/pdf', sha256: lost, size: 34 }] }),
    );
    assert.equal((await evil.post(beta, env)).status, 202);
    const fetchesOf = () => fed.net.sent.filter(r => r.url.endsWith(`/simon/parts/${lost}`)).length;
    for (let i = 0; i < 12; i++) {
      fed.clock.advance(3600_000);
      await fed.work();
    }
    const tries = fetchesOf();
    assert.ok(tries > 0, 'fetched on its own schedule');
    assert.equal((await bob.part(lost)).status, 404, 'given up: a final answer');
    fed.clock.advance(3600_000);
    await fed.work();
    assert.equal(fetchesOf(), tries, 'and the read fetched nothing');
  });

  it('lets an agent forward a part it received, and serves it to the next server', async () => {
    const gamma = await fed.server('gamma');
    const bytes = Buffer.from('%PDF-1.7 minutes of the meeting');
    const part = { type: 'application/pdf', sha256: sha256Hex(bytes), size: bytes.length };
    await ada.upload(bytes);
    const sent = await ada.send(ada.message([bob.address], 'see attached', { parts: [TEXT, part] }));
    assert.equal(sent.status, 200);
    await fed.work();
    fed.clock.advance(PREFETCH_JITTER_MS);
    await fed.work();
    assert.deepEqual((await bob.part(part.sha256)).bytes, bytes, 'bob holds it, fetched from alpha');
    const carol = await gamma.agent('carol');
    const forward = bob.message([carol.address], 'from ada', { parts: [TEXT, part] });
    assert.equal((await bob.send(forward)).status, 200, 'no upload needed');
    await fed.work();
    fed.clock.advance(PREFETCH_JITTER_MS);
    await fed.work();
    assert.deepEqual((await carol.part(part.sha256)).bytes, bytes, "gamma fetched it from bob's server");
  });

  it('lets a received part travel through several agents here, each able to read and forward it', async () => {
    const bytes = Buffer.from('%PDF-1.7 passed along');
    const part = { type: 'application/pdf', sha256: sha256Hex(bytes), size: bytes.length };
    await ada.upload(bytes);
    await ada.send(ada.message([bob.address], 'for bob', { parts: [TEXT, part] }));
    await fed.work();
    fed.clock.advance(PREFETCH_JITTER_MS);
    await fed.work();
    let holder = bob;
    for (const name of ['bea', 'bix', 'bo']) {
      const next = await beta.agent(name);
      assert.equal((await holder.send(holder.message([next.address], 'fwd', { parts: [TEXT, part] }))).status, 200);
      await fed.work();
      const res = await next.part(part.sha256);
      assert.deepEqual([res.status, res.bytes], [200, bytes], `${name} reads what it was forwarded`);
      holder = next;
    }
  });

  it('carries a message whole: the files it names count as named by the forward (spec section 5.3)', async () => {
    const delta = await fed.server('delta');
    const bytes = Buffer.from('%PDF-1.7 the signed lease');
    const part = { type: 'application/pdf', sha256: sha256Hex(bytes), size: bytes.length };
    await ada.upload(bytes);
    const original = ada.message([bob.address], 'the lease', { parts: [TEXT, part] });
    assert.equal((await ada.send(original)).status, 200);
    await fed.work();
    fed.clock.advance(PREFETCH_JITTER_MS);
    await fed.work();
    const dan = await delta.agent('dan');
    const whole = { type: 'application/simon-message', data: canonicalBytes(original).toString('base64') };
    const forward = bob.message([dan.address], 'forwarded', {
      inReplyTo: messageId(original),
      headers: { rel: 'forward' },
      parts: [TEXT, whole],
    });
    assert.equal((await bob.send(forward)).status, 200, 'bob holds the file the carried message names');
    await fed.work();
    fed.clock.advance(PREFETCH_JITTER_MS);
    await fed.work();
    assert.deepEqual((await dan.part(part.sha256)).bytes, bytes, "delta fetched it from bob's server");
  });
});

describe('local forwarding and publication grants compose', () => {
  it('serves every recipient after repeated forwards without granting unrelated private access', async () => {
    const fed = new Federation();
    try {
      const home = await fed.server('local');
      const agents = await Promise.all(['a', 'b', 'c', 'd', 'outsider'].map(n => home.agent(n)));
      const bytes = Buffer.from('a file forwarded repeatedly');
      const part = { type: 'application/octet-stream', sha256: sha256Hex(bytes), size: bytes.length };
      await agents[0].upload(bytes);
      for (let i = 0; i < 3; i++) {
        if (i > 0) fed.clock.advance(86_400_000);
        assert.equal(
          (await agents[i].send(agents[i].message([agents[i + 1].address], 'forward', { parts: [part] }))).status,
          200,
        );
        await fed.work();
        assert.deepEqual((await agents[i + 1].part(part.sha256)).bytes, bytes);
      }
      assert.equal((await agents[4].part(part.sha256)).status, 404);
      fed.clock.advance(29 * 86_400_000);
      await home.store.sweep(new Date(fed.clock.t).toISOString(), new Date(fed.clock.t).toISOString());
      assert.equal(
        await home.store.part(part.sha256, { uploader: agents[0].address }),
        null,
        'original source expired',
      );
      assert.deepEqual(
        (await agents[3].part(part.sha256)).bytes,
        bytes,
        'final forward retains its own authorized copy',
      );
      assert.equal((await agents[4].part(part.sha256)).status, 404);
    } finally {
      await fed.close();
    }
  });

  it('serves an existing private grant without evaluating unrelated publication policy', async () => {
    const fed = new Federation();
    let audienceCalls = 0;
    try {
      const home = await fed.server('local', {
        extensions: [
          {
            name: 'broken-policy',
            admitsReader: () => {
              audienceCalls++;
              throw new Error('policy backend down');
            },
          },
        ],
      });
      const uploader = await home.agent('uploader');
      const author = await home.agent('author');
      const recipient = await home.agent('recipient');
      const bytes = Buffer.from('same bytes, independently authorized');
      const part = { type: 'application/octet-stream', sha256: sha256Hex(bytes), size: bytes.length };
      await uploader.upload(bytes);
      await author.upload(bytes);
      await uploader.send(uploader.message([recipient.address], 'private copy', { parts: [part] }));
      await fed.work();
      await author.send(author.message([], 'gated copy', { parts: [part], headers: { audience: 'members' } }));
      assert.deepEqual((await uploader.part(part.sha256)).bytes, bytes);
      assert.deepEqual((await recipient.part(part.sha256)).bytes, bytes);
      assert.equal(audienceCalls, 0, 'a separate publication cannot revoke an existing grant');
    } finally {
      await fed.close();
    }
  });

  it('preserves a pending private grant when an unrelated publication policy fails', async () => {
    const fed = new Federation();
    try {
      const home = await fed.server('local', {
        extensions: [
          {
            name: 'broken-policy',
            admitsReader: () => {
              throw new Error('policy backend down');
            },
          },
        ],
      });
      const foreign = await fed.server('foreign');
      const sender = await foreign.agent('sender');
      const reader = await home.agent('reader');
      const publisher = await home.agent('publisher');
      const bytes = Buffer.from('pending foreign bytes and a separate gated copy');
      const part = { type: 'application/octet-stream', sha256: sha256Hex(bytes), size: bytes.length };
      await sender.upload(bytes);
      await sender.send(sender.message([reader.address], 'private pending', { parts: [part] }));
      await fed.work();
      assert.equal((await reader.part(part.sha256)).status, 503);
      await publisher.upload(bytes);
      await publisher.send(
        publisher.message([], 'broken publication', { parts: [part], headers: { audience: 'members' } }),
      );
      assert.equal(
        (await reader.part(part.sha256)).status,
        503,
        'a separate failed hook cannot replace the private fetching response',
      );
      assert.equal(
        (await reader.request('GET', `/simon/parts/${part.sha256}`, { sign: false })).status,
        404,
        'the failed policy alone grants an anonymous caller nothing',
      );
    } finally {
      await fed.close();
    }
  });

  it('answers a failed hidden audience exactly like an absent hash and logs the policy failure', async () => {
    const fed = new Federation();
    const logs: string[] = [];
    try {
      const home = await fed.server('hidden', {
        log: (_level, message) => logs.push(message),
        extensions: [
          {
            name: 'failure',
            admitsReader: () => {
              throw new Error('audience unavailable');
            },
          },
        ],
      });
      const author = await home.agent('author');
      const reader = await home.agent('reader');
      const bytes = Buffer.from('hidden bytes');
      const part = { type: 'application/octet-stream', sha256: sha256Hex(bytes), size: bytes.length };
      await author.upload(bytes);
      await author.send(author.message([], 'restricted', { parts: [part], headers: { audience: 'hidden' } }));
      const denied = await reader.request('GET', `/simon/parts/${part.sha256}`, { sign: false });
      const absent = await reader.request('GET', `/simon/parts/${'f'.repeat(64)}`, { sign: false });
      assert.deepEqual([denied.status, denied.bytes, denied.headers], [absent.status, absent.bytes, absent.headers]);
      assert.equal(denied.status, 404);
      assert.ok(logs.includes('part audience policy failed'));
      const heldFor = home.store.heldFor.bind(home.store);
      home.store.heldFor = async () => {
        throw new Error('database unavailable');
      };
      assert.equal((await author.part(part.sha256)).status, 500, 'Store errors are not audience denials');
      home.store.heldFor = heldFor;
    } finally {
      await fed.close();
    }
  });

  for (const restrictedFirst of [false, true])
    it(`serves a held public grant before an unresolved audience policy, restrictedFirst=${restrictedFirst}`, async () => {
      const fed = new Federation();
      let release!: () => void;
      const blocked = new Promise<void>(resolve => (release = resolve));
      let released = false;
      let policyCalls = 0;
      let request: Promise<Answer> | undefined;
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const home = await fed.server('public', {
          extensions: [
            {
              name: 'pending',
              admitsReader: async () => {
                policyCalls++;
                await blocked;
                return 'refuse' as const;
              },
            },
          ],
        });
        const author = await home.agent('author');
        const reader = await home.agent('reader');
        const bytes = Buffer.from('held bytes with independent public consent');
        const part = { type: 'application/octet-stream', sha256: sha256Hex(bytes), size: bytes.length };
        await author.upload(bytes);
        await author.send(author.message([], 'restricted', { parts: [part], headers: { audience: 'blocked' } }));
        await author.send(author.message([], 'public', { parts: [part] }));
        const namers = home.store.partNamers.bind(home.store);
        home.store.partNamers = async (...args) =>
          (await namers(...args)).sort((a, b) => {
            const aRestricted = Number(audienceOf(a.message) !== null);
            const bRestricted = Number(audienceOf(b.message) !== null);
            return restrictedFirst ? bRestricted - aRestricted : aRestricted - bRestricted;
          });
        request = reader.request('GET', `/simon/parts/${part.sha256}`, { sign: false });
        const deadline = new Promise<never>((_resolve, reject) => {
          timer = setTimeout(() => reject(new Error('public grant waited for an unrelated policy')), 1000);
        });
        const answer = await Promise.race([request, deadline]);
        assert.deepEqual([answer.status, answer.bytes], [200, bytes]);
        assert.equal(released, false, 'positive response completes before releasing the unrelated policy');
        assert.equal(policyCalls, 0, 'unrelated policy work is never started or retained');
      } finally {
        if (timer) clearTimeout(timer);
        released = true;
        release();
        await request;
        await fed.close();
      }
    });

  for (const failingFirst of [false, true])
    for (const admittedAudience of [false, true])
      it(`keeps independent publication grants when a policy fails, failingFirst=${failingFirst}, admittedAudience=${admittedAudience}`, async () => {
        const fed = new Federation();
        try {
          const home = await fed.server('local', {
            extensions: [
              {
                name: 'part-policy',
                admitsReader: ({ audience }) => {
                  if (audience === 'broken') throw new Error('policy backend down');
                  return audience === 'members' ? 'admit' : 'refuse';
                },
              },
            ],
          });
          const author = await home.agent('author');
          const reader = await home.agent('reader');
          const bytes = Buffer.from('independently published bytes');
          const part = { type: 'application/octet-stream', sha256: sha256Hex(bytes), size: bytes.length };
          await author.upload(bytes);
          await author.send(author.message([], 'broken policy', { parts: [part], headers: { audience: 'broken' } }));
          assert.equal((await reader.part(part.sha256)).status, 404, 'a failed policy alone does not grant access');
          await author.send(
            author.message([], 'independent grant', {
              parts: [part],
              headers: admittedAudience ? { audience: 'members' } : {},
            }),
          );
          // Stores may return namers in either order. Exercise the route with both, without changing their grants.
          const partNamers = home.store.partNamers.bind(home.store);
          home.store.partNamers = async (...args) =>
            (await partNamers(...args)).sort((a, b) => {
              const aBroken = Number(audienceOf(a.message) === 'broken');
              const bBroken = Number(audienceOf(b.message) === 'broken');
              return failingFirst ? bBroken - aBroken : aBroken - bBroken;
            });
          const signed = await reader.part(part.sha256);
          const anonymous = await reader.request('GET', `/simon/parts/${part.sha256}`, { sign: false });
          assert.deepEqual([signed.status, signed.bytes], [200, bytes]);
          assert.deepEqual([anonymous.status, anonymous.bytes], [200, bytes]);
        } finally {
          await fed.close();
        }
      });

  for (const gated of [false, true])
    it(`combines local and publication grants, gated=${gated}`, async () => {
      const fed = new Federation();
      try {
        const home = await fed.server('local', {
          extensions: [
            { name: 'audience', admitsReader: ({ reader }) => (reader?.startsWith('reader@') ? 'admit' : 'refuse') },
          ],
        });
        const author = await home.agent('author');
        const reader = await home.agent('reader');
        const refused = await home.agent('refused');
        const foreign = await fed.server('foreign');
        const foreignReader = await foreign.agent('reader');
        const bytes = Buffer.from(`published file ${gated}`);
        const part = { type: 'application/octet-stream', sha256: sha256Hex(bytes), size: bytes.length };
        await author.upload(bytes);
        const m = author.message([], 'published', { parts: [part], headers: gated ? { audience: 'members' } : {} });
        assert.equal((await author.send(m)).status, 200);
        assert.equal((await reader.request('GET', `/simon/messages/${messageId(m)}`)).status, 200);
        assert.deepEqual((await reader.part(part.sha256)).bytes, bytes);
        assert.equal((await refused.part(part.sha256)).status, gated ? 404 : 200);
        const url = new URL(`${home.origin}/simon/parts/${part.sha256}`);
        const badHeaders = signRequest(reader.key, {
          method: 'GET',
          url: url.href,
          now: fed.clock.t,
          agent: reader.address,
        });
        badHeaders['simon-signature'] = 'AAAA';
        const badHosted = await home.server.handle(toRequest('GET', url, badHeaders, Buffer.alloc(0), '203.0.113.20'));
        assert.deepEqual(
          [badHosted.status, (badHosted.json as { code: string }).code, badHosted.headers?.['www-authenticate']],
          [401, 'bad_signature', 'SIMON'],
          'invalid hosted authentication remains a client error even when the bytes are public',
        );
        const foreignHeaders = signRequest(foreignReader.key, {
          method: 'GET',
          url: url.href,
          now: fed.clock.t,
          agent: foreignReader.address,
        });
        const validForeign = await home.server.handle(
          toRequest('GET', url, foreignHeaders, Buffer.alloc(0), '203.0.113.21'),
        );
        assert.deepEqual([validForeign.status, replyBody(validForeign)], [200, bytes]);
        const badForeignHeaders = signRequest(foreignReader.key, {
          method: 'GET',
          url: url.href,
          now: fed.clock.t,
          agent: foreignReader.address,
        });
        badForeignHeaders['simon-signature'] = 'AAAA';
        const badForeign = await home.server.handle(
          toRequest('GET', url, badForeignHeaders, Buffer.alloc(0), '203.0.113.22'),
        );
        assert.equal(badForeign.status, gated ? 404 : 200, 'foreign invalid authentication asks anonymously');
        if (!gated) assert.deepEqual(replyBody(badForeign), bytes);
        assert.equal(
          (await reader.request('GET', `/simon/parts/${part.sha256}`, { sign: false })).status,
          gated ? 404 : 200,
        );
      } finally {
        await fed.close();
      }
    });
});

describe('part fetches are bounded, and shared fairly between carriers', () => {
  /** A carrier that holds every fetch open a while, then answers 404; it records each fetch's start. */
  const slow = (fed: Federation, origin: string, starts: string[], counts: { now: number; peak: number }) =>
    fed.net.hosts.set(origin, async () => {
      starts.push(origin);
      counts.peak = Math.max(counts.peak, ++counts.now);
      await new Promise(r => setTimeout(r, 20));
      counts.now--;
      return { status: 404, json: {} };
    });
  const queue = (server: { store: Store }, carrier: string, n: number, size: number, dueAt: string) =>
    Promise.all(
      Array.from({ length: n }, (_, i) =>
        server.store.queueFetch({ sha256: sha256Hex(`${carrier} ${size} ${i}`), carrier, size, attempts: 0, dueAt }),
      ),
    );

  it(`runs at most ${MAX_FETCHES} at once, ${MAX_FETCHES_PER_CARRIER} per carrier, and at most ${MAX_FETCH_BYTES} declared bytes`, async () => {
    const fed = new Federation();
    const gamma = await fed.server('gamma');
    const counts = { now: 0, peak: 0 };
    const starts: string[] = [];
    for (const c of ['https://simon.slow1.test', 'https://simon.slow2.test', 'https://simon.slow3.test']) {
      slow(fed, c, starts, counts);
    }
    const due = new Date(fed.clock.t).toISOString();
    await queue(gamma, 'https://simon.slow1.test', 10, 1000, due);
    await gamma.server.work();
    assert.equal(counts.peak, MAX_FETCHES_PER_CARRIER, 'one carrier never holds every slot');
    await queue(gamma, 'https://simon.slow2.test', 10, 1000, due);
    await queue(gamma, 'https://simon.slow3.test', 10, 1000, due);
    counts.peak = 0;
    await gamma.server.work();
    assert.equal(counts.peak, MAX_FETCHES);

    counts.peak = 0;
    fed.clock.advance(3600_000);
    const later = new Date(fed.clock.t).toISOString();
    for (const f of await gamma.store.fetches(later, 1000)) {
      const token = `cleanup:${f.sha256}`;
      assert.equal(
        await gamma.store.claimFetch(f, later, {
          token,
          until: new Date(fed.clock.t + 60_000).toISOString(),
        }),
        true,
      );
      assert.equal(await gamma.store.fetchDone(f.sha256, f.carrier, token), true);
    }
    await queue(gamma, 'https://simon.slow1.test', 3, 40 * 1024 * 1024, later);
    await gamma.server.work();
    assert.equal(counts.peak, 1, 'two of these would pass the byte budget');
    await fed.close();
  });

  it("never lets one carrier's backlog delay another's fetch", async () => {
    const fed = new Federation();
    const gamma = await fed.server('gamma');
    const counts = { now: 0, peak: 0 };
    const starts: string[] = [];
    slow(fed, 'https://simon.flood.test', starts, counts);
    slow(fed, 'https://simon.honest.test', starts, counts);
    const due = new Date(fed.clock.t).toISOString();
    await queue(gamma, 'https://simon.flood.test', 200, 1000, due);
    await queue(gamma, 'https://simon.honest.test', 1, 1000, new Date(fed.clock.t + 1).toISOString());
    fed.clock.advance(1);
    await gamma.server.work();
    assert.ok(
      starts.indexOf('https://simon.honest.test') < MAX_FETCHES,
      `honest started at ${starts.indexOf('https://simon.honest.test')}`,
    );
    await fed.close();
  });

  it('gives a slot that frees to a carrier with nothing underway before carriers with older backlogs', async () => {
    const fed = new Federation();
    const gamma = await fed.server('gamma');
    // A Fetcher ticked as the worker ticks it, every moment, not only once the fetches underway have ended.
    const config = defineConfig({
      origin: gamma.origin,
      hostedDomains: [gamma.domain],
      leaseDomain: gamma.leaseDomain,
      serverKey: generateKey().privateKey,
    });
    const fetcher = new Fetcher({
      config,
      store: gamma.store,
      now: fed.clock.now,
      http: fed.net,
      log: () => {},
    } as never);
    const starts: string[] = [];
    const flood = ['https://simon.flood1.test', 'https://simon.flood2.test'];
    const honest = 'https://simon.honest.test';
    // Fetches of differing lengths, so slots free one at a time.
    for (const c of [...flood, honest])
      fed.net.hosts.set(c, async () => {
        starts.push(c);
        await new Promise(r => setTimeout(r, 10 + 7 * (starts.length % 4)));
        return { status: 404, json: {} };
      });
    // Two carriers within their budget, each with an older backlog, hold every slot between them.
    for (const c of flood) await queue(gamma, c, 50, 10, new Date(fed.clock.t - 60_000).toISOString());
    assert.equal(await fetcher.tick(), MAX_FETCHES);
    await queue(gamma, honest, 1, 10, new Date(fed.clock.t).toISOString());
    while (!starts.includes(honest) && starts.length < 100) {
      await new Promise(r => setTimeout(r, 2));
      await fetcher.tick();
    }
    assert.ok(
      starts.includes(honest) && starts.indexOf(honest) <= MAX_FETCHES + flood.length,
      `the honest fetch started within a turn of every carrier, not at ${starts.indexOf(honest)}`,
    );
    await fetcher.idle();
    await fed.close();
  });

  for (const k of [MAX_FETCHES, MAX_FETCHES + 2])
    it(`starts a waiting carrier's fetch promptly while ${k} carriers within their budget keep every slot busy`, async () => {
      const fed = new Federation();
      const gamma = await fed.server('gamma');
      const config = defineConfig({
        origin: gamma.origin,
        hostedDomains: [gamma.domain],
        leaseDomain: gamma.leaseDomain,
        serverKey: generateKey().privateKey,
      });
      const fetcher = new Fetcher({
        config,
        store: gamma.store,
        now: fed.clock.now,
        http: fed.net,
        log: () => {},
      } as never);
      const starts: string[] = [];
      const flood = Array.from({ length: k }, (_, i) => `https://simon.flood${i}.test`);
      const honest = 'https://simon.honest.test';
      for (const c of [...flood, honest])
        fed.net.hosts.set(c, async () => {
          starts.push(c);
          await new Promise(r => setTimeout(r, 5 + 3 * (starts.length % 5)));
          return { status: 404, json: {} };
        });
      // Every flooder has an older backlog and finishes fetches quickly, so a slot it frees is its again unless
      // the carrier that waited longest is preferred.
      for (const c of flood) await queue(gamma, c, 100, 10, new Date(fed.clock.t - 60_000).toISOString());
      assert.equal(await fetcher.tick(), MAX_FETCHES);
      const before = starts.length;
      await queue(gamma, honest, 1, 10, new Date(fed.clock.t).toISOString());
      while (!starts.includes(honest) && starts.length < before + 200) {
        await new Promise(r => setTimeout(r, 1));
        await fetcher.tick();
      }
      const waited = starts.indexOf(honest) - before;
      assert.ok(starts.includes(honest) && waited <= MAX_FETCHES, `the honest fetch started after ${waited} others`);
      await fetcher.idle();
      await fed.close();
    });

  it(`queues at most ${MAX_PENDING_FETCHES_PER_CARRIER} fetches for one carrier, and gives up the rest at once`, async () => {
    const fed = new Federation();
    const gamma = await fed.server('gamma');
    const ada = await gamma.agent('ada');
    const carrier = 'https://simon.flood.test';
    const due = new Date(fed.clock.t + 3600_000).toISOString();
    // The queue helper names each hash by size and index: a size per batch keeps every hash distinct.
    for (let i = 0; i < MAX_PENDING_FETCHES_PER_CARRIER / 256; i++) await queue(gamma, carrier, 256, 10 + i, due);
    const pending = async () =>
      (await gamma.store.fetches(new Date(fed.clock.t + 7200_000).toISOString(), 100_000)).length;
    const full = await pending();
    assert.equal(full, MAX_PENDING_FETCHES_PER_CARRIER);
    const sha = sha256Hex('one more');
    const record = {
      id: 'f'.repeat(64),
      message: ada.message([ada.address], 'x', { parts: [TEXT, { type: 'application/pdf', sha256: sha, size: 5 }] }),
      carrier,
      claims: [],
      signedClaims: null,
      receivedAt: new Date(fed.clock.t).toISOString(),
      expiresAt: new Date(fed.clock.t + 86_400_000).toISOString(),
    };
    const ctx = { config: gamma.server.api.config, store: gamma.store, now: fed.clock.now, wake: () => {} };
    await queuePrefetch(ctx as never, record as never);
    assert.equal(await pending(), full, 'no row past the cap');
    const now = new Date(fed.clock.t).toISOString();
    assert.equal(await gamma.store.marked('part-given-up', `${sha} ${carrier}`, now), true, 'given up, so read as 404');
    await fed.close();
  });

  it('never lets carriers past their budget hold the due fetches another is waiting behind', async () => {
    const fed = new Federation();
    const gamma = await fed.server('gamma', { config: { fetchBytesPerHour: 1000 } });
    const counts = { now: 0, peak: 0 };
    const starts: string[] = [];
    const due = new Date(fed.clock.t).toISOString();
    // 64 carriers, each declaring two parts of its whole hour's budget: after one attempt each, the rest wait.
    for (let i = 0; i < 64; i++) {
      slow(fed, `https://simon.flood${i}.test`, starts, counts);
      await queue(gamma, `https://simon.flood${i}.test`, 2, 1000, due);
    }
    slow(fed, 'https://simon.honest.test', starts, counts);
    await queue(gamma, 'https://simon.honest.test', 1, 1000, new Date(fed.clock.t + 1).toISOString());
    for (let minute = 0; minute < 30 && !starts.includes('https://simon.honest.test'); minute++) {
      fed.clock.advance(60_000);
      await gamma.server.work();
    }
    assert.ok(starts.includes('https://simon.honest.test'), 'the honest fetch started within 30 minutes');
    await fed.close();
  });

  it("releases a carrier's slot only while it still holds it", async () => {
    const fed = new Federation();
    const SLOT = 'part-fetch-slot';
    // Whenever this process is about to see whether it still holds a slot, another takes the slot first.
    const gamma = await fed.server('gamma', {
      wrapStore: target =>
        new Proxy(target, {
          get(t, name) {
            const value = Reflect.get(t, name);
            if (typeof value !== 'function') return value;
            if (name !== 'value' && name !== 'releaseValue') return value.bind(t);
            return async (scope: string, id: string, ...rest: unknown[]) => {
              const takeover = () => t.setValue(scope, id, 'another', new Date(fed.clock.t + 3600_000).toISOString());
              if (scope === SLOT && name === 'releaseValue') await takeover();
              const answer = await (value as (...a: unknown[]) => unknown).call(t, scope, id, ...rest);
              if (scope === SLOT && name === 'value') await takeover();
              return answer;
            };
          },
        }),
    });
    fed.net.hosts.set('https://simon.slow1.test', async () => ({ status: 404, json: {} }));
    await queue(gamma, 'https://simon.slow1.test', 1, 500, new Date(fed.clock.t).toISOString());
    await gamma.server.work();
    const now = new Date(fed.clock.t).toISOString();
    assert.equal(
      await gamma.store.value(SLOT, 'https://simon.slow1.test 0', now),
      'another',
      "the other's slot stands",
    );
    await fed.close();
  });

  it('never runs a fetch from a row read before another process settled it', async () => {
    const fed = new Federation();
    const first = await fed.server('gamma');
    // The second process reads the due fetches, then waits until the first has run them before going on.
    let resume!: () => void;
    const paused = new Promise<void>(r => (resume = r));
    const second = await fed.server('gamma2', {
      wrapStore: () =>
        new Proxy(first.store, {
          get(target, name) {
            const value = Reflect.get(target, name);
            if (name !== 'fetches') return typeof value === 'function' ? value.bind(target) : value;
            return async (...args: [string, number]) => {
              const rows = await target.fetches(...args);
              await paused;
              return rows;
            };
          },
        }),
    });
    const requests: string[] = [];
    fed.net.hosts.set('https://simon.slow1.test', async req => (requests.push(req.path), { status: 404, json: {} }));
    await queue(first, 'https://simon.slow1.test', 1, 500, new Date(fed.clock.t).toISOString());
    const late = second.server.work();
    await first.server.work();
    resume();
    await late;
    assert.equal(requests.length, 1, 'the second process skipped its stale row');
    const [row] = await first.store.fetches(new Date(fed.clock.t + 3600_000).toISOString(), 10);
    assert.equal(row.attempts, 1, 'one attempt spent, its backoff kept');
    await fed.close();
  });

  it('renews the claim of a fetch that outlasts its lease, so no other process runs it meanwhile', async () => {
    const fed = new Federation();
    const second = await fed.server('gamma');
    // The first process's store takes the fetched bytes only once the test lets it: a store slow to write.
    let written!: () => void;
    const slowWrite = new Promise<void>(r => (written = r));
    const first = await fed.server('gamma1', {
      wrapStore: () =>
        new Proxy(second.store, {
          get(target, name) {
            const value = Reflect.get(target, name);
            if (name !== 'putPart') return typeof value === 'function' ? value.bind(target) : value;
            return async (...args: Parameters<Store['putPart']>) => (await slowWrite, target.putPart(...args));
          },
        }),
    });
    const files = [1, 2, 3].map(i => Buffer.from(`slow to store ${i}`));
    const requests: string[] = [];
    fed.net.hosts.set('https://simon.slow1.test', async req => {
      requests.push(req.path);
      return { status: 200, bytes: files.find(b => req.path.endsWith(sha256Hex(b)))! };
    });
    for (const b of files) {
      await second.store.queueFetch({
        sha256: sha256Hex(b),
        carrier: 'https://simon.slow1.test',
        size: b.length,
        attempts: 0,
        dueAt: new Date(fed.clock.t).toISOString(),
      });
    }
    const running = first.server.work();
    await new Promise(r => setTimeout(r, 50));
    assert.equal(requests.length, MAX_FETCHES_PER_CARRIER, "the carrier's two slots taken");
    const bytes = files[0];
    // Three minutes pass by the servers' clock, more than a lease, while the first process still writes.
    for (let i = 0; i < 3; i++) {
      fed.clock.advance(61_000);
      await new Promise(r => setTimeout(r, 400));
    }
    await second.server.work();
    assert.equal(
      requests.length,
      MAX_FETCHES_PER_CARRIER,
      'the other process found both fetches still claimed, and both slots still held',
    );
    written();
    await running;
    assert.deepEqual(await second.store.part(sha256Hex(bytes), { carrier: 'https://simon.slow1.test' }), bytes);
    await fed.close();
  });

  it('logs lost ownership and leaves a successor fetch claim intact', async () => {
    const fed = new Federation();
    const second = await fed.server('gamma');
    let written!: () => void;
    const slowWrite = new Promise<void>(r => (written = r));
    let entered!: () => void;
    const writing = new Promise<void>(r => (entered = r));
    let lost!: () => void;
    const ownershipLost = new Promise<void>(r => (lost = r));
    const logged: string[] = [];
    const first = await fed.server('gamma1', {
      log: (_, message) => {
        logged.push(message);
        if (message === 'part fetch ownership lost') lost();
      },
      wrapStore: () =>
        new Proxy(second.store, {
          get(target, name) {
            const value = Reflect.get(target, name);
            if (name !== 'putPart') return typeof value === 'function' ? value.bind(target) : value;
            return async (...args: Parameters<Store['putPart']>) => {
              entered();
              await slowWrite;
              return target.putPart(...args);
            };
          },
        }),
    });
    const bytes = Buffer.from('claimed away');
    fed.net.hosts.set('https://simon.slow1.test', async () => ({ status: 200, bytes }));
    const f = { sha256: sha256Hex(bytes), carrier: 'https://simon.slow1.test', size: bytes.length, attempts: 0 };
    await second.store.queueFetch({ ...f, dueAt: new Date(fed.clock.t).toISOString() });
    const running = first.server.work();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        writing,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error('fetch did not reach its write gate')), 2000);
        }),
      ]);
      clearTimeout(timer);
      // Advance beyond the full lease and claim synchronously before the old renewal timer can run.
      fed.clock.advance(121_000);
      const now = fed.clock.now().toISOString();
      const snapshot = (await second.store.fetches(now, 10)).find(row => row.sha256 === f.sha256)!;
      assert.ok(snapshot, 'the original lease has expired');
      const successor = 'successor-claim';
      assert.equal(
        await second.store.claimFetch(snapshot, now, {
          token: successor,
          until: new Date(fed.clock.t + 120_000).toISOString(),
        }),
        true,
      );
      await Promise.race([
        ownershipLost,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error(`ownership loss not observed: ${JSON.stringify(logged)}`)), 2000);
        }),
      ]);
      clearTimeout(timer);
      written();
      await running;
      // A stale successful fetch must not delete or defer the successor's row.
      assert.equal(await second.store.fetchDone(f.sha256, f.carrier, successor), true);
      assert.deepEqual(await second.store.part(f.sha256, { carrier: f.carrier }), bytes);
    } finally {
      clearTimeout(timer);
      written();
      await running;
      await fed.close();
    }
  });

  it('keeps one budget and one per-carrier cap for every process on a store, across restarts', async () => {
    const fed = new Federation();
    const config = { fetchBytesPerHour: 2000 };
    const first = await fed.server('gamma', { config });
    const process = (name: string) => fed.server(name, { config, wrapStore: () => first.store });
    const [second, third] = [await process('gamma2'), await process('gamma3')];
    const counts = { now: 0, peak: 0 };
    const starts: string[] = [];
    const fetched: string[] = [];
    fed.net.hosts.set('https://simon.slow1.test', async req => {
      starts.push(req.path);
      fetched.push(req.path);
      counts.peak = Math.max(counts.peak, ++counts.now);
      await new Promise(r => setTimeout(r, 20));
      counts.now--;
      return { status: 404, json: {} };
    });
    await queue(first, 'https://simon.slow1.test', 6, 500, new Date(fed.clock.t).toISOString());
    await Promise.all([first.server.work(), second.server.work()]);
    assert.ok(counts.peak <= MAX_FETCHES_PER_CARRIER, `${counts.peak} at once from one carrier, across processes`);
    assert.equal(starts.length, 4, 'four of 500 bytes fill the hour of 2000, whichever process ran them');
    assert.equal(new Set(fetched).size, fetched.length, 'and no two processes ran the same fetch');
    await third.server.work();
    assert.equal(starts.length, 4, 'a process started afresh spends the same budget');
    fed.clock.advance(3600_000);
    await third.server.work();
    assert.ok(starts.length > 4, 'the next hour, fetches go on');
    await fed.close();
  });
});

describe('an agent here whose domain cannot be resolved for now', () => {
  it('is answered 503 for its own file, as for any other, never a final 404', async () => {
    const fed = new Federation();
    const alpha = await fed.server('alpha');
    fed.dns.point('own.test', alpha.origin);
    const cy = alpha.newAgent();
    // An address on a domain of its own is bound by the code mailed to it.
    assert.equal((await cy.register({ address: 'cy@own.test' })).status, 202);
    const registered = await cy.register({ address: 'cy@own.test', code: alpha.code('cy@own.test') });
    assert.equal(registered.status, 200, JSON.stringify(registered.json));
    const bytes = Buffer.from('cy wrote this');
    await cy.upload(bytes);
    assert.equal((await cy.part(sha256Hex(bytes))).status, 200);
    fed.dns.failing.add('_simon.own.test');
    fed.clock.advance(11 * 60_000);
    assert.equal((await cy.part(sha256Hex(bytes))).status, 503, 'its own file, while the lookup fails');
    assert.equal((await cy.part('0'.repeat(64))).status, 503, 'and a file it has not, alike');
    fed.dns.failing.delete('_simon.own.test');
    fed.clock.advance(2 * 60_000);
    assert.equal((await cy.part(sha256Hex(bytes))).status, 200);
    await fed.close();
  });
});
