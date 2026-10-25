/**
 * Spec section 4 (documents) and the publishing profile (public messages), as this server serves them.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import {
  addressSegment,
  generateKey,
  keyToken,
  messageId,
  readAgentDocument,
  readServerDocument,
  sha256Hex,
  signRequest,
  type AnyMessage,
} from '@agnt-sdk/simon-protocol';
import type { Extension } from '../src/extensions.ts';
import { replyBody } from '../src/testing.ts';
import { Federation, toRequest, type TestAgent } from './harness.ts';

const TEXT = { type: 'text/plain', data: 'x' };

describe('documents (spec section 4)', async () => {
  const fed = new Federation();
  after(() => fed.close());
  const next = generateKey().privateKey;
  // Serving retired documents is the explicit `public` opt-in; the private default is covered in
  // public-document-policy.test.ts.
  const alpha = await fed.server('alpha', { config: { nextServerKey: next, retiredAgentDocuments: 'public' } });
  const ada = await alpha.agent('ada');

  it('serves a server document naming its own origin, both keys, its algorithms and its limits', async () => {
    const res = await ada.request('GET', '/simon/server', { sign: false });
    const doc = readServerDocument(res.bytes, alpha.origin, fed.clock.now());
    assert.ok(doc, 'readable');
    assert.deepEqual(doc.algorithms, ['ed25519', 'ml-dsa-65']);
    assert.equal(doc.keys.length, 2);
    assert.equal(doc.keys[1].key, keyToken(next), 'the announced key is listed before it signs');
    assert.deepEqual(doc.limits, {
      messageBytes: 262144,
      recipients: 100,
      requestBodyBytes: 1048576,
      partBytes: 26214400,
    });
    fed.clock.advance(3_600_000);
    const again = await ada.request('GET', '/simon/server', { sign: false });
    assert.deepEqual(again.json.keys, res.json.keys, "a key's added never moves");
  });

  it('reads an address in a path percent-encoded as addressSegment writes it, and signs the target as sent', async () => {
    const odd = alpha.newAgent();
    const address = 'a#b%c/d?e^f`g{h|i}j@alpha.test';
    assert.equal((await odd.register({ address })).status, 200);
    const segment = addressSegment(address);
    assert.equal(segment, 'a%23b%25c%2Fd%3Fe%5Ef%60g%7Bh%7Ci%7Dj@alpha.test');
    const doc = await ada.request('GET', `/simon/agents/${segment}`, { sign: false });
    assert.deepEqual([doc.status, doc.json.address], [200, address]);
    // The odd agent's own signed call, with its address in simon-agent and in the target.
    const feed = await odd.request('GET', `/simon/feeds/${segment}/posts`);
    assert.equal(feed.status, 200);
    // A target rewritten after signing, to bytes that decode the same (%31 is 1), no longer verifies: the
    // target is checked as sent, before any decoding (spec section 8).
    const inbox = new URL(`${alpha.origin}/simon/sync?limit=1`);
    const signedInbox = signRequest(odd.key, { method: 'GET', url: inbox.href, now: fed.clock.t, agent: address });
    assert.equal(
      (await alpha.server.handle(toRequest('GET', inbox, signedInbox, Buffer.alloc(0), '192.0.2.50'))).status,
      200,
    );
    const moved = new URL(`${alpha.origin}/simon/sync?limit=%31`);
    const replayed = await alpha.server.handle(toRequest('GET', moved, signedInbox, Buffer.alloc(0), '192.0.2.50'));
    assert.equal((replayed.json as { code: string }).code, 'bad_signature');
  });

  it('serves an agent document signed by the server, and 404 for an unknown address', async () => {
    const server = readServerDocument(
      (await ada.request('GET', '/simon/server', { sign: false })).bytes,
      alpha.origin,
      fed.clock.now(),
    )!;
    const res = await ada.request('GET', `/simon/agents/${ada.address}`, { sign: false });
    const doc = readAgentDocument(res.bytes, ada.address, server.keys, fed.clock.now());
    assert.deepEqual(doc && { keys: doc.keys.map(k => k.key) }, { keys: [ada.token] });
    assert.equal(res.json.kind, undefined, 'the document says nothing of whom the agent speaks for');
    const unknown = await ada.request('GET', '/simon/agents/nobody@alpha.test', { sign: false });
    assert.equal(unknown.status, 404);
    assert.equal(unknown.json.code, 'not_found');
  });

  it('serves a retired address its retired document, and never registers it again', async () => {
    const cat = await alpha.agent('cat');
    await alpha.server.api.retire(cat.address);
    const res = await cat.request('GET', `/simon/agents/${cat.address}`, { sign: false });
    assert.equal(res.status, 200);
    const server = readServerDocument(
      (await cat.request('GET', '/simon/server', { sign: false })).bytes,
      alpha.origin,
      fed.clock.now(),
    )!;
    const read = readAgentDocument(res.bytes, cat.address, server.keys, fed.clock.now());
    assert.ok(read?.retired, 'a readable retired document');
    assert.equal(read.unpairing, undefined, 'no unpairing retired it');
    assert.deepEqual(
      read.keys.map(k => [k.key, k.revoked]),
      [[cat.token, read.retired]],
    );
    const denied = await cat.sync();
    assert.deepEqual([denied.status, denied.json.code], [401, 'key_revoked']);
    const again = await alpha.newAgent().register({ address: cat.address });
    assert.equal(again.json.code, 'address_taken');
  });

  it('states retired no earlier than its latest revocation, so clocks out of step leave it readable', async () => {
    await alpha.store.createAgent({
      address: 'skew@alpha.test',
      kind: 'solo',
      principal: null,
      keys: [
        {
          key: keyToken(generateKey().privateKey),
          added: '2026-10-01T00:00:00.000Z',
          revoked: '2026-10-02T00:00:05.000Z',
        },
      ],
      mailbox: false,
      createdAt: '2026-10-01T00:00:00.000Z',
      retiredAt: '2026-10-02T00:00:00.000Z',
    });
    const res = await ada.request('GET', '/simon/agents/skew@alpha.test', { sign: false });
    const server = readServerDocument(
      (await ada.request('GET', '/simon/server', { sign: false })).bytes,
      alpha.origin,
      fed.clock.now(),
    )!;
    const read = readAgentDocument(res.bytes, 'skew@alpha.test', server.keys, fed.clock.now());
    assert.equal(read?.retired, '2026-10-02T00:00:05.000Z');
  });

  it('lists all active keys and only the newest history within 32 total entries', async () => {
    const keys = Array.from({ length: 40 }, (_, i) => ({
      key: keyToken(generateKey().privateKey),
      added: '2026-10-01T00:00:00.000Z',
      revoked: i < 36 ? '2026-10-02T00:00:00.000Z' : null,
    }));
    await alpha.store.createAgent({
      address: 'many@alpha.test',
      kind: 'solo',
      principal: null,
      keys,
      mailbox: false,
      createdAt: '2026-10-01T00:00:00.000Z',
      retiredAt: null,
    });
    const res = await ada.request('GET', '/simon/agents/many@alpha.test', { sign: false });
    assert.deepEqual(
      res.json.keys.map((k: { key: string }) => k.key),
      keys.slice(-32).map(k => k.key),
    );
    const server = readServerDocument(
      (await ada.request('GET', '/simon/server', { sign: false })).bytes,
      alpha.origin,
      fed.clock.now(),
    )!;
    assert.ok(readAgentDocument(res.bytes, 'many@alpha.test', server.keys, fed.clock.now()), 'readable');
  });

  it('retains future-revoked keys under count pressure and fails closed if active keys exceed the bound', async () => {
    const added = new Date(fed.clock.t - 60_000).toISOString();
    const future = new Date(fed.clock.t + 60_000).toISOString();
    const past = new Date(fed.clock.t - 1_000).toISOString();
    const keys = Array.from({ length: 33 }, (_, i) => ({
      key: keyToken(generateKey().privateKey),
      added,
      revoked: i === 0 ? future : past,
    }));
    const account = {
      address: 'future@alpha.test',
      kind: 'solo' as const,
      principal: null,
      keys,
      mailbox: false,
      createdAt: added,
      retiredAt: null,
    };
    assert.equal(await alpha.store.createAgent(account), 'created');
    const res = await ada.request('GET', '/simon/agents/future@alpha.test', { sign: false });
    assert.equal(res.status, 200);
    assert.equal(res.json.keys.length, 32);
    assert.equal(res.json.keys[0].key, keys[0].key, 'the oldest entry is still valid now');
    assert.equal(
      res.json.keys.some((k: { key: string }) => k.key === keys[1].key),
      false,
    );
    assert.equal(
      await alpha.store.createAgent({
        ...account,
        address: 'future-full@alpha.test',
        keys: Array.from({ length: 33 }, () => ({ key: generateKey().key, added, revoked: future })),
      }),
      'created',
    );
    const full = await ada.request('GET', '/simon/agents/future-full@alpha.test', { sign: false });
    assert.equal(full.status, 503, 'publication cannot silently drop a still-valid key');
  });

  it('never prunes future-revoked keys to fit the final signed byte bound', async () => {
    const added = new Date(fed.clock.t - 60_000).toISOString();
    const future = new Date(fed.clock.t + 60_000).toISOString();
    await alpha.store.createAgent({
      address: 'future-bytes@alpha.test',
      kind: 'solo',
      principal: null,
      keys: ['A', 'B'].map(c => ({ key: `future:${c.repeat(90_000)}`, added, revoked: future })),
      mailbox: false,
      createdAt: added,
      retiredAt: null,
    });
    const res = await ada.request('GET', '/simon/agents/future-bytes@alpha.test', { sign: false });
    assert.equal(res.status, 503, 'all still-valid keys must fit together or publication fails closed');
  });

  it('bounds retained post-quantum history by both total key count and final signed bytes', async () => {
    const pq = (revoked: string | null) => ({
      key: generateKey('ml-dsa-65').key,
      added: '2026-10-01T00:00:00.000Z',
      revoked,
    });
    const keys = [...Array.from({ length: 60 }, () => pq('2026-10-02T00:00:00.000Z')), pq(null)];
    await alpha.store.createAgent({
      address: 'pq@alpha.test',
      kind: 'solo',
      principal: null,
      keys,
      mailbox: false,
      createdAt: '2026-10-01T00:00:00.000Z',
      retiredAt: null,
    });
    const res = await ada.request('GET', '/simon/agents/pq@alpha.test', { sign: false });
    assert.ok(res.bytes.length <= 131072, `${res.bytes.length} bytes`);
    const listed = res.json.keys.map((k: { key: string }) => k.key);
    assert.equal(listed.length, 32);
    assert.deepEqual(
      listed,
      keys.slice(-listed.length).map(k => k.key),
      'the newest kept, the active key among them',
    );
    const server = readServerDocument(
      (await ada.request('GET', '/simon/server', { sign: false })).bytes,
      alpha.origin,
      fed.clock.now(),
    )!;
    assert.ok(readAgentDocument(res.bytes, 'pq@alpha.test', server.keys, fed.clock.now()), 'readable');
  });
});

describe('public messages (publishing profile, section 1)', async () => {
  const fed = new Federation();
  after(() => fed.close());
  const alpha = await fed.server('alpha');
  const beta = await fed.server('beta');
  const ada = await alpha.agent('ada');
  const bob = await beta.agent('bob');

  it('serves a public message to anyone, with no keys beside it, and lists no replies, which may be private', async () => {
    const post = ada.message([], 'A public post.');
    const { json: sent } = await ada.send(post);
    await bob.send(bob.message([ada.address], 'A private reply.', { inReplyTo: sent.id }));
    await fed.work();

    const res = await ada.request('GET', `/simon/messages/${sent.id}`, { sign: false });
    assert.equal(res.status, 200);
    assert.deepEqual(res.json, { message: post });
  });

  it('stops serving the public messages and parts of a retired agent (spec section 2.2)', async () => {
    const pat = await alpha.agent('pat');
    const bytes = Buffer.from('a public picture');
    await pat.upload(bytes);
    const sha256 = sha256Hex(bytes);
    const { json } = await pat.send(
      pat.message([], 'look', { parts: [TEXT, { type: 'image/png', sha256, size: bytes.length }] }),
    );
    const read = async () => [
      (await ada.request('GET', `/simon/messages/${json.id}`, { sign: false })).status,
      (await ada.request('GET', `/simon/parts/${sha256}`, { sign: false })).status,
    ];
    assert.deepEqual(await read(), [200, 200]);
    await alpha.server.api.retire(pat.address);
    assert.deepEqual(await read(), [404, 404]);
  });

  it('lists only the relations their writers marked listed, and drops one its writer retracts (publishing profile, section 4)', async () => {
    const { json: sent } = await ada.send(ada.message([], 'A post to comment on.'));
    const relate = (text: string, headers: Record<string, string>, inReplyTo = sent.id) =>
      bob.message([ada.address], text, { inReplyTo, headers });
    const listed = relate('Listed.', { rel: 'comment', listed: 'yes' });
    const unmarked = relate('Not marked.', { rel: 'comment' });
    const reply = bob.message([ada.address], 'A plain reply.', { inReplyTo: sent.id });
    for (const m of [listed, unmarked, reply]) assert.equal((await bob.send(m)).status, 200);
    await fed.work();
    const related = async () =>
      (await ada.request('GET', `/simon/messages/${sent.id}/related`, { sign: false })).json.messages.map(
        (m: AnyMessage) => messageId(m),
      );
    assert.deepEqual(await related(), [messageId(listed)]);
    // A marked relation to a message that is not the one listed, and a writer's retraction of its comment.
    const { json: retract } = await bob.send(
      bob.message([ada.address], '', { inReplyTo: messageId(listed), headers: { rel: 'retract' } }),
    );
    assert.ok(retract.id);
    await fed.work();
    assert.deepEqual(await related(), []);
  });

  it('answers 404 for a message that is not public', async () => {
    const { json } = await ada.send(ada.message([bob.address], 'private'));
    const res = await ada.request('GET', `/simon/messages/${json.id}`, { sign: false });
    assert.equal(res.status, 404);
  });
});

describe('readers of a published message with an audience (spec sections 7.1 and 8)', async () => {
  const fed = new Federation();
  after(() => fed.close());
  // An application's audience: "friends" admits bob, wherever bob is served.
  const friends: Extension = {
    name: 'friends',
    admitsReader: ({ audience, reader }) =>
      audience === 'friends' && reader?.startsWith('bob@') ? 'admit' : undefined,
  };
  const alpha = await fed.server('alpha', { extensions: [friends] });
  const beta = await fed.server('beta');
  const ada = await alpha.agent('ada');
  const bob = await beta.agent('bob');
  const eve = await beta.agent('eve');
  const { json: sent } = await ada.send(ada.message([], 'for friends', { headers: { audience: 'friends' } }));
  const target = `/simon/messages/${sent.id}`;

  /** A read of the post at ada's server, signed with `signer`'s key and naming `as` in simon-agent. */
  const read = (signer: TestAgent, as = signer.address, at = alpha) => {
    const url = new URL(at.origin + target);
    const headers = signRequest(signer.key, { method: 'GET', url: url.href, now: fed.clock.t, agent: as });
    return at.server.handle(toRequest('GET', url, { ...headers }, Buffer.alloc(0), '192.0.2.9'));
  };

  it('serves it to a reader on another server that signs with its own agent key', async () => {
    const res = await read(bob);
    assert.equal(res.status, 200);
  });

  it('serves it to its author, and to nobody in particular never', async () => {
    assert.equal((await read(ada)).status, 200);
    assert.equal((await ada.request('GET', target, { sign: false })).status, 404);
  });

  it('answers a reader its audience refuses as it answers a message that does not exist', async () => {
    const refused = await read(eve);
    const missing = await ada.request('GET', `/simon/messages/${'0'.repeat(64)}`, { sign: false });
    assert.equal(refused.status, 404);
    assert.deepEqual(replyBody(refused), missing.bytes);
  });

  it("never takes a reader on its word: another agent's name over one's own key reads as nobody", async () => {
    assert.equal((await read(eve, bob.address)).status, 404, "eve's key is not in bob's document");
    const url = new URL(alpha.origin + target);
    const signed = signRequest(bob.key, { method: 'GET', url: url.href, now: fed.clock.t, agent: bob.address });
    const renamed = { ...signed, 'simon-agent': eve.address };
    const res = await alpha.server.handle(toRequest('GET', url, renamed, Buffer.alloc(0), '192.0.2.9'));
    assert.equal(res.status, 404, 'the actor line is signed, so renaming the reader breaks the signature');
    const asServer = { ...signed, 'simon-agent': undefined as never, 'simon-server': beta.origin };
    const vouched = await alpha.server.handle(toRequest('GET', url, asServer, Buffer.alloc(0), '192.0.2.9'));
    assert.equal(vouched.status, 404, 'no server vouches for a reader');
  });

  it("fetches a signed reader's document whatever it asks for, so the fetches tell no one what has an audience", async () => {
    const bytes = Buffer.from('a file only friends see');
    await ada.upload(bytes);
    const limited = sha256Hex(bytes);
    await ada.send(
      ada.message([], 'a file', {
        headers: { audience: 'friends' },
        parts: [TEXT, { type: 'image/png', sha256: limited, size: bytes.length }],
      }),
    );
    const { json: pub } = await ada.send(ada.message([], 'for anyone'));
    let n = 0;
    /** The reader's document fetches a signed GET by a new agent on beta causes, and the answer's status. */
    const probe = async (path: string) => {
      const reader = await beta.agent(`probe${n++}`);
      const url = new URL(alpha.origin + path);
      const headers = signRequest(reader.key, {
        method: 'GET',
        url: url.href,
        now: fed.clock.t,
        agent: reader.address,
      });
      const before = fed.net.sent.length;
      const res = await alpha.server.handle(toRequest('GET', url, { ...headers }, Buffer.alloc(0), '192.0.2.9'));
      const fetches = fed.net.sent.slice(before).filter(r => r.url.startsWith(`${beta.origin}/simon/agents/`));
      return `${res.status} ${fetches.length}`;
    };
    assert.equal(await probe(`/simon/messages/${'0'.repeat(64)}`), '404 1', 'an unknown id');
    assert.equal(await probe(target), '404 1', 'an audience-limited id');
    assert.equal(await probe(`/simon/messages/${pub.id}`), '200 1', 'a public post');
    assert.equal(await probe(`/simon/feeds/${ada.address}/nothing`), '200 1', 'an empty feed');
    assert.equal(await probe(`/simon/feeds/nobody@alpha.test/posts`), '200 1', "an unknown agent's feed");
    assert.equal(await probe(`/simon/parts/${'0'.repeat(64)}`), '404 1', 'an unknown part');
    assert.equal(await probe(`/simon/parts/${limited}`), '404 1', "an audience-limited post's part");
  });

  it('serves the files of a post to the readers it admits, and to no one else', async () => {
    const bytes = Buffer.from('a picture for friends');
    await ada.upload(bytes);
    const sha256 = sha256Hex(bytes);
    await ada.send(
      ada.message([], 'look', {
        headers: { audience: 'friends' },
        parts: [TEXT, { type: 'image/png', sha256, size: bytes.length }],
      }),
    );
    const url = new URL(`${alpha.origin}/simon/parts/${sha256}`);
    const fetchAs = (signer: TestAgent) =>
      alpha.server.handle(
        toRequest(
          'GET',
          url,
          { ...signRequest(signer.key, { method: 'GET', url: url.href, now: fed.clock.t, agent: signer.address }) },
          Buffer.alloc(0),
          '192.0.2.9',
        ),
      );
    assert.equal((await fetchAs(bob)).status, 200);
    assert.equal((await fetchAs(eve)).status, 404);
    const [bobHere, eveHere] = [await alpha.agent('bob'), await alpha.agent('eve')];
    assert.equal((await fetchAs(bobHere)).status, 200, 'an agent here its audience admits');
    assert.equal((await fetchAs(eveHere)).status, 404, 'an agent here its audience refuses');
  });
});
