/**
 * The reader profile, live: a reader's rules are not a server's to show, so the conformance suite only checks
 * that a server carries what readers act on (`reading.*`). This runs the readers themselves, the JavaScript
 * client's `verifyAuthor` and the protocol library's `readsAs`, over entries the reference server kept and its
 * sync returned: `critical`, a relation the reader does not know, and a relation that names nothing.
 */
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import {
  canonicalize,
  messageId,
  PROTOCOL_HEADERS,
  readsAs,
  type Message,
  type ResolverIO,
} from '@agnt-sdk/simon-protocol';
import { verifyAuthor } from '../../clients/js/src/read.ts';
import type { Fetch } from '../../clients/js/src/http.ts';
import { replyBody, toRequest } from '../../server/src/testing.ts';
import { Federation, type TestAgent, type TestServer } from '../../server/test/harness.ts';

describe('readers over what the reference server kept', () => {
  const fed = new Federation();
  let alpha: TestServer;
  let ada: TestAgent;
  let bob: TestAgent;

  // The client reaches the server as it would over HTTPS: through the server's own request handler.
  const fetch: Fetch = async (url, init) => {
    const u = new URL(url);
    const reply = await alpha.server.handle(
      toRequest(init?.method ?? 'GET', u, {}, Buffer.from((init?.body as string | undefined) ?? ''), '192.0.2.77'),
    );
    return new Response(new Uint8Array(replyBody(reply)), { status: reply.status, headers: reply.headers });
  };
  const resolver: ResolverIO = { txt: name => fed.dns.txt(name), get: async () => null };
  const opts = () => ({ fetch, resolver, now: fed.clock.now });

  before(async () => {
    alpha = await fed.server('alpha');
    ada = await alpha.agent('ada');
    bob = await alpha.agent('bob');
  });
  after(() => fed.close());

  /** ada sends bob a message; what bob's sync shows, and what the server must have left of it. */
  async function kept(message: Message) {
    const res = await ada.send(message);
    assert.equal(res.status, 200, JSON.stringify(res.json));
    await fed.work();
    const entry = (await bob.received()).find(e => e.id === messageId(message));
    assert.ok(entry, 'the message reached the recipient');
    assert.equal(canonicalize(entry.message), canonicalize(message), 'the server kept the message byte for byte');
    return entry;
  }

  it('presents a message whose critical header lists a header it does not know as not understood', async () => {
    const entry = await kept(
      ada.message([bob.address], 'needs a feature', {
        headers: { critical: 'x-future-feature', 'x-future-feature': 'yes' },
      }),
    );
    const trust = await verifyAuthor(entry.message, opts());
    assert.ok(trust.verified, 'the signature still verifies: whose key signed it is all a reader may say');
    assert.equal(trust.understood, false);
    assert.equal(trust.principal, null);
  });

  it('understands a critical header it implements, and ignores one the message does not carry', async () => {
    const known = PROTOCOL_HEADERS.find(h => h === 'rel')!;
    const withKnown = await kept(
      ada.message([bob.address], 'a relation, critical', { headers: { critical: known, rel: 'comment' } }),
    );
    const absent = await kept(ada.message([bob.address], 'nothing there', { headers: { critical: 'x-not-here' } }));
    for (const entry of [withKnown, absent]) {
      const trust = await verifyAuthor(entry.message, opts());
      assert.ok(trust.verified);
      assert.equal(trust.understood, true);
    }
  });

  it('reads a relation it does not know as a reply, and a rel that names nothing as a reply', async () => {
    const parent = await kept(ada.message([bob.address], 'the message replied to'));
    const known = new Set(['comment', 'reaction', 'edit', 'retract', 'vote']);
    const unknown = await kept(
      ada.message([bob.address], 'a new kind of relation', {
        inReplyTo: parent.id,
        headers: { rel: 'x-future-relation' },
      }),
    );
    const loose = await kept(ada.message([bob.address], 'a rel that names nothing', { headers: { rel: 'reaction' } }));
    const reaction = await kept(
      ada.message([bob.address], 'a thumbs up', { inReplyTo: parent.id, headers: { rel: 'reaction' } }),
    );
    assert.equal(readsAs(unknown.message, parent.message, known), 'reply');
    assert.equal(readsAs(loose.message, null, known), 'reply');
    assert.equal(readsAs(reaction.message, parent.message, known), 'relation');
  });
});
