/** Execute the core publication/feed vectors through the reference routes; cursors remain opaque. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { it } from 'node:test';
import { messageId, type AnyMessage } from '@agnt-sdk/simon-protocol';
import { Federation } from './harness.ts';

const v = JSON.parse(fs.readFileSync(new URL('../../spec/vectors/v1.json', import.meta.url), 'utf8')).publications;
it('returns the published signed claims and follows every opaque feed page', async () => {
  const fed = new Federation();
  try {
    const home = await fed.server('fixture');
    const r = v.post.response;
    await home.store.createAgent({
      address: r.message.from,
      kind: 'paired',
      principal: r.message.headers.for,
      keys: r.keys,
      mailbox: false,
      createdAt: r.message.sentAt,
      retiredAt: null,
    });
    for (const m of v.feed.stored) {
      await home.store.putMessage({
        id: messageId(m),
        message: m,
        carrier: home.origin,
        claims: r.claims,
        signedClaims: messageId(m) === v.post.id ? { claims: r.claims, signature: r.claimsSignature } : null,
        receivedAt: m.sentAt,
        expiresAt: '2099-01-01T00:00:00Z',
      });
    }
    const caller = home.newAgent();
    const result = await caller.request('GET', `/simon/messages/${v.post.id}`, { sign: false });
    assert.equal(result.status, 200);
    assert.deepEqual(result.json, r);
    let cursor: string | null = null;
    for (const page of v.feed.pages) {
      const query = `?limit=${page.limit}${cursor ? `&before=${encodeURIComponent(cursor)}` : ''}`;
      const got = await caller.request('GET', `/simon/feeds/${v.feed.address}/${v.feed.name}${query}`, { sign: false });
      assert.equal(got.status, 200);
      assert.deepEqual(
        got.json.messages.map((m: AnyMessage) => messageId(m)),
        page.messageIds,
      );
      assert.equal(got.json.more, page.more);
      assert.equal(got.json.cursor !== null, page.more);
      if (page.more) assert.match(got.json.cursor, /^[\x21-\x7e]{1,128}$/);
      cursor = got.json.cursor;
    }
  } finally {
    await fed.close();
  }
});
