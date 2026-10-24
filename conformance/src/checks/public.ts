/**
 * PROTOCOL section 7: published messages, their audience, feeds and relations, and what a retired agent's
 * server stops serving.
 */
import crypto from 'node:crypto';
import {
  canonicalize,
  isJsonObject,
  messageId,
  sha256Hex,
  validAt,
  verifyMessage,
  type KeyEntry,
  type Message,
} from '@agnt-protocol/protocol';
import { buildFrom, Prerequisite, type Ctx } from '../context.ts';
import { sleep, type Res, type T } from '../harness.ts';
import { agentDocument, awaitSync, def } from './common.ts';
import { requireControl } from './deliver.ts';

const S = 'PROTOCOL 7.1';

/** A public message from agent a. */
const post = (ctx: Ctx) =>
  ctx.once('a public message', async t => {
    const a = await ctx.agent('a');
    const m = a.message({ to: [], text: 'a public post' });
    const res = await a.send(t, m, {}, 'send a public message');
    if (res.status !== 200) throw new Prerequisite(`sending a public message answered ${res.status}`);
    return { a, m, id: messageId(m) };
  });

const fetchPublic = (t: T, ctx: Ctx, id: string, label = 'public message') =>
  t.http({ method: 'GET', origin: ctx.origin, target: `/agnt/messages/${id}` }, { label });

def(
  {
    id: 'public.served',
    section: S,
    level: 'must',
    title: "A public message is served to anyone, with its author's keys",
    expected:
      '200 {"message","keys"} for an unsigned GET /agnt/messages/<id>: the message byte for byte, and keys valid at its sentAt that verify it; no replies member (replies are ordinary messages to the author)',
  },
  async (t: T, ctx: Ctx) => {
    const { m, id } = await post(ctx);
    const res = await fetchPublic(t, ctx, id);
    t.status(res, 200);
    const b = res.json;
    t.assert(isJsonObject(b?.message) && canonicalize(b.message) === canonicalize(m), 'message is not the one sent');
    t.assert(Array.isArray(b.keys), 'keys is not an array');
    const keys = b.keys as KeyEntry[];
    const at = new Date(Date.parse(m.sentAt));
    t.assert(
      keys.every(k => validAt(k, at)),
      `keys lists an entry not valid at sentAt: ${JSON.stringify(keys)}`,
    );
    t.assert(verifyMessage(m, keys), 'no listed key verifies the message');
    t.assert(!('replies' in b), `the answer still lists replies: ${JSON.stringify(b.replies)}`);
  },
);

def(
  {
    id: 'public.not-found',
    section: `${S}, PROTOCOL 9`,
    level: 'must',
    title: 'A private or unknown message is 404 not_found',
    expected: '404 not_found for the id of a message with recipients, and for an id nobody sent',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    const b = await ctx.agent('b');
    const m = a.message({ to: [b.address] });
    t.status(await a.send(t, m), 200, 'send a private message');
    t.error(await fetchPublic(t, ctx, messageId(m), 'a private message'), 404, 'not_found', 'a private message');
    t.error(await fetchPublic(t, ctx, 'f'.repeat(64), 'an unknown id'), 404, 'not_found', 'an unknown id');
  },
);

def(
  {
    id: 'public.retired',
    section: `${S}, PROTOCOL 2.2, 7.2`,
    level: 'must',
    title: "A retired agent's public messages and their parts are no longer served",
    expected:
      "after the operator's --retire-command retires an agent that posted a public message naming a part: 404 not_found for the public message and the part, each of which answered 200 before, and its agent document either 404 or an optional readable retired document (PROTOCOL 4), every key revoked by retirement",
  },
  async (t: T, ctx: Ctx) => {
    if (!ctx.opts.retireCommand) t.skip('no --retire-command was given');
    const a = await ctx.agent('retiring');
    const bytes = crypto.randomBytes(300);
    const sha256 = sha256Hex(bytes);
    const get = (what: string, target: string, when: string) =>
      t.http({ method: 'GET', origin: ctx.origin, target }, { label: `${what}, ${when}` });
    const up = await a.call(t, 'PUT', `/agnt/parts/${sha256}`, bytes, {
      headers: { 'content-type': 'application/octet-stream' },
    });
    t.status(up, 200, 'upload');
    const m = a.message({ to: [], parts: [{ type: 'application/octet-stream', sha256, size: bytes.length }] });
    t.status(await a.send(t, m, {}, 'a public message naming the part'), 200, 'send');
    t.status(await get('the agent document', `/agnt/agents/${a.address}`, 'before'), 200, 'the agent document before');
    const targets: [string, string][] = [
      ['the public message', `/agnt/messages/${messageId(m)}`],
      ['the part', `/agnt/parts/${sha256}`],
    ];
    for (const [what, target] of targets) t.status(await get(what, target, 'before'), 200, `${what} before`);
    // A retire command may write the time to the second; retiring a second later keeps the message before it.
    await sleep(1100);
    try {
      await ctx.retire(a.address);
    } catch (e) {
      throw new Prerequisite((e as Error).message);
    }
    for (const [what, target] of targets) {
      t.error(await get(what, target, 'after retiring'), 404, 'not_found', `${what} after retiring`);
    }
    const { res, read } = await agentDocument(t, ctx, a.address, 'the retired document');
    if (res.status === 404) t.error(res, 404, 'not_found', 'the host keeps retirement private');
    else {
      t.status(res, 200, 'the optional retired document');
      t.assert(read?.retired !== undefined, 'the agent document after retiring is not a readable retired document');
      t.assert(
        read.keys.every(k => k.revoked !== null && Date.parse(k.revoked) <= Date.parse(read.retired!)),
        'a key in the retired document remains valid after retirement',
      );
      // A bounded retired document may have pruned this key; no archive is promised.
      if (read.keys.some(k => k.key === a.token))
        t.assert(verifyMessage(m, read.keys), 'the retained signing key does not verify its pre-retirement message');
    }
  },
);

/** A feed name of this run, so no earlier run's posts are listed. */
const feedName = (ctx: Ctx) => `${ctx.runId}-feed`;

/**
 * Posts by agent a, in order: in the run's feed; in the feed with an audience; in the feed and another; and
 * in no feed. A feed lists them newest first, without the one with an audience.
 */
const feedPosts = (ctx: Ctx) =>
  ctx.once('posts in a feed', async t => {
    const a = await ctx.agent('a');
    const feed = feedName(ctx);
    const posts = [
      a.message({ to: [], text: 'first', headers: { feed } }),
      a.message({ to: [], text: 'for some', headers: { feed, audience: `${ctx.runId}-friends` } }),
      a.message({ to: [], text: 'third', headers: { feed: `${feed},${feed}-other` } }),
      a.message({ to: [], text: 'in no feed' }),
    ];
    for (const m of posts) {
      const res = await a.send(t, m, {}, 'publish a post');
      if (res.status !== 200) throw new Prerequisite(`publishing a post answered ${res.status}`);
    }
    return { a, feed, posts };
  });

const get = (t: T, ctx: Ctx, target: string, label?: string) =>
  t.http({ method: 'GET', origin: ctx.origin, target }, { label });

def(
  {
    id: 'public.audience-refused',
    section: `${S}, PROTOCOL 11.2`,
    level: 'must',
    title: 'A published message with an audience is refused to an unknown reader exactly as nothing is',
    expected:
      '404 not_found for an unsigned GET /agnt/messages/<id> of a post with an audience header, byte-identical to the answer for an id nobody sent',
  },
  async (t: T, ctx: Ctx) => {
    const { posts } = await feedPosts(ctx);
    const limited = await get(t, ctx, `/agnt/messages/${messageId(posts[1])}`, 'a post with an audience');
    const nothing = await get(t, ctx, `/agnt/messages/${'e'.repeat(64)}`, 'an id nobody sent');
    t.error(limited, 404, 'not_found', 'a post with an audience');
    t.assert(limited.text === nothing.text, `the refusal (${limited.text}) differs from nothing (${nothing.text})`);
  },
);

def(
  {
    id: 'public.audience-signed-refused',
    section: `${S}, PROTOCOL 8`,
    level: 'must',
    title: 'A signed read of a post with an audience that does not prove its reader asks as nobody',
    expected:
      "404 not_found, byte-identical to the answer for an id nobody sent, for a GET /agnt/messages/<id> of a post with an audience signed by the author's key but naming another agent in agnt-agent, and for one signed by another agent's key naming the author",
  },
  async (t: T, ctx: Ctx) => {
    const { a, posts } = await feedPosts(ctx);
    const b = await ctx.agent('b');
    const target = `/agnt/messages/${messageId(posts[1])}`;
    const nothing = await get(t, ctx, `/agnt/messages/${'e'.repeat(64)}`, 'an id nobody sent');
    const renamed = await a.call(
      t,
      'GET',
      target,
      undefined,
      { override: { 'agnt-agent': b.address } },
      'agnt-agent renamed after signing',
    );
    const borrowed = await b.call(
      t,
      'GET',
      target,
      undefined,
      { agent: a.address },
      "another agent's key naming the author",
    );
    for (const [res, label] of [
      [renamed, 'agnt-agent renamed after signing'],
      [borrowed, "another agent's key naming the author"],
    ] as const) {
      t.error(res, 404, 'not_found', label);
      t.assert(res.text === nothing.text, `${label}: the refusal (${res.text}) differs from nothing (${nothing.text})`);
    }
  },
);

def(
  {
    id: 'public.audience-author',
    section: `${S}, PROTOCOL 8`,
    level: 'should',
    title: 'The author, signing with its own agent key, reads its own post with an audience',
    expected:
      '200 {"message"} for a GET /agnt/messages/<id> of a post with an audience, signed with the author\'s key and naming the author in agnt-agent: the reader is identified by its agent key, with no server vouching for it',
  },
  async (t: T, ctx: Ctx) => {
    const { a, posts } = await feedPosts(ctx);
    const res = await a.call(t, 'GET', `/agnt/messages/${messageId(posts[1])}`, undefined, {}, 'the author reads');
    t.status(res, 200);
    const m = isJsonObject(res.json) ? res.json.message : undefined;
    t.assert(isJsonObject(m) && canonicalize(m) === canonicalize(posts[1]), 'message is not the post');
  },
);

def(
  {
    id: 'public.feed',
    section: 'PROTOCOL 7.3',
    level: 'must',
    title: "An agent's feed lists its published messages in it, newest first, by cursor",
    expected:
      'GET /agnt/feeds/<address>/<feed>?limit=1 answers {"messages","cursor","more"} holding the newest post in the feed; passing its cursor as before gives the one before it; never the post with an audience or the post in no feed, and more false with cursor null at the end',
  },
  async (t: T, ctx: Ctx) => {
    const { a, feed, posts } = await feedPosts(ctx);
    const target = (q: string) => `/agnt/feeds/${a.address}/${feed}?${q}`;
    const first = await get(t, ctx, target('limit=1'), 'the newest');
    t.status(first, 200, 'the newest');
    const page1 = first.json;
    t.assert(
      Array.isArray(page1?.messages) && page1.messages.length === 1,
      `the first page is ${first.text.slice(0, 200)}`,
    );
    t.assert(canonicalize(page1.messages[0]) === canonicalize(posts[2]), 'the newest post in the feed is not first');
    t.assert(page1.more === true && typeof page1.cursor === 'string', `more ${page1.more}, cursor ${page1.cursor}`);
    const second = await get(t, ctx, target(`limit=5&before=${encodeURIComponent(page1.cursor)}`), 'older');
    t.status(second, 200, 'older');
    const ids = (second.json?.messages ?? []).map((m: Record<string, unknown>) => messageId(m));
    t.assert(
      JSON.stringify(ids) === JSON.stringify([messageId(posts[0])]),
      `the rest of the feed is ${JSON.stringify(ids)}, expected only the first post`,
    );
    t.assert(
      second.json.more === false && second.json.cursor === null,
      `more ${second.json.more}, cursor ${second.json.cursor}`,
    );
  },
);

def(
  {
    id: 'public.feed-empty',
    section: 'PROTOCOL 7.3',
    level: 'must',
    title: 'A feed that does not exist, and an agent that does not, answer alike',
    expected:
      'byte-identical 200 {"messages":[],"cursor":null,"more":false} for a feed name nobody used and for an address nobody holds; 400 invalid for limit=0 and limit=201',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    const answers: Res[] = [
      await get(t, ctx, `/agnt/feeds/${a.address}/${ctx.runId}-nothing`, 'a feed nobody used'),
      await get(t, ctx, `/agnt/feeds/${ctx.runId}-nobody@${await ctx.domain()}/${feedName(ctx)}`, 'nobody'),
    ];
    for (const res of answers) {
      t.status(res, 200);
      t.assert(
        canonicalize(res.json) === canonicalize({ messages: [], cursor: null, more: false }),
        `answered ${res.text.slice(0, 200)}`,
      );
      t.assert(res.text === answers[0].text, `the answers differ: ${answers[0].text} and ${res.text}`);
    }
    for (const q of ['limit=0', 'limit=201']) {
      t.error(await get(t, ctx, `/agnt/feeds/${a.address}/${feedName(ctx)}?${q}`, q), 400, 'invalid', q);
    }
  },
);

/** The relations to post a of `feedPosts` this run delivered: a comment marked listed, an unmarked one, a plain reply. */
const relations = (ctx: Ctx) =>
  ctx.once('relations to a post', async (t: T) => {
    await requireControl(ctx);
    const { a, posts } = await feedPosts(ctx);
    const post = messageId(posts[0]);
    const p = ctx.peer.agent('commenter');
    const build = (text: string, extra: Parameters<typeof buildFrom>[3]) =>
      buildFrom(p, [a.address], ctx.now(), { text, ...extra });
    const marked = build('Nice.', { inReplyTo: post, headers: { rel: 'comment', listed: 'yes' } });
    const unmarked = build('Only for you.', { inReplyTo: post, headers: { rel: 'comment' } });
    const reply = build('Between us: no.', { inReplyTo: post });
    const deliver = async (t: T, m: Message) => {
      t.status(await ctx.deliver(t, ctx.peer.envelope(m)), 202, 'deliver to the author');
      t.assert(await awaitSync(t, a, messageId(m), ctx.opts.deliveryWaitMs), 'it never reached the author');
    };
    for (const m of [marked, unmarked, reply]) await deliver(t, m);
    const listing = async (t: T, label: string) => {
      const res = await get(t, ctx, `/agnt/messages/${post}/related`, label);
      // Listing relations is the author's server's choice (PROTOCOL 7.4): a server that lists none answers 404.
      if (res.status === 404) t.skip('the server lists no relations under the post (404), which PROTOCOL 7.4 allows');
      t.status(res, 200);
      return (res.json?.messages ?? []).map((m: Record<string, unknown>) => messageId(m)) as string[];
    };
    return { p, a, post, marked, unmarked, reply, deliver, listing };
  });

def(
  {
    id: 'public.related-only-listed',
    section: 'PROTOCOL 7.4, 5.4',
    level: 'must',
    title: 'A relation its writer did not mark listed, and a plain reply, are never listed under a post',
    expected:
      "once a comment without listed and a plain reply from the simulator to a post are in its author's inbox, GET /agnt/messages/<id>/related holds neither; a server that lists no relations (404) skips",
  },
  async (t: T, ctx: Ctx) => {
    const r = await relations(ctx);
    const ids = await r.listing(t, 'the relations listed');
    t.assert(!ids.includes(messageId(r.unmarked)), 'a comment its writer did not mark listed is listed');
    t.assert(!ids.includes(messageId(r.reply)), 'a plain reply is listed under the post');
  },
);

def(
  {
    id: 'public.related',
    section: 'PROTOCOL 7.4',
    level: 'should',
    title: 'A comment its writer marked listed may be listed under the post, until its writer retracts it',
    expected:
      "once a comment marked listed: yes from the simulator to a post is in its author's inbox, GET /agnt/messages/<id>/related holds it; once the simulator retracts it (rel: retract), the listing no longer does",
  },
  async (t: T, ctx: Ctx) => {
    const r = await relations(ctx);
    const ids = await r.listing(t, 'the relations listed');
    t.assert(ids.includes(messageId(r.marked)), `the marked comment is not listed: ${JSON.stringify(ids)}`);
    await r.deliver(
      t,
      buildFrom(r.p, [r.a.address], ctx.now(), {
        inReplyTo: messageId(r.marked),
        headers: { rel: 'retract' },
        text: '',
      }),
    );
    const after = await r.listing(t, 'the relations listed after the retraction');
    t.assert(!after.includes(messageId(r.marked)), 'a comment its writer retracted is still listed');
  },
);
