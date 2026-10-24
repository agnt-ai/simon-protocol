/**
 * PROTOCOL section 6 from the other side: the deliveries the server under test makes to the simulator,
 * checked as a receiving server checks them, and the client API's sent call that reports on them.
 */
import { isDeepStrictEqual } from 'node:util';
import {
  canonicalize,
  checkServed,
  domainOf,
  isJsonObject,
  messageId,
  MINIMUM_LIMITS,
  parseEnvelope,
  parseTimestamp,
  readAgentDocument,
  serverOrigin,
  verifyEnvelope,
  verifyMessage,
  type AnyMessage,
  type Message,
} from '@agnt-protocol/protocol';
import type { TargetAgent } from '../agent.ts';
import { Prerequisite, type Ctx } from '../context.ts';
import { poll, problem, show, sleep, type Exchange, type T } from '../harness.ts';
import type { Peer, Received } from '../peer.ts';
import { def } from './common.ts';

const S = 'PROTOCOL 6 (the server delivering)';

/** Show a delivery the simulator received in a check's exchanges. */
export function shown(r: Received, label: string): Exchange {
  return {
    label,
    direction: 'from-target',
    at: r.at.toISOString(),
    request: { method: 'POST', url: '/simon/deliver (at the simulator)', headers: {}, body: show(r.raw) },
    response: { status: r.answer, headers: {} },
  };
}

interface Outbound {
  a: TargetAgent;
  m: AnyMessage;
  sent: { status: number; text: string };
  /** For the retry scenario: the status `sent` reported between the 503 and the retry. */
  pendingStatus?: string;
}

/** Send one message from agent a, once per name, and keep what happened. */
function outbound(
  ctx: Ctx,
  name: string,
  build: (a: TargetAgent, b: TargetAgent) => AnyMessage,
  hints?: (a: TargetAgent, b: TargetAgent) => object,
) {
  return ctx.once(`outbound ${name}`, async t => {
    const a = await ctx.agent('a');
    const b = await ctx.agent('b');
    const m = build(a, b);
    const res = await a.send(
      t,
      m,
      hints ? { headers: { 'simon-hints': hintsHeader(hints(a, b)) } } : {},
      `send ${name}`,
    );
    if (res.status !== 200)
      throw new Prerequisite(`send answered ${res.status} ${problem(res)?.code ?? ''} for the ${name} message`);
    return { a, m, sent: { status: res.status, text: res.text } } as Outbound;
  });
}

/** The hints the plain message carries for its first simulated recipient; one value is not ASCII. */
const PLAIN_HINTS = { invite: 'one', note: '\u00e9t\u00e9 \u2713' };

/** A simon-hints header value: ASCII, every other character escaped as \uXXXX (CLIENT send, "Hints"). */
const hintsHeader = (h: object) =>
  JSON.stringify(h).replace(/[\u0080-\uffff]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);

export const plain = (ctx: Ctx) =>
  outbound(
    ctx,
    'to two simulated agents and one local',
    (a, b) => a.message({ to: [ctx.peer.address('plain1'), ctx.peer.address('plain2'), b.address] }),
    (_, b) => ({ [ctx.peer.address('plain1')]: PLAIN_HINTS, [b.address]: { invite: 'local' } }),
  );

/** A message to agents at both simulators and one local agent, each with hints of its own. */
const split = (ctx: Ctx, second: Peer) =>
  outbound(
    ctx,
    'to agents at two simulated servers',
    (a, b) =>
      a.message({ to: [ctx.peer.address('split1'), second.address('split2'), ctx.peer.address('split3'), b.address] }),
    (_, b) => ({
      [ctx.peer.address('split1')]: { invite: 'first' },
      [second.address('split2')]: { invite: 'second' },
      [b.address]: { invite: 'local' },
    }),
  );

/** How far ahead of the server's clock the early message is dated: well inside the 5 minutes send allows. */
const AHEAD_SECONDS = 45;

/**
 * A message dated AHEAD_SECONDS ahead, sent early in the run: when it reached the simulator, if it did
 * within the delivery wait after its sentAt.
 */
export const early = (ctx: Ctx) =>
  ctx.once('outbound dated ahead', async () => {
    const o = await outbound(ctx, 'dated ahead of the clock', a =>
      a.message({ to: [ctx.peer.address('early')], ageSeconds: -AHEAD_SECONDS }),
    );
    const sentAt = parseTimestamp(o.m.sentAt)!;
    // Within the retry wait: a first attempt at sentAt may be answered for now, and retried.
    const r = await poll(
      async () => arrivals(ctx, o.m)[0],
      Math.max(0, sentAt - ctx.now()) + ctx.opts.retryWaitMs,
      250,
    );
    return { ...o, sentAt, arrived: r };
  });

export const rejected = (ctx: Ctx) =>
  outbound(ctx, 'to a recipient the simulator refuses', a => a.message({ to: [ctx.peer.address('x400-reject')] }));

/**
 * Send a message the simulator answers 503 the first time. Started before the checks run, so the server
 * under test has the whole run to retry it. Notes what `sent` says between the 503 and the retry.
 */
export const retried = (ctx: Ctx) =>
  ctx.once('outbound retry', async t => {
    const o = await outbound(ctx, 'to a recipient the simulator answers 503 first', a =>
      a.message({ to: [ctx.peer.address('x503-retry')] }),
    );
    const text = canonicalize(o.m);
    // Within the retry wait: the first attempt may itself have met a failure that passes.
    const first = await poll(async () => ctx.peer.received.find(r => r.messageText === text), ctx.opts.retryWaitMs);
    if (first && ctx.peer.received.filter(r => r.messageText === text).length === 1) {
      const res = await o.a.call(
        t,
        'GET',
        `/simon/sent/${messageId(o.m)}`,
        undefined,
        {},
        'sent, between the 503 and a retry',
      );
      o.pendingStatus = res.json?.servers?.find((s: { server: string }) => s.server === ctx.peer.origin)?.status;
    }
    return o;
  });

/** The envelopes the simulator received carrying exactly this message. */
const arrivals = (ctx: Ctx, m: AnyMessage) => ctx.peer.received.filter(r => r.messageText === canonicalize(m));

async function arrival(t: T, ctx: Ctx, m: AnyMessage, ms = ctx.opts.deliveryWaitMs): Promise<Received> {
  const r = await poll(async () => arrivals(ctx, m)[0], ms);
  if (!r) t.fail(`the server did not deliver message ${messageId(m)} to the simulator within ${ms / 1000} s`);
  t.record(shown(r, 'the delivery the simulator received'));
  return r;
}

def(
  {
    id: 'outbound.delivered',
    section: S,
    level: 'must',
    title: "The server delivers to the server a recipient's domain resolves to",
    expected: `a message sent to agents on ${"the simulator's domain"} arrives at the simulator's /simon/deliver within the delivery wait`,
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await plain(ctx);
    await arrival(t, ctx, m);
  },
);

def(
  {
    id: 'outbound.envelope',
    section: `${S}, 6.2-6.3`,
    level: 'must',
    title: "The envelope passes a receiver's steps 1 to 5",
    expected:
      "the body parses under section 5.1's rules, has the envelope's shape, carries the message in canonical form, the message keeps version 1's rules, and the envelope is for the simulator and recipients on its domain",
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await plain(ctx);
    const r = await arrival(t, ctx, m);
    try {
      const e = parseEnvelope(r.raw, MINIMUM_LIMITS, { origin: ctx.peer.origin, allowHttp: true });
      checkServed(e.recipients, d => d === ctx.opts.peerDomain);
    } catch (e) {
      t.fail(
        `a receiver would refuse it: ${(e as Error).message} ${JSON.stringify((e as { details?: unknown }).details ?? '')}`,
      );
    }
  },
);

/** What is wrong with an envelope's destination, for a simulator expecting exactly `recipients`; or null. */
function destinationFault(r: Received, peer: Peer, recipients: string[]): string | null {
  const e = r.envelope;
  if (!e) return 'the body is not an envelope';
  if (serverOrigin(e.server, true) !== peer.origin) return `server is ${JSON.stringify(e.server)}, not ${peer.origin}`;
  const got = Array.isArray(e.recipients) ? [...e.recipients].sort() : e.recipients;
  if (!isDeepStrictEqual(got, [...recipients].sort())) {
    return `recipients are ${JSON.stringify(e.recipients)}, expected ${JSON.stringify(recipients)}`;
  }
  return null;
}

def(
  {
    id: 'outbound.destination',
    section: `${S}.1`,
    level: 'must',
    title: 'The envelope names the server it is for, and exactly the recipients that server serves',
    expected:
      "server is the simulator's origin, and recipients are exactly the addresses of to on the simulator's domain, as written (not the recipient on the server itself)",
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await plain(ctx);
    const r = await arrival(t, ctx, m);
    const fault = destinationFault(
      r,
      ctx.peer,
      m.to.filter(x => domainOf(x) === ctx.opts.peerDomain),
    );
    t.assert(!fault, fault!);
  },
);

def(
  {
    id: 'outbound.envelope-signature',
    section: `${S}.1`,
    level: 'must',
    title: 'The envelope is signed by a key of the server valid when it arrives',
    expected:
      "the envelope's signature, over SIMON-ENVELOPE\\n and the canonical envelope without signature, verifies with a key the server's document lists valid at arrival",
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await plain(ctx);
    const r = await arrival(t, ctx, m);
    const { doc } = await ctx.serverDoc();
    t.assert(
      r.envelope && verifyEnvelope(r.envelope, doc.keys, r.at),
      'the envelope signature does not verify with any listed key valid at arrival',
    );
  },
);

def(
  {
    id: 'outbound.message-intact',
    section: `${S}, PROTOCOL 1`,
    level: 'must',
    title: 'The message arrives exactly as the agent sent it',
    expected: "the envelope's message member is the canonical bytes the agent sent, so its id is unchanged",
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await plain(ctx);
    const r = await arrival(t, ctx, m);
    t.assert(
      r.raw.includes(Buffer.from(`"message":${canonicalize(m)}`)),
      'the envelope does not carry the message member byte for byte as sent',
    );
  },
);

def(
  {
    id: 'outbound.author-verifiable',
    section: `${S}.1, PROTOCOL 4`,
    level: 'must',
    title: "A receiver can verify the author through the server's agent document",
    expected:
      "the author's agent document, fetched from the server, lists a key that verifies the delivered message at its sentAt",
  },
  async (t: T, ctx: Ctx) => {
    const { a, m } = await plain(ctx);
    await arrival(t, ctx, m);
    const { doc } = await ctx.serverDoc();
    const res = await t.http(
      { method: 'GET', origin: ctx.origin, target: `/simon/agents/${a.address}` },
      { label: "the author's document" },
    );
    const read = readAgentDocument(res.bytes, a.address, doc.keys, new Date(ctx.now()));
    t.assert(read, "the author's document is unreadable");
    t.assert(verifyMessage(m, read.keys), "no key in the author's document verifies the message");
  },
);

def(
  {
    id: 'outbound.one-envelope',
    section: S,
    level: 'must',
    title: 'One envelope per server, however many of its agents are recipients',
    expected: 'a message to two agents at the simulator arrives in exactly one envelope (the simulator answered 202)',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await plain(ctx);
    await arrival(t, ctx, m);
    await sleep(3000);
    const all = arrivals(ctx, m);
    t.assert(all.length === 1, `${all.length} envelopes arrived`);
  },
);

def(
  {
    id: 'outbound.hints',
    section: `${S}.2, CLIENT send "Hints"`,
    level: 'must',
    title: "Each recipient's hints go to that recipient's server, and only there",
    expected:
      "the envelope's hints hold exactly the hints the simon-hints header gave for recipients at the simulator (a non-ASCII value, escaped in the header, arrives as itself), and none for the recipient on the server itself",
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await plain(ctx);
    const r = await arrival(t, ctx, m);
    const want = { [ctx.peer.address('plain1')]: PLAIN_HINTS };
    t.assert(
      isDeepStrictEqual(r.envelope?.hints, want),
      `hints are ${JSON.stringify(r.envelope?.hints)}, expected ${JSON.stringify(want)}`,
    );
  },
);

def(
  {
    id: 'outbound.per-server',
    section: `${S}, 6.1-6.2, CLIENT send "Hints"`,
    level: 'must',
    title: 'A message to two servers goes as one envelope to each, each with only its own recipients and hints',
    expected:
      'for a message to agents at both simulators (given --second-peer-domain) and one local agent: each simulator receives exactly one envelope, naming its own origin, exactly its own recipients, and only their hints',
  },
  async (t: T, ctx: Ctx) => {
    const second = ctx.secondPeer;
    if (!second) t.skip('no --second-peer-domain was given');
    const { m } = await split(ctx, second);
    const text = canonicalize(m);
    for (const peer of [ctx.peer, second]) {
      const r = await poll(async () => peer.received.find(x => x.messageText === text), ctx.opts.deliveryWaitMs);
      if (!r) t.fail(`${peer.domain} received no envelope within ${ctx.opts.deliveryWaitMs / 1000} s`);
      t.record(shown(r, `the delivery ${peer.domain} received`));
    }
    await sleep(2000);
    for (const peer of [ctx.peer, second]) {
      const all = peer.received.filter(x => x.messageText === text);
      t.assert(all.length === 1, `${peer.domain} received ${all.length} envelopes`);
      const mine = m.to.filter(x => domainOf(x) === peer.domain);
      const fault = destinationFault(all[0], peer, mine);
      t.assert(!fault, `${peer.domain}: ${fault}`);
      const want = { [mine[0]]: { invite: mine[0] === ctx.peer.address('split1') ? 'first' : 'second' } };
      t.assert(
        isDeepStrictEqual(all[0].envelope?.hints, want),
        `${peer.domain}: hints are ${JSON.stringify(all[0].envelope?.hints)}, expected ${JSON.stringify(want)}`,
      );
    }
  },
);

def(
  {
    id: 'outbound.claims',
    section: `${S}.2`,
    level: 'must',
    title: "Claims are well formed and about the message's author",
    expected:
      "claims, when present, are at most 16 objects with a non-empty string type; an acts-for claim names the author as agent and the message's for header as for",
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await plain(ctx);
    const r = await arrival(t, ctx, m);
    const claims = r.envelope?.claims;
    if (claims === undefined) return;
    t.assert(Array.isArray(claims) && claims.length <= 16, `claims is ${JSON.stringify(claims).slice(0, 200)}`);
    const forHeader = (m as Message).headers?.for;
    for (const c of claims) {
      t.assert(
        isJsonObject(c) && typeof c.type === 'string' && c.type !== '',
        `a claim is malformed: ${JSON.stringify(c)}`,
      );
      if (c.type === 'acts-for') {
        t.assert(
          c.agent === m.from && forHeader !== undefined && c.for === forHeader,
          `an acts-for claim is not about this message's author and for: ${JSON.stringify(c)}`,
        );
      }
    }
  },
);

def(
  {
    id: 'outbound.not-before-sent-at',
    section: `${S}.3 "Delivery"`,
    level: 'must',
    title: 'The server does not deliver a message before its sentAt',
    expected: `a message dated ${AHEAD_SECONDS} s ahead of the server's clock reaches the simulator no earlier than its sentAt (less the clock margin), and within the retry wait after it`,
  },
  async (t: T, ctx: Ctx) => {
    const o = await early(ctx);
    if (!o.arrived) t.fail(`the message dated ${o.m.sentAt} never reached the simulator`);
    t.record(shown(o.arrived, 'the delivery the simulator received'));
    const at = o.arrived.at.getTime() + ctx.clockOffsetMs;
    t.assert(
      at >= o.sentAt - ctx.opts.clockMarginSeconds * 1000,
      `it arrived at ${new Date(at).toISOString()} by the server's clock, before its sentAt ${o.m.sentAt}`,
    );
  },
);

def(
  {
    id: 'outbound.no-retry-on-4xx',
    section: `${S}.3 "Delivery"`,
    level: 'should',
    title: 'A 4xx answer other than 429 is permanent',
    expected: 'after the simulator answers 400, the server does not deliver the same message again (watched for 10 s)',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await rejected(ctx);
    await arrival(t, ctx, m);
    await sleep(10_000);
    const all = arrivals(ctx, m);
    all.slice(1).forEach((r, i) => t.record(shown(r, `repeat ${i + 1}`)));
    t.assert(all.length === 1, `the server delivered it ${all.length} times`);
  },
);

def(
  {
    id: 'outbound.retry',
    section: `${S}.3 "Delivery", PROTOCOL 9`,
    level: 'must',
    title: 'A delivery answered 503 is retried, with the same message',
    expected:
      'after the simulator answers 503 (Retry-After: 1), the server delivers the same message again, byte for byte, within the retry wait',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await retried(ctx);
    const first = await arrival(t, ctx, m);
    t.assert(first.answer === 503, `the simulator answered the first delivery ${first.answer}`);
    const wait = Math.max(0, first.at.getTime() + ctx.opts.retryWaitMs - Date.now());
    const second = await poll(async () => arrivals(ctx, m)[1], wait, 1000);
    t.assert(second, `no retry within ${ctx.opts.retryWaitMs / 1000} s of the 503`);
    t.record(shown(second, 'the retry'));
    t.assert(second.messageText === first.messageText, 'the retry carries a different message');
  },
);

// CLIENT sent.

/** The `sent` report for a message, polled until `done` says so or the time runs out; shows the last read. */
async function sentReport(t: T, a: TargetAgent, m: AnyMessage, ms: number, done: (b: any) => boolean) {
  const s = t.scratch();
  let last: any;
  try {
    await poll(
      async () => {
        const res = await a.call(s, 'GET', `/simon/sent/${messageId(m)}`, undefined, {}, 'sent');
        last = res;
        return res.status === 200 && done(res.json) ? true : undefined;
      },
      ms,
      1000,
    );
  } finally {
    t.adopt(s.exchanges.slice(-1));
  }
  return last as { status: number; json: any; text: string };
}

const entryFor = (b: any, server: string | null, recipient: string) =>
  b?.servers?.find((s: any) => s.server === server && Array.isArray(s.recipients) && s.recipients.includes(recipient));

def(
  {
    id: 'sent.shape',
    section: 'CLIENT sent',
    level: 'must',
    title: 'sent reports one entry per recipient server',
    expected:
      '200 {"id","servers":[{"server","recipients","status"}]}, each recipient in exactly one entry, the simulator\'s two agents together under its origin, status pending, delivered or failed',
  },
  async (t: T, ctx: Ctx) => {
    const { a, m } = await plain(ctx);
    const res = await a.call(t, 'GET', `/simon/sent/${messageId(m)}`);
    t.status(res, 200);
    const b = res.json;
    t.assert(b?.id === messageId(m), `id is ${JSON.stringify(b?.id)}`);
    t.assert(Array.isArray(b.servers), 'servers is not an array');
    for (const s of b.servers) {
      t.assert(s.server === null || typeof s.server === 'string', `server ${JSON.stringify(s.server)}`);
      t.assert(Array.isArray(s.recipients), `recipients ${JSON.stringify(s.recipients)}`);
      t.assert(['pending', 'delivered', 'failed'].includes(s.status), `status ${JSON.stringify(s.status)}`);
    }
    const listed = b.servers.flatMap((s: any) => s.recipients);
    for (const r of m.to)
      t.assert(
        listed.filter((x: string) => x === r).length === 1,
        `${r} appears ${listed.filter((x: string) => x === r).length} times`,
      );
    const peer = b.servers.find((s: any) => s.server === ctx.peer.origin);
    t.assert(
      peer &&
        isDeepStrictEqual([...peer.recipients].sort(), m.to.filter(x => x.endsWith(`@${ctx.opts.peerDomain}`)).sort()),
      `the simulator's recipients are not one entry under ${ctx.peer.origin}`,
    );
  },
);

def(
  {
    id: 'sent.delivered',
    section: 'CLIENT sent',
    level: 'must',
    title: 'sent says delivered once the receiving server answered 202',
    expected: 'the entry for the simulator becomes "delivered" after the simulator answered 202',
  },
  async (t: T, ctx: Ctx) => {
    const { a, m } = await plain(ctx);
    await arrival(t, ctx, m);
    const res = await sentReport(
      t,
      a,
      m,
      ctx.opts.deliveryWaitMs,
      b => entryFor(b, ctx.peer.origin, ctx.peer.address('plain1'))?.status === 'delivered',
    );
    const e = entryFor(res.json, ctx.peer.origin, ctx.peer.address('plain1'));
    t.assert(e?.status === 'delivered', `the entry is ${JSON.stringify(e)}`);
  },
);

def(
  {
    id: 'sent.local',
    section: 'CLIENT sent',
    level: 'should',
    title: 'sent reports a recipient on the server itself',
    expected: "the recipient on the server itself is in an entry under the server's own origin that becomes delivered",
  },
  async (t: T, ctx: Ctx) => {
    const { a, m } = await plain(ctx);
    const b = await ctx.agent('b');
    const res = await sentReport(
      t,
      a,
      m,
      ctx.opts.deliveryWaitMs,
      j => entryFor(j, ctx.origin, b.address)?.status === 'delivered',
    );
    t.assert(
      entryFor(res.json, ctx.origin, b.address)?.status === 'delivered',
      `the report is ${res.text.slice(0, 300)}`,
    );
  },
);

def(
  {
    id: 'sent.failed-not-found',
    section: 'CLIENT sent',
    level: 'must',
    title: 'A domain that names no server fails with the resolution outcome',
    expected:
      '{"server":null,"recipients":[...],"status":"failed","reason":"not_found"} for a recipient on a domain with no SIMON server',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    const to = `${ctx.runId}-eve@${ctx.opts.unresolvableDomain}`;
    const m = a.message({ to: [to] });
    t.status(await a.send(t, m), 200, 'send');
    const res = await sentReport(t, a, m, ctx.opts.deliveryWaitMs, b => entryFor(b, null, to)?.status === 'failed');
    const e = entryFor(res.json, null, to);
    t.assert(
      e?.status === 'failed' && e.reason === 'not_found',
      `the entry is ${JSON.stringify(e ?? res.json?.servers)}`,
    );
  },
);

def(
  {
    id: 'sent.failed-code',
    section: 'CLIENT sent, PROTOCOL 6.3 "Delivery"',
    level: 'must',
    title: 'A permanent refusal fails with the code the receiver answered',
    expected: 'status "failed" with reason "invalid" once the simulator answered 400 invalid',
  },
  async (t: T, ctx: Ctx) => {
    const { a, m } = await rejected(ctx);
    await arrival(t, ctx, m);
    const to = ctx.peer.address('x400-reject');
    const res = await sentReport(
      t,
      a,
      m,
      ctx.opts.deliveryWaitMs,
      b => entryFor(b, ctx.peer.origin, to)?.status === 'failed',
    );
    const e = entryFor(res.json, ctx.peer.origin, to);
    t.assert(e?.status === 'failed' && e.reason === 'invalid', `the entry is ${JSON.stringify(e)}`);
  },
);

def(
  {
    id: 'sent.pending-while-retrying',
    section: 'CLIENT sent',
    level: 'should',
    title: 'A delivery waiting to be retried is pending',
    expected: 'between the simulator\'s 503 and the retry, the entry says "pending"',
  },
  async (t: T, ctx: Ctx) => {
    const o = await retried(ctx);
    if (o.pendingStatus === undefined) t.skip('the server retried before the suite could read sent');
    t.assert(o.pendingStatus === 'pending', `the entry said ${JSON.stringify(o.pendingStatus)}`);
  },
);

def(
  {
    id: 'sent.after-retry',
    section: 'CLIENT sent',
    level: 'must',
    title: 'A retried delivery ends delivered',
    expected: 'once the retry was answered 202, the entry says "delivered"',
  },
  async (t: T, ctx: Ctx) => {
    const o = await retried(ctx);
    const all = arrivals(ctx, o.m);
    if (!all.some(r => r.answer === 202)) t.skip('the server never retried (see outbound.retry)');
    const to = ctx.peer.address('x503-retry');
    const res = await sentReport(
      t,
      o.a,
      o.m,
      ctx.opts.deliveryWaitMs,
      b => entryFor(b, ctx.peer.origin, to)?.status === 'delivered',
    );
    t.assert(
      entryFor(res.json, ctx.peer.origin, to)?.status === 'delivered',
      `the report is ${res.text.slice(0, 300)}`,
    );
  },
);

def(
  {
    id: 'sent.expired',
    section: 'CLIENT sent, PROTOCOL 6.3 "Delivery"',
    level: 'should',
    title: 'A delivery still failing at its deadline is reported expired',
    expected:
      'status "failed" with reason "expired" once the deadline passed (the earlier of five days after acceptance and 143 hours after sentAt); not observable black-box, so always skipped',
  },
  async (t: T) => {
    t.skip(
      'the deadline is at least 119 hours after the server accepts a message, and the suite cannot move its clock',
    );
  },
);

def(
  {
    id: 'sent.not-found',
    section: 'CLIENT sent, PROTOCOL 9',
    level: 'must',
    title: 'sent for an unknown id is 404 not_found',
    expected: '404 not_found for an id the agent never sent',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    t.error(await a.call(t, 'GET', `/simon/sent/${'0'.repeat(64)}`), 404, 'not_found');
  },
);

def(
  {
    id: 'sent.not-yours',
    section: 'CLIENT sent',
    level: 'must',
    title: "sent does not report another agent's message",
    expected: '404 not_found when an agent asks for the id of a message another agent sent',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await plain(ctx);
    const b = await ctx.agent('b');
    t.error(await b.call(t, 'GET', `/simon/sent/${messageId(m)}`), 404, 'not_found');
  },
);
