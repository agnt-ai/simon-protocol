/**
 * PROTOCOL section 6: deliver, as the simulated peer posts envelopes to the server under test. Every step
 * of section 6.3 has its own checks, and pairs of faults show the order: the answer is always the first
 * failing step's. The steps: 1 parse, 2 envelope shape, 3 canonical form, 4 message, 5 destination
 * (with no lookup), 6 resolution, 7 envelope signature and claims signature, 8 recipients served, 9 repeat,
 * 10 freshness, 11 author signature, 12 accepted.
 */
import crypto from 'node:crypto';
import {
  canonicalize,
  claimsBytes,
  domainOf,
  keyToken,
  MAX_ENVELOPE_EXTRAS_BYTES,
  messageId,
  sign,
  signingBytes,
  signPairing,
  timestamp,
  type Envelope,
  type KeyEntry,
  type Message,
  type Part,
} from '@agnt-sdk/simon-protocol';
import { buildFrom, Prerequisite, type Ctx } from '../context.ts';
import { sleep, type Res, type T } from '../harness.ts';
import { LONG_AGO, type PeerAgent } from '../peer.ts';
import { resign } from '../agent.ts';
import { awaitSync, def, readSync } from './common.ts';

const S = 'PROTOCOL 6.3';
const HOUR = 3600;

/** The simulated agent most checks send from. */
const sender = (ctx: Ctx) => ctx.once('the simulator sender', async () => ctx.peer.agent('sender'));

/** A valid message from the simulator to agent a, ready to deliver. */
async function valid(ctx: Ctx, f: Parameters<typeof buildFrom>[3] = {}, from?: PeerAgent) {
  const a = await ctx.agent('a');
  await ctx.peerReady();
  const p = from ?? (await sender(ctx));
  return { a, p, m: buildFrom(p, f.to ?? [a.address], ctx.now(), f) };
}

function accepted(t: T, res: Res, what = '') {
  t.status(res, 202, what);
  t.assert(
    res.json?.accepted === true,
    `${what ? `${what}: ` : ''}a 202 answers {"accepted":true}; got ${res.text.slice(0, 200)}`,
  );
}

/** An envelope's canonical text with its message member replaced by `messageText`, exactly as given. */
function withMessageText(e: Envelope, messageText: string) {
  const text = canonicalize(e);
  const canonical = canonicalize(e.message);
  const at = text.indexOf(`"message":${canonical}`);
  return text.slice(0, at) + `"message":${messageText}` + text.slice(at + `"message":`.length + canonical.length);
}

/** Whether a plain message from the simulator reaches agent a's inbox: what the inbox checks build on. */
function controlSeen(ctx: Ctx): Promise<boolean> {
  return ctx.once('a plain delivery reaches the inbox', async t => {
    const { a, m } = await valid(ctx);
    const res = await ctx.deliver(t, ctx.peer.envelope(m), 'control delivery');
    if (res.status !== 202) return false;
    return (await awaitSync(t, a, messageId(m), ctx.opts.deliveryWaitMs)) !== undefined;
  });
}

async function requireControl(ctx: Ctx) {
  if (!(await controlSeen(ctx))) {
    throw new Prerequisite(
      `a plain message delivered from the simulator never reached the recipient's inbox within ${ctx.opts.deliveryWaitMs / 1000} s; the server's policy may hold mail from ${ctx.opts.peerDomain} (allow it and run again)`,
    );
  }
}

// Step 6 needs the simulator's server document. Check what a failure to fetch it does before anything
// else makes the server under test fetch and cache it.
def(
  {
    id: 'deliver.server-document-unavailable',
    section: `${S} steps 6-7, PROTOCOL 9`,
    level: 'must',
    title: "A sender's server document that cannot be fetched just now is 503",
    expected:
      "503 unavailable with retryable: true when the from-domain's server answers its server document with 503; never a permanent refusal",
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    const p = await sender(ctx);
    const m = buildFrom(p, [a.address], ctx.now());
    const before = ctx.peer.requests.length;
    ctx.peer.serverDocStatus = 503;
    let res: Res;
    try {
      res = await ctx.deliver(t, ctx.peer.envelope(m), "the simulator's server document answers 503");
    } finally {
      ctx.peer.serverDocStatus = 200;
    }
    const fetched = ctx.peer.requests.slice(before).some(r => r.target.split('?')[0] === '/simon/server');
    if (res.status !== 503 && !fetched) {
      t.skip(
        `the server answered ${res.status} without fetching the simulator's server document during this check, so it holds it from an earlier run; run against a server that has not seen ${ctx.peer.origin} in the last ten minutes`,
      );
    }
    const err = t.error(res, 503, 'unavailable');
    t.assert(err.retryable === true, 'a 503 is retryable: true');
  },
);

def(
  {
    id: 'deliver.accepted',
    section: `${S} step 12`,
    level: 'must',
    title: 'A valid delivery is 202 {"accepted":true}',
    expected:
      '202 with the body {"accepted":true} for a valid envelope from a server whose domain resolves, carrying a message its author signed',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(m)));
  },
);

// Step 1.

def(
  {
    id: 'deliver.body-too-large',
    section: `${S} step 1`,
    level: 'must',
    title: 'A body over requestBodyBytes is 413, before parsing',
    expected: '413 body_too_large for a body one byte over the published requestBodyBytes, even when it is not JSON',
  },
  async (t: T, ctx: Ctx) => {
    const { requestBodyBytes } = await ctx.limits();
    const res = await ctx.deliver(t, Buffer.alloc(requestBodyBytes + 1, 0x41), `${requestBodyBytes + 1} bytes of "A"`);
    t.error(res, 413, 'body_too_large');
  },
);

def(
  {
    id: 'deliver.body-at-limit',
    section: `${S} step 1, PROTOCOL 9`,
    level: 'must',
    title: 'A body of exactly requestBodyBytes is taken',
    expected: '202 for a valid envelope padded with whitespace to exactly the published requestBodyBytes',
  },
  async (t: T, ctx: Ctx) => {
    const { requestBodyBytes } = await ctx.limits();
    const { m } = await valid(ctx);
    const text = canonicalize(ctx.peer.envelope(m));
    const body = text.slice(0, -1) + ' '.repeat(requestBodyBytes - Buffer.byteLength(text)) + '}';
    accepted(t, await ctx.deliver(t, body, `${Buffer.byteLength(body)} bytes`));
  },
);

def(
  {
    id: 'deliver.parse',
    section: `${S} step 1, PROTOCOL 5.1`,
    level: 'must',
    title: "A body that does not parse under section 5.1's rules is 400 invalid",
    expected:
      '400 invalid for: truncated JSON, a repeated key, a fraction, an exponent, -0, a leading zero, an integer beyond 2^53-1, a lone surrogate escape, a byte order mark, invalid UTF-8, and 65 levels of nesting',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const env = canonicalize(ctx.peer.envelope(m));
    const extra = (member: string) => `{"x":${member},${env.slice(1)}`;
    const cases: [string, string | Buffer][] = [
      ['truncated', env.slice(0, -1)],
      ['a repeated key', `{"x":1,"x":2,${env.slice(1)}`],
      ['a fraction', extra('1.5')],
      ['an exponent', extra('1e3')],
      ['-0', extra('-0')],
      ['a leading zero', extra('01')],
      ['an integer beyond 2^53-1', extra('9007199254740992')],
      ['a lone surrogate escape', extra('"\\ud800"')],
      ['a byte order mark', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(env)])],
      [
        'invalid UTF-8',
        Buffer.concat([Buffer.from('{"x":"'), Buffer.from([0xc3, 0x28]), Buffer.from(`",${env.slice(1)}`)]),
      ],
      ['65 levels of nesting', extra(`${'['.repeat(64)}${']'.repeat(64)}`)],
    ];
    for (const [what, body] of cases) t.error(await ctx.deliver(t, body, what), 400, 'invalid', what);
  },
);

// Step 2.

/** Each case: an envelope object (sent canonical) and the details.field the refusal must name. */
async function shapeCases(t: T, ctx: Ctx, cases: [string, unknown, string | string[] | null][]) {
  for (const [what, body, field] of cases) {
    const res = await ctx.deliver(t, typeof body === 'string' ? body : canonicalize(body), what);
    t.error(res, 400, 'invalid', what, field === null ? { anyField: true } : { field });
  }
}

def(
  {
    id: 'deliver.shape-envelope',
    section: `${S} step 2`,
    level: 'must',
    title: 'An envelope that is not an object, or whose message is not an object, is 400 with details.field',
    expected:
      '400 invalid with a details.field for an array or a string as the envelope; details.field "message" when message is missing, a string or an array',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const env = (o: Parameters<typeof ctx.peer.envelope>[1]) => ctx.peer.envelope(m, o);
    await shapeCases(t, ctx, [
      ['an array', [m], null],
      ['a string', '"envelope"', null],
      ['no message', env({ omit: ['message'] }), 'message'],
      ['message a string', env({ members: { message: canonicalize(m) } }), 'message'],
      ['message an array', env({ members: { message: [m] } }), 'message'],
    ]);
  },
);

def(
  {
    id: 'deliver.shape-signature',
    section: `${S} step 2`,
    level: 'must',
    title: 'An envelope signature that is not base64url is 400 on signature',
    expected: '400 invalid with details.field "signature" when it is missing, a number, padded, or empty',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const e = ctx.peer.envelope(m);
    const { signature: _, ...unsigned } = e;
    await shapeCases(t, ctx, [
      ['no signature', unsigned, 'signature'],
      ['a number', { ...e, signature: 7 }, 'signature'],
      ['padded', { ...e, signature: `${e.signature}==` }, 'signature'],
      ['empty', { ...e, signature: '' }, 'signature'],
    ]);
  },
);

def(
  {
    id: 'deliver.shape-server',
    section: `${S} step 2, PROTOCOL 6.1`,
    level: 'must',
    title: 'An envelope whose server is not an origin is 400 on server',
    expected:
      '400 invalid with details.field "server" when it is missing, a number, a URL with a path, or not a URL, the envelope signed as sent',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const env = (o: Parameters<typeof ctx.peer.envelope>[1]) => ctx.peer.envelope(m, o);
    await shapeCases(t, ctx, [
      ['no server', env({ omit: ['server'] }), 'server'],
      ['server a number', env({ members: { server: 8080 } }), 'server'],
      ['server with a path', env({ members: { server: `${ctx.origin}/simon` } }), 'server'],
      ['server not a URL', env({ members: { server: 'simon server' } }), 'server'],
    ]);
  },
);

def(
  {
    id: 'deliver.shape-recipients',
    section: `${S} step 2, PROTOCOL 6.1`,
    level: 'must',
    title: 'recipients must be a non-empty array of distinct addresses',
    expected:
      '400 invalid with details.field "recipients" when it is missing, empty, a string, holds a number or an address in upper case, or names one address twice',
  },
  async (t: T, ctx: Ctx) => {
    const { a, m } = await valid(ctx);
    const env = (recipients: unknown) => ctx.peer.envelope(m, { members: { recipients } });
    await shapeCases(t, ctx, [
      ['no recipients', ctx.peer.envelope(m, { omit: ['recipients'] }), 'recipients'],
      ['an empty list', env([]), 'recipients'],
      ['a string', env(a.address), 'recipients'],
      ['a number in the list', env([a.address, 7]), 'recipients'],
      ['an address in upper case', env([a.address.toUpperCase()]), 'recipients'],
      ['one address twice', env([a.address, a.address]), 'recipients'],
    ]);
  },
);

def(
  {
    id: 'deliver.shape-claims',
    section: `${S} step 2, PROTOCOL 6.2`,
    level: 'must',
    title: 'Claims that are not at most 16 objects with a non-empty string type are 400 on claims',
    expected:
      '400 invalid with details.field "claims" for an object, a number in the array, a claim with no type, an empty type, a numeric type, and 17 claims',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const env = (claims: unknown) => ctx.peer.envelope(m, { members: { claims } });
    await shapeCases(t, ctx, [
      ['claims an object', env({ type: 'x' }), 'claims'],
      ['a number in claims', env([1]), 'claims'],
      ['a claim without type', env([{ note: 'x' }]), 'claims'],
      ['an empty type', env([{ type: '' }]), 'claims'],
      ['a numeric type', env([{ type: 7 }]), 'claims'],
      ['17 claims', env(Array.from({ length: 17 }, (_, i) => ({ type: `x-${i}` }))), 'claims'],
    ]);
  },
);

def(
  {
    id: 'deliver.claims-null',
    section: `${S} step 2, PROTOCOL 6.2`,
    level: 'must',
    title: 'claims: null is refused, not read as absent',
    expected:
      '400 invalid with details.field "claims" for an envelope whose claims is null (only an absent member reads as none)',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    await shapeCases(t, ctx, [['claims null', ctx.peer.envelope(m, { members: { claims: null } }), 'claims']]);
  },
);

def(
  {
    id: 'deliver.shape-hints',
    section: `${S} step 2, PROTOCOL 6.2`,
    level: 'must',
    title: "Hints keyed by anything but one of the envelope's recipients, or not objects of strings, are 400 on hints",
    expected:
      '400 invalid with details.field "hints" for hints that are an array, null, keyed by an address not in to, keyed by an address in to but not in recipients, keyed by a recipient in another case, holding a string, or holding a number',
  },
  async (t: T, ctx: Ctx) => {
    const { a, m } = await valid(ctx, { to: [(await ctx.agent('a')).address, (await ctx.agent('b')).address] });
    const b = m.to[1];
    const env = (hints: unknown) => ctx.peer.envelope(m, { recipients: [a.address], members: { hints } });
    await shapeCases(t, ctx, [
      ['hints an array', env([{ invite: 'x' }]), 'hints'],
      ['hints null', env(null), 'hints'],
      ['keyed by an address not in to', env({ [`other-${a.address}`]: { invite: 'x' } }), 'hints'],
      ['keyed by an address in to, not in recipients', env({ [b]: { invite: 'x' } }), 'hints'],
      ['keyed by a recipient in upper case', env({ [a.address.toUpperCase()]: { invite: 'x' } }), 'hints'],
      ["a recipient's hints a string", env({ [a.address]: 'x' }), 'hints'],
      ['a hint that is a number', env({ [a.address]: { invite: 7 } }), 'hints'],
    ]);
  },
);

def(
  {
    id: 'deliver.hints-valid',
    section: `${S} step 2, PROTOCOL 6.2`,
    level: 'must',
    title: 'Hints keyed by a recipient as written are taken',
    expected: '202 for an envelope whose hints name one of its recipients exactly as written, with string values',
  },
  async (t: T, ctx: Ctx) => {
    const { a, m } = await valid(ctx);
    accepted(
      t,
      await ctx.deliver(t, ctx.peer.envelope(m, { hints: { [a.address]: { invite: 'conformance', 'x-note': 'y' } } })),
    );
  },
);

/** Claims whose canonical `{"claims":..,"hints":{}}` is exactly `bytes` long. */
function claimsOfSize(bytes: number) {
  const base = Buffer.byteLength(canonicalize({ claims: [{ pad: '', type: 'x-pad' }], hints: {} }));
  return [{ type: 'x-pad', pad: 'p'.repeat(bytes - base) }];
}

def(
  {
    id: 'deliver.extras-limit',
    section: `${S} step 2, PROTOCOL 6.2, 9`,
    level: 'must',
    title: `Claims and hints together are at most ${MAX_ENVELOPE_EXTRAS_BYTES} canonical bytes`,
    expected: `202 when canonical {"claims":..,"hints":..} is exactly ${MAX_ENVELOPE_EXTRAS_BYTES} bytes; 400 invalid (details.field "claims" or "hints") at ${MAX_ENVELOPE_EXTRAS_BYTES + 1}`,
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    accepted(
      t,
      await ctx.deliver(
        t,
        ctx.peer.envelope(m, { claims: claimsOfSize(MAX_ENVELOPE_EXTRAS_BYTES) }),
        'exactly at the limit',
      ),
      'exactly at the limit',
    );
    const { m: m2 } = await valid(ctx);
    const res = await ctx.deliver(
      t,
      ctx.peer.envelope(m2, { claims: claimsOfSize(MAX_ENVELOPE_EXTRAS_BYTES + 1) }),
      'one byte over',
    );
    t.error(res, 400, 'invalid', 'one byte over', { field: ['claims', 'hints'] });
  },
);

/** An envelope whose claimsSignature is replaced, then signed again as a whole by the simulator. */
function withClaimsSignature(ctx: Ctx, e: Envelope, claimsSignature: string | undefined) {
  const { signature: _, claimsSignature: __, ...rest } = e;
  const unsigned = claimsSignature === undefined ? rest : { ...rest, claimsSignature };
  return { ...unsigned, signature: sign(ctx.peer.serverKey, signingBytes('SIMON-ENVELOPE', unsigned)) };
}

def(
  {
    id: 'deliver.claims-signed',
    section: `${S} steps 2, 7, PROTOCOL 6.2`,
    level: 'must',
    title: "Claims carry the carrier's signature over the claims and the message id",
    expected:
      '400 invalid with details.field "claimsSignature" for claims without a claimsSignature, and for a claimsSignature without claims; 403 bad_signature for a claimsSignature made over other claims, though the envelope itself verifies',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const note = { type: 'x-note', note: 'one' };
    const e = ctx.peer.envelope(m, { claims: [note] });
    const bare = ctx.peer.envelope(m);
    const missing = withClaimsSignature(ctx, e, undefined);
    const stray = withClaimsSignature(ctx, bare, e.claimsSignature);
    for (const [what, env] of [
      ['claims without claimsSignature', missing],
      ['claimsSignature without claims', stray],
    ] as const) {
      t.error(await ctx.deliver(t, env, what), 400, 'invalid', what, { field: 'claimsSignature' });
    }
    const other = sign(ctx.peer.serverKey, claimsBytes([{ ...note, note: 'two' }], messageId(m)));
    t.error(
      await ctx.deliver(t, withClaimsSignature(ctx, e, other), 'claimsSignature over other claims'),
      403,
      'bad_signature',
      'a claimsSignature over other claims',
    );
  },
);

def(
  {
    id: 'deliver.unknown-members',
    section: 'PROTOCOL 6.1, 10',
    level: 'must',
    title: 'Envelope members the receiver does not know are ignored, and signed',
    expected: '202 for an envelope carrying members this version does not define, covered by its signature',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    accepted(
      t,
      await ctx.deliver(
        t,
        ctx.peer.envelope(m, { members: { 'x-conformance': { nested: [1, 'two'] }, priority: 'low' } }),
      ),
    );
  },
);

def(
  {
    id: 'deliver.order-shape-before-canonical',
    section: `${S} steps 2-3`,
    level: 'must',
    title: 'A malformed envelope is refused on its shape before the message is checked for canonical form',
    expected:
      '400 invalid with details.field "claims" and no details.canonical, for claims that are a string and a message that is not canonical',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const e = ctx.peer.envelope(m, { members: { claims: 'none' } });
    const res = await ctx.deliver(t, withMessageText(e, JSON.stringify(m, null, 1)));
    const err = t.error(res, 400, 'invalid', '', { field: 'claims' });
    t.assert(
      err.details?.canonical === undefined,
      "the refusal carries details.canonical: the canonical form was checked before the envelope's shape",
    );
  },
);

// Step 3.

/** Non-canonical spellings of a message, each with the canonical form the refusal must return. */
function nonCanonical(m: Message): [string, string][] {
  const c = canonicalize(m);
  const reordered = `{"v":${m.v},${c.slice(1).replace(`,"v":${m.v}`, '')}`;
  return [
    ['whitespace between tokens', JSON.stringify(m, null, 2)],
    ['keys out of order', reordered],
    ['an escaped solidus', c.replace('"text/plain"', '"text\\/plain"')],
    ['a \\u escape for a plain letter', c.replace('"text/plain"', '"\\u0074ext/plain"')],
  ];
}

def(
  {
    id: 'deliver.canonical',
    section: `${S} step 3, PROTOCOL 5.1`,
    level: 'must',
    title: 'A message not in canonical form is 400, returning its canonical form',
    expected:
      '400 invalid with details.canonical exactly the canonical form, for whitespace, keys out of order, an escaped solidus, and a needless \\u escape',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const e = ctx.peer.envelope(m);
    for (const [what, text] of nonCanonical(m)) {
      t.error(await ctx.deliver(t, withMessageText(e, text), what), 400, 'invalid', what, {
        canonical: canonicalize(m),
      });
    }
  },
);

def(
  {
    id: 'deliver.envelope-need-not-be-canonical',
    section: 'PROTOCOL 6.1',
    level: 'must',
    title: 'The envelope itself need not be canonical',
    expected:
      '202 for an envelope with whitespace and its members out of order, whose message member is canonical and whose signature is over the canonical envelope',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const e = ctx.peer.envelope(m);
    const body =
      `{\n  "signature" : "${e.signature}",\n  "recipients" : [ ${e.recipients.map(r => JSON.stringify(r)).join(', ')} ],\n` +
      `  "message" : ${canonicalize(m)},\n  "server" : ${JSON.stringify(e.server)}\n}\n`;
    accepted(t, await ctx.deliver(t, body));
  },
);

def(
  {
    id: 'deliver.order-canonical-before-message',
    section: `${S} steps 3-4`,
    level: 'must',
    title: 'Canonical form is checked before the message rules',
    expected:
      '400 invalid with details.canonical for a non-canonical message that also has a field version 2 does not define',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const bad = { ...m, note: 'extra' };
    const e = ctx.peer.envelope(bad);
    const res = await ctx.deliver(t, withMessageText(e, JSON.stringify(bad, null, 1)));
    t.error(res, 400, 'invalid', '', { canonical: canonicalize(bad) });
  },
);

def(
  {
    id: 'deliver.order-canonical-before-signature',
    section: `${S} steps 3, 7`,
    level: 'must',
    title: 'A non-canonical message with a bad envelope signature is refused for its form',
    expected:
      "400 invalid with details.canonical (not 403) for a non-canonical message in an envelope signed by a key the sender's server does not list",
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const e = ctx.peer.envelope(m, { signer: crypto.generateKeyPairSync('ed25519').privateKey });
    t.error(await ctx.deliver(t, withMessageText(e, JSON.stringify(m, null, 1))), 400, 'invalid', '', {
      canonical: canonicalize(m),
    });
  },
);

// Step 4.

/** Each case: a message, refused at step 4 naming the field; the envelope lists `recipients` whatever its to says. */
async function messageCases(
  t: T,
  ctx: Ctx,
  recipients: string[],
  cases: [string, Record<string, unknown>, string | string[]][],
) {
  for (const [what, msg, field] of cases) {
    t.error(await ctx.deliver(t, ctx.peer.envelope(msg, { recipients }), what), 400, 'invalid', what, { field });
  }
}

def(
  {
    id: 'deliver.invariants',
    section: `${S} step 4, PROTOCOL 1`,
    level: 'must',
    title: 'A message breaking an invariant is 400, naming the field',
    expected:
      '400 invalid with details.field naming v, from, to, sentAt or signature when it is missing or malformed: v absent, 0 or "1"; from in upper case or without @; to in upper case, not an array, or holding a non-address; sentAt with an offset or naming 30 February; signature missing or padded',
  },
  async (t: T, ctx: Ctx) => {
    const { a, m } = await valid(ctx);
    const without = (k: string) => Object.fromEntries(Object.entries(m).filter(([n]) => n !== k));
    await messageCases(
      t,
      ctx,
      [a.address],
      [
        ['no v', without('v'), 'v'],
        ['v 0', { ...m, v: 0 }, 'v'],
        ['v "1"', { ...m, v: '1' }, 'v'],
        ['from in upper case', { ...m, from: m.from.toUpperCase() }, 'from'],
        ['from without @', { ...m, from: 'nobody' }, 'from'],
        ['to in upper case', { ...m, to: m.to.map(x => x.toUpperCase()) }, 'to'],
        ['to a string', { ...m, to: m.to[0] }, 'to'],
        ['to holding a number', { ...m, to: [7] }, 'to'],
        ['sentAt with an offset', { ...m, sentAt: m.sentAt.replace(/\.\d{3}Z$|Z$/, '+00:00') }, 'sentAt'],
        ['sentAt on 30 February', { ...m, sentAt: '2026-02-30T00:00:00Z' }, 'sentAt'],
        ['no signature', without('signature'), 'signature'],
        ['a padded signature', { ...m, signature: `${m.signature}=` }, 'signature'],
      ],
    );
  },
);

def(
  {
    id: 'deliver.version-rules',
    section: `${S} step 4, PROTOCOL 5.2-5.4`,
    level: 'must',
    title: "A version 2 message breaking version 2's rules is 400, naming the field",
    expected:
      '400 invalid with details.field naming the field at fault: an undefined field, inReplyTo missing or not an id, a repeated recipient, a non-ASCII local part, 33 parts, a part with an upper-case type or both data and sha256, non-base64 data in a binary part, 33 headers, a header name in upper case, a header that is not a string, a for that is no principal, pairing without a simon-key for, a simon-key for without pairing, and critical with spaces',
  },
  async (t: T, ctx: Ctx) => {
    const { a, m } = await valid(ctx);
    const without = (k: string) => Object.fromEntries(Object.entries(m).filter(([n]) => n !== k));
    const text = { type: 'text/plain', data: 'x' };
    const keyFor = `simon-key:${keyToken(crypto.generateKeyPairSync('ed25519').privateKey)}`;
    const headers = (h: Record<string, unknown>) => ({ ...m, headers: h });
    await messageCases(
      t,
      ctx,
      [a.address],
      [
        ['a field version 2 does not define', { ...m, note: 'x' }, 'note'],
        ['no inReplyTo', without('inReplyTo'), 'inReplyTo'],
        ['inReplyTo not an id', { ...m, inReplyTo: 'ABC' }, 'inReplyTo'],
        ['a recipient twice', { ...m, to: [a.address, a.address] }, 'to'],
        ['a non-ASCII local part', { ...m, to: [`zo\u00eb@${a.address.split('@')[1]}`] }, 'to'],
        ['33 parts', { ...m, parts: Array.from({ length: 33 }, () => text) }, 'parts'],
        ['a type in upper case', { ...m, parts: [{ type: 'Text/Plain', data: 'x' }] }, 'parts'],
        [
          'data and sha256',
          { ...m, parts: [{ type: 'text/plain', data: 'x', sha256: '0'.repeat(64), size: 1 }] },
          'parts',
        ],
        [
          'binary data not base64',
          { ...m, parts: [{ type: 'application/octet-stream', data: 'not base64!' }] },
          'parts',
        ],
        ['33 headers', headers(Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`h${i}`, 'x']))), 'headers'],
        ['a header name in upper case', headers({ Subject: 'x' }), 'headers'],
        ['a header that is a number', headers({ subject: 7 }), 'headers'],
        ['for that is no principal', headers({ for: 'alice@example.org' }), 'headers'],
        ['pairing with a mailto: for', headers({ for: 'mailto:alice@example.org', pairing: 'AAAA' }), 'headers'],
        ['a simon-key: for without pairing', headers({ for: keyFor }), 'headers'],
        ['critical with a space', headers({ critical: 'subject, x' }), 'headers'],
      ],
    );
  },
);

def(
  {
    id: 'deliver.any-parts',
    section: `${S} step 4, PROTOCOL 5.3`,
    level: 'must',
    title: 'A version 2 message carries 0 to 32 parts of any type, with no content rule',
    expected:
      '202 for a message with no parts, one with only a file, one whose only text is HTML, one whose text is content-addressed, a sealed message, and one of 32 parts; 400 invalid with details.field "parts" for one of 33 parts',
  },
  async (t: T, ctx: Ctx) => {
    const { a, m } = await valid(ctx);
    const file = (i: number) => ({ type: 'application/pdf', sha256: i.toString(16).padStart(64, '0'), size: 1 });
    const sealed = {
      type: 'application/simon-sealed',
      data: Buffer.from(`ciphertext ${Date.now()}`).toString('base64'),
    };
    const cases: [string, Part[]][] = [
      ['no parts', []],
      ['only a file', [file(1)]],
      ['only HTML', [{ type: 'text/html', data: `<p>Yes, ${Date.now()}.</p>` }]],
      ['text by content address', [{ ...file(2), type: 'text/plain' }]],
      ['a sealed message, carried unchanged', [sealed]],
      ['32 parts', Array.from({ length: 32 }, (_, i) => file(i + 3))],
    ];
    for (const [what, parts] of cases) {
      const msg = (await valid(ctx, { parts, bare: true })).m;
      accepted(t, await ctx.deliver(t, ctx.peer.envelope(msg), what), what);
    }
    await messageCases(
      t,
      ctx,
      [a.address],
      [['33 parts', { ...m, parts: Array.from({ length: 33 }, (_, i) => file(i)) }, 'parts']],
    );
  },
);

def(
  {
    id: 'deliver.part-labels',
    section: `${S} step 4, PROTOCOL 5.3`,
    level: 'must',
    title: "A part's name and alt are safe to show, and a member a server does not know is ignored",
    expected:
      '202 for a part with a name and an alt, and for one with a member the server does not know; 400 invalid with details.field "parts" for a name with a slash, a name that is .., a name with a right-to-left override, a name of 256 bytes, an alt of two lines, an alt with a right-to-left override, and an empty alt',
  },
  async (t: T, ctx: Ctx) => {
    const text = (labels: Record<string, unknown>) => [{ type: 'text/plain', data: 'See below.', ...labels }];
    const named = (await valid(ctx, { parts: text({ name: 'agenda 2026.txt', alt: 'The agenda' }) })).m;
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(named), 'a name and an alt'), 'a name and an alt');
    const unknown = (await valid(ctx, { parts: text({ lang: 'en' }) })).m;
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(unknown), 'a member it does not know'), 'an unknown member');
    const { a, m } = await valid(ctx);
    await messageCases(
      t,
      ctx,
      [a.address],
      [
        ['a name with a slash', { ...m, parts: text({ name: '../agenda.txt' }) }, 'parts'],
        ['a name that is ..', { ...m, parts: text({ name: '..' }) }, 'parts'],
        ['a name with a right-to-left override', { ...m, parts: text({ name: 'invoice\u202efdp.exe' }) }, 'parts'],
        ['a name of 256 bytes', { ...m, parts: text({ name: 'n'.repeat(256) }) }, 'parts'],
        ['an alt of two lines', { ...m, parts: text({ alt: 'two\nlines' }) }, 'parts'],
        ['an empty alt', { ...m, parts: text({ alt: '' }) }, 'parts'],
        ['an alt with a right-to-left override', { ...m, parts: text({ alt: 'agenda\u202efdp.exe' }) }, 'parts'],
      ],
    );
  },
);

def(
  {
    id: 'deliver.part-size',
    section: `${S} step 4, PROTOCOL 5.3, 7.2`,
    level: 'must',
    title: 'A content-addressed part is at most the published partBytes',
    expected:
      '400 invalid with details.field "parts" for a message naming a part one byte over partBytes, so no part is ever fetched only on demand',
  },
  async (t: T, ctx: Ctx) => {
    const { partBytes } = await ctx.limits();
    const { a, m } = await valid(ctx);
    const over = { type: 'application/octet-stream', sha256: '0'.repeat(64), size: partBytes + 1 };
    await messageCases(t, ctx, [a.address], [['a part over partBytes', { ...m, parts: [...m.parts, over] }, 'parts']]);
  },
);

def(
  {
    id: 'deliver.carried-files',
    section: `${S} step 4, PROTOCOL 5.3, 7.2`,
    level: 'must',
    title: 'The files a message carried inline names are checked as its own are',
    expected:
      '400 invalid with details.field "parts" for a message carrying inline a message that names a file one byte over partBytes, and for one naming more than 1024 files in all, counting those of the messages it carries inline: so no carrier can make a recipient fetch unbounded bytes',
  },
  async (t: T, ctx: Ctx) => {
    const { partBytes } = await ctx.limits();
    const { a, m } = await valid(ctx);
    const file = (i: number, size = 1) => ({
      type: 'application/octet-stream',
      sha256: crypto.createHash('sha256').update(`${ctx.runId} ${i}`).digest('hex'),
      size,
    });
    // A message carried inline is the canonical bytes of a message; nothing checks its signature.
    const carry = (parts: object[]) => ({
      type: 'application/simon-message',
      data: Buffer.from(canonicalize({ ...m, parts })).toString('base64'),
    });
    const many = (from: number) => Array.from({ length: 32 }, (_, i) => file(from + i));
    await messageCases(
      t,
      ctx,
      [a.address],
      [
        [
          'a carried file one byte over partBytes',
          { ...m, parts: [...m.parts, carry([file(0, partBytes + 1)])] },
          'parts',
        ],
        [
          '1025 files in all, some carried inside carried messages',
          {
            ...m,
            parts: [
              ...Array.from({ length: 31 }, (_, i) => carry(many(32 * i))),
              carry([...many(992).slice(0, 31), carry([file(1023), file(1024)])]),
            ],
          },
          'parts',
        ],
      ],
    );
  },
);

def(
  {
    id: 'deliver.header-placement',
    section: `${S} step 4, PROTOCOL 5.4`,
    level: 'must',
    title:
      'audience only on a published one; a misplaced rel or feed ignored; listed only as yes, on a relation with recipients',
    expected:
      '202 for a message with inReplyTo and a rel the registry does not list, for a relation marked listed: yes, for rel without inReplyTo and for feed on a message with recipients (each ignored); 400 invalid with details.field "headers" for rel in upper case, audience on a message with recipients, listed on a plain reply, and listed: Yes',
  },
  async (t: T, ctx: Ctx) => {
    const parent = 'a'.repeat(64);
    const rel = (await valid(ctx, { inReplyTo: parent, headers: { rel: 'x-poke' } })).m;
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(rel), 'an unknown relation'), 'an unknown relation');
    const listed = (await valid(ctx, { inReplyTo: parent, headers: { rel: 'comment', listed: 'yes' } })).m;
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(listed), 'a listed relation'), 'a listed relation');
    const loose = (await valid(ctx, { headers: { rel: 'reaction' } })).m;
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(loose), 'rel without inReplyTo'), 'rel without inReplyTo');
    const fed = (await valid(ctx, { headers: { feed: 'posts' } })).m;
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(fed), 'feed with recipients'), 'feed with recipients');
    const { a, m } = await valid(ctx);
    await messageCases(
      t,
      ctx,
      [a.address],
      [
        ['rel in upper case', { ...m, inReplyTo: parent, headers: { rel: 'Reaction' } }, 'headers'],
        ['audience on a message with recipients', { ...m, headers: { audience: 'followers' } }, 'headers'],
        ['listed on a plain reply', { ...m, inReplyTo: parent, headers: { listed: 'yes' } }, 'headers'],
        ['listed: Yes', { ...m, inReplyTo: parent, headers: { rel: 'comment', listed: 'Yes' } }, 'headers'],
      ],
    );
  },
);

def(
  {
    id: 'deliver.pairing-signature-not-checked-by-servers',
    section: 'PROTOCOL 2.2, 5.4',
    level: 'should',
    title: "A server checks the pairing header's presence, not its signature",
    expected:
      '202 for a message with a simon-key: for and a well-formed pairing, valid or not: verifying it is for readers who rely on it',
  },
  async (t: T, ctx: Ctx) => {
    const principal = crypto.generateKeyPairSync('ed25519').privateKey;
    const forValue = `simon-key:${keyToken(principal)}`;
    const p = ctx.peer.agent('paired', { kind: 'paired' });
    const good = (
      await valid(ctx, { headers: { for: forValue, pairing: signPairing(principal, p.address, forValue) } }, p)
    ).m;
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(good), 'a valid pairing'), 'a valid pairing');
    const forged = (
      await valid(
        ctx,
        { headers: { for: forValue, pairing: signPairing(principal, 'someone@else.example', forValue) } },
        p,
      )
    ).m;
    accepted(
      t,
      await ctx.deliver(t, ctx.peer.envelope(forged), 'a pairing for another agent'),
      'a pairing signed for another agent',
    );
  },
);

def(
  {
    id: 'deliver.recipients-limit',
    section: `${S} step 4, PROTOCOL 9`,
    level: 'must',
    title: 'to is within the published recipients, and a full list is taken',
    expected: '202 for exactly `recipients` recipients; 400 invalid with details.field "to" for one more',
  },
  async (t: T, ctx: Ctx) => {
    const { recipients } = await ctx.limits();
    const domain = await ctx.domain();
    const list = (n: number) => Array.from({ length: n }, (_, i) => `${ctx.runId}-r${i}@${domain}`);
    const at = (await valid(ctx, { to: list(recipients) })).m;
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(at), `${recipients} recipients`), `${recipients} recipients`);
    const over = (await valid(ctx, { to: list(recipients + 1) })).m;
    t.error(
      await ctx.deliver(t, ctx.peer.envelope(over), `${recipients + 1} recipients`),
      400,
      'invalid',
      `${recipients + 1} recipients`,
      { field: 'to' },
    );
  },
);

/** A message from `p` to a, signed, whose canonical form is exactly `bytes` long. */
function messageOfSize(ctx: Ctx, p: PeerAgent, to: string, bytes: number) {
  const probe = buildFrom(p, [to], ctx.now(), { text: '' });
  const pad = bytes - Buffer.byteLength(canonicalize(probe));
  if (pad < 0) throw new Error('the limit is smaller than an empty message');
  return buildFrom(p, [to], ctx.now(), { text: 'x'.repeat(pad), sentAt: probe.sentAt });
}

def(
  {
    id: 'deliver.message-size',
    section: `${S} step 4, PROTOCOL 5.5`,
    level: 'must',
    title: 'A message is at most messageBytes, and one of exactly that size is taken',
    expected:
      '202 for a message of exactly the published messageBytes; 400 invalid with details.field "message" for one byte more',
  },
  async (t: T, ctx: Ctx) => {
    const { messageBytes, requestBodyBytes } = await ctx.limits();
    if (messageBytes + 1024 > requestBodyBytes)
      t.skip(
        `messageBytes (${messageBytes}) leaves no room under requestBodyBytes (${requestBodyBytes}) for an envelope`,
      );
    const { a, p } = await valid(ctx);
    const at = messageOfSize(ctx, p, a.address, messageBytes);
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(at), `${messageBytes} bytes`), `exactly ${messageBytes} bytes`);
    const over = messageOfSize(ctx, p, a.address, messageBytes + 1);
    t.error(
      await ctx.deliver(t, ctx.peer.envelope(over), `${messageBytes + 1} bytes`),
      400,
      'invalid',
      'one byte over',
      { field: 'message' },
    );
  },
);

/** A version 7 message: the invariants, and fields no version 2 reader knows. */
function version7(p: PeerAgent, to: string[], now: number, extra: Record<string, unknown> = {}) {
  const unsigned = {
    v: 7,
    from: p.address,
    to,
    sentAt: timestamp(Math.floor(now / 1000) * 1000),
    headers: 5,
    body: { blocks: [{ kind: 'paragraph', text: 'a later version' }], nonce: crypto.randomUUID() },
    ...extra,
  };
  return resign({ ...unsigned, signature: '' } as never, p.key) as Record<string, any>;
}

def(
  {
    id: 'deliver.unknown-version',
    section: 'PROTOCOL 1, 6.3 step 4',
    level: 'must',
    title: 'A message of an unknown version is taken on its invariants',
    expected:
      '202 for a version 7 message with fields version 2 does not define (and a headers member version 2 would refuse), signed by its author; and for one whose to also names a non-ASCII local part, which only version 2 forbids',
  },
  async (t: T, ctx: Ctx) => {
    const { a, p } = await valid(ctx);
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(version7(p, [a.address], ctx.now())), 'version 7'), 'version 7');
    const wide = version7(p, [a.address, `zo\u00eb-${ctx.runId}@${a.address.split('@')[1]}`], ctx.now());
    accepted(
      t,
      await ctx.deliver(t, ctx.peer.envelope(wide), 'a non-ASCII local part'),
      'a non-ASCII local part in version 7',
    );
  },
);

def(
  {
    id: 'deliver.unknown-version-stored',
    section: 'PROTOCOL 1',
    level: 'must',
    title: 'A message of an unknown version is stored and delivered unchanged',
    expected:
      "the version 7 message appears in the recipient's inbox with its id, byte for byte (given that a plain version 2 message from the same sender does)",
  },
  async (t: T, ctx: Ctx) => {
    await requireControl(ctx);
    const { a, p } = await valid(ctx);
    const m = version7(p, [a.address], ctx.now());
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(m)));
    const entry = await awaitSync(t, a, messageId(m), ctx.opts.deliveryWaitMs);
    if (!entry)
      t.fail(`the message ${messageId(m)} did not reach the inbox within ${ctx.opts.deliveryWaitMs / 1000} s`);
    t.assert(
      canonicalize(entry.message) === canonicalize(m),
      'the inbox holds a different message than the one delivered',
    );
  },
);

def(
  {
    id: 'deliver.unknown-version-invariants',
    section: 'PROTOCOL 1, 6.3 step 4',
    level: 'must',
    title: 'A message of an unknown version still has to keep the invariants',
    expected:
      '400 invalid naming from for a version 7 message whose from is in upper case, and naming to for one without to',
  },
  async (t: T, ctx: Ctx) => {
    const { a, p } = await valid(ctx);
    const upper = version7(p, [a.address], ctx.now());
    const noTo = version7(p, [a.address], ctx.now());
    delete noTo.to;
    await messageCases(
      t,
      ctx,
      [a.address],
      [
        ['from in upper case', { ...upper, from: upper.from.toUpperCase() }, 'from'],
        ['no to', noTo, 'to'],
      ],
    );
  },
);

def(
  {
    id: 'deliver.order-message-before-resolution',
    section: `${S} steps 4, 6`,
    level: 'must',
    title: 'The message is checked before its from-domain is resolved',
    expected: `400 invalid naming the field, not 403 or 503, for a message with an undefined field from a domain that names no server`,
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const bad = { ...m, from: `x@${ctx.opts.unresolvableDomain}`, note: 'x' };
    t.error(await ctx.deliver(t, ctx.peer.envelope(bad)), 400, 'invalid', '', { field: 'note' });
  },
);

// Step 5.

def(
  {
    id: 'deliver.destination-server',
    section: `${S} step 5, PROTOCOL 6.1`,
    level: 'must',
    title: 'An envelope for another server is refused',
    expected:
      '400 invalid with details.field "server" for an envelope signed for the simulator\'s own origin, and for another port of the server\'s host, delivered here',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const other = new URL(ctx.origin);
    other.port = String((Number(other.port || (other.protocol === 'https:' ? 443 : 80)) % 65535) + 1);
    for (const [what, server] of [
      ["the simulator's origin", ctx.peer.origin],
      ['another port of this host', other.origin],
    ]) {
      t.error(await ctx.deliver(t, ctx.peer.envelope(m, { server }), what), 400, 'invalid', what, { field: 'server' });
    }
  },
);

def(
  {
    id: 'deliver.destination-recipients',
    section: `${S} step 5, PROTOCOL 6.1`,
    level: 'must',
    title: "Every recipient of an envelope is in the message's to",
    expected: '400 invalid with details.field "recipients" for a recipient that is not in to',
  },
  async (t: T, ctx: Ctx) => {
    const { a, m } = await valid(ctx);
    const recipients = [a.address, `${ctx.runId}-other@${domainOf(a.address)}`];
    const res = await ctx.deliver(t, ctx.peer.envelope(m, { recipients }), 'a recipient not in to');
    t.error(res, 400, 'invalid', 'a recipient not in to', { field: 'recipients' });
  },
);

def(
  {
    id: 'deliver.served-recipients',
    section: `${S} step 8, PROTOCOL 6.1`,
    level: 'must',
    title: 'Every recipient of an envelope is on a domain the server serves',
    expected: '400 invalid with details.field "recipients" for a recipient in to on a domain the server does not serve',
  },
  async (t: T, ctx: Ctx) => {
    const { a } = await valid(ctx);
    const foreign = `${ctx.runId}-someone@${ctx.opts.unresolvableDomain}`;
    const { m } = await valid(ctx, { to: [a.address, foreign] });
    const res = await ctx.deliver(t, ctx.peer.envelope(m, { recipients: [a.address, foreign] }), 'not served');
    t.error(res, 400, 'invalid', 'a recipient on a domain not served', { field: 'recipients' });
  },
);

def(
  {
    id: 'deliver.order-signature-before-served',
    section: `${S} steps 7-8, PROTOCOL 11.2`,
    level: 'must',
    title: "Whether the recipients are served here is checked only after the carrier's signature",
    expected:
      '403 bad_signature, not 400 on recipients, for an envelope signed by an unlisted key naming a recipient on a domain the server does not serve: no recipient is looked up for an unauthenticated caller',
  },
  async (t: T, ctx: Ctx) => {
    const { a } = await valid(ctx);
    const foreign = `${ctx.runId}-someone@${ctx.opts.unresolvableDomain}`;
    const { m } = await valid(ctx, { to: [a.address, foreign] });
    const forged = ctx.peer.envelope(m, {
      recipients: [a.address, foreign],
      signer: crypto.generateKeyPairSync('ed25519').privateKey,
    });
    t.error(await ctx.deliver(t, forged, 'forged, naming a recipient not served'), 403, 'bad_signature');
  },
);

def(
  {
    id: 'deliver.no-lookup-before-signature',
    section: `${S} steps 5-8, PROTOCOL 11.2`,
    level: 'must',
    title: 'An unauthenticated envelope makes the server look up no recipient domain',
    expected:
      "no request to the second simulator's /.well-known/simon while the server refuses a forged envelope naming a recipient on the second simulator's domain (needs a second simulator reached by its well-known answer, as behind a tunnel)",
  },
  async (t: T, ctx: Ctx) => {
    const second = ctx.secondPeer;
    if (!second || new URL(second.origin).hostname !== second.domain) {
      t.skip(
        'the second simulator is not resolved by its well-known answer (give --second-peer-domain and --second-peer-origin for a tunnel whose name is that domain), so a lookup of its domain cannot be observed',
      );
    }
    const { a } = await valid(ctx);
    const elsewhere = `${ctx.runId}-probe@${second!.domain}`;
    const { m } = await valid(ctx, { to: [a.address, elsewhere] });
    const before = second!.requests.length;
    const forged = ctx.peer.envelope(m, {
      recipients: [a.address, elsewhere],
      signer: crypto.generateKeyPairSync('ed25519').privateKey,
    });
    t.error(await ctx.deliver(t, forged, 'forged, naming a recipient elsewhere'), 403, 'bad_signature');
    await sleep(500);
    const asked = second!.requests.slice(before).filter(r => r.target.startsWith('/.well-known/simon'));
    t.assert(asked.length === 0, `the server fetched ${second!.origin}/.well-known/simon before the envelope verified`);
  },
);

def(
  {
    id: 'deliver.order-message-before-destination',
    section: `${S} steps 4-5`,
    level: 'must',
    title: 'The message is checked before the destination',
    expected:
      '400 invalid naming the undefined field (not server) for a message with a field version 2 does not define, in an envelope for another server',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const bad = { ...m, note: 'x' };
    t.error(await ctx.deliver(t, ctx.peer.envelope(bad, { server: ctx.peer.origin })), 400, 'invalid', '', {
      field: 'note',
    });
  },
);

def(
  {
    id: 'deliver.order-destination-before-resolution',
    section: `${S} steps 5-6`,
    level: 'must',
    title: 'The destination is checked before the from-domain is resolved',
    expected:
      '400 invalid on server, not 403 or 503, for an envelope for another server carrying a message from a domain that names no server',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const k = crypto.generateKeyPairSync('ed25519').privateKey;
    const from = buildFrom({ address: `x@${ctx.opts.unresolvableDomain}`, key: k } as PeerAgent, m.to, ctx.now());
    t.error(await ctx.deliver(t, ctx.peer.envelope(from, { server: ctx.peer.origin })), 400, 'invalid', '', {
      field: 'server',
    });
  },
);

// Step 6.

def(
  {
    id: 'deliver.from-unresolvable',
    section: `${S} step 6, PROTOCOL 3`,
    level: 'must',
    title: 'A from-domain that names no server is 403 bad_signature',
    expected: `403 bad_signature for a message from a domain whose resolution is not_found (the default, ${'example.invalid'}, has no DNS at all)`,
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const k = crypto.generateKeyPairSync('ed25519').privateKey;
    const from = buildFrom({ address: `x@${ctx.opts.unresolvableDomain}`, key: k } as PeerAgent, m.to, ctx.now());
    const res = await ctx.deliver(t, ctx.peer.envelope(from));
    if (res.status === 503)
      t.fail(
        `503: the server reported resolving ${ctx.opts.unresolvableDomain} as temporary; if its DNS is unreachable, give --unresolvable-domain a domain it can look up and find empty`,
      );
    t.error(res, 403, 'bad_signature');
  },
);

def(
  {
    id: 'deliver.from-own-domain',
    section: `${S} step 6`,
    level: 'must',
    title: "A message claiming the receiver's own domain, carried by another server, is 403",
    expected: "403 bad_signature for a message from an address on the server's own domain, carried by the simulator",
  },
  async (t: T, ctx: Ctx) => {
    const { a, m } = await valid(ctx);
    const own = buildFrom(
      { address: `${ctx.runId}-forged@${a.address.split('@')[1]}`, key: a.key } as PeerAgent,
      m.to,
      ctx.now(),
    );
    t.error(await ctx.deliver(t, ctx.peer.envelope(own)), 403, 'bad_signature');
  },
);

def(
  {
    id: 'deliver.order-resolution-before-freshness',
    section: `${S} steps 6, 10`,
    level: 'must',
    title: 'Resolution is checked before freshness',
    expected: '403 bad_signature, not 400, for a stale message from a domain that names no server',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const k = crypto.generateKeyPairSync('ed25519').privateKey;
    const stale = buildFrom({ address: `x@${ctx.opts.unresolvableDomain}`, key: k } as PeerAgent, m.to, ctx.now(), {
      ageSeconds: 200 * HOUR,
    });
    t.error(await ctx.deliver(t, ctx.peer.envelope(stale)), 403, 'bad_signature');
  },
);

// Step 7.

def(
  {
    id: 'deliver.envelope-signature',
    section: `${S} step 7, PROTOCOL 6.1`,
    level: 'must',
    title: 'An envelope must verify with a key of the sending server valid now',
    expected:
      "403 bad_signature for an envelope signed by a key the sender's server does not list, by a listed key revoked in the past, and by a listed key added in the future",
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const cases: [string, crypto.KeyObject][] = [
      ['an unlisted key', crypto.generateKeyPairSync('ed25519').privateKey],
      ['a revoked key', ctx.peer.revokedKey],
      ['a key added in the future', ctx.peer.futureKey],
    ];
    for (const [what, signer] of cases) {
      t.error(await ctx.deliver(t, ctx.peer.envelope(m, { signer }), what), 403, 'bad_signature', what);
    }
  },
);

def(
  {
    id: 'deliver.envelope-covers-everything',
    section: 'PROTOCOL 6.1, 6.2',
    level: 'must',
    title: 'The envelope signature covers every member as sent',
    expected:
      '403 bad_signature for an unknown member added after signing, hints changed after signing, claims: [] with its claimsSignature added to an envelope signed without claims, claims and their claimsSignature removed from one signed with claims: [], and a recipient added after signing (one the message names)',
  },
  async (t: T, ctx: Ctx) => {
    const b = await ctx.agent('b');
    const { a, m } = await valid(ctx, { to: [(await ctx.agent('a')).address, b.address] });
    const e = ctx.peer.envelope(m, { hints: { [a.address]: { invite: 'one' } } });
    const bare = ctx.peer.envelope(m);
    const withEmpty = ctx.peer.envelope(m, { claims: [] });
    const { claims: _, claimsSignature: __, ...stripped } = withEmpty;
    const one = ctx.peer.envelope(m, { recipients: [a.address] });
    const cases: [string, unknown][] = [
      ['a member added after signing', { ...bare, 'x-added': 'later' }],
      ['hints changed after signing', { ...e, hints: { [a.address]: { invite: 'two' } } }],
      ['claims: [] added after signing', { ...bare, claims: [], claimsSignature: withEmpty.claimsSignature }],
      ['claims removed after signing', stripped],
      ['a recipient added after signing', { ...one, recipients: [a.address, b.address] }],
    ];
    for (const [what, env] of cases) t.error(await ctx.deliver(t, canonicalize(env), what), 403, 'bad_signature', what);
  },
);

def(
  {
    id: 'deliver.order-envelope-before-repeat',
    section: `${S} steps 7, 9`,
    level: 'must',
    title: 'A repeat in a forged envelope is refused, not acknowledged',
    expected: '202 for a message, then 403 bad_signature for the same message in an envelope signed by an unlisted key',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(m), 'first'), 'first');
    const forged = ctx.peer.envelope(m, { signer: crypto.generateKeyPairSync('ed25519').privateKey });
    t.error(await ctx.deliver(t, forged, 'again, forged envelope'), 403, 'bad_signature');
  },
);

def(
  {
    id: 'deliver.order-envelope-before-freshness',
    section: `${S} steps 7, 10`,
    level: 'must',
    title: 'The envelope signature is checked before freshness',
    expected: '403 bad_signature, not 400, for a stale message in an envelope signed by an unlisted key',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx, { ageSeconds: 200 * HOUR });
    const forged = ctx.peer.envelope(m, { signer: crypto.generateKeyPairSync('ed25519').privateKey });
    t.error(await ctx.deliver(t, forged), 403, 'bad_signature');
  },
);

// Step 9.

def(
  {
    id: 'deliver.repeat',
    section: `${S} step 9, PROTOCOL 11.2`,
    level: 'must',
    title: 'A repeat is 202 and is stored once',
    expected: "202 for the same message delivered twice, and the recipient's inbox holds it once",
  },
  async (t: T, ctx: Ctx) => {
    const { a, m } = await valid(ctx);
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(m), 'first'), 'first');
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(m), 'again'), 'again');
    await requireControl(ctx);
    const entry = await awaitSync(t, a, messageId(m), ctx.opts.deliveryWaitMs);
    t.assert(entry, 'the message never reached the inbox');
    await sleep(1000);
    const copies = (await readSync(t, a)).filter(e => e.id === messageId(m)).length;
    t.assert(copies === 1, `the inbox holds the message ${copies} times`);
  },
);

def(
  {
    id: 'deliver.repeat-other-envelope',
    section: `${S} step 9`,
    level: 'should',
    title: 'A repeat is recognised by message id and recipients, whatever else the envelope carries',
    expected: '202 for a message delivered again to the same recipients with different hints and claims',
  },
  async (t: T, ctx: Ctx) => {
    const { a, m } = await valid(ctx);
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(m), 'first'), 'first');
    accepted(
      t,
      await ctx.deliver(
        t,
        ctx.peer.envelope(m, { hints: { [a.address]: { invite: 'z' } }, claims: [{ type: 'x-note' }] }),
        'again',
      ),
      'again',
    );
  },
);

def(
  {
    id: 'deliver.order-repeat-before-author',
    section: `${S} steps 9, 11`,
    level: 'must',
    title: 'A repeat is acknowledged without checking the author again',
    expected:
      "202 for a message accepted before, delivered again after its author's document stopped being served (404)",
  },
  async (t: T, ctx: Ctx) => {
    const p = ctx.peer.agent('retiring');
    const { m } = await valid(ctx, {}, p);
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(m), 'first'), 'first');
    p.doc = '404';
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(m), 'again, author document now 404'), 'again');
  },
);

def(
  {
    id: 'deliver.repeat-per-recipient',
    section: `${S} steps 9-10, 12`,
    level: 'must',
    title: 'A repeat is a message accepted before for every recipient the envelope lists',
    expected:
      'for a message to a and b first delivered to a just inside the 144-hour window: once the window closed, 202 for a again (a repeat), but 400 on sentAt for a and b, and for b alone, which are not repeats',
  },
  async (t: T, ctx: Ctx) => {
    const margin = ctx.opts.clockMarginSeconds;
    const b = await ctx.agent('b');
    const { a, p } = await valid(ctx);
    const sentAtMs = Math.floor((ctx.now() - (144 * HOUR - margin - 1) * 1000) / 1000) * 1000;
    const m = buildFrom(p, [a.address, b.address], ctx.now(), { sentAt: timestamp(sentAtMs) });
    const to = (recipients: string[], what: string) => ctx.deliver(t, ctx.peer.envelope(m, { recipients }), what);
    accepted(t, await to([a.address], 'to a, just inside 144 h'), 'to a, just inside 144 hours');
    await sleep(Math.max(0, sentAtMs + 144 * HOUR * 1000 + margin * 1000 - ctx.now()));
    accepted(t, await to([a.address], 'to a again, just past 144 h'), 'to a again, just past 144 hours');
    for (const [what, recipients] of [
      ['to a and b, just past 144 h', [a.address, b.address]],
      ['to b, just past 144 h', [b.address]],
    ] as const) {
      t.error(await to([...recipients], what), 400, 'invalid', `${what}: b was never accepted`, { field: 'sentAt' });
    }
  },
);

def(
  {
    id: 'deliver.repeat-new-recipient',
    section: `${S} step 12, PROTOCOL 11.2`,
    level: 'must',
    title: 'A message accepted for one recipient is accepted again for another',
    expected:
      "for a message to a and b: 202 for an envelope to a, then 202 for one to b; b's inbox then holds the message, and a's holds it once",
  },
  async (t: T, ctx: Ctx) => {
    await requireControl(ctx);
    const b = await ctx.agent('b');
    const { a, m } = await valid(ctx, { to: [(await ctx.agent('a')).address, b.address] });
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(m, { recipients: [a.address] }), 'to a'), 'to a');
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(m, { recipients: [b.address] }), 'to b'), 'to b');
    const id = messageId(m);
    t.assert(await awaitSync(t, b, id, ctx.opts.deliveryWaitMs), "the message never reached b's inbox");
    t.assert(await awaitSync(t, a, id, ctx.opts.deliveryWaitMs), "the message never reached a's inbox");
    const copies = (await readSync(t, a)).filter(e => e.id === id).length;
    t.assert(copies === 1, `a's inbox holds the message ${copies} times`);
  },
);

def(
  {
    id: 'deliver.fan-out-recipients',
    section: `${S} step 12, PROTOCOL 6.1`,
    level: 'must',
    title: 'A delivery reaches only the recipients its envelope lists',
    expected:
      "for a message to a and b in an envelope listing only a: a's inbox holds it, and b's does not (read after a's has it, and again a second later)",
  },
  async (t: T, ctx: Ctx) => {
    await requireControl(ctx);
    const b = await ctx.agent('b');
    const { a, m } = await valid(ctx, { to: [(await ctx.agent('a')).address, b.address] });
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(m, { recipients: [a.address] }), 'to a only'));
    const id = messageId(m);
    t.assert(await awaitSync(t, a, id, ctx.opts.deliveryWaitMs), "the message never reached a's inbox");
    await sleep(1000);
    t.assert(
      !(await readSync(t, b, "b's inbox")).some(e => e.id === id),
      "b's inbox holds a message it was not delivered",
    );
  },
);

def(
  {
    id: 'deliver.order-repeat-before-freshness',
    section: `${S} steps 9-10`,
    level: 'must',
    title: 'A repeat older than 144 hours, but within 168, is still 202',
    expected:
      '202 for a message first delivered just inside the 144-hour window and delivered again just after it closed; 400 on sentAt for a new message with the same sentAt',
  },
  async (t: T, ctx: Ctx) => {
    const margin = ctx.opts.clockMarginSeconds;
    const { a, p } = await valid(ctx);
    const sentAtMs = Math.floor((ctx.now() - (144 * HOUR - margin - 1) * 1000) / 1000) * 1000;
    const sentAt = timestamp(sentAtMs);
    const m = buildFrom(p, [a.address], ctx.now(), { sentAt });
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(m), 'just inside 144 h'), 'just inside 144 hours');
    const wait = sentAtMs + 144 * HOUR * 1000 + margin * 1000 - ctx.now();
    await sleep(Math.max(0, wait));
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(m), 'again, just past 144 h'), 'the repeat just past 144 hours');
    const fresh = buildFrom(p, [a.address], ctx.now(), { sentAt });
    t.error(
      await ctx.deliver(t, ctx.peer.envelope(fresh), 'a new message, same sentAt'),
      400,
      'invalid',
      'a new message with that sentAt',
      { field: 'sentAt' },
    );
  },
);

// Step 10.

def(
  {
    id: 'deliver.freshness',
    section: `${S} step 10`,
    level: 'must',
    title: 'sentAt is at most 144 hours old and at most 5 minutes ahead',
    expected:
      '202 just inside each bound (by the clock margin); 400 invalid with details.field "sentAt" just outside each',
  },
  async (t: T, ctx: Ctx) => {
    const margin = ctx.opts.clockMarginSeconds;
    const cases: [string, number, boolean][] = [
      ['144 h old less the margin', 144 * HOUR - margin, true],
      ['144 h old plus the margin', 144 * HOUR + margin, false],
      ['5 min ahead less the margin', -(300 - margin), true],
      ['5 min ahead plus the margin', -(300 + margin), false],
    ];
    for (const [what, ageSeconds, ok] of cases) {
      const { m } = await valid(ctx, { ageSeconds });
      const res = await ctx.deliver(t, ctx.peer.envelope(m), what);
      if (ok) accepted(t, res, what);
      else t.error(res, 400, 'invalid', what, { field: 'sentAt' });
    }
  },
);

def(
  {
    id: 'deliver.order-freshness-before-author',
    section: `${S} steps 10-11`,
    level: 'must',
    title: "Freshness is checked before the author's signature",
    expected: '400 invalid on sentAt, not 403, for a stale message whose signature does not verify',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx, {
      ageSeconds: 150 * HOUR,
      signWith: crypto.generateKeyPairSync('ed25519').privateKey,
    });
    t.error(await ctx.deliver(t, ctx.peer.envelope(m)), 400, 'invalid', '', { field: 'sentAt' });
  },
);

// Step 11.

def(
  {
    id: 'deliver.author-signature',
    section: `${S} step 11`,
    level: 'must',
    title: "A message its author's keys do not verify is 403 bad_signature",
    expected:
      "403 bad_signature for a message signed by a key its author's document does not list, and for one altered after signing",
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx, { signWith: crypto.generateKeyPairSync('ed25519').privateKey });
    t.error(await ctx.deliver(t, ctx.peer.envelope(m), 'another key'), 403, 'bad_signature', 'signed by another key');
    const { m: m2 } = await valid(ctx);
    const altered = { ...m2, parts: [{ type: 'text/plain', data: 'altered' }] };
    t.error(await ctx.deliver(t, ctx.peer.envelope(altered), 'altered'), 403, 'bad_signature', 'altered after signing');
  },
);

def(
  {
    id: 'deliver.author-strict-ed25519',
    section: `${S} step 11, PROTOCOL 2.3`,
    level: 'must',
    title: 'Ed25519 signatures are verified strictly',
    expected:
      '403 bad_signature for a valid signature with L added to S, which the bare verification equation still accepts',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx);
    const sig = Buffer.from(m.signature, 'base64url');
    const L = 2n ** 252n + 27742317777372353535851937790883648493n;
    let s = 0n;
    for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]);
    s += L;
    for (let i = 32; i < 64; i++, s >>= 8n) sig[i] = Number(s & 0xffn);
    const malleated = { ...m, signature: sig.toString('base64url') };
    t.error(await ctx.deliver(t, ctx.peer.envelope(malleated)), 403, 'bad_signature');
  },
);

def(
  {
    id: 'deliver.author-document-unavailable',
    section: `${S} step 11, PROTOCOL 4`,
    level: 'must',
    title: "An author's document that cannot be fetched just now is 503",
    expected:
      "503 unavailable with retryable: true when the author's server answers the agent document with 503, 500 or 429: those are temporary",
  },
  async (t: T, ctx: Ctx) => {
    for (const doc of ['503', '500', '429'] as const) {
      const { m } = await valid(ctx, {}, ctx.peer.agent(`doc${doc}`, { doc }));
      const err = t.error(
        await ctx.deliver(t, ctx.peer.envelope(m), `document answered ${doc}`),
        503,
        'unavailable',
        `document answered ${doc}`,
      );
      t.assert(err.retryable === true, 'a 503 is retryable: true');
    }
  },
);

def(
  {
    id: 'deliver.author-document-unreadable',
    section: `${S} step 11, PROTOCOL 4`,
    level: 'must',
    title: 'No readable author document is 403 bad_signature',
    expected:
      '403 bad_signature when the agent document is answered 404 or 403 (no document), names another address, is signed by a key the server does not list, lists a malformed Ed25519 key, lists 33 keys, or is over 131072 bytes',
  },
  async (t: T, ctx: Ctx) => {
    const modes = [
      '404',
      '403',
      'wrong-address',
      'bad-signature',
      'malformed-key',
      'too-many-keys',
      'too-large',
    ] as const;
    for (const doc of modes) {
      const { m } = await valid(ctx, {}, ctx.peer.agent(`doc-${doc}`, { doc }));
      t.error(await ctx.deliver(t, ctx.peer.envelope(m), `document: ${doc}`), 403, 'bad_signature', `document ${doc}`);
    }
  },
);

def(
  {
    id: 'deliver.author-document-extensible',
    section: 'PROTOCOL 2.3, 4',
    level: 'must',
    title: 'Unknown algorithms, kinds and members in an agent document are skipped, not errors',
    expected:
      "202 when the author's document also lists a key of an algorithm nobody implements, when its kind is a string other than paired or solo, and when it has members no reader knows (the simulator's server document always has one too)",
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx, {}, ctx.peer.agent('doc-alg', { doc: 'unknown-algorithm' }));
    accepted(
      t,
      await ctx.deliver(t, ctx.peer.envelope(m), 'an unknown algorithm listed'),
      'an unknown algorithm listed',
    );
    const { m: m2 } = await valid(ctx, {}, ctx.peer.agent('doc-kind', { kind: 'x-later-kind' }));
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(m2), 'an unknown kind'), 'an unknown kind');
    const { m: m3 } = await valid(ctx, {}, ctx.peer.agent('doc-members', { doc: 'extra-members' }));
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(m3), 'unknown members'), 'unknown members');
  },
);

def(
  {
    id: 'deliver.author-key-valid-at-sentAt',
    section: `${S} step 11, PROTOCOL 2.4`,
    level: 'must',
    title: "The author's key must be valid at sentAt, at the boundaries",
    expected:
      '202 when the key was added 299 s after sentAt or revoked 1 s after it; 403 bad_signature when added 301 s after sentAt or revoked exactly at it',
  },
  async (t: T, ctx: Ctx) => {
    const sentAtMs = Math.floor((ctx.now() - 60_000) / 1000) * 1000;
    const at = (s: number) => timestamp(sentAtMs + s * 1000);
    const cases: [string, (token: string) => { key: string; added: string; revoked: string | null }, boolean][] = [
      ['added 299 s after sentAt', key => ({ key, added: at(299), revoked: null }), true],
      ['added 301 s after sentAt', key => ({ key, added: at(301), revoked: null }), false],
      ['revoked 1 s after sentAt', key => ({ key, added: LONG_AGO, revoked: at(1) }), true],
      ['revoked at sentAt', key => ({ key, added: LONG_AGO, revoked: at(0) }), false],
    ];
    let i = 0;
    for (const [what, entry, ok] of cases) {
      const p = ctx.peer.agent(`validity-${i++}`);
      p.keys = [entry(p.token)];
      const { m } = await valid(ctx, { sentAt: timestamp(sentAtMs) }, p);
      const res = await ctx.deliver(t, ctx.peer.envelope(m), what);
      if (ok) accepted(t, res, what);
      else t.error(res, 403, 'bad_signature', what);
    }
  },
);

def(
  {
    id: 'deliver.author-ml-dsa',
    section: `${S} step 11, PROTOCOL 2.3`,
    level: 'must',
    title: 'Every server verifies ML-DSA-65',
    expected: '202 for a message signed by an author whose key is ml-dsa-65',
  },
  async (t: T, ctx: Ctx) => {
    const { m } = await valid(ctx, {}, ctx.peer.agent('mldsa', { alg: 'ml-dsa-65' }));
    accepted(t, await ctx.deliver(t, ctx.peer.envelope(m)));
  },
);

/** A key token of an algorithm no implementation knows, well formed as a token. */
const FUTURE_KEY = `x-future-alg:${Buffer.alloc(32, 9).toString('base64url')}`;

def(
  {
    id: 'deliver.author-unsupported-algorithm',
    section: `${S} step 11, PROTOCOL 2.3, 9`,
    level: 'must',
    title: 'An author whose only keys valid at sentAt are of an unknown algorithm is 403 unsupported_algorithm',
    expected:
      '403 unsupported_algorithm when the author document lists only a key of an algorithm nobody implements, and when it also lists an Ed25519 key revoked before sentAt; 403 bad_signature, not unsupported_algorithm, when an Ed25519 key valid at sentAt is listed beside it and the signature does not verify',
  },
  async (t: T, ctx: Ctx) => {
    const sentAtMs = Math.floor((ctx.now() - 60_000) / 1000) * 1000;
    const future = { key: FUTURE_KEY, added: LONG_AGO, revoked: null };
    const cases: [string, (token: string) => KeyEntry[], string][] = [
      ['only an unknown algorithm', () => [future], 'unsupported_algorithm'],
      [
        'an unknown algorithm, and an Ed25519 key revoked before sentAt',
        key => [future, { key, added: LONG_AGO, revoked: timestamp(sentAtMs - 1000) }],
        'unsupported_algorithm',
      ],
      [
        'an unknown algorithm, and an Ed25519 key valid at sentAt that did not sign',
        () => [
          future,
          { key: keyToken(crypto.generateKeyPairSync('ed25519').privateKey), added: LONG_AGO, revoked: null },
        ],
        'bad_signature',
      ],
    ];
    let i = 0;
    for (const [what, keys, code] of cases) {
      const p = ctx.peer.agent(`future-alg-${i++}`);
      p.keys = keys(p.token);
      const { m } = await valid(ctx, { sentAt: timestamp(sentAtMs) }, p);
      t.error(await ctx.deliver(t, ctx.peer.envelope(m), what), 403, code, what);
    }
  },
);

// Policy is silent.

def(
  {
    id: 'deliver.silence',
    section: 'PROTOCOL 6.3 "Policy is silent"',
    level: 'must',
    title: 'Known and unknown recipients get the same answer',
    expected:
      "byte-identical 202 answers for a valid message to a known agent, to an unknown name on the server's domain, and to an unknown name whose message also names an address elsewhere",
  },
  async (t: T, ctx: Ctx) => {
    const { a } = await valid(ctx);
    const domain = await ctx.domain();
    const nobody = `${ctx.runId}-nobody@${domain}`;
    const answers: [string, Res][] = [];
    for (const [what, to] of [
      ['a known agent', [a.address]],
      ['an unknown name', [nobody]],
      ['an unknown name beside an address elsewhere', [nobody, `${ctx.runId}-someone@${ctx.opts.unresolvableDomain}`]],
    ] as const) {
      const { m } = await valid(ctx, { to: [...to] });
      answers.push([what, await ctx.deliver(t, ctx.peer.envelope(m, { recipients: [to[0]] }), what)]);
    }
    for (const [what, res] of answers) accepted(t, res, what);
    const first = answers[0][1].text;
    for (const [what, res] of answers)
      t.assert(res.text === first, `${what} answered ${res.text}; ${answers[0][0]} answered ${first}`);
  },
);

export { requireControl, controlSeen };
