/** CLIENT send: the order of its checks, the paired and solo rule, its time window, parts and hints. */
import crypto from 'node:crypto';
import { canonicalize, keyToken, messageId, parseTimestamp, sha256Hex, signPairing } from '@agnt-sdk/simon-protocol';
import { resign, type TargetAgent } from '../agent.ts';
import type { Ctx } from '../context.ts';
import type { T } from '../harness.ts';
import { def } from './common.ts';
import { pairedAgent } from './register.ts';

const DAY = 86_400_000;
const S = 'CLIENT send';

async function pair(ctx: Ctx) {
  return { a: await ctx.agent('a'), b: await ctx.agent('b') };
}

def(
  {
    id: 'send.accepted',
    section: S,
    level: 'must',
    title: 'send answers the message id and when it was received',
    expected:
      '200 {"id","receivedAt"} where id is the hex SHA-256 of the canonical message without signature, and receivedAt a timestamp',
  },
  async (t: T, ctx: Ctx) => {
    const { a, b } = await pair(ctx);
    const m = a.message({ to: [b.address] });
    const res = await a.send(t, m);
    t.status(res, 200);
    t.assert(res.json?.id === messageId(m), `id is ${JSON.stringify(res.json?.id)}, expected ${messageId(m)}`);
    t.assert(
      parseTimestamp(res.json?.receivedAt) !== null,
      `receivedAt ${JSON.stringify(res.json?.receivedAt)} is not a timestamp`,
    );
  },
);

def(
  {
    id: 'send.repeat',
    section: `${S} "Idempotence"`,
    level: 'must',
    title: 'Sending the same message again returns the same answer',
    expected: 'the same message sent twice answers 200 both times with the same id and receivedAt',
  },
  async (t: T, ctx: Ctx) => {
    const { a, b } = await pair(ctx);
    const m = a.message({ to: [b.address] });
    const first = await a.send(t, m, {}, 'first');
    t.status(first, 200, 'first');
    const again = await a.send(t, m, {}, 'again');
    t.status(again, 200, 'again');
    t.assert(
      again.json?.id === first.json?.id && again.json?.receivedAt === first.json?.receivedAt,
      `first ${first.text}, then ${again.text}`,
    );
  },
);

def(
  {
    id: 'send.body-too-large',
    section: 'CLIENT, PROTOCOL 6.3 step 1',
    level: 'must',
    title: 'A send body over requestBodyBytes is 413',
    expected: '413 body_too_large for a correctly signed body one byte over requestBodyBytes',
  },
  async (t: T, ctx: Ctx) => {
    const { a } = await pair(ctx);
    const { requestBodyBytes } = await ctx.limits();
    t.error(await a.send(t, 'A'.repeat(requestBodyBytes + 1)), 413, 'body_too_large');
  },
);

def(
  {
    id: 'send.canonical',
    section: `${S}, PROTOCOL 5.1`,
    level: 'must',
    title: 'A message not in canonical form is 400 with its canonical form',
    expected: '400 invalid with details.canonical exactly the canonical form',
  },
  async (t: T, ctx: Ctx) => {
    const { a, b } = await pair(ctx);
    const m = a.message({ to: [b.address] });
    t.error(await a.send(t, JSON.stringify(m, null, 2)), 400, 'invalid', '', { canonical: canonicalize(m) });
  },
);

def(
  {
    id: 'send.message-rules',
    section: `${S}, PROTOCOL 6.3 step 4`,
    level: 'must',
    title: 'send applies the message rules of section 6.3 step 4',
    expected:
      '400 invalid naming the field for a field version 2 does not define, naming to for one recipient over the published limit, and naming headers for a message to no one with no audience',
  },
  async (t: T, ctx: Ctx) => {
    const { a, b } = await pair(ctx);
    const { recipients } = await ctx.limits();
    const extra = resign({ ...a.message({ to: [b.address] }), note: 'x' }, a.key);
    t.error(await a.send(t, extra, {}, 'an undefined field'), 400, 'invalid', 'an undefined field', { field: 'note' });
    const domain = b.address.split('@')[1];
    const many = a.message({ to: Array.from({ length: recipients + 1 }, (_, i) => `${ctx.runId}-r${i}@${domain}`) });
    t.error(await a.send(t, many, {}, `${recipients + 1} recipients`), 400, 'invalid', 'too many recipients', {
      field: 'to',
    });
    // Publishing is explicit: a message to no one says who may read it (PROTOCOL 5.4).
    const unsaid = a.message({ to: [], headers: {} });
    const bare = resign({ ...unsaid, headers: {} }, a.key);
    t.error(await a.send(t, bare, {}, 'a message to no one with no audience'), 400, 'invalid', 'no audience', {
      field: 'headers',
    });
  },
);

def(
  {
    id: 'send.order',
    section: S,
    level: 'must',
    title: 'send checks the message (steps 1 to 4) before whose it is',
    expected:
      "400 invalid with details.canonical, not 409, for a non-canonical message from another agent; 400 naming the field, not 409, for another agent's message with an undefined field",
  },
  async (t: T, ctx: Ctx) => {
    const { a, b } = await pair(ctx);
    const hers = b.message({ to: [a.address] });
    t.error(
      await a.send(t, JSON.stringify(hers, null, 1), {}, 'not canonical, not mine'),
      400,
      'invalid',
      'not canonical and from another agent',
      {
        canonical: canonicalize(hers),
      },
    );
    const bad = resign({ ...b.message({ to: [a.address] }), note: 'x' }, b.key);
    t.error(
      await a.send(t, bad, {}, 'an undefined field, not mine'),
      400,
      'invalid',
      'an undefined field, from another agent',
      { field: 'note' },
    );
  },
);

def(
  {
    id: 'send.from',
    section: S,
    level: 'must',
    title: "An agent cannot send another agent's message",
    expected:
      '400 invalid with details.field "from" for a message whose from is another agent\'s address, sent by this agent',
  },
  async (t: T, ctx: Ctx) => {
    const { a, b } = await pair(ctx);
    t.error(await a.send(t, b.message({ to: [a.address] })), 400, 'invalid', '', { field: 'from' });
  },
);

def(
  {
    id: 'send.solo',
    section: `${S}, PROTOCOL 2.2`,
    level: 'must',
    title: "A solo agent's message carries no for",
    expected: '400 invalid with details.field "headers" for a solo agent\'s message with a for header',
  },
  async (t: T, ctx: Ctx) => {
    const { a, b } = await pair(ctx);
    const m = a.message({ to: [b.address], headers: { for: 'mailto:someone@example.org' } });
    t.error(await a.send(t, m), 400, 'invalid', '', { field: 'headers' });
  },
);

def(
  {
    id: 'send.paired',
    section: `${S}, PROTOCOL 2.2, 5.4`,
    level: 'must',
    title: "A paired agent's message carries its principal and a pairing that verifies",
    expected:
      '200 with the principal as for and its pairing; 400 invalid with details.field "headers" with no for, with another principal (and that principal\'s valid pairing), with a pairing signed for another address, with a pairing that lapsed a minute before sentAt, and with one lasting more than 366 days past it',
  },
  async (t: T, ctx: Ctx) => {
    const p = await pairedAgent(ctx);
    const { b } = await pair(ctx);
    const a = p.agent;
    const pairing = signPairing(p.principal, a.address, p.for, ctx.until());
    t.status(
      await a.send(t, a.message({ to: [b.address], headers: { for: p.for, pairing } }), {}, 'with for and pairing'),
      200,
      'for and pairing',
    );
    const other = crypto.generateKeyPairSync('ed25519').privateKey;
    const otherFor = `simon-key:${keyToken(other)}`;
    const cases: [string, Record<string, string>][] = [
      ['no for', {}],
      ['another principal', { for: otherFor, pairing: signPairing(other, a.address, otherFor, ctx.until()) }],
      [
        'a pairing for another address',
        { for: p.for, pairing: signPairing(p.principal, `other-${a.address}`, p.for, ctx.until()) },
      ],
      ['a lapsed pairing', { for: p.for, pairing: signPairing(p.principal, a.address, p.for, ctx.until(-60_000)) }],
      [
        'a pairing over 366 days',
        { for: p.for, pairing: signPairing(p.principal, a.address, p.for, ctx.until(367 * DAY)) },
      ],
    ];
    for (const [what, headers] of cases) {
      t.error(await a.send(t, a.message({ to: [b.address], headers }), {}, what), 400, 'invalid', what, {
        field: 'headers',
      });
    }
  },
);

def(
  {
    id: 'send.sent-at',
    section: S,
    level: 'must',
    title: 'sentAt is at most 5 minutes ahead, and at most 24 hours old',
    expected:
      '200 for sentAt 5 minutes ahead less the clock margin; 400 invalid with details.field "sentAt" 5 minutes ahead plus the margin; 401 bad_signature for 24 hours old plus the margin, since the signature is checked first and a key registered during the run was not valid 24 hours earlier',
  },
  async (t: T, ctx: Ctx) => {
    const { a, b } = await pair(ctx);
    const m = ctx.opts.clockMarginSeconds;
    t.status(
      await a.send(t, a.message({ to: [b.address], ageSeconds: -(300 - m) }), {}, 'ahead less the margin'),
      200,
      '5 min ahead less the margin',
    );
    t.error(
      await a.send(t, a.message({ to: [b.address], ageSeconds: -(300 + m) }), {}, 'ahead plus the margin'),
      400,
      'invalid',
      '5 min ahead plus the margin',
      {
        field: 'sentAt',
      },
    );
    const old = await a.send(
      t,
      a.message({ to: [b.address], ageSeconds: 24 * 3600 + m }),
      {},
      '24 h old plus the margin',
    );
    t.error(old, 401, 'bad_signature', '24 h old plus the margin');
  },
);

def(
  {
    id: 'send.part-not-uploaded',
    section: S,
    level: 'must',
    title: 'A content-addressed part the server does not hold for the agent is refused',
    expected:
      '400 part_not_uploaded with details.sha256 for a part nobody uploaded, and for a part another agent uploaded',
  },
  async (t: T, ctx: Ctx) => {
    const { a, b } = await pair(ctx);
    const nobody = sha256Hex(crypto.randomBytes(32));
    const part = (sha256: string) => [{ type: 'application/octet-stream', sha256, size: 32 }];
    const err = t.error(
      await a.send(t, a.message({ to: [b.address], parts: part(nobody) }), {}, 'never uploaded'),
      400,
      'part_not_uploaded',
      'never uploaded',
    );
    t.assert(err.details?.sha256 === nobody, `details.sha256 is ${JSON.stringify(err.details?.sha256)}`);
    const bytes = crypto.randomBytes(32);
    const hers = sha256Hex(bytes);
    const up = await b.call(
      t,
      'PUT',
      `/simon/parts/${hers}`,
      bytes,
      { headers: { 'content-type': 'application/octet-stream' } },
      'agent b uploads',
    );
    t.status(up, 200, 'agent b uploads a part');
    const err2 = t.error(
      await a.send(t, a.message({ to: [b.address], parts: part(hers) }), {}, "b's part"),
      400,
      'part_not_uploaded',
      "another agent's part",
    );
    t.assert(err2.details?.sha256 === hers, `details.sha256 is ${JSON.stringify(err2.details?.sha256)}`);
  },
);

/** A version 7 message from `from`, signed by `key`: the invariants, and members version 2 does not define. */
function version7(from: TargetAgent, to: string[] | undefined, key = from.key) {
  const unsigned: Record<string, unknown> = {
    v: 7,
    from: from.address,
    sentAt: from.message().sentAt,
    body: { text: 'later' },
  };
  if (to) unsigned.to = to;
  return resign({ ...unsigned, signature: '' } as never, key) as Record<string, unknown>;
}

def(
  {
    id: 'send.unsupported-version',
    section: `${S}, CLIENT errors, PROTOCOL 1`,
    level: 'must',
    title: 'send refuses a message of a version the server does not implement',
    expected:
      '400 unsupported_version for a version 7 message, signed by the agent, that keeps the invariants (a server routes such a message on deliver, but takes none from its own agents)',
  },
  async (t: T, ctx: Ctx) => {
    const { a, b } = await pair(ctx);
    t.error(await a.send(t, version7(a, [b.address]) as never), 400, 'unsupported_version');
  },
);

def(
  {
    id: 'send.bad-signature',
    section: S,
    level: 'must',
    title: "send refuses a message its agent's keys do not verify",
    expected:
      '401 bad_signature for a message altered after signing, and for one signed by a key the agent does not hold',
  },
  async (t: T, ctx: Ctx) => {
    const { a, b } = await pair(ctx);
    const altered = { ...a.message({ to: [b.address] }), headers: { subject: 'altered' } };
    t.error(await a.send(t, altered, {}, 'altered'), 401, 'bad_signature', 'altered after signing');
    const other = a.message({ to: [b.address], signWith: crypto.generateKeyPairSync('ed25519').privateKey });
    t.error(await a.send(t, other, {}, 'another key'), 401, 'bad_signature', 'signed by another key');
  },
);

def(
  {
    id: 'send.order-version',
    section: S,
    level: 'must',
    title: "The version is checked after the message's own rules and before whose it is",
    expected:
      "400 invalid with details.canonical for a non-canonical version 7 message; 400 invalid naming to for a version 7 message without to; 400 unsupported_version, not 400 on from, for another agent's version 7 message",
  },
  async (t: T, ctx: Ctx) => {
    const { a, b } = await pair(ctx);
    const v7 = version7(a, [b.address]);
    t.error(
      await a.send(t, JSON.stringify(v7, null, 1), {}, 'version 7, not canonical'),
      400,
      'invalid',
      'not canonical',
      {
        canonical: canonicalize(v7),
      },
    );
    t.error(await a.send(t, version7(a, undefined) as never, {}, 'version 7 without to'), 400, 'invalid', 'no to', {
      field: 'to',
    });
    t.error(
      await a.send(t, version7(b, [a.address]) as never, {}, "another agent's version 7"),
      400,
      'unsupported_version',
      "another agent's version 7 message",
    );
  },
);

def(
  {
    id: 'send.order-after-message',
    section: S,
    level: 'must',
    title: "send's own checks come in the order CLIENT lists them (from, signature, principal, sentAt, parts)",
    expected:
      "400 on from (not 401) for another agent's message with a bad signature; 401 bad_signature (not 400 on headers) for a solo agent's message with a for header and a bad signature; 400 on headers (not on sentAt) for a solo agent's message with a for header, 5 minutes ahead plus the margin; 400 on sentAt (not part_not_uploaded) for a message that far ahead naming a part never uploaded; 401 bad_signature (not part_not_uploaded) for a bad signature naming a part never uploaded",
  },
  async (t: T, ctx: Ctx) => {
    const { a, b } = await pair(ctx);
    const ahead = -(300 + ctx.opts.clockMarginSeconds);
    const forged = crypto.generateKeyPairSync('ed25519').privateKey;
    const hers = b.message({ to: [a.address], signWith: forged });
    t.error(await a.send(t, hers, {}, 'not mine, bad signature'), 400, 'invalid', 'from and signature', {
      field: 'from',
    });
    const withFor = { to: [b.address], headers: { for: 'mailto:someone@example.org' } };
    t.error(
      await a.send(t, a.message({ ...withFor, signWith: forged }), {}, 'for on a solo agent, bad signature'),
      401,
      'bad_signature',
      'signature and headers',
    );
    t.error(
      await a.send(t, a.message({ ...withFor, ageSeconds: ahead }), {}, 'for on a solo agent, too far ahead'),
      400,
      'invalid',
      'headers and sentAt',
      { field: 'headers' },
    );
    const part = [{ type: 'application/octet-stream', sha256: sha256Hex(crypto.randomBytes(8)), size: 8 }];
    t.error(
      await a.send(
        t,
        a.message({ to: [b.address], parts: part, ageSeconds: ahead }),
        {},
        'no such part, too far ahead',
      ),
      400,
      'invalid',
      'sentAt and parts',
      { field: 'sentAt' },
    );
    t.error(
      await a.send(t, a.message({ to: [b.address], parts: part, signWith: forged }), {}, 'no such part, bad signature'),
      401,
      'bad_signature',
      'signature and parts',
    );
  },
);

def(
  {
    id: 'send.hints',
    section: `${S} "Hints"`,
    level: 'must',
    title: 'simon-hints is an object keyed by recipients, and is not signed',
    expected:
      '200 with a valid simon-hints header added after signing; 400 invalid for simon-hints that is not JSON, an array, or names an address not in to',
  },
  async (t: T, ctx: Ctx) => {
    const { a, b } = await pair(ctx);
    const good = a.message({ to: [b.address] });
    const ok = await a.send(
      t,
      good,
      { headers: { 'simon-hints': JSON.stringify({ [b.address]: { invite: 'x' } }) } },
      'valid hints',
    );
    t.status(ok, 200, 'valid hints');
    const cases: [string, string][] = [
      ['not JSON', 'invite=x'],
      ['an array', '[1,2]'],
      ['an address not in to', JSON.stringify({ [`other-${b.address}`]: { invite: 'x' } })],
    ];
    for (const [what, hints] of cases) {
      t.error(
        await a.send(t, a.message({ to: [b.address] }), { headers: { 'simon-hints': hints } }, what),
        400,
        'invalid',
        what,
      );
    }
  },
);

def(
  {
    id: 'send.ml-dsa',
    section: `${S}, PROTOCOL 2.3`,
    level: 'must',
    title: 'An agent with an ML-DSA-65 key sends',
    expected: '200 for a message signed with ml-dsa-65 by an agent registered with that key',
  },
  async (t: T, ctx: Ctx) => {
    const m = await ctx.agent('mldsa', 'ml-dsa-65');
    const { b } = await pair(ctx);
    t.status(await m.send(t, m.message({ to: [b.address] })), 200);
  },
);
