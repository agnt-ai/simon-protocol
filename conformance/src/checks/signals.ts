/**
 * PROTOCOL section 6.4: signals, posted by the simulator to the server under test. Every check is about what
 * the receiving server answers; what it passes on to its agents is for its client API, and never stored.
 */
import crypto from 'node:crypto';
import { canonicalize, messageId, signSignal, timestamp, type UnsignedSignal } from '@agnt-protocol/protocol';
import type { TargetAgent } from '../agent.ts';
import { buildFrom, type Ctx } from '../context.ts';
import { sleep, type Res, type T } from '../harness.ts';
import type { PeerAgent } from '../peer.ts';
import { awaitSync, def, readSync } from './common.ts';
import { requireControl } from './deliver.ts';

const S = 'PROTOCOL 6.4';

/** An agent here that receives one message from a simulated agent and nothing else, and that message. */
const thread = (ctx: Ctx) =>
  ctx.once('a thread for signals', async t => {
    await requireControl(ctx);
    const a = await ctx.agent('signals');
    const p = ctx.peer.agent('signaller');
    const m = buildFrom(p, [a.address], ctx.now());
    await ctx.deliver(t, ctx.peer.envelope(m), 'a message the signals are about');
    await awaitSync(t, a, messageId(m), ctx.opts.deliveryWaitMs);
    return { a, p, about: messageId(m) };
  });

/** A signal from `p` to `a` about `about`, signed by the simulator unless `signer` is given. */
function signal(
  ctx: Ctx,
  s: { a: TargetAgent; p: PeerAgent; about: string },
  patch: Partial<UnsignedSignal> = {},
  signer = ctx.peer.serverKey,
) {
  const unsigned: UnsignedSignal = {
    type: 'read',
    from: s.p.address,
    to: [s.a.address],
    about: s.about,
    at: timestamp(Math.floor(ctx.now() / 1000) * 1000),
    server: ctx.origin,
    ...patch,
  };
  return signSignal(unsigned, signer);
}

const post = (t: T, ctx: Ctx, body: object | string, label?: string) =>
  t.http(
    {
      method: 'POST',
      origin: ctx.origin,
      target: '/agnt/signal',
      body: typeof body === 'string' ? body : canonicalize(body),
    },
    { label },
  );

function accepted(t: T, res: Res, what: string) {
  t.status(res, 202, what);
  t.assert(res.json?.accepted === true, `${what}: a 202 answers {"accepted":true}; got ${res.text.slice(0, 200)}`);
}

def(
  {
    id: 'signal.accepted',
    section: S,
    level: 'must',
    title: 'A valid signal is 202 {"accepted":true}',
    expected:
      '202 with the body {"accepted":true} for typing, collected and read signals, and for a type the registry may add, each signed by the simulator\'s server key and naming this server',
  },
  async (t: T, ctx: Ctx) => {
    const s = await thread(ctx);
    for (const type of ['typing', 'collected', 'read', 'x-later-signal']) {
      accepted(t, await post(t, ctx, signal(ctx, s, { type }), type), type);
    }
  },
);

def(
  {
    id: 'signal.shape',
    section: S,
    level: 'must',
    title: 'A malformed signal is 400, naming the member at fault',
    expected:
      '400 invalid with details.field "type" for a type in upper case, "to" for an empty to, "about" for an about that is not a message id, "at" for an at that is not a timestamp, and "signal" for a signal over 4096 canonical bytes without its signature; 413 body_too_large for a body over 16384 bytes',
  },
  async (t: T, ctx: Ctx) => {
    const s = await thread(ctx);
    const cases: [string, Partial<UnsignedSignal>, string][] = [
      ['a type in upper case', { type: 'Read' }, 'type'],
      ['an empty to', { to: [] }, 'to'],
      ['about that is not a message id', { about: 'x' }, 'about'],
      ['at that is not a timestamp', { at: 'now' }, 'at'],
    ];
    for (const [what, patch, field] of cases) {
      t.error(await post(t, ctx, signal(ctx, s, patch), what), 400, 'invalid', what, { field });
    }
    const big = signal(ctx, s, { pad: 'x'.repeat(4096) } as never);
    t.error(await post(t, ctx, big, 'over 4096 bytes without its signature'), 400, 'invalid', 'over 4096 bytes', {
      field: 'signal',
    });
    const huge = signal(ctx, s, { pad: 'x'.repeat(16384) } as never);
    t.error(await post(t, ctx, huge, 'a body over 16384 bytes'), 413, 'body_too_large', 'over 16384 bytes');
  },
);

def(
  {
    id: 'signal.destination',
    section: S,
    level: 'must',
    title: 'A signal for another server is refused',
    expected: '400 invalid with details.field "server" for a signal naming the simulator\'s own origin as its server',
  },
  async (t: T, ctx: Ctx) => {
    const s = await thread(ctx);
    t.error(await post(t, ctx, signal(ctx, s, { server: ctx.peer.origin })), 400, 'invalid', '', { field: 'server' });
  },
);

def(
  {
    id: 'signal.signature',
    section: S,
    level: 'must',
    title: "A signal must verify with a key of the sender's server valid now",
    expected:
      "403 bad_signature for a signal signed by a key the simulator's server document does not list, and for one changed after signing",
  },
  async (t: T, ctx: Ctx) => {
    const s = await thread(ctx);
    const forged = signal(ctx, s, {}, crypto.generateKeyPairSync('ed25519').privateKey);
    t.error(await post(t, ctx, forged, 'an unlisted key'), 403, 'bad_signature', 'an unlisted key');
    const changed = { ...signal(ctx, s), type: 'typing' };
    t.error(await post(t, ctx, changed, 'changed after signing'), 403, 'bad_signature', 'changed after signing');
  },
);

def(
  {
    id: 'signal.served',
    section: S,
    level: 'must',
    title: 'Every recipient of a signal is on a domain the server serves',
    expected:
      '400 invalid with details.field "to" for a signal also naming an address on a domain the server does not serve',
  },
  async (t: T, ctx: Ctx) => {
    const s = await thread(ctx);
    const to = [s.a.address, `${ctx.runId}-someone@${ctx.opts.unresolvableDomain}`];
    t.error(await post(t, ctx, signal(ctx, s, { to })), 400, 'invalid', '', { field: 'to' });
  },
);

def(
  {
    id: 'signal.order-signature-before-served',
    section: `${S} steps 5-6, PROTOCOL 11.2`,
    level: 'must',
    title: "Whether a signal's recipients are served here is checked only after its signature",
    expected:
      "403 bad_signature, not 400 on to, for a signal signed by a key the simulator's server document does not list and naming an address on a domain the server does not serve: no recipient is looked up for an unauthenticated caller",
  },
  async (t: T, ctx: Ctx) => {
    const s = await thread(ctx);
    const to = [s.a.address, `${ctx.runId}-someone@${ctx.opts.unresolvableDomain}`];
    const forged = signal(ctx, s, { to }, crypto.generateKeyPairSync('ed25519').privateKey);
    t.error(await post(t, ctx, forged, 'forged, naming a recipient not served'), 403, 'bad_signature');
  },
);

def(
  {
    id: 'signal.freshness',
    section: S,
    level: 'must',
    title: "A signal's at is within 300 seconds of the receiver's clock",
    expected:
      '202 for an at 300 s old less the clock margin; 400 invalid with details.field "at" for one 300 s old plus the margin, and one 300 s ahead plus the margin',
  },
  async (t: T, ctx: Ctx) => {
    const s = await thread(ctx);
    const margin = ctx.opts.clockMarginSeconds;
    const at = (seconds: number) => timestamp(Math.floor((ctx.now() - seconds * 1000) / 1000) * 1000);
    accepted(t, await post(t, ctx, signal(ctx, s, { at: at(300 - margin) }), 'just inside'), 'just inside 300 s');
    for (const [what, seconds] of [
      ['300 s old plus the margin', 300 + margin],
      ['300 s ahead plus the margin', -(300 + margin)],
    ] as const) {
      t.error(await post(t, ctx, signal(ctx, s, { at: at(seconds) }), what), 400, 'invalid', what, { field: 'at' });
    }
  },
);

def(
  {
    id: 'signal.silence',
    section: `${S}, 6.3 "Policy is silent"`,
    level: 'must',
    title: 'A signal for an unknown name gets the same answer as one for an agent',
    expected:
      "byte-identical 202 answers for a signal to the agent the message went to, to an unknown name on the server's domain, and about a message nobody here holds",
  },
  async (t: T, ctx: Ctx) => {
    const s = await thread(ctx);
    const nobody = `${ctx.runId}-nobody@${await ctx.domain()}`;
    const answers: [string, Res][] = [
      ['the agent', await post(t, ctx, signal(ctx, s), 'to the agent')],
      ['an unknown name', await post(t, ctx, signal(ctx, s, { to: [nobody] }), 'to an unknown name')],
      ['an unknown message', await post(t, ctx, signal(ctx, s, { about: 'f'.repeat(64) }), 'about nothing')],
    ];
    for (const [what, res] of answers) accepted(t, res, what);
    for (const [what, res] of answers) {
      t.assert(
        res.text === answers[0][1].text,
        `${what} answered ${res.text}; the agent's answered ${answers[0][1].text}`,
      );
    }
  },
);

def(
  {
    id: 'signal.not-stored',
    section: S,
    level: 'must',
    title: 'A signal never enters an inbox',
    expected: "the recipient's inbox holds exactly the entries it held before, a second after valid signals to it",
  },
  async (t: T, ctx: Ctx) => {
    const s = await thread(ctx);
    const before = (await readSync(t, s.a, 'the inbox before')).map(e => e.id);
    for (const type of ['typing', 'read']) accepted(t, await post(t, ctx, signal(ctx, s, { type }), type), type);
    await sleep(1000);
    const after = (await readSync(t, s.a, 'the inbox after')).map(e => e.id);
    t.assert(
      JSON.stringify(after) === JSON.stringify(before),
      `the inbox changed: ${JSON.stringify(before)} became ${JSON.stringify(after)}`,
    );
  },
);
