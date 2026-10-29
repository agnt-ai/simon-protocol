/**
 * What a server must leave to its readers. A reader obeys `critical`, ignores the headers it does not know and
 * reads an unknown relation as a reply (PROTOCOL 5.4, 5.5, reader profile); a server does none of it. It
 * routes, stores and syncs the message whole, so a reader that understands the header sees what its author
 * signed. Whether a reader obeys these rules is not a server's to show: test/integration/reader-live.test.ts
 * runs the JavaScript client's reader over what the reference server kept, and the vectors (`reading`) cover
 * the rest (readme.md, "What the suite cannot test").
 */
import { canonicalize, messageId } from '@agnt-sdk/simon-protocol';
import { buildFrom, type Ctx } from '../context.ts';
import type { T } from '../harness.ts';
import { awaitSync, def } from './common.ts';
import { requireControl } from './deliver.ts';

const S = 'PROTOCOL 5.4';

/**
 * Both ways a message reaches an agent's sync, with these headers: delivered by the simulator, and sent by
 * the agent to itself. Each must be taken, and must come back byte for byte.
 */
async function carried(t: T, ctx: Ctx, headers: Record<string, string>, who: string, what: string) {
  await requireControl(ctx);
  const a = await ctx.agent('a');
  const p = ctx.peer.agent(`reading-${who}`);
  const delivered = buildFrom(p, [a.address], ctx.now(), { headers });
  t.status(await ctx.deliver(t, ctx.peer.envelope(delivered), `a delivery with ${what}`), 202, `delivery with ${what}`);
  const sent = a.message({ to: [a.address], headers });
  t.status(await a.send(t, sent, {}, `send with ${what}`), 200, `send with ${what}`);
  for (const [how, m] of [
    ['delivered', delivered],
    ['sent', sent],
  ] as const) {
    const entry = await awaitSync(t, a, messageId(m), ctx.opts.deliveryWaitMs);
    if (!entry) t.fail(`the message ${how} with ${what} never reached the sync`);
    t.assert(
      canonicalize(entry.message) === canonicalize(m),
      `the message ${how} with ${what} came back different: ${canonicalize(entry.message).slice(0, 300)}`,
    );
  }
}

def(
  {
    id: 'reading.critical-carried',
    section: `${S} "critical", reader profile 2`,
    level: 'must',
    title: 'A server carries a message whose critical header lists a header it does not know',
    expected:
      '202 for a delivery and 200 for a send of a message with critical: "x-future-feature,com.example.absent", x-future-feature present and com.example.absent not; the message in the recipient’s sync byte for byte (critical binds readers only)',
  },
  (t: T, ctx: Ctx) =>
    carried(
      t,
      ctx,
      { critical: 'x-future-feature,com.example.absent', 'x-future-feature': 'yes' },
      'critical',
      'a critical header',
    ),
);

def(
  {
    id: 'reading.headers-carried',
    section: `${S}, PROTOCOL 10`,
    level: 'must',
    title: 'A server carries headers it does not know, whoever named them',
    expected:
      '202 for a delivery and 200 for a send of a message with a header the registry does not list and one with a private reversed-domain name; the message in the recipient’s sync byte for byte',
  },
  (t: T, ctx: Ctx) =>
    carried(
      t,
      ctx,
      { 'x-conformance-note': 'a header no reader knows', 'com.example.conformance': 'a private header' },
      'unknown',
      'unknown headers',
    ),
);
