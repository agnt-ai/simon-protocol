/** CLIENT sync: its shape, carrier and claims, its parameters, and paging by opaque token. */
import {
  canonicalize,
  isJsonObject,
  keyToken,
  messageId,
  parseTimestamp,
  verifyClaims,
} from '@agnt-sdk/simon-protocol';
import { buildFrom, type Ctx } from '../context.ts';
import type { T } from '../harness.ts';
import { awaitSync, def, readSync, type SyncEntry } from './common.ts';
import { LONG_AGO } from '../peer.ts';
import { requireControl } from './deliver.ts';

const S = 'CLIENT sync';

/** What is wrong with an sync entry's shape, or null. */
function entryFault(e: SyncEntry): string | null {
  if (!isJsonObject(e as never)) return 'an entry is not an object';
  if (!isJsonObject(e.message as never)) return 'message is not an object';
  if (e.id !== messageId(e.message)) return `id ${e.id} is not the id of its message (${messageId(e.message)})`;
  if (typeof e.carrier !== 'string') return `carrier ${JSON.stringify(e.carrier)} is not an origin`;
  if (!Array.isArray(e.claims)) return `claims ${JSON.stringify(e.claims)} is not an array`;
  const unjudged = e.claims.find(c => c?.type === 'acts-for' && typeof c.authoritative !== 'boolean');
  if (unjudged) return `an acts-for claim without a boolean authoritative: ${JSON.stringify(unjudged)}`;
  if (parseTimestamp(e.receivedAt) === null) return `receivedAt ${JSON.stringify(e.receivedAt)} is not a timestamp`;
  const signed = (e as { signedClaims?: unknown }).signedClaims;
  if (
    signed !== undefined &&
    !(isJsonObject(signed as never) && Array.isArray((signed as SyncEntry['signedClaims'])!.claims))
  ) {
    return `signedClaims ${JSON.stringify(signed).slice(0, 200)} is not {"claims","signature"}`;
  }
  return null;
}

/** A self-sent message, in the sync: the entry, or undefined when the server did not put it there. */
const selfSent = (ctx: Parameters<typeof requireControl>[0]) =>
  ctx.once('a message an agent sends itself', async t => {
    const a = await ctx.agent('a');
    const m = a.message({ to: [a.address], text: 'note to self' });
    const res = await a.send(t, m, {}, 'send to self');
    if (res.status !== 200) return { m, entry: undefined };
    return { m, entry: await awaitSync(t, a, messageId(m), ctx.opts.deliveryWaitMs) };
  });

def(
  {
    id: 'sync.shape',
    section: S,
    level: 'must',
    title: 'Sync answers messages, signals, marks, removed, an opaque token and more',
    expected:
      '200 {"messages","marks","removed","signals","token","more"} with token a string and more a boolean; each entry has id (the id of its message), message, carrier, claims (an array, each acts-for claim with a boolean authoritative) and receivedAt',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    // Keep malformed sync answers inside this check: a shared setup failure would become a skip.
    const message = a.message({ to: [a.address], text: 'sync shape' });
    const sent = await a.send(t, message, {}, 'send for sync shape');
    if (sent.status === 200) await awaitSync(t, a, messageId(message), ctx.opts.deliveryWaitMs);
    const res = await a.sync(t, 'limit=200');
    t.status(res, 200);
    const b = res.json;
    t.assert(Array.isArray(b?.messages), 'messages is not an array');
    t.assert(typeof b.token === 'string' && b.token.length > 0, `token is ${JSON.stringify(b.token)}`);
    for (const member of ['marks', 'removed', 'signals'])
      t.assert(Array.isArray(b[member]), `${member} is not an array`);
    t.assert(typeof b.more === 'boolean', `more is ${JSON.stringify(b.more)}`);
    for (const e of b.messages) {
      const fault = entryFault(e);
      t.assert(!fault, `entry ${JSON.stringify(e).slice(0, 200)}: ${fault}`);
    }
  },
);

def(
  {
    id: 'sync.self',
    section: S,
    level: 'should',
    title: 'A message an agent sends itself reaches its sync',
    expected: `the message appears in the sync within the delivery wait`,
  },
  async (t: T, ctx: Ctx) => {
    const { entry } = await selfSent(ctx);
    t.adopt(ctx.setupExchanges.filter(e => e.label === 'send to self'));
    t.assert(entry, 'the message never reached the sync (a policy may hold it)');
  },
);

def(
  {
    id: 'sync.carrier-local',
    section: S,
    level: 'must',
    title: "A message written here has this server's origin as carrier",
    expected: "carrier is the server's own origin, and the message is the one sent, byte for byte",
  },
  async (t: T, ctx: Ctx) => {
    const { m, entry } = await selfSent(ctx);
    if (!entry) t.skip('the self-sent message never reached the sync (see sync.self)');
    t.assert(entry.carrier === ctx.origin, `carrier is ${JSON.stringify(entry.carrier)}, expected ${ctx.origin}`);
    t.assert(canonicalize(entry.message) === canonicalize(m), 'the message differs from the one sent');
  },
);

def(
  {
    id: 'sync.carrier-peer',
    section: S,
    level: 'must',
    title: "A delivered message has the delivering server's origin as carrier",
    expected: "carrier is the simulator's origin for a message it delivered, and the message is unchanged",
  },
  async (t: T, ctx: Ctx) => {
    await requireControl(ctx);
    const a = await ctx.agent('a');
    const p = ctx.peer.agent('carrier');
    const m = buildFrom(p, [a.address], ctx.now());
    t.status(await ctx.deliver(t, ctx.peer.envelope(m)), 202, 'delivery');
    const entry = await awaitSync(t, a, messageId(m), ctx.opts.deliveryWaitMs);
    if (!entry) t.fail('the delivered message never reached the sync');
    t.assert(
      entry.carrier === ctx.peer.origin,
      `carrier is ${JSON.stringify(entry.carrier)}, expected ${ctx.peer.origin}`,
    );
    t.assert(canonicalize(entry.message) === canonicalize(m), 'the message differs from the one delivered');
  },
);

/** An acts-for claim about `agent` and `forValue`, well formed. */
const actsFor = (agent: string, forValue: string, extra: Record<string, unknown> = {}) => ({
  type: 'acts-for',
  agent,
  for: forValue,
  scope: ['converse'],
  verifiedAt: '2026-09-01T00:00:00Z',
  ...extra,
});

/**
 * A message from a new simulated agent to agent a, with `forValue` as its for header when given, delivered
 * with these claims: the sync entry, once it arrives.
 */
async function claimed(
  t: T,
  ctx: Ctx,
  name: string,
  forValue: string | null,
  claims: (author: string) => Record<string, unknown>[],
  kind = forValue ? 'paired' : 'solo',
) {
  await requireControl(ctx);
  const a = await ctx.agent('a');
  const p = ctx.peer.agent(name, { kind });
  const m = buildFrom(p, [a.address], ctx.now(), forValue ? { headers: { for: forValue } } : {});
  t.status(
    await ctx.deliver(t, ctx.peer.envelope(m, { claims: claims(p.address) as never })),
    202,
    `delivery (${name})`,
  );
  const entry = await awaitSync(t, a, messageId(m), ctx.opts.deliveryWaitMs);
  if (!entry) t.fail(`the message delivered with claims (${name}) never reached the sync`);
  t.assert(Array.isArray(entry.claims), `claims is ${JSON.stringify(entry.claims)}`);
  return { p, m, entry, shown: entry.claims.filter(c => isJsonObject(c as never) && c.type === 'acts-for') };
}

/** The peer's own domain as a mailto: principal: its server is the carrier, so a claim for it is authoritative. */
const ownMailto = (ctx: Ctx, local: string) => `mailto:${ctx.runId}-${local}@${ctx.opts.peerDomain}`;

/** Messages whose acts-for claims are not authoritative: an email elsewhere (claim forged authoritative) and a phone. */
const notAuthoritative = (ctx: Ctx) =>
  ctx.once('claims that are not authoritative', async t => {
    const mail = `mailto:alice@${ctx.opts.unresolvableDomain}`;
    const tel = 'tel:+15550001234';
    return [
      await claimed(t, ctx, 'claims-mail', mail, author => [actsFor(author, mail, { authoritative: true })]),
      await claimed(t, ctx, 'claims-tel', tel, author => [actsFor(author, tel)]),
    ];
  });

def(
  {
    id: 'sync.claims-considered',
    section: `${S}, PROTOCOL 6.2, 11.2`,
    level: 'must',
    title: 'An acts-for claim that does not count is never shown',
    expected:
      "no acts-for claim in the entry for a message without a for header delivered with acts-for claims naming another agent and naming its author; nor for a message whose for is the carrier's own domain, with acts-for claims lacking scope, with a malformed verifiedAt, or naming another for",
  },
  async (t: T, ctx: Ctx) => {
    const { shown } = await claimed(t, ctx, 'claims', null, author => [
      actsFor(`someone-else@${ctx.opts.peerDomain}`, 'mailto:alice@example.org'),
      actsFor(author, 'mailto:alice@example.org'),
      { type: 'x-conformance' },
    ]);
    t.assert(shown.length === 0, `the entry shows acts-for claims that do not count: ${JSON.stringify(shown)}`);
    const forValue = ownMailto(ctx, 'malformed-owner');
    const { shown: malformed } = await claimed(t, ctx, 'claims-malformed', forValue, author => {
      const { scope: _, ...noScope } = actsFor(author, forValue);
      return [
        noScope,
        actsFor(author, forValue, { verifiedAt: 'yesterday' }),
        actsFor(author, ownMailto(ctx, 'someone-else')),
      ];
    });
    t.assert(malformed.length === 0, `the entry shows malformed acts-for claims: ${JSON.stringify(malformed)}`);
  },
);

def(
  {
    id: 'sync.claims-authoritative',
    section: `${S}, PROTOCOL 2.2, 6.2`,
    level: 'must',
    title: "A claim for an email address on the carrier's own domain is shown as authoritative",
    expected:
      "the entry shows the acts-for claim, as sent, with authoritative: true, for a message whose for is mailto: an address on the simulator's own domain, carried by the simulator (whose word the server need not otherwise trust)",
  },
  async (t: T, ctx: Ctx) => {
    const forValue = ownMailto(ctx, 'owner');
    let sent: Record<string, unknown> = {};
    const { shown } = await claimed(t, ctx, 'claims-own', forValue, author => [(sent = actsFor(author, forValue))]);
    t.assert(shown.length === 1, `the entry shows ${shown.length} acts-for claims: ${JSON.stringify(shown)}`);
    const { authoritative, ...rest } = shown[0];
    t.assert(authoritative === true, `authoritative is ${JSON.stringify(authoritative)}`);
    t.assert(
      canonicalize(rest) === canonicalize(sent),
      `the claim shown differs from the one sent: ${JSON.stringify(rest)}`,
    );
  },
);

def(
  {
    id: 'sync.claims-not-authoritative',
    section: `${S}, PROTOCOL 6.2`,
    level: 'must',
    title: 'A claim about an identifier the carrier does not speak for is never shown as authoritative',
    expected:
      'for a message whose for is mailto: an address on a domain naming no server (its claim sent with authoritative: true), and one whose for is tel:, the acts-for claim is absent or shown with authoritative: false',
  },
  async (t: T, ctx: Ctx) => {
    for (const { p, shown } of await notAuthoritative(ctx)) {
      const wrong = shown.filter(c => c.authoritative !== false);
      t.assert(wrong.length === 0, `${p.name}: shown as ${JSON.stringify(wrong)}`);
    }
  },
);

def(
  {
    id: 'sync.claims-elsewhere-not-authoritative',
    section: `${S}, PROTOCOL 2.2, 6.2`,
    level: 'must',
    title: 'A carrier speaks with authority only for a domain that names it, not for another server or the receiver',
    expected:
      "for a message carried by the simulator whose for is mailto: an address on the server's own domain, and one whose for is an address on the second simulator's domain (with --second-peer-domain), the acts-for claim is absent or shown with authoritative: false",
  },
  async (t: T, ctx: Ctx) => {
    const cases: [string, string][] = [['claims-receiver', `mailto:${ctx.runId}-boss@${await ctx.domain()}`]];
    if (ctx.secondPeer) cases.push(['claims-second', `mailto:${ctx.runId}-boss@${ctx.secondPeer.domain}`]);
    else
      ctx.notes.push(
        'sync.claims-elsewhere-not-authoritative ran without a second simulator: give --second-peer-domain to check a domain naming another server.',
      );
    for (const [name, forValue] of cases) {
      const { shown } = await claimed(t, ctx, name, forValue, author => [
        actsFor(author, forValue, { scope: ['commit'] }),
      ]);
      const wrong = shown.filter(c => c.authoritative !== false);
      t.assert(wrong.length === 0, `${forValue}: shown as ${JSON.stringify(wrong)}`);
    }
  },
);

def(
  {
    id: 'sync.claims-solo',
    section: `${S}, PROTOCOL 2.2, 6.2`,
    level: 'must',
    title: 'A principal never counts for a solo agent, whatever its carrier claims',
    expected:
      "no acts-for claim in the entry for a message carrying a for header from an agent whose document says solo, though the claim names an address on the carrier's own domain",
  },
  async (t: T, ctx: Ctx) => {
    const forValue = ownMailto(ctx, 'solo-owner');
    const { shown } = await claimed(t, ctx, 'claims-solo', forValue, author => [actsFor(author, forValue)], 'solo');
    t.assert(shown.length === 0, `the entry shows ${JSON.stringify(shown)} for a solo agent`);
  },
);

def(
  {
    id: 'sync.claims-own-judgement',
    section: `${S}, PROTOCOL 6.2`,
    level: 'must',
    title: 'A carrier cannot mark its own claims authoritative',
    expected:
      'no claim of a type the server does not judge (an operator claim sent with authoritative: true) carries an authoritative member in the entry: the member is dropped, or the claim not shown',
  },
  async (t: T, ctx: Ctx) => {
    const { entry } = await claimed(t, ctx, 'claims-operator', null, author => [
      { type: 'operator', agent: author, operator: 'Big Bank plc', authoritative: true },
    ]);
    const marked = entry.claims.filter(c => c?.type === 'operator' && 'authoritative' in c);
    t.assert(marked.length === 0, `the entry shows ${JSON.stringify(marked)}`);
  },
);

def(
  {
    id: 'sync.signed-claims',
    section: `${S}, PROTOCOL 6.2`,
    level: 'must',
    title: "An entry carries the carrier's claims as signed for the message, checkable by any client",
    expected:
      'signedClaims is {"claims","signature"}: every claim exactly as the simulator sent it, with the envelope\'s claimsSignature, which verifies with the simulator\'s key for the message',
  },
  async (t: T, ctx: Ctx) => {
    const forValue = ownMailto(ctx, 'signed');
    let sent: Record<string, unknown>[] = [];
    const { m, entry } = await claimed(t, ctx, 'claims-signed', forValue, author => {
      sent = [actsFor(author, forValue), { type: 'x-conformance', note: 'opaque' }];
      return sent;
    });
    const signed = entry.signedClaims;
    t.assert(isJsonObject(signed as never), `signedClaims is ${JSON.stringify(signed)}`);
    t.assert(
      canonicalize(signed!.claims) === canonicalize(sent),
      `signedClaims.claims differs from the claims sent: ${JSON.stringify(signed!.claims)}`,
    );
    const keys = [{ key: keyToken(ctx.peer.serverKey), added: LONG_AGO, revoked: null }];
    t.assert(
      verifyClaims({ claims: signed!.claims as never, signature: signed!.signature }, m, keys),
      "signedClaims does not verify with the simulator's key",
    );
  },
);

/** The registry's identifier claim about `agent`, well formed. */
const identifier = (agent: string, of: string, value: string) => ({
  type: 'identifier',
  agent,
  of,
  identifier: value,
  verifiedAt: '2026-09-01T00:00:00Z',
});

def(
  {
    id: 'sync.claims-identifier',
    section: `${S}, PROTOCOL 6.2, registry identifier`,
    level: 'should',
    title: "An identifier claim is judged as an acts-for claim is: shown as authoritative for the carrier's own domain",
    expected:
      "for a message without a for header, the entry shows the identifier claim of: agent naming mailto: an address on the simulator's own domain, as sent, with authoritative: true; and no identifier claim naming an address on a domain naming no server, naming another agent, or of: principal",
  },
  async (t: T, ctx: Ctx) => {
    const own = ownMailto(ctx, 'mailbox');
    let sent: Record<string, unknown> = {};
    const { entry } = await claimed(t, ctx, 'claims-identifier', null, author => [
      (sent = identifier(author, 'agent', own)),
      identifier(author, 'agent', `mailto:alice@${ctx.opts.unresolvableDomain}`),
      identifier(`someone-else@${ctx.opts.peerDomain}`, 'agent', ownMailto(ctx, 'someone-else')),
      identifier(author, 'principal', ownMailto(ctx, 'principal')),
    ]);
    const shown = entry.claims.filter(c => isJsonObject(c as never) && c.type === 'identifier');
    t.assert(shown.length === 1, `the entry shows ${shown.length} identifier claims: ${JSON.stringify(shown)}`);
    const { authoritative, ...rest } = shown[0];
    t.assert(authoritative === true, `authoritative is ${JSON.stringify(authoritative)}`);
    t.assert(
      canonicalize(rest) === canonicalize(sent),
      `the claim shown differs from the one sent: ${JSON.stringify(rest)}`,
    );
  },
);

def(
  {
    id: 'sync.claims-untrusted-hidden',
    section: `${S}, PROTOCOL 6.2`,
    level: 'should',
    title: 'A claim that is not authoritative is hidden unless the server trusts the carrier',
    expected:
      'the entries of sync.claims-not-authoritative show no acts-for claim at all (a server trusts no carrier unless its operator chose it, and the simulator is no such carrier)',
  },
  async (t: T, ctx: Ctx) => {
    for (const { p, shown } of await notAuthoritative(ctx)) {
      t.assert(shown.length === 0, `${p.name}: the entry shows ${JSON.stringify(shown)}`);
    }
  },
);

def(
  {
    id: 'sync.parameters',
    section: S,
    level: 'must',
    title: 'limit is 1 to 200 and wait is 0 to 60 whole seconds',
    expected:
      '200 for no parameters, limit=1, limit=200 and wait=0; 400 invalid for out-of-range or non-integer limit and wait',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    for (const q of ['', 'limit=1', 'limit=200', 'wait=0']) t.status(await a.sync(t, q), 200, q || 'no parameters');
    for (const q of ['limit=0', 'limit=201', 'limit=ten', 'wait=-1', 'wait=61', 'wait=1.5', 'wait=ten']) {
      t.error(await a.sync(t, q), 400, 'invalid', q);
    }
  },
);

def(
  {
    id: 'sync.unknown-token',
    section: S,
    level: 'must',
    title: 'An unknown token reports the gap',
    expected: '410 token_expired for a token the server never issued',
  },
  async (t: T, ctx: Ctx) => {
    t.error(
      await (await ctx.agent('a')).sync(t, `since=${encodeURIComponent(`conformance-unknown-${ctx.runId}`)}`),
      410,
      'token_expired',
    );
  },
);

def(
  {
    id: 'sync.paging',
    section: S,
    level: 'must',
    title: 'Sync pages by opaque token in the order the server took messages',
    expected:
      'passing each token as since with limit=1 gives the same messages in the same order as reading with limit=200, without losing entries',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('sync-pages');
    for (let i = 0; i < 3; i++) t.status(await a.send(t, a.message({ to: [], text: `page ${i}` })), 200);
    const all = await readSync(t, a);
    t.assert(all.length >= 3, `sync holds ${all.length} messages after three accepted sends`);
    const seen: string[] = [];
    let since: string | undefined;
    for (let i = 0; i <= all.length; i++) {
      const res = await a.sync(
        t,
        `limit=1${since === undefined ? '' : `&since=${encodeURIComponent(since)}`}`,
        `page ${i + 1}`,
      );
      t.status(res, 200);
      const b = res.json;
      t.assert(Array.isArray(b?.messages) && b.messages.length <= 1, 'limit=1 was not respected');
      t.assert(typeof b.token === 'string' && b.token.length > 0, 'missing token');
      t.assert(typeof b.more === 'boolean', 'missing more');
      seen.push(...b.messages.map((e: SyncEntry) => e.id));
      if (!b.more) {
        t.assert(
          JSON.stringify(seen) === JSON.stringify(all.map(e => e.id)),
          `paged ids ${JSON.stringify(seen)} differ from ${JSON.stringify(all.map(e => e.id))}`,
        );
        const again = await a.sync(t, `since=${encodeURIComponent(b.token)}`);
        t.status(again, 200);
        t.assert(
          again.json?.messages?.length === 0 && again.json.more === false,
          'sync repeats messages after its returned token',
        );
        return;
      }
      t.assert(b.token !== since, 'sync did not move its token despite more=true');
      since = b.token;
    }
    t.fail('sync failed to finish paging');
  },
);

def(
  {
    id: 'sync.sent',
    section: S,
    level: 'must',
    title: 'A sent message appears even when addressed only to another agent',
    expected: 'sync includes an accepted outgoing message with this server as carrier and exactly the message sent',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('sync-sender');
    const b = await ctx.agent('sync-recipient');
    const m = a.message({ to: [b.address] });
    t.status(await a.send(t, m), 200);
    const entry = await awaitSync(t, a, messageId(m), ctx.opts.deliveryWaitMs);
    t.assert(entry, 'the outgoing message never appeared in the sender sync');
    t.assert(
      entry.carrier === ctx.origin && canonicalize(entry.message) === canonicalize(m),
      'outgoing entry differs from the sent message or carrier',
    );
  },
);
