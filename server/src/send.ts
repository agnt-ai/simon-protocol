/**
 * `POST /simon/send` (client.md): an agent here hands over a message for delivery. Checked in the order the
 * client API gives: the message as a delivery would check it (spec section 6.3, steps 1, 3 and 4); a
 * version this server implements; `from` the agent's own address, on a domain that still names this
 * server; the author's signature; the paired or solo rule; the 24-hour window; no message with an audience
 * carried whole (spec section 5.4); every content-addressed
 * part held for this agent, uploaded or received, so a part it received can be forwarded. Then the message,
 * this server's claims about it signed for it (spec section 6.2), and one delivery row per recipient domain
 * are stored as one, and the answer is given; delivery follows.
 *
 * A repeat answers as the first call did, and stores again whatever rows a store lost, so a client that
 * retries after a crash never leaves its message undelivered.
 */
import {
  carriedMessages,
  checkEnvelopeShape,
  claimsBytes,
  checkMessage,
  checkPrincipal,
  checkSupportedVersion,
  deliveryWindow,
  domainOf,
  header,
  invalid,
  isFresh,
  isJsonObject,
  judgeClaims,
  messageId,
  namedFiles,
  parseMessage,
  parseStrict,
  readSuccession,
  SEND_WINDOW_MS,
  sign,
  unauthorized,
  verifyMessage,
  type AnyMessage,
  type Claim,
  type Hints,
  type Json,
  type Message,
  VERSION,
} from '@agnt-sdk/simon-protocol';
import { authenticateAgent } from './auth.ts';
import { iso, later, type Context } from './context.ts';
import { badRequest, conflict } from './errors.ts';
import { json, type Reply, type Request } from './http.ts';
import { MOVE_WINDOW_MS, SERVING_SINCE } from './outbox.ts';
import type { Agent, Delivery, StoredMessage } from './store/store.ts';
import { changed } from './sync.ts';

const DAY_MS = 86_400_000;

export async function send(ctx: Context, req: Request): Promise<Reply> {
  const agent = await authenticateAgent(ctx, req);
  const m = parseMessage(req.body, ctx.config.limits);
  return json(await write(ctx, agent, m, readHintsHeader(req.headers['simon-hints'])));
}

/** `send` for an extension's own agent, with the message as an object: checked from step 4 on. */
export async function sendAs(ctx: Context, m: AnyMessage, hints?: Hints) {
  const agent = await ctx.store.agentByAddress(m.from);
  if (!agent || agent.retiredAt) throw invalid(`${m.from} is not an agent here.`, { field: 'from' });
  return write(ctx, agent, checkMessage(m, ctx.config.limits), hints ?? {});
}

/** The checks after the message's own, then storage. Answers the id and when it was received. */
async function write(ctx: Context, agent: Agent, m: AnyMessage, hints: Json) {
  checkSupportedVersion(m);
  const id = messageId(m);
  const now = ctx.now();

  const earlier = await ctx.store.message(id);
  if (earlier && earlier.message.from === agent.address && earlier.carrier === ctx.config.origin) {
    // The claims that travel, as the first call checked them: without this server's judgement.
    checkHints(ctx, hints, m, earlier.signedClaims?.claims ?? []);
    await ctx.store.putMessage(earlier, { deliveries: deliveriesFor(earlier, hints as Hints) });
    // The first call may have stored the message and stopped before it moved the record.
    await follow(ctx, agent, earlier.message);
    ctx.wake();
    return { id, receivedAt: earlier.receivedAt };
  }

  if (m.from !== agent.address) throw invalid(`This agent sends only as ${agent.address}.`, { field: 'from' });
  const domain = domainOf(agent.address);
  // Its lookups are the agent's, in its share of the server's own pool (resolver.ts).
  const payer = { agent: agent.address };
  if (!(await ctx.resolver.servesHere(domain, payer))) {
    await ctx.store.setValue(SERVING_SINCE, domain, null, iso(now));
    throw conflict('address_not_served', `${domain} no longer names this server.`);
  }
  await notedServing(ctx, domain, now);
  if (!verifyMessage(m, agent.keys)) {
    throw unauthorized('bad_signature', "The message does not verify with the author's keys valid at its sentAt.", now);
  }
  checkPrincipal(m, agent.principal === null ? { kind: 'solo' } : { kind: 'paired', for: agent.principal }, now);
  if (!isFresh(m, now, SEND_WINDOW_MS)) {
    throw invalid('sentAt is more than 24 hours old or more than 5 minutes ahead.', { field: 'sentAt' });
  }
  checkCarriedAudience(m);
  for (const p of contentParts(m)) {
    if (!(await holds(ctx, agent.address, p))) {
      throw badRequest('part_not_uploaded', `Upload part ${p.sha256} (${p.size} bytes) first.`, { sha256: p.sha256 });
    }
  }
  const made = await ctx.hooks.claimsFor(m, agent);
  const claims = await judgeClaims(m, made, ctx.config.origin, d => ctx.resolver.resolve(d, { charge: payer }));
  // What travels, and is signed for the message, is the claims considered, without this server's judgement.
  const sent = claims.map(({ authoritative: _, ...c }) => c as Claim);
  checkHints(ctx, hints, m, sent);

  ctx.rate.hit('send', agent.address);
  ctx.rate.distinct('destinations', agent.address, m.to.map(domainOf));

  // A succession its principal signed moves a paired agent's principal on to the successor (spec section 2.2),
  // once the message is stored, so a message that is not stored moves nothing. A concurrent send may have made
  // the same move first; anything else that changed the record meanwhile refuses this one.
  const forValue = m.v === VERSION ? header(m as Message, 'for') : null;
  const moving = agent.principal !== null && forValue !== null && forValue !== agent.principal;
  if (moving) {
    const held = (await ctx.store.agentByAddress(agent.address))?.principal;
    if (held !== agent.principal && held !== forValue) {
      throw conflict('principal_changed', "This agent's principal changed meanwhile: compose the message again.");
    }
  }

  const record: StoredMessage = {
    id,
    message: m,
    carrier: ctx.config.origin,
    claims,
    signedClaims: sent.length ? { claims: sent, signature: sign(ctx.config.serverKey, claimsBytes(sent, id)) } : null,
    receivedAt: iso(now),
    expiresAt: later(now, ctx.config.retentionDays * DAY_MS),
  };
  const stored = await ctx.store.putMessage(record, { deliveries: deliveriesFor(record, hints as Hints) });
  if (moving) await follow(ctx, agent, m);
  ctx.defer(() => ctx.hooks.emit('stored', { message: stored }));
  await changed(ctx, agent.address);
  return { id, receivedAt: stored.receivedAt };
}

/**
 * Move the agent's record on to the successor a stored message names along its succession from the principal
 * held (spec section 2.2), as a compare-and-set. A record that changed otherwise since the message was checked
 * stays as that change left it: the message was checked against the record as it was, as any message racing
 * a change is.
 */
async function follow(ctx: Context, agent: Agent, m: AnyMessage) {
  const from = agent.principal;
  if (from === null || m.v !== VERSION) return;
  const to = header(m as Message, 'for');
  const succession = header(m as Message, 'succession');
  if (to === null || to === from || succession === null) return;
  if (!readSuccession(succession, to)?.some(step => step.from === from)) return;
  if (await ctx.store.succeedPrincipal(agent.address, from, to)) {
    ctx.log('info', 'principal succeeded', { address: agent.address });
  } else if ((await ctx.store.agentByAddress(agent.address))?.principal !== to) {
    ctx.log('warn', 'principal changed while a move was stored', { address: agent.address });
  }
}

/** How often a send renews what it noted about serving its domain, at most. */
const SERVING_CHECKED_EVERY_MS = 10 * 60_000;

/**
 * Note when this server began serving an agent's domain, as far as it can tell: the outbox retries a 403 for
 * an hour after it, while receivers' caches may still name the server before (spec section 6.3). The note
 * lapses an hour after the last send that found the domain naming this server, so a domain that moved away
 * and back unseen in between begins again, rather than keeping a beginning from before it left.
 */
async function notedServing(ctx: Context, domain: string, now: Date): Promise<void> {
  const noted = await ctx.store.value<{ since: string; checked: string } | string>(SERVING_SINCE, domain, iso(now));
  const expires = later(now, MOVE_WINDOW_MS);
  const fresh = { since: iso(now), checked: iso(now) };
  if (!noted) {
    await ctx.store.valueOnce(SERVING_SINCE, domain, fresh, expires, iso(now));
  } else if (typeof noted !== 'object') {
    // An earlier version noted a bare time that never lapsed; it is read as lapsed, and the note begins anew.
    await ctx.store.setValue(SERVING_SINCE, domain, fresh, expires);
  } else if (now.getTime() - Date.parse(noted.checked) >= SERVING_CHECKED_EVERY_MS) {
    await ctx.store.setValue(SERVING_SINCE, domain, { since: noted.since, checked: iso(now) }, expires);
  }
}

/**
 * A message for a narrower audience than `public` is never forwarded or quoted whole (spec section 5.4): a
 * message that carries one inline, at any depth, is refused as the message checks refuse a part (`400
 * invalid`, `parts`). Narrower means an `audience` other than `public`, whatever the carried message's
 * version (one that cannot tell keeps it to itself), or a message of this version to no one with no
 * audience, which is its author's alone. One carried by content address is not seen here; its bytes are the
 * client's to keep to itself.
 */
function checkCarriedAudience(m: AnyMessage): void {
  for (const inner of carriedMessages(m)) {
    const headers = inner.headers;
    if (!isJsonObject(headers)) continue;
    const narrower = Object.hasOwn(headers, 'audience')
      ? headers.audience !== 'public'
      : inner.v === VERSION && Array.isArray(inner.to) && inner.to.length === 0;
    if (narrower) {
      throw invalid(
        'A message for a narrower audience than public is never forwarded or quoted whole (spec section 5.4).',
        {
          field: 'parts',
        },
      );
    }
  }
}

/**
 * Verify possession at the declared size and retain received bytes as this sender's own source. Its new
 * naming message then pins that copy even after earlier messages and their inbox grants expire.
 */
async function holds(ctx: Context, address: string, p: { sha256: string; size: number }) {
  for (const source of await ctx.store.heldFor(p.sha256, address, ctx.config.origin)) {
    if (source.size !== p.size) continue;
    const bytes = await ctx.store.part(p.sha256, source);
    if (bytes?.length !== p.size) continue;
    if (!('uploader' in source) || source.uploader !== address) {
      await ctx.store.putPart(p.sha256, bytes, { uploader: address }, iso(ctx.now()));
    }
    return true;
  }
  return false;
}

/**
 * The files a version 1 message names by content address: its own, and those of every message it carries
 * whole, which count as its own (spec section 5.3). A later version's are not known here.
 */
export function contentParts(m: AnyMessage): { sha256: string; size: number }[] {
  const seen = new Set<string>();
  return namedFiles(m).filter(p => !seen.has(p.sha256) && seen.add(p.sha256));
}

/**
 * The `simon-hints` header: one JSON object, in ASCII (client.md send), or `{}` when absent. A byte outside
 * printable ASCII is refused rather than read as Latin-1 and passed on changed.
 */
function readHintsHeader(header: string | string[] | undefined): Json {
  if (header === undefined) return {};
  if (typeof header === 'string' && /[^\x20-\x7e]/.test(header)) {
    throw invalid('simon-hints is ASCII: escape every other character as \\uXXXX.', { field: 'simon-hints' });
  }
  try {
    const hints = typeof header === 'string' ? parseStrict(header) : null;
    if (isJsonObject(hints)) return hints;
  } catch {
    // Refused below, as any other value that is not a JSON object.
  }
  throw invalid('simon-hints is one JSON object keyed by recipient address.', { field: 'simon-hints' });
}

/**
 * Hints: an object keyed by recipients in `to`, of objects of strings, small enough to travel in an
 * envelope beside this server's claims, checked as the envelope they will travel in. The message's own
 * signature stands in for the envelope's: only the shape is checked here.
 */
function checkHints(ctx: Context, hints: Json, m: AnyMessage, claims: Claim[]): void {
  if (isJsonObject(hints) && Object.keys(hints).length === 0) return;
  if (m.to.length === 0)
    throw invalid('A public message has no recipients to give hints to.', { field: 'simon-hints' });
  const envelope = {
    message: m,
    server: ctx.config.origin,
    recipients: m.to,
    ...(claims.length ? { claims, claimsSignature: m.signature } : {}),
    hints,
    signature: m.signature,
  };
  checkEnvelopeShape(envelope as unknown as Json, ctx.config.dev);
}

/**
 * One delivery row per recipient domain, each with its recipients' hints, first due at `sentAt` (never
 * before it) and ending at the delivery deadline (spec section 6.3).
 */
function deliveriesFor(record: StoredMessage, hints: Hints): Delivery[] {
  const accepted = new Date(record.receivedAt);
  const { earliest, deadline } = deliveryWindow(record.message, accepted);
  const byDomain = Map.groupBy(record.message.to, domainOf);
  return [...byDomain].map(([domain, recipients]) => ({
    id: record.id,
    domain,
    recipients,
    hints: Object.fromEntries(recipients.filter(r => hints[r]).map(r => [r, hints[r]])),
    server: null,
    status: 'pending',
    reason: null,
    attempts: 0,
    nextAttemptAt: iso(earliest > accepted ? earliest : accepted),
    createdAt: record.receivedAt,
    deadline: iso(deadline),
  }));
}
