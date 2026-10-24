/**
 * `POST /simon/deliver` (spec section 6.3): an envelope from another server, checked in exactly the
 * section's order, answering the first failure:
 *
 *   1-5  body size and parse, envelope shape, canonical message, message rules, and the envelope for this
 *        server with its recipients in `to`, all without a lookup                (parseEnvelope)
 *   6    the `from` domain resolves to another server                             (403 otherwise)
 *   7    the envelope, and its claims, verify with that server's keys valid now, by a key trusted under
 *        continuity
 *   8    every recipient on a domain served here: only now, with the carrier known, may that need a lookup
 *   9    a repeat for recipients all accepted here in the last 168 hours is 202
 *   10   `sentAt` fresh
 *   11   the author's agent document readable, and the message verifies at its `sentAt`
 *   12   202: accepted once per (id, recipient)
 *
 * Deliver is the one call anyone can make that sends this server out to the network, so the one lookup it
 * makes before the carrier is known, the `from` domain, is counted against the client's network (`lookup`).
 * Every lookup after it is the carrier's: its recipients' domains and its claims count against its
 * `carrierLookup` rate, and those and its author's document run in the carrier's share of a pool of their
 * own, never in the one the server's own sending uses. Recipients' domains are resolved side by side, as
 * many at once as the carrier's share allows, and none is started past RECIPIENT_LOOKUPS_MS, so an envelope
 * naming many slow domains holds a delivery a bounded time. Before step 7, the (client network, claimed
 * server) pair must have signature failures to spare: a sender whose signatures keep failing costs one counter read, not a
 * verification. Every delivery past step 7, a repeat as much as a new one, counts against the carrier's
 * `deliver` rate. Accepting stores the message whoever the recipients are, and queues the fetch of its parts
 * (spec section 7.2), so the answer, its timing and the fetches say nothing about them; offering it to them
 * happens afterwards, in the worker.
 */
import crypto from 'node:crypto';
import {
  checkAuthorSignature,
  checkEnvelopeBeside,
  checkFreshness,
  checkServed,
  claimsBytes,
  domainOf,
  forbidden,
  isRepeat,
  judgeClaims,
  messageId,
  parseEnvelope,
  parseTimestamp,
  REPEAT_WINDOW_MS,
  signedByAny,
  signingBytes,
  verifyMessage,
  WireError,
  type Envelope,
  type ServerDocument,
} from '@agnt-protocol/protocol';
import { iso, later, type Context } from './context.ts';
import { arrivalsFor } from './fanout.ts';
import { queuePrefetch } from './parts.ts';
import { json, type Reply, type Request } from './http.ts';
import { clientKey, networkKey } from './net/ip.ts';
import { unavailable } from './errors.ts';
import { isRefusal, type Charge, type Payer } from './resolver.ts';

const DAY_MS = 86_400_000;
const ACCEPTED = { accepted: true };

export async function deliver(ctx: Context, req: Request): Promise<Reply> {
  const now = ctx.now();
  const client = clientKey(req.ip);
  const charge: Charge = () => ctx.rate.hit('lookup', client);

  // Steps 1 to 5 need no lookup, so an envelope meant for another server, or for no one here, costs none.
  const { origin, dev: allowHttp } = ctx.config;
  const envelope = parseEnvelope(req.body, ctx.config.limits, { origin, allowHttp });
  checkEnvelopeBeside(envelope, ctx.config.envelopeExtrasBytes);
  const m = envelope.message;
  const domain = domainOf(m.from);

  let cached = ctx.resolver.isCached(domain);
  let peer = await ctx.resolver.peer(domain, charge);
  const noServer = () =>
    forbidden('bad_signature', `${domain} names no other SIMON server, so no envelope from it verifies.`);
  // Even a cached absence or our own old route can hide a move to the actual carrying server.
  if (cached && (peer.outcome !== 'server' || peer.server === ctx.config.origin)) {
    peer = (await reresolve(ctx, domain, () => ctx.resolver.peer(domain, charge, { fresh: true }))) ?? peer;
    cached = false;
  }
  if (peer.outcome !== 'server' || peer.server === ctx.config.origin) throw noServer();
  let server = peer.server;
  const failures = `${client} ${server}`;
  ctx.rate.check('badSignature', failures);
  const fail = (e: WireError) => {
    if (e.code === 'bad_signature') ctx.rate.hit('badSignature', failures);
    return e;
  };

  let signed =
    signer(envelope, peer.document, now) ??
    signer(envelope, await ctx.resolver.serverDocument(server, { refresh: true, charge }), now);
  // Step 7's last chance: a domain that just moved its server is found at the new one. Resolved and read
  // again without the cache, when the resolution came from it, at most once a minute for one domain (a mark
  // in the store, which every process shares); a re-resolution that fails for now is 503.
  const again =
    !signed && cached ? await reresolve(ctx, domain, () => ctx.resolver.peer(domain, charge, { fresh: true })) : null;
  if (again) {
    peer = again;
    if (peer.outcome !== 'server' || peer.server === ctx.config.origin) throw fail(noServer());
    server = peer.server;
    signed = signer(envelope, peer.document, now);
  }
  if (!signed) {
    throw fail(forbidden('bad_signature', `The envelope is not signed by a key of ${server} valid now.`));
  }
  await ctx.resolver.trustSigner(domain, server, signed.key, signed.document);
  ctx.rate.hit('deliver', server);
  const network = networkKey(req.ip);
  const carrier: Payer = { carrier: server, network, charge: () => ctx.rate.hit('carrierLookup', server) };
  checkServed(envelope.recipients, await servedDomains(ctx, envelope.recipients, carrier));

  const id = messageId(m);
  const accepted = new Set<string>();
  for (const r of envelope.recipients) if (await ctx.store.marked('accepted', `${id}\n${r}`, iso(now))) accepted.add(r);
  if (isRepeat(envelope, accepted, now)) return json(ACCEPTED, 202);
  checkFreshness(m, now);

  const authorOf = (refresh: boolean) => ctx.resolver.agentKeys(m.from, server, refresh, { carrier: server, network });
  let author = await authorOf(false);
  if (!author || !verifyMessage(m, author.keys)) author = await authorOf(true);
  if (!author) throw fail(forbidden('bad_signature', `${server} serves no agent document for ${m.from}.`));
  try {
    checkAuthorSignature(m, author.keys);
  } catch (e) {
    throw e instanceof WireError ? fail(e) : e;
  }

  const fresh = envelope.recipients.filter(r => !accepted.has(r));
  const record = await ctx.store.putMessage(
    {
      id,
      message: m,
      carrier: server,
      claims: await judgeClaims(m, envelope.claims, author.kind, server, d =>
        ctx.resolver.resolve(d, { charge: carrier }),
      ),
      signedClaims: envelope.claims ? { claims: envelope.claims, signature: envelope.claimsSignature! } : null,
      receivedAt: iso(now),
      expiresAt: later(now, ctx.config.retentionDays * DAY_MS),
    },
    { arrivals: arrivalsFor(id, fresh, envelope.hints ?? {}, now) },
  );
  await queuePrefetch(ctx, record);
  const until = new Date(parseTimestamp(m.sentAt)! + REPEAT_WINDOW_MS).toISOString();
  for (const r of fresh) await ctx.store.mark('accepted', `${id}\n${r}`, until, iso(now));
  await ctx.resolver.vouch(domain, signed.document);
  ctx.wake();
  return json(ACCEPTED, 202);
}

/**
 * The carrier key that signed the envelope, and its claims, among `document`'s keys valid now, or null. The
 * signed bytes are made once, however many keys the document lists.
 */
function signer(e: Envelope, document: ServerDocument | null, now: Date) {
  if (!document) return null;
  const envelopeBytes = signingBytes('SIMON-ENVELOPE', e);
  const claims = e.claims && claimsBytes(e.claims, messageId(e.message));
  const key = document.keys.find(k => signedByAny([k], now, envelopeBytes, e.signature));
  if (!key || (claims && !signedByAny(document.keys, now, claims, e.claimsSignature))) return null;
  return { key: key.key, document };
}

/** How long step 8 may go on starting lookups of recipients' domains; a lookup underway ends by its own deadline. */
export const RECIPIENT_LOOKUPS_MS = 20_000;

/** A domain is resolved again without the cache, before a 403 at step 7 or a 400 at step 8, this often at most. */
export const RERESOLVE_EVERY_MS = 60_000;

/**
 * Resolve a domain again without the cache with `lookup`, at most once a minute for one domain across processes
 * (a store value only one caller takes), or answer null without looking when that minute's re-resolution is
 * taken. A call refused before it made any lookup (the payer out of room or rate) gives the minute back, so
 * a forger out of budget cannot use it up for everyone; one refused after a lookup was made keeps it.
 */
export async function reresolve<T>(ctx: Context, domain: string, lookup: () => Promise<T>): Promise<T | null> {
  const token = crypto.randomUUID();
  const until = later(ctx.now(), RERESOLVE_EVERY_MS);
  if ((await ctx.store.valueOnce('reresolve', domain, token, until, iso(ctx.now()))) !== token) return null;
  const tally = { made: false };
  try {
    return await ctx.resolver.tallied(tally, lookup);
  } catch (e) {
    if (isRefusal(e) && !tally.made) await ctx.store.releaseValue('reresolve', domain, token);
    throw e;
  }
}

/**
 * Step 8 for deliver and signal: whether each address's domain is served here, hosted or leased on, or
 * resolving here. The domains needing a lookup are resolved side by side, as many at once as the
 * payer's free share (at most MAX_LOOKUPS_PER_CARRIER), each paid for by `payer`; once RECIPIENT_LOOKUPS_MS
 * have passed no more are started, and the answer is 503.
 */
export async function servedDomains(ctx: Context, addresses: readonly string[], payer: Payer) {
  const { hostedDomains, leaseDomain } = ctx.config;
  const domains = [...new Set(addresses.map(domainOf))];
  const served = new Set(domains.filter(d => hostedDomains.includes(d) || d === leaseDomain));
  const queue = domains.filter(d => !served.has(d));
  const wasCached = new Set(queue.filter(d => ctx.resolver.isCached(d)));
  const deadline = ctx.now().getTime() + RECIPIENT_LOOKUPS_MS;
  let stopped = false;
  const lookups = async () => {
    for (let d; !stopped && (d = queue.shift()) !== undefined; ) {
      if (ctx.now().getTime() > deadline) throw unavailable("Could not resolve the recipients' domains in time.");
      if (await ctx.resolver.servesHere(d, payer)) served.add(d);
    }
  };
  // As many side by side as the payer's free share allows now, so its other deliveries' lookups underway
  // never make this one refuse itself; at least one, which a full share refuses for now (503).
  const width = Math.max(1, ctx.resolver.room(payer));
  const workers = Array.from({ length: Math.min(queue.length, width) }, lookups);
  await Promise.all(workers).catch(e => {
    stopped = true;
    throw e;
  });
  // Before answering 400 for a domain whose answer came from the cache, it is resolved again without it, at
  // most once a minute for one domain, so a domain that has just moved here is found (spec section 6.3 step 8);
  // within the same deadline, past which the answer is 503.
  for (const d of wasCached) {
    if (served.has(d)) continue;
    if (ctx.now().getTime() > deadline) throw unavailable("Could not resolve the recipients' domains in time.");
    if (await reresolve(ctx, d, () => ctx.resolver.servesHere(d, payer, true))) served.add(d);
  }
  return (d: string) => served.has(d);
}
