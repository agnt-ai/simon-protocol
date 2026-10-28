/**
 * Fan-out: offering a stored message to its recipients here, after the answer was given, so no answer and
 * no timing depends on who is here or what they decide (spec section 6.3, "Policy is silent").
 *
 *   - **Arrivals.** A message accepted for recipients here waits as one arrival per recipient. Each is
 *     offered on its own: an arrival whose offer fails (an extension that throws, a store error) is tried
 *     again later, with backoff, and holds up no other.
 *   - **The admit chain** decides for each recipient. A message from another server that no recipient here
 *     took or holds is not kept.
 *   - **Inbox events** are written with the inbox entry and told afterwards, at least once: a crash between
 *     the two repeats the event, never loses it.
 */
import type { Claim, Hints } from '@agnt-sdk/simon-protocol';
import { iso, later, type Context } from './context.ts';
import type { QueuedArrival, StoredMessage } from './store/store.ts';
import { changed } from './sync.ts';

const BATCH = 50;
const MIN_BACKOFF_MS = 60_000;
const MAX_BACKOFF_MS = 3600_000;

/** Whether this server shows its agents a carrier's claims that are not authoritative: its own, or one trusted. */
export const trustsClaimsOf = (ctx: Context, carrier: string) =>
  carrier === ctx.config.origin || ctx.config.trustedClaimServers.includes(carrier);

/**
 * The claims an agent here is shown with a message (client.md sync): the authoritative ones always, and
 * the others only from a carrier this server trusts. Each acts-for and identifier claim carries `authoritative`.
 */
export const shownClaims = (ctx: Context, carrier: string, claims: Claim[]) =>
  trustsClaimsOf(ctx, carrier) ? claims : claims.filter(c => c.authoritative === true);

/** One arrival per recipient, each with its own hints, due now. */
export const arrivalsFor = (id: string, recipients: string[], hints: Hints, now: Date): QueuedArrival[] =>
  recipients.map(recipient => ({ id, recipient, hints: hints[recipient] ?? {}, attempts: 0, dueAt: iso(now) }));

/** Offer due arrivals, each on its own. Returns how many were taken up. */
export async function processArrivals(ctx: Context): Promise<number> {
  const due = await ctx.store.arrivals(iso(ctx.now()), BATCH);
  for (const { arrival, message: record, generation } of due) {
    try {
      const kept = await offer(ctx, record, arrival.recipient, arrival.hints, generation);
      if ((await ctx.store.arrivalDone(record.id, arrival.recipient, kept, generation)) === 'kept') {
        await ctx.hooks.emit('stored', { message: record });
      }
    } catch (e) {
      const delay = Math.min(MIN_BACKOFF_MS * 2 ** arrival.attempts, MAX_BACKOFF_MS);
      ctx.log('error', 'offering an arrival failed; retrying', {
        id: record.id,
        recipient: arrival.recipient,
        error: String(e),
      });
      await ctx.store.arrivalRetry(record.id, arrival.recipient, later(ctx.now(), delay), generation);
    }
  }
  return due.length;
}

/** Offer a stored message to those of `recipients` who are agents here. True when any took it or holds it. */
export async function fanOut(ctx: Context, record: StoredMessage, recipients: string[], hints: Hints) {
  let kept = false;
  for (const address of recipients) if (await offer(ctx, record, address, hints[address] ?? {})) kept = true;
  return kept;
}

/** Offer a message to one recipient here through the admit chain: true when it took or holds it. */
async function offer(
  ctx: Context,
  record: StoredMessage,
  address: string,
  hints: Record<string, string>,
  generation?: string,
) {
  const agent = await ctx.store.agentByAddress(address);
  if (!agent || agent.retiredAt) return false;
  const decision = await ctx.hooks.admit({
    id: record.id,
    message: record.message,
    recipient: address,
    carrier: record.carrier,
    claims: shownClaims(ctx, record.carrier, record.claims),
    hints,
  });
  if (decision === 'accept') await takeIntoInbox(ctx, address, record, generation);
  return decision !== 'refuse';
}

/** Put a message into an agent's inbox once; its inbox event is told by `tellInboxEvents`. */
export async function takeIntoInbox(
  ctx: Context,
  address: string,
  record: StoredMessage,
  generation?: string,
): Promise<boolean> {
  const added = await ctx.store.addToInbox(
    address,
    record.id,
    iso(ctx.now()),
    generation,
    later(ctx.now(), ctx.config.syncDays * 86_400_000),
  );
  if (added) await changed(ctx, address);
  return added;
}

/** Tell the extensions of new inbox entries, at least once each. Returns how many were told. */
export async function tellInboxEvents(ctx: Context): Promise<number> {
  const entries = await ctx.store.inboxEvents(BATCH);
  for (const e of entries) {
    const message = await ctx.store.message(e.id);
    if (message) await ctx.hooks.emit('inbox', { address: e.address, message });
    await ctx.store.inboxEventDone(e.cursor);
  }
  return entries.length;
}
