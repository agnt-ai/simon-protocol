/**
 * The rules that bind readers rather than servers: what a reader may make of a message it holds. No server
 * test can show a reader obeys them, so they live here as functions, with vectors, until a reader profile
 * tests them (spec section 15).
 *
 * - A message of a version the reader does not implement, or listing in `critical` a header it does not
 *   understand, is presented as not understood (sections 1 and 5.4).
 * - A principal counts only for a message that names one in `for`, on its evidence (section 2.2); a key
 *   principal's pairing counts while it has not lapsed.
 * - A relation the reader does not know is shown as a reply, and an author-only relation from anyone but
 *   the original's author is shown as a reply and never applied (section 5.5).
 */
import { header, messageId, VERSION, type AnyMessage, type Message } from './message.ts';
import { parsePairing, principalKey, readSuccession, verifyPairing } from './principal.ts';
import { parseTimestamp } from './time.ts';

/** The relations the registry marks author-only: they change or withdraw the message they name. */
export const AUTHOR_ONLY_RELATIONS: readonly string[] = ['edit', 'retract'];

/**
 * Relations the reference server lists under a published message. Which relations an author's server lists is
 * its own choice (publishing profile, section 4); this is one server's policy, kept here so its clients can share it.
 */
export const PUBLIC_RELATIONS: readonly string[] = ['comment', 'reaction', 'vote'];

/**
 * Whether a reader that implements version 1 and understands the headers in `understood` may act on a
 * message, or must present it as not understood: only whose key signed it, nothing it says.
 */
export function isUnderstood(m: AnyMessage, understood: ReadonlySet<string>): boolean {
  if (m.v !== VERSION) return false;
  const critical = header(m as Message, 'critical');
  return critical === null || critical.split(',').every(h => header(m as Message, h) === null || understood.has(h));
}

/**
 * The principal a message names: the `for` header of a message of this version, or null. It is only the
 * agent's word until evidence backs it, a pairing that verifies or a claim the reader trusts (spec section
 * 2.2); a message without `for` speaks for no one.
 */
export function claimedPrincipal(m: AnyMessage): string | null {
  if (m.v !== VERSION) return null;
  return header(m as Message, 'for');
}

/**
 * What a reader shows for a message, given relations to it it holds (reader profile, section 4): its
 * author's latest edit naming it, by `sentAt` then id, or the message itself; and whether its author
 * retracted it. A retraction is final: nothing restores the message, and a relation naming an edit or a
 * retraction, rather than the original, changes nothing. Relations from anyone else change nothing here.
 */
export function currentVersion(
  original: Message,
  relations: readonly AnyMessage[],
): { message: Message; retracted: boolean } {
  const id = messageId(original);
  const own = relations.filter(
    (r): r is Message => r.v === VERSION && r.from === original.from && (r as Message).inReplyTo === id,
  );
  const retracted = own.some(r => header(r, 'rel') === 'retract');
  const edits = own.filter(r => header(r, 'rel') === 'edit');
  const latest = edits.reduce<Message | null>((best, r) => {
    if (best === null) return r;
    // A sentAt that is not a timestamp sorts first, so it never wins.
    const [a, b] = [parseTimestamp(r.sentAt) ?? -Infinity, parseTimestamp(best.sentAt) ?? -Infinity];
    return a > b || (a === b && messageId(r) > messageId(best)) ? r : best;
  }, null);
  return { message: latest ?? original, retracted };
}

/**
 * Where a key principal's pairing stands for a reader at `now` (spec section 2.2), or null when the message
 * names no key principal:
 *
 * - `counts`: it counted when the message was sent and has not lapsed; the message speaks for the principal.
 * - `lapsed`: it counted when sent, but `now` is at or past its `until`. The message spoke for the principal
 *   then; act on nothing in it for the principal now.
 * - `refused`: it did not count at the message's `sentAt`, so the message names its principal falsely.
 *
 * A reader whose clock runs behind the sender's can see a pairing count at `sentAt` but reach more than 366
 * days ahead of its own now; that is the clocks' disagreement, not a lapse, so it counts.
 */
export function pairingStanding(m: AnyMessage, now: Date | number): 'counts' | 'lapsed' | 'refused' | null {
  const forValue = claimedPrincipal(m);
  if (forValue === null || principalKey(forValue) === null) return null;
  const pairing = header(m as Message, 'pairing');
  if (!verifyPairing(m.from, forValue, pairing, parseTimestamp(m.sentAt) ?? NaN)) return 'refused';
  return new Date(now).getTime() >= parseTimestamp(parsePairing(pairing)!.until)! ? 'lapsed' : 'counts';
}

/**
 * The earlier keys of a message's key principal, oldest first, as its `succession` header names them (spec
 * section 2.2): [] when it carries none, or `refused` when it does not verify. A reader that knew any of them
 * may treat `for` as the same principal, unless it holds a fork, two steps from one key to different keys:
 * then neither successor inherits that key's place.
 */
export function predecessors(m: AnyMessage): string[] | 'refused' {
  const forValue = claimedPrincipal(m);
  const succession = m.v === VERSION ? header(m as Message, 'succession') : null;
  if (forValue === null || succession === null) return [];
  return readSuccession(succession, forValue)?.map(step => step.from) ?? 'refused';
}

/**
 * How a reader that knows the relations in `known` reads a message, given the message its `inReplyTo`
 * names (`target`, or null when the reader does not hold it):
 *
 * - `reply`: no `rel`, a `rel` the reader does not know, a `rel` on a message whose `inReplyTo` is null
 *   (it names nothing, and is ignored), or an author-only relation whose author is not the target's. Shown
 *   by its blocks, as a reply.
 * - `relation`: a relation the reader applies to the target.
 * - `pending`: a relation the reader would apply, to a target it does not hold yet.
 */
export function readsAs(
  m: Message,
  target: Pick<AnyMessage, 'from'> | null,
  known: ReadonlySet<string>,
): 'reply' | 'relation' | 'pending' {
  const rel = header(m, 'rel');
  if (rel === null || !known.has(rel) || m.inReplyTo === null) return 'reply';
  if (target === null) return 'pending';
  if (AUTHOR_ONLY_RELATIONS.includes(rel) && target.from !== m.from) return 'reply';
  return 'relation';
}
