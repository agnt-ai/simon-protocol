/**
 * The rules that bind readers rather than servers: what a reader may make of a message it holds. No server
 * test can show a reader obeys them, so they live here as functions, with vectors, until a reader profile
 * tests them (spec section 15).
 *
 * - A message of a version the reader does not implement, or listing in `critical` a header it does not
 *   understand, is presented as not understood (sections 1 and 5.4).
 * - A principal counts only for a paired agent (section 2.2).
 * - A relation the reader does not know is shown as a reply, and an author-only relation from anyone but
 *   the original's author is shown as a reply and never applied (section 5.5).
 */
import { header, VERSION, type AnyMessage, type Message } from './message.ts';

/** The relations the registry marks author-only: they change or withdraw the message they name. */
export const AUTHOR_ONLY_RELATIONS: readonly string[] = ['edit', 'retract'];

/**
 * Relations the reference server lists under a published message. Which relations an author's server lists is
 * its own choice (spec section 7.4); this is one server's policy, kept here so its clients can share it.
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
 * The principal a message names that may count, given what the author's agent document says its kind is:
 * the `for` header of a version 1 message from a paired agent, or null. A solo agent, or an agent of a kind
 * the reader does not know, speaks for no one whatever its message carries. Whether the principal is
 * verified is a further question (a pairing, or a claim).
 */
export function claimedPrincipal(m: AnyMessage, kind: string): string | null {
  if (m.v !== VERSION || kind !== 'paired') return null;
  return header(m as Message, 'for');
}

/**
 * How a reader that knows the relations in `known` reads a message, given the message its `inReplyTo`
 * names (`target`, or null when the reader does not hold it):
 *
 * - `reply`: no `rel`, a `rel` the reader does not know, or an author-only relation whose author is not the
 *   target's. Shown by its blocks, as a reply.
 * - `relation`: a relation the reader applies to the target.
 * - `pending`: a relation the reader would apply, to a target it does not hold yet.
 */
export function readsAs(
  m: Message,
  target: Pick<AnyMessage, 'from'> | null,
  known: ReadonlySet<string>,
): 'reply' | 'relation' | 'pending' {
  const rel = header(m, 'rel');
  if (rel === null || !known.has(rel)) return 'reply';
  if (target === null) return 'pending';
  if (AUTHOR_ONLY_RELATIONS.includes(rel) && target.from !== m.from) return 'reply';
  return 'relation';
}
