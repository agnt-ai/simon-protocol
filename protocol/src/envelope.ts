/**
 * The transport envelope: what one server posts to another, `POST /simon/deliver` (spec section 6).
 *
 *   { message, server, recipients, claims?, claimsSignature?, hints?, signature }
 *
 * The message's own signature proves its author. The envelope's signature, by the carrying server, proves
 * which server carried it, and to whom: `server` is the receiving origin and `recipients` the addresses in
 * `to` that it serves, so an envelope can be neither replayed to another server nor stretched to other
 * recipients. Hints (per-recipient notes for the receiving server's policy) rest on it too. Claims
 * (statements the carrier makes about the author) are also signed on their own, over `SIMON-CLAIMS` and
 * `{"claims","message":<id>}`, so they travel with the message into inboxes and stay checkable wherever it
 * goes. Members a receiver does not know are ignored, and are signed like any other, so an envelope is kept
 * exactly as it arrived.
 */
import type { KeyObject } from 'node:crypto';
import { domainOf, isAddress } from './address.ts';
import { canonicalize, isJsonObject, signingBytes, type Json } from './canonical.ts';
import { bodyTooLarge, forbidden, invalid } from './errors.ts';
import { isB64url, sign, signedByAny, validDuring, verify, type KeyEntry } from './keys.ts';
import { isPrincipal } from './principal.ts';
import { claimedPrincipal } from './reading.ts';
import {
  DELIVERY_AFTER_ACCEPT_MS,
  DELIVERY_AFTER_SENT_MS,
  DELIVERY_WINDOW_MS,
  MAX_CLAIMS,
  MAX_ENVELOPE_BESIDE_MESSAGE_BYTES,
  MAX_ENVELOPE_EXTRAS_BYTES,
  MINIMUM_LIMITS,
  REPEAT_WINDOW_MS,
  type Limits,
} from './limits.ts';
import { checkMessage, isFresh, messageId, parseJsonWithMembers, type AnyMessage } from './message.ts';
import { serverOrigin, type Resolve, type Resolution } from './resolve.ts';
import { parseTimestamp } from './time.ts';

/** A statement the carrying server makes about the author. Opaque to the protocol; `type` names it. */
export interface Claim {
  type: string;
  [field: string]: Json | undefined;
}

/**
 * The protocol's one claim type (spec section 6.2): the carrier verified that the principal in the message's
 * `for` header approved this agent. `authoritative` is not sent: it is the receiving server's judgement,
 * passed to its agents with the claim (`judgeClaims`).
 */
export interface ActsForClaim extends Claim {
  type: 'acts-for';
  agent: string;
  for: string;
  verifiedAt: string;
  scope: string[];
  authoritative?: boolean;
}

/**
 * The registry's `identifier` claim: the carrier verified that an email address or phone number belongs to
 * the author (`of: agent`) or to its principal (`of: principal`). Its authority is judged as an acts-for
 * claim's is, by the identifier.
 */
export interface IdentifierClaim extends Claim {
  type: 'identifier';
  agent: string;
  of: 'agent' | 'principal';
  identifier: string;
  verifiedAt: string;
  authoritative?: boolean;
}

export type Hints = Record<string, Record<string, string>>;

/** An envelope as sent. An absent `claims` or `hints` stays absent, since the signature covers what was sent. */
export interface UnsignedEnvelope {
  message: AnyMessage;
  /** The origin of the server the envelope is for. */
  server: string;
  /** The addresses in `to`, exactly as written, that `server` serves: at least one, all distinct. */
  recipients: string[];
  claims?: Claim[];
  /** The carrier's signature over the claims and the message id; present exactly when `claims` is. */
  claimsSignature?: string;
  hints?: Hints;
  /** Members this version does not define: ignored, and signed. */
  [member: string]: unknown;
}

export interface Envelope extends UnsignedEnvelope {
  signature: string;
}

/** The server a delivery arrives at: its own origin. */
export interface Receiver {
  origin: string;
  /** Local development only: `server` may be `http:` or a local host. */
  allowHttp?: boolean;
}

/** Claims as their carrier signed them for one message: what an inbox entry carries as `signedClaims`. */
export interface SignedClaims {
  claims: Claim[];
  signature: string;
}

/** The bytes a carrier signs for its claims about one message: `SIMON-CLAIMS`, then `{"claims","message"}`. */
export const claimsBytes = (claims: readonly Claim[], id: string) =>
  signingBytes('SIMON-CLAIMS', { claims, message: id });

/** Sign an envelope; one that carries `claims` gets its `claimsSignature` first, by the same key. */
export function signEnvelope(e: UnsignedEnvelope, serverKey: string | KeyObject): Envelope {
  const unsigned = e.claims
    ? { ...e, claimsSignature: sign(serverKey, claimsBytes(e.claims, messageId(e.message))) }
    : e;
  return { ...unsigned, signature: sign(serverKey, signingBytes('SIMON-ENVELOPE', unsigned)) };
}

/** Whether one of the carrying server's keys valid at `at` (when the envelope arrives) signed it. */
export const verifyEnvelope = (e: Envelope, serverKeys: readonly KeyEntry[], at: Date) =>
  signedByAny(serverKeys, at, signingBytes('SIMON-ENVELOPE', e), e.signature) &&
  (e.claims === undefined ||
    signedByAny(serverKeys, at, claimsBytes(e.claims, messageId(e.message)), e.claimsSignature));

/** Step 7 of spec section 6.3: the envelope, and its claims, verify with a carrier key valid now, or `403 bad_signature`. */
export function checkEnvelopeSignature(e: Envelope, serverKeys: readonly KeyEntry[], now: Date): void {
  if (!verifyEnvelope(e, serverKeys, now)) {
    throw forbidden('bad_signature', "The envelope does not verify with a key of the carrier's server valid now.");
  }
}

/**
 * Whether a carrier made these claims about this message (spec section 6.2), checked by anyone, at any time:
 * one of the carrier's keys valid at some moment of the message's delivery window, from its `sentAt` to 144
 * hours after, signed them. `carrierKeys` are the keys of the server the message's `from` domain resolves
 * to, read by the checker itself, never taken from whoever handed it the message.
 */
export function verifyClaims(signed: SignedClaims, message: AnyMessage, carrierKeys: readonly KeyEntry[]): boolean {
  const sent = parseTimestamp(message.sentAt);
  if (sent === null) return false;
  const [from, to] = [new Date(sent), new Date(sent + DELIVERY_WINDOW_MS)];
  let bytes: Buffer;
  try {
    bytes = claimsBytes(signed.claims, messageId(message));
  } catch {
    return false; // claims with no canonical form were never signed by anyone
  }
  return carrierKeys.some(k => validDuring(k, from, to) && verify(k.key, bytes, signed.signature));
}

/**
 * Steps 1 to 4 of spec section 6.3, in order, on the body of a delivery: no larger than `requestBodyBytes`
 * (413) and parsed; the envelope's shape; the message exactly in canonical form as it arrived (the refusal
 * carries the canonical form); then `checkMessage`. Given the `receiver`, also step 5, `checkDestination`,
 * which needs no lookup. Steps 6 on need the network and the server's store.
 */
export function parseEnvelope(body: Uint8Array, limits: Limits = MINIMUM_LIMITS, receiver?: Receiver): Envelope {
  if (body.length > limits.requestBodyBytes) throw bodyTooLarge(limits.requestBodyBytes);
  const { value, members } = parseJsonWithMembers(body);
  const envelope = checkEnvelopeShape(value, receiver?.allowHttp);
  const canonical = canonicalize(envelope.message);
  if (members.get('message') !== canonical) throw invalid('The message is not in canonical form.', { canonical });
  checkMessage(envelope.message, limits);
  if (receiver) checkDestination(envelope, receiver);
  return envelope;
}

/**
 * Step 2 of spec section 6.3: the envelope is an object, `message` an object, `signature` base64url, `server`
 * an origin, `recipients` a non-empty array of distinct addresses, and `claims` and `hints`, when present, as
 * section 6.2 says, with hints keyed only by `recipients`. Anything else is ignored.
 */
export function checkEnvelopeShape(value: Json, allowHttp = false): Envelope {
  if (!isJsonObject(value)) throw invalid('The envelope must be a JSON object.', { field: 'envelope' });
  if (!isJsonObject(value.message)) throw invalid('message must be a JSON object.', { field: 'message' });
  if (!isB64url(value.signature)) throw invalid('signature must be canonical base64url.', { field: 'signature' });
  if (!serverOrigin(value.server, allowHttp)) {
    throw invalid('server must be the origin of the server the envelope is for.', { field: 'server' });
  }
  const { recipients } = value;
  if (
    !Array.isArray(recipients) ||
    recipients.length === 0 ||
    !recipients.every(isAddress) ||
    new Set(recipients).size !== recipients.length
  ) {
    throw invalid('recipients must be a non-empty array of distinct addresses.', { field: 'recipients' });
  }

  const { claims = [], hints = {} } = value;
  if (!Array.isArray(claims) || claims.length > MAX_CLAIMS) {
    throw invalid(`claims must be an array of at most ${MAX_CLAIMS} objects.`, { field: 'claims' });
  }
  if (!claims.every(c => isJsonObject(c) && typeof c.type === 'string' && c.type !== '')) {
    throw invalid('Each claim is an object with a non-empty string type.', { field: 'claims' });
  }
  if (value.claims === undefined ? value.claimsSignature !== undefined : !isB64url(value.claimsSignature)) {
    throw invalid('claimsSignature, the carrier signature over the claims, is present exactly when claims is.', {
      field: 'claimsSignature',
    });
  }

  if (!isJsonObject(hints)) throw invalid('hints must be an object keyed by recipient address.', { field: 'hints' });
  for (const [recipient, h] of Object.entries(hints)) {
    if (!recipients.includes(recipient)) {
      throw invalid(`hints name ${recipient}, which is not one of this envelope's recipients.`, { field: 'hints' });
    }
    if (!isJsonObject(h) || !Object.values(h).every(x => typeof x === 'string')) {
      throw invalid("Each recipient's hints are an object of strings.", { field: 'hints' });
    }
  }

  const extras = Buffer.byteLength(canonicalize({ claims, hints }));
  if (extras > MAX_ENVELOPE_EXTRAS_BYTES) {
    throw invalid(`Claims and hints together are at most ${MAX_ENVELOPE_EXTRAS_BYTES} canonical bytes.`, {
      field: 'claims',
    });
  }
  return value as unknown as Envelope;
}

/**
 * A server's own bound on everything in an envelope but its message, in canonical bytes, so checking an
 * envelope costs little more than checking its message. Not a protocol rule: the reference server
 * applies it with `MAX_ENVELOPE_BESIDE_MESSAGE_BYTES` as its default (docs/REFERENCE-SERVER.md).
 */
export function checkEnvelopeBeside(envelope: Envelope, maxBytes = MAX_ENVELOPE_BESIDE_MESSAGE_BYTES): void {
  const { message: _, ...beside } = envelope as unknown as Record<string, Json>;
  if (Buffer.byteLength(canonicalize(beside)) > maxBytes) {
    throw invalid(`Everything in an envelope but its message is at most ${maxBytes} bytes here.`, {
      field: 'envelope',
    });
  }
}

/**
 * Step 5: the envelope is for this server, and every recipient is in the message's `to`. Otherwise `400
 * invalid` on `server` or `recipients`. Nothing is resolved: whether this server serves the recipients is
 * step 8, once the carrier is known.
 */
export function checkDestination(e: Pick<Envelope, 'server' | 'recipients' | 'message'>, receiver: Receiver): void {
  if (serverOrigin(e.server, true) !== serverOrigin(receiver.origin, true)) {
    throw invalid(`This envelope is for ${e.server}, not this server.`, { field: 'server' });
  }
  for (const r of e.recipients) {
    if (!e.message.to.includes(r)) throw invalid(`${r} is not in the message's to.`, { field: 'recipients' });
  }
}

/**
 * Step 8: every recipient is on a domain this server serves, or `400 invalid` on `field`. A server may need
 * to resolve a domain to know, which it does only now, after the carrier's signature verified.
 */
export function checkServed(recipients: readonly string[], serves: (domain: string) => boolean, field = 'recipients') {
  for (const r of recipients) {
    if (!serves(domainOf(r))) throw invalid(`This server does not serve ${r}.`, { field });
  }
}

/** Whether a delivery of a message is still recognised as a repeat: within 168 hours of `sentAt`, or ahead of it. */
export function withinRepeatWindow(m: Pick<AnyMessage, 'sentAt'>, now: Date): boolean {
  const t = parseTimestamp(m.sentAt);
  return t !== null && t >= now.getTime() - REPEAT_WINDOW_MS;
}

/**
 * Step 9: a repeat, answered `202` at once, when this message was accepted here before for every address in
 * `recipients` and is within the repeat window. `acceptedFor` holds the recipients accepted for its id.
 */
export const isRepeat = (e: Pick<Envelope, 'message' | 'recipients'>, acceptedFor: ReadonlySet<string>, now: Date) =>
  withinRepeatWindow(e.message, now) && e.recipients.every(r => acceptedFor.has(r));

/** Step 10: `sentAt` at most 144 hours old and at most five minutes ahead, or `400 invalid` on `sentAt`. */
export function checkFreshness(m: Pick<AnyMessage, 'sentAt'>, now: Date): void {
  if (!isFresh(m, now, DELIVERY_WINDOW_MS)) {
    throw invalid('sentAt is more than 144 hours old or more than 5 minutes ahead.', { field: 'sentAt' });
  }
}

const isActsFor = (c: Claim, m: AnyMessage, forHeader: string | null): c is ActsForClaim =>
  c.agent === m.from &&
  forHeader !== null &&
  c.for === forHeader &&
  parseTimestamp(c.verifiedAt) !== null &&
  Array.isArray(c.scope) &&
  c.scope.every(s => typeof s === 'string');

// A principal's identifier only for a principal named by a key: one named by an email address or phone
// number is its own identifier, which an acts-for claim covers.
const isIdentifier = (c: Claim, m: AnyMessage, forHeader: string | null): c is IdentifierClaim =>
  c.agent === m.from &&
  (c.of === 'agent' || (c.of === 'principal' && !!forHeader?.startsWith('simon-key:'))) &&
  isPrincipal(c.identifier) &&
  !c.identifier.startsWith('simon-key:') &&
  parseTimestamp(c.verifiedAt) !== null;

/**
 * The claims a receiver may consider (spec section 6.2, and the registry for `identifier`): an acts-for
 * claim only when it names the message's author as `agent` and its `for` header as `for`, with a timestamp
 * `verifiedAt` and a `scope` of strings; an identifier claim only when it names the author as `agent`, an
 * email address or phone number as `identifier`, a timestamp `verifiedAt`, and `of` the agent, or the
 * principal of a message whose `for` header names a key. A message of a version whose headers this reader
 * does not know, or from an agent whose document does not say `paired` (`kind`), has no acts-for or
 * principal claim that counts. Any other claim type passes through, opaque.
 */
export function claimsAbout(message: AnyMessage, claims: readonly Claim[], kind: string): Claim[] {
  const forHeader = claimedPrincipal(message, kind);
  return claims.filter(
    c =>
      (c.type !== 'acts-for' || isActsFor(c, message, forHeader)) &&
      (c.type !== 'identifier' || isIdentifier(c, message, forHeader)),
  );
}

/**
 * Whether an acts-for claim is authoritative (spec section 6.2): its `for` is a `mailto:` identifier whose
 * domain names the carrier by its `_simon` TXT record, so the domain's DNS speaks for its mail as a DKIM key
 * does. A domain whose server only its well-known answer names grants no authority: whoever runs a domain's
 * website need not run its mail. Never for a phone number or a key. An identifier claim is judged the same
 * way, by its `identifier` as the `for`.
 */
// The legacy fourth argument is accepted for reader compatibility; author-domain alignment is not authority.
export async function isAuthoritative(
  claim: Pick<ActsForClaim, 'for'>,
  carrier: string,
  resolve: Resolve,
  _agent?: string,
) {
  if (!claim.for.startsWith('mailto:')) return false;
  const domain = domainOf(claim.for);
  const r = await resolve(domain);
  return r.outcome === 'server' && r.via === 'dns' && r.server === serverOrigin(carrier, true);
}

/** The member naming the identifier a claim type's authority is judged by. */
const JUDGED_BY: Record<string, string | undefined> = { 'acts-for': 'for', identifier: 'identifier' };

/**
 * The claims a receiver considers, each acts-for and identifier claim marked with its `authoritative`
 * judgement under the identifier domain's DNS authority (`isAuthoritative`). A received claim's own `authoritative`
 * member means nothing (the carrier cannot judge itself), so it is dropped from every claim, and only the
 * judged types get one back.
 */
export async function judgeClaims(
  message: AnyMessage,
  claims: readonly Claim[] | undefined,
  kind: string,
  carrier: string,
  resolve: Resolve,
): Promise<Claim[]> {
  return Promise.all(
    claimsAbout(message, claims ?? [], kind).map(async ({ authoritative: _, ...c }) => {
      const subject = Object.hasOwn(JUDGED_BY, c.type) ? JUDGED_BY[c.type] : undefined;
      if (!subject) return c;
      return {
        ...c,
        authoritative: await isAuthoritative({ for: c[subject] as string }, carrier, resolve),
      };
    }),
  );
}

/**
 * Where a message's recipients go: the addresses of `to` grouped by the server their domains resolve to, in
 * the order they first appear, each domain resolved once. Recipients whose domains resolve to no server are
 * grouped by outcome, with `server` null. The author's server's own origin may be among them.
 */
export interface Destination {
  outcome: Resolution['outcome'];
  server: string | null;
  recipients: string[];
}

export async function destinations(to: readonly string[], resolve: Resolve): Promise<Destination[]> {
  const domains = [...new Set(to.map(domainOf))];
  const resolved = new Map(await Promise.all(domains.map(async d => [d, await resolve(d)] as const)));
  const groups = new Map<string, Destination>();
  for (const address of to) {
    const r = resolved.get(domainOf(address))!;
    const server = r.outcome === 'server' ? r.server : null;
    const key = server ?? r.outcome;
    const group = groups.get(key) ?? groups.set(key, { outcome: r.outcome, server, recipients: [] }).get(key)!;
    group.recipients.push(address);
  }
  return [...groups.values()];
}

/** The unsigned envelope for one destination: the message, its server and recipients, and only their hints. */
export function envelopeFor(
  message: AnyMessage,
  d: { server: string; recipients: readonly string[] },
  extras: { claims?: Claim[]; hints?: Hints } = {},
): UnsignedEnvelope {
  const hints = Object.fromEntries(Object.entries(extras.hints ?? {}).filter(([a]) => d.recipients.includes(a)));
  return {
    message,
    server: d.server,
    recipients: [...d.recipients],
    ...(extras.claims ? { claims: extras.claims } : {}),
    ...(Object.keys(hints).length ? { hints } : {}),
  };
}

/**
 * When an author's server may deliver a message it accepted at `acceptedAt` (spec section 6.3): not before
 * `sentAt`, and not at or after the deadline, the earlier of five days after acceptance and 143 hours after
 * `sentAt`.
 */
export function deliveryWindow(m: Pick<AnyMessage, 'sentAt'>, acceptedAt: Date): { earliest: Date; deadline: Date } {
  const sent = parseTimestamp(m.sentAt);
  if (sent === null) throw new RangeError(`${m.sentAt} is not a wire timestamp.`);
  const deadline = Math.min(acceptedAt.getTime() + DELIVERY_AFTER_ACCEPT_MS, sent + DELIVERY_AFTER_SENT_MS);
  return { earliest: new Date(sent), deadline: new Date(deadline) };
}

/** Whether a delivery attempt at `now` is too early, due, or past the deadline (then the recipients are `expired`). */
export function deliveryState(m: Pick<AnyMessage, 'sentAt'>, acceptedAt: Date, now: Date): 'early' | 'due' | 'expired' {
  const { earliest, deadline } = deliveryWindow(m, acceptedAt);
  if (now >= deadline) return 'expired';
  return now < earliest ? 'early' : 'due';
}
