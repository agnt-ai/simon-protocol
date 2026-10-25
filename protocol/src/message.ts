/**
 * The message: the protocol's only object (spec sections 1 and 5).
 *
 * Every version has `v`, `from`, `to`, `sentAt` and `signature`. Those, the canonical form and the size are
 * all a server checks of a version it does not know, so it routes later versions unchanged. Version 2 has
 * exactly eight fields:
 *
 *   { v, from, to, inReplyTo, parts, headers, sentAt, signature }
 *
 * The id is the hex SHA-256 of the canonical bytes without `signature`; the signature is over `SIMON-MESSAGE`,
 * a newline, and those same bytes. `id` is never a field: everyone computes it.
 */
import type { KeyObject } from 'node:crypto';
import {
  canonicalBytes,
  CanonicalError,
  isCanonical,
  isJsonObject,
  parseStrict,
  parseWithMembers,
  signingBytes,
  unsignedBytes,
  type Json,
} from './canonical.ts';
import { isAddress, isV1Address } from './address.ts';
import { bodyTooLarge, forbidden, invalid, unsupportedVersion } from './errors.ts';
import { isB64url, sha256Hex, sign, signatureVerdict, type KeyEntry, type SignatureVerdict } from './keys.ts';
import {
  isPrincipal,
  isSuccessionValue,
  pairingBytes,
  parsePairing,
  principalKey,
  readSuccession,
  verifyPairing,
} from './principal.ts';
import {
  MAX_ALT_BYTES,
  MAX_HEADERS,
  MAX_NAMED_FILES,
  MAX_NAMED_FILES_PART_MULTIPLE,
  MAX_PART_NAME_BYTES,
  MAX_PARTS,
  MINIMUM_LIMITS,
  SENT_AT_FUTURE_MS,
  type Limits,
} from './limits.ts';
import { parseTimestamp } from './time.ts';

/** The wire version this library implements (spec section 5.2): one counter for every incompatible revision. */
export const VERSION = 2;

/** A message of any version, as far as the invariants say. A later version's other fields ride along unread. */
export interface AnyMessage {
  v: number;
  from: string;
  to: string[];
  sentAt: string;
  signature: string;
}

/** A block's optional members (spec section 5.3): the file name its author suggests, and a one-line text version. */
type PartLabels = { name?: string; alt?: string };

/**
 * A block: inline `data` (a JSON value for a JSON media type, the text itself for `text/*`, base64 for any
 * other type), or bytes named by `sha256` and `size`.
 */
export type Part = ({ type: string; data: Json } | { type: string; sha256: string; size: number }) & PartLabels;

/** A message of the version this library implements. */
export interface Message extends AnyMessage {
  inReplyTo: string | null;
  parts: Part[];
  headers: Record<string, string>;
}

export type Unsigned<M extends AnyMessage> = Omit<M, 'signature'>;

const FIELDS = ['v', 'from', 'to', 'inReplyTo', 'parts', 'headers', 'sentAt', 'signature'];
const HEX64 = /^[0-9a-f]{64}$/;
/** An RFC 6838 restricted name, in lower case. */
const NAME = '[a-z0-9][a-z0-9!#$&^_.+-]{0,126}';
/**
 * A media type: a lower-case `type/subtype` of restricted names, then parameters, each `;`, an optional
 * space, a lower-case restricted name, `=`, and a value of restricted-name characters in any case or a
 * quoted string of printable ASCII without `"` or `\`.
 */
const MEDIA_TYPE = new RegExp(`^${NAME}/${NAME}(; ?${NAME}=([A-Za-z0-9!#$&^_.+-]+|"[ !#-[\\]-~]*"))*$`);
/**
 * A name (spec section 5.4): lower-case letters and digits in groups joined by single hyphens, and for a
 * private name, several such labels joined by dots, reverse-domain (`com.example.approve`).
 */
const NAME_RE = /^[a-z0-9]+(-[a-z0-9]+)*(\.[a-z0-9]+(-[a-z0-9]+)*)*$/;
/** The longest name, header, relation, feed or signal type. */
export const MAX_NAME_LENGTH = 128;
/** The headers the protocol names (spec section 5.4); every other header is a registry convention. */
export const PROTOCOL_HEADERS: readonly string[] = [
  'for',
  'pairing',
  'succession',
  'critical',
  'rel',
  'feed',
  'audience',
  'listed',
];

/** What a part's `name` never holds: `/`, a backslash, category Cc, and the bidirectional formatting characters. */
const NOT_IN_NAME = /[/\\\p{Cc}\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;
/** What a part's `alt` never holds: category Cc (so it is one line) and the bidirectional formatting characters. */
const NOT_IN_ALT = /[\p{Cc}\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;

export const messageId = (m: object) => sha256Hex(unsignedBytes(m));

export function signMessage<M extends AnyMessage>(m: Unsigned<M>, key: string | KeyObject): M {
  return { ...m, signature: sign(key, signingBytes('SIMON-MESSAGE', m)) } as M;
}

/**
 * What the author's keys say of a message's signature, at its `sentAt`: `verified`, `unsupported_algorithm`
 * when no key valid then is of an algorithm implemented here, or `bad_signature`.
 */
export function messageVerdict(m: AnyMessage, keys: readonly KeyEntry[]): SignatureVerdict {
  const at = parseTimestamp(m.sentAt);
  if (at === null) return 'bad_signature';
  return signatureVerdict(keys, new Date(at), signingBytes('SIMON-MESSAGE', m), m.signature);
}

/** Whether the signature verifies with one of the author's keys valid at the message's `sentAt`. */
export const verifyMessage = (m: AnyMessage, keys: readonly KeyEntry[]) => messageVerdict(m, keys) === 'verified';

/**
 * Step 11 of spec section 6.3, once the author's agent document is read: `403 unsupported_algorithm` when
 * the author has no valid key at `sentAt` this server can verify, `403 bad_signature` when none verifies.
 */
export function checkAuthorSignature(m: AnyMessage, keys: readonly KeyEntry[]): void {
  const verdict = messageVerdict(m, keys);
  if (verdict === 'unsupported_algorithm') {
    throw forbidden(verdict, 'The author has no key valid at sentAt of an algorithm this server implements.');
  }
  if (verdict === 'bad_signature') {
    throw forbidden(verdict, "The message does not verify with its author's keys valid at its sentAt.");
  }
}

/** `send` takes only versions this server implements (CLIENT.md), so no version steps around another's rules. */
export function checkSupportedVersion(m: AnyMessage): asserts m is Message {
  if (m.v !== VERSION) throw unsupportedVersion(m.v);
}

/** Parse a body under the canonical rules, refusing anything else as `invalid`. */
export const parseJson = (bytes: Uint8Array): Json => parseJsonWithMembers(bytes).value;

/** `parseJson`, also with the text of each top-level member as sent (see `parseWithMembers`). */
export function parseJsonWithMembers(bytes: Uint8Array) {
  try {
    return parseWithMembers(bytes);
  } catch (e) {
    throw invalid(e instanceof CanonicalError ? e.message : 'Not JSON.');
  }
}

/**
 * A body that is a message, checked in the order of spec section 6.3 (steps 1, 3 and 4), as the client API's
 * `send` checks it: no larger than `requestBodyBytes`, parsed, already canonical (the refusal carries the
 * canonical form in `details.canonical`), then `checkMessage`.
 */
export function parseMessage(body: Uint8Array, limits: Limits = MINIMUM_LIMITS): AnyMessage {
  if (body.length > limits.requestBodyBytes) throw bodyTooLarge(limits.requestBodyBytes);
  const value = parseJson(body);
  const canonical = canonicalBytes(value);
  if (!canonical.equals(body)) {
    throw invalid('The message is not in canonical form.', { canonical: canonical.toString('utf8') });
  }
  return checkMessage(value, limits);
}

/**
 * Step 4 of spec section 6.3, for a message already known to be canonical: the invariants hold, the size is
 * within `messageBytes`, `to` is within `recipients`, and a version 2 message keeps version 2's rules. A
 * later version passes on its invariants alone.
 */
export function checkMessage(value: unknown, limits: Limits = MINIMUM_LIMITS): AnyMessage {
  const m = checkInvariants(value);
  const size = canonicalBytes(m).length;
  if (size > limits.messageBytes) {
    throw invalid(`A message is at most ${limits.messageBytes} canonical bytes here; this one is ${size}.`, {
      field: 'message',
    });
  }
  if (m.to.length > limits.recipients) throw invalid(`At most ${limits.recipients} recipients here.`, { field: 'to' });
  if (m.v === VERSION) checkVersionRules(value as Record<string, Json>, limits);
  return m;
}

/** The fields every version has (spec section 1): a positive integer `v`, `from`, `to`, `sentAt` and `signature`. */
export function checkInvariants(value: unknown): AnyMessage {
  if (!isJsonObject(value)) throw invalid('The message must be a JSON object.', { field: 'message' });
  if (!Number.isSafeInteger(value.v) || (value.v as number) < 1) {
    throw invalid('v must be a positive integer.', { field: 'v' });
  }
  if (!isAddress(value.from)) throw invalid('from must be an address in lower case.', { field: 'from' });
  if (!Array.isArray(value.to) || !value.to.every(isAddress)) {
    throw invalid('to must be an array of addresses in lower case.', { field: 'to' });
  }
  if (parseTimestamp(value.sentAt) === null) {
    throw invalid('sentAt must be a UTC timestamp, e.g. 2026-10-14T21:00:00Z or 2026-10-14T21:00:00.000Z.', {
      field: 'sentAt',
    });
  }
  if (!isB64url(value.signature)) throw invalid('signature must be canonical base64url.', { field: 'signature' });
  return value as unknown as AnyMessage;
}

/** This version's own rules (spec section 5), beyond the invariants. */
function checkVersionRules(m: Record<string, Json>, limits: Limits) {
  const extra = Object.keys(m).find(k => !FIELDS.includes(k));
  if (extra !== undefined) throw invalid(`A version ${VERSION} message has no field ${extra}.`, { field: extra });
  if (!isV1Address(m.from)) throw invalid(`from must be an ASCII address in version ${VERSION}.`, { field: 'from' });
  const to = m.to as string[];
  if (!to.every(isV1Address)) throw invalid(`to must hold ASCII addresses in version ${VERSION}.`, { field: 'to' });
  if (new Set(to).size !== to.length) throw invalid('An address appears twice in to.', { field: 'to' });
  if (m.inReplyTo !== null && !(typeof m.inReplyTo === 'string' && HEX64.test(m.inReplyTo))) {
    throw invalid('inReplyTo must be null or a message id (64 lower-case hex).', { field: 'inReplyTo' });
  }

  if (!Array.isArray(m.parts) || m.parts.length > MAX_PARTS) {
    throw invalid(`parts must be an array of 0 to ${MAX_PARTS}.`, { field: 'parts' });
  }
  m.parts.forEach((p, i) => checkPart(p, i, limits));
  checkCarriedFiles(m, limits);

  if (!isJsonObject(m.headers) || Object.keys(m.headers).length > MAX_HEADERS) {
    throw invalid(`headers must be an object of at most ${MAX_HEADERS} strings.`, { field: 'headers' });
  }
  for (const [name, value] of Object.entries(m.headers)) {
    if (!isHeaderName(name)) {
      throw invalid(
        `Header names are lower-case letters and digits joined by single hyphens, or such labels joined by dots, at most ${MAX_NAME_LENGTH}: ${name}`,
        {
          field: 'headers',
        },
      );
    }
    if (typeof value !== 'string') throw invalid(`Header ${name} must be a string.`, { field: 'headers' });
  }
  const { for: forValue, pairing, critical } = m.headers;
  if (forValue !== undefined && !isPrincipal(forValue)) {
    throw invalid('The for header is a principal: mailto: with an address, tel: with an E.164 number, or simon-key:.', {
      field: 'headers',
    });
  }
  // Presence and grammar only: whether the pairing verifies is for readers and the agent's own server.
  if ((pairing !== undefined) !== (typeof forValue === 'string' && principalKey(forValue) !== null)) {
    throw invalid('The pairing header is present exactly when for is a simon-key: principal.', { field: 'headers' });
  }
  if (pairing !== undefined && parsePairing(pairing) === null) {
    throw invalid('The pairing header is a timestamp, one space, and a signature in canonical base64url.', {
      field: 'headers',
    });
  }
  const { succession } = m.headers;
  if (succession !== undefined && pairing === undefined) {
    throw invalid('The succession header goes only with a simon-key: for and its pairing.', { field: 'headers' });
  }
  if (succession !== undefined && !isSuccessionValue(succession)) {
    throw invalid('The succession header is steps joined by commas: a key token and two signatures, one space apart.', {
      field: 'headers',
    });
  }
  if (critical !== undefined && !isCriticalValue(critical)) {
    throw invalid('The critical header is header names joined by commas, with no spaces.', { field: 'headers' });
  }
  const { rel, feed, audience } = m.headers;
  // A rel without inReplyTo, or a feed on a message with recipients, means nothing and is ignored; audience is
  // security metadata, so its placement is checked (spec section 5.4).
  if (rel !== undefined && !isHeaderName(rel)) {
    throw invalid('The rel header is a relation name.', { field: 'headers' });
  }
  if (feed !== undefined && !isCriticalValue(feed)) {
    throw invalid('The feed header is feed names joined by commas, with no spaces.', { field: 'headers' });
  }
  if (audience !== undefined && to.length > 0) {
    throw invalid('The audience header belongs only on a published message, whose to is empty.', {
      field: 'headers',
    });
  }
  // Publishing is explicit: a message names recipients, or says who may read it (spec section 5.2).
  if (to.length === 0 && audience === undefined) {
    throw invalid(
      'A message with no recipients is published, and says who may read it: an audience header, public for anyone.',
      {
        field: 'headers',
      },
    );
  }
  // The writer's consent to have a relation listed under the published message it names (publishing profile, section 4).
  const { listed } = m.headers;
  if (listed !== undefined && !(isListedValue(listed) && rel !== undefined && m.inReplyTo !== null && to.length > 0)) {
    throw invalid('The listed header is yes, on a relation (it carries rel) whose to is not empty.', {
      field: 'headers',
    });
  }
}

function checkPart(value: Json, i: number, limits: Limits) {
  if (!isJsonObject(value)) throw invalid(`Part ${i} must be a JSON object.`, { field: 'parts' });
  if (typeof value.type !== 'string' || value.type.length > 200 || !MEDIA_TYPE.test(value.type)) {
    throw invalid(`Part ${i} needs a lower-case media type of at most 200 characters, e.g. text/plain.`, {
      field: 'parts',
    });
  }
  const { data, sha256, size, name, alt } = value;
  if (name !== undefined && !isPartName(name)) {
    throw invalid(
      `Part ${i}: name is 1 to ${MAX_PART_NAME_BYTES} bytes, not . or .., with no slash, backslash, control or bidirectional formatting character.`,
      { field: 'parts' },
    );
  }
  if (alt !== undefined && !isAlt(alt)) {
    throw invalid(
      `Part ${i}: alt is one line of 1 to ${MAX_ALT_BYTES} bytes, with no control or bidirectional formatting character.`,
      { field: 'parts' },
    );
  }
  // Other members are ignored, so a later one needs no flag day; the content is one of exactly two shapes.
  const content = [data, sha256, size].map(x => (x === undefined ? '-' : '+')).join('');
  if (content === '+--') {
    // One encoding per type: a JSON value for a JSON type, the text for text/*, base64 for anything else.
    if (!isJsonType(value.type)) {
      if (typeof value.data !== 'string') throw invalid(`Part ${i}: data must be a string.`, { field: 'parts' });
      if (!value.type.startsWith('text/') && !isBase64(value.data)) {
        throw invalid(`Part ${i}: data of a part that is neither JSON nor text is padded, canonical base64.`, {
          field: 'parts',
        });
      }
    }
  } else if (content === '-++') {
    if (typeof value.sha256 !== 'string' || !HEX64.test(value.sha256)) {
      throw invalid(`Part ${i}: sha256 must be 64 lower-case hex.`, { field: 'parts' });
    }
    if (!Number.isSafeInteger(value.size) || (value.size as number) < 0) {
      throw invalid(`Part ${i}: size must be a whole number of bytes.`, { field: 'parts' });
    }
    if ((value.size as number) > limits.partBytes) {
      throw invalid(`Part ${i}: a part is at most ${limits.partBytes} bytes here; share a larger one by reference.`, {
        field: 'parts',
      });
    }
  } else {
    throw invalid(`Part ${i} has data, or sha256 and size, beside its type.`, { field: 'parts' });
  }
}

/** Whether a value is a part's `name`: 1 to 255 bytes, not `.` or `..`, with none of the characters that disguise one. */
const isPartName = (value: unknown): value is string =>
  typeof value === 'string' &&
  value !== '.' &&
  value !== '..' &&
  value.isWellFormed() &&
  between(Buffer.byteLength(value), 1, MAX_PART_NAME_BYTES) &&
  !NOT_IN_NAME.test(value);

/** Whether a value is a part's `alt`: one line of 1 to 1024 bytes, with no control character. */
const isAlt = (value: unknown): value is string =>
  typeof value === 'string' &&
  value.isWellFormed() &&
  between(Buffer.byteLength(value), 1, MAX_ALT_BYTES) &&
  !NOT_IN_ALT.test(value);

const between = (n: number, min: number, max: number) => n >= min && n <= max;

const isBase64 = (s: string) =>
  /^[A-Za-z0-9+/]*={0,2}$/.test(s) && s.length % 4 === 0 && Buffer.from(s, 'base64').toString('base64') === s;

/**
 * Whether a value is a name (a header, relation, feed or signal type): lower-case letters and digits in
 * groups joined by single hyphens, or several such labels joined by dots for a private name, at most 128.
 */
export const isHeaderName = (value: unknown): value is string =>
  typeof value === 'string' && value.length <= MAX_NAME_LENGTH && NAME_RE.test(value);

/**
 * Whether a media type is a JSON type (spec section 5.3), whose inline `data` is a JSON value:
 * `application/json`, or any type with the `+json` suffix, whatever its parameters.
 */
export function isJsonType(type: string): boolean {
  const base = type.split(';', 1)[0].trim();
  return base === 'application/json' || base.endsWith('+json');
}

/** Whether a value is a `listed` header: exactly `yes` (spec section 5.4). */
export const isListedValue = (value: unknown): value is 'yes' => value === 'yes';

/** Whether a value is a `critical` header: header names joined by commas, with no spaces. */
export const isCriticalValue = (value: unknown): value is string =>
  typeof value === 'string' && value.split(',').every(isHeaderName);

/** Whom an agent speaks for (spec section 2.2): a paired agent's principal is its `for` header's one value. */
export type Principal = { kind: 'paired'; for: string } | { kind: 'solo' };

/**
 * What an agent's own server checks on `send`, beyond the message's validity (CLIENT.md). A paired agent's
 * version 2 message carries its principal as `for`; with a key principal it also carries a `pairing` that
 * verifies, and with any other it carries none. A solo agent's message carries neither. A `succession` must
 * verify; with one, a key principal's `for` may be a successor of the agent's principal, and the server then
 * moves its record to it (spec section 2.2). Refused as `400 invalid` on `headers`. A later version's headers
 * are not known here, so its messages pass.
 */
export function checkPrincipal(m: AnyMessage, agent: Principal): void {
  if (m.v !== VERSION) return;
  const forValue = header(m as Message, 'for');
  const pairing = header(m as Message, 'pairing');
  const refuse = (why: string) => invalid(why, { field: 'headers' });
  if (agent.kind === 'solo') {
    if (forValue !== null || pairing !== null) throw refuse('A solo agent speaks for no one: no for, no pairing.');
    return;
  }
  const succession = header(m as Message, 'succession');
  const steps = succession === null || forValue === null ? [] : readSuccession(succession, forValue);
  if (steps === null) {
    throw refuse(
      `Each succession step must be signed by both its keys over SIMON-SUCCEED, the old and the new identifier, leading to for.`,
    );
  }
  if (forValue !== agent.for && !steps.some(s => s.from === agent.for)) {
    throw refuse(`A paired agent's messages carry its principal as for, or a successor it signed: ${agent.for}.`);
  }
  // The agent's principal, or the successor it moves to: either way the one that must have signed the pairing.
  const principal = forValue!;
  if (principalKey(principal) === null) {
    if (pairing !== null) throw refuse('Only a key principal pairs by signature: this message carries no pairing.');
  } else if (!verifyPairing(m.from, principal, pairing, parseTimestamp(m.sentAt) ?? NaN)) {
    const until = parsePairing(pairing)?.until ?? '<until>';
    throw refuse(
      `The pairing header must be <until> <signature>: the principal's signature over ${JSON.stringify(pairingBytes(m.from, principal, until))}, valid at sentAt: before until, by at most 366 days. The principal renews a lapsed pairing by signing a later until.`,
    );
  }
}

/** Whether `sentAt` is at most `pastMs` before `now` and at most five minutes after it. */
export function isFresh(m: Pick<AnyMessage, 'sentAt'>, now: Date, pastMs: number): boolean {
  const t = parseTimestamp(m.sentAt);
  return t !== null && t >= now.getTime() - pastMs && t <= now.getTime() + SENT_AT_FUTURE_MS;
}

/** A version 2 header's value, or null. Names are lower case on the wire. */
export const header = (m: Pick<Message, 'headers'>, name: string): string | null =>
  Object.hasOwn(m.headers, name) ? m.headers[name] : null;

/** The text of a message's text parts (any `text/*` type), joined by `separator`. */
export const textOf = (m: Pick<Message, 'parts'>, separator = '\n') =>
  m.parts
    .flatMap(p => ('data' in p && p.type.startsWith('text/') && typeof p.data === 'string' ? [p.data] : []))
    .join(separator);

/** The media type of a part that carries another message whole (spec section 5.3). */
export const CARRIED_MESSAGE_TYPE = 'application/simon-message';
/**
 * How deep messages are carried inline: a message a part of the carrying message carries is at depth 1, one
 * its parts carry at depth 2, and so on. A message carried deeper is refused (spec section 5.3).
 */
export const MAX_CARRIED_DEPTH = 8;

/**
 * The message a carried part's inline `data` holds (spec section 5.3, Form): canonical base64 of the canonical
 * bytes (section 5.1) of a JSON object whose members of section 1's item 2 are well formed, so its id can be
 * computed; or null. Its signature is not checked.
 */
function readCarried(data: string): Record<string, Json> | null {
  if (!isBase64(data)) return null;
  const bytes = Buffer.from(data, 'base64');
  try {
    const value = parseStrict(bytes);
    if (!isJsonObject(value) || !isCanonical(bytes, value)) return null;
    checkInvariants(value);
    return value;
  } catch {
    return null;
  }
}

/**
 * The parts of every message a version 2 message carries whole inline, at every depth up to MAX_CARRIED_DEPTH.
 * With `strict`, a carried message that `readCarried` refuses, or one carried deeper, makes the carrying
 * message invalid; without it, such a message names nothing.
 */
function carriedParts(m: AnyMessage | Record<string, Json>, strict: boolean, depth = 0): Json[] {
  const parts = m.v === VERSION ? (m as { parts?: unknown }).parts : undefined;
  if (!Array.isArray(parts)) return [];
  const found: Json[] = [];
  for (const p of parts as Json[]) {
    if (!isJsonObject(p) || typeof p.type !== 'string' || typeof p.data !== 'string') continue;
    if (
      p.type
        .split(';')[0]
        .replace(/^ +| +$/g, '')
        .toLowerCase() !== CARRIED_MESSAGE_TYPE
    )
      continue;
    if (depth >= MAX_CARRIED_DEPTH) {
      throw invalid(`Messages are carried inline at most ${MAX_CARRIED_DEPTH} deep.`, { field: 'parts' });
    }
    const inner = readCarried(p.data);
    if (!inner) {
      if (!strict) continue;
      throw invalid(
        depth < MAX_CARRIED_DEPTH
          ? 'A message carried inline is the canonical bytes of a message (v, from, to, sentAt and signature well formed), in canonical base64.'
          : `Messages are carried inline at most ${MAX_CARRIED_DEPTH} deep.`,
        { field: 'parts' },
      );
    }
    if (inner.v === VERSION && Array.isArray(inner.parts)) found.push(...inner.parts);
    found.push(...carriedParts(inner, strict, depth + 1));
  }
  return found;
}

const isFileEntry = (p: Json): p is { sha256: string; size: number } =>
  isJsonObject(p) && p.sha256 !== undefined && p.size !== undefined;

/**
 * Spec section 5.3: every message carried inline is the canonical bytes of an object, at most MAX_CARRIED_DEPTH
 * deep; every file one names has a sha256 of lower-case hex and a size within `partBytes`; and a message names
 * at most `MAX_NAMED_FILES` files in all, its own and its carried messages', whose sizes add up to at most
 * `MAX_NAMED_FILES_PART_MULTIPLE` times `partBytes`.
 */
function checkCarriedFiles(m: Record<string, Json>, limits: Limits) {
  const carried = carriedParts(m, true).filter(isFileEntry);
  const ownFiles = (m.parts as Json[]).filter(isFileEntry);
  const own = ownFiles.length;
  if (own + carried.length > MAX_NAMED_FILES) {
    throw invalid(`A message names at most ${MAX_NAMED_FILES} files, its own and those of the messages it carries.`, {
      field: 'parts',
    });
  }
  for (const f of carried) {
    if (typeof f.sha256 !== 'string' || !HEX64.test(f.sha256)) {
      throw invalid('A file named by a carried message needs a sha256 of 64 lower-case hex.', { field: 'parts' });
    }
    if (!Number.isSafeInteger(f.size) || f.size < 0 || f.size > limits.partBytes) {
      throw invalid(`A file named by a carried message is a whole number of bytes, at most ${limits.partBytes} here.`, {
        field: 'parts',
      });
    }
  }
  // Totals: the sizes of every file it names, its own (each already within partBytes) and its carried ones.
  const files = [...ownFiles, ...carried];
  const sizes = new Map<string, number>();
  let total = 0n;
  for (const f of files) {
    const hash = f.sha256 as string;
    const size = f.size as number;
    const earlier = sizes.get(hash);
    if (earlier !== undefined && earlier !== size) {
      throw invalid('Every occurrence of a content hash must declare the same file size.', { field: 'parts' });
    }
    sizes.set(hash, size);
    total += BigInt(size);
  }
  // Readers use positive Infinity for an unrestricted byte limit; all structural checks still apply.
  if (limits.partBytes === Infinity) return;
  const bound = BigInt(MAX_NAMED_FILES_PART_MULTIPLE) * BigInt(limits.partBytes);
  if (total > bound) {
    throw invalid(
      `The files a message names add up to at most ${MAX_NAMED_FILES_PART_MULTIPLE} times partBytes, ${bound} bytes here.`,
      { field: 'parts' },
    );
  }
}

/**
 * The files a version 2 message names by content address (spec sections 5.3 and 7.2): its own, and those of
 * every message it carries whole inline, which count as named by the message that carries it. A carried
 * message the checks above would refuse names nothing, and neither does one carried by content address. Only well-formed
 * entries are returned, so a message that skipped the checks above still names nothing unsafe.
 */
export function namedFiles(m: AnyMessage): { sha256: string; size: number }[] {
  const own = m.v === VERSION ? (m as { parts?: unknown }).parts : undefined;
  if (!Array.isArray(own)) return [];
  return [...(own as Json[]), ...carriedParts(m, false)]
    .filter(isFileEntry)
    .filter(f => typeof f.sha256 === 'string' && HEX64.test(f.sha256) && Number.isSafeInteger(f.size) && f.size >= 0)
    .slice(0, MAX_NAMED_FILES)
    .map(f => ({ sha256: f.sha256, size: f.size }));
}

/**
 * Every message a version 2 message carries whole inline (spec section 5.3), at every depth up to
 * MAX_CARRIED_DEPTH, as the JSON objects they are. A carried part that does not hold a readable message, or
 * one carried by content address, is not among them: its bytes are not in the message.
 */
export function carriedMessages(m: AnyMessage | Record<string, Json>, depth = 0): Record<string, Json>[] {
  const parts = m.v === VERSION ? (m as { parts?: unknown }).parts : undefined;
  if (!Array.isArray(parts) || depth >= MAX_CARRIED_DEPTH) return [];
  const found: Record<string, Json>[] = [];
  for (const p of parts as Json[]) {
    if (!isJsonObject(p) || typeof p.type !== 'string' || typeof p.data !== 'string') continue;
    if (
      p.type
        .split(';')[0]
        .replace(/^ +| +$/g, '')
        .toLowerCase() !== CARRIED_MESSAGE_TYPE
    )
      continue;
    const inner = readCarried(p.data);
    if (!inner) continue;
    found.push(inner, ...carriedMessages(inner, depth + 1));
  }
  return found;
}
