/**
 * Every bound the protocol sets (spec section 9), in one place. Fixed rules are the same for every server;
 * the four minimums are what a server may raise, and publishes in its server document when it does.
 */

/** The limits a server publishes. Each is at least its minimum. */
export interface Limits {
  messageBytes: number;
  recipients: number;
  requestBodyBytes: number;
  partBytes: number;
}

/** What every server accepts, so a sender that stays within these is never refused for size. */
export const MINIMUM_LIMITS: Readonly<Limits> = Object.freeze({
  messageBytes: 262_144,
  recipients: 100,
  requestBodyBytes: 1_048_576,
  partBytes: 26_214_400,
});

/** A version 1 message's parts and headers, and a part's optional name and alt, in UTF-8 bytes. */
export const MAX_PARTS = 32;
/** Files one message names by content address in all: its own and those of the messages it carries inline. */
export const MAX_NAMED_FILES = 1024;
/** Those files' sizes add up to at most this many times `partBytes` (spec section 5.3, Totals). */
export const MAX_NAMED_FILES_PART_MULTIPLE = 32;
export const MAX_HEADERS = 32;
export const MAX_PART_NAME_BYTES = 255;
export const MAX_ALT_BYTES = 1024;

/** Claims in one envelope, and claims and hints together in canonical bytes (`{"claims":..,"hints":..}`). */
export const MAX_CLAIMS = 16;
export const MAX_ENVELOPE_EXTRAS_BYTES = 16_384;
/** The largest signature an algorithm here makes, in bytes (ML-DSA-65's), and in base64url characters. */
export const MAX_SIGNATURE_BYTES = 3309;
const MAX_SIGNATURE_CHARS = Math.ceil((MAX_SIGNATURE_BYTES * 4) / 3);

/**
 * The most an envelope for `recipients` recipients holds beside its message, in canonical bytes: each
 * recipient an address of the longest form (a local part of 64 bytes, each of which may be written as two,
 * an `@` and a domain of 253), claims and hints at their bound, the longest origin, two signatures of the
 * largest algorithm here, and the members' names. A bound set at this refuses no envelope the spec allows.
 */
export function envelopeBesideBytes(recipients: number): number {
  const address = 2 * 64 + 1 + 253 + '"",'.length;
  const origin = 'https://'.length + 253 + ':65535'.length + '""'.length;
  const signature = MAX_SIGNATURE_CHARS + '""'.length;
  const names = '{"claims":,"claimsSignature":,"hints":,"recipients":[],"server":,"signature":}'.length;
  return recipients * address + MAX_ENVELOPE_EXTRAS_BYTES + origin + 2 * signature + names;
}

/**
 * The reference server's default bound on everything in an envelope but its message, at the minimum
 * `recipients` (not a protocol rule). A server that raises `recipients` raises it with them.
 */
export const MAX_ENVELOPE_BESIDE_MESSAGE_BYTES = envelopeBesideBytes(MINIMUM_LIMITS.recipients);

/** A signal's body, and how far its `at` may be from the receiver's clock either way; a server keeps one no longer. */
/** A signal without its signature, in canonical bytes; the signature is bounded by its algorithm. */
export const MAX_SIGNAL_BYTES = 4096;
/** A signal's whole body, room for the largest signature an algorithm here makes. */
export const MAX_SIGNAL_BODY_BYTES = 16384;
export const SIGNAL_SKEW_MS = 300_000;

/** Feed and relations listings (spec section 7.3): how many per page, as the inbox's, and a cursor's length. */
export const MAX_LISTING_LIMIT = 200;
export const DEFAULT_LISTING_LIMIT = 50;
export const MAX_CURSOR_LENGTH = 128;

/** A server or agent document, and all key entries it lists, including retained revoked history. */
export const MAX_DOCUMENT_BYTES = 131_072;
export const MAX_DOCUMENT_KEYS = 32;
/** A document with a key revoked more than this after the time of reading is unreadable (spec sections 2.4 and 4). */
export const REVOCATION_AHEAD_MS = 300_000;

const HOUR_MS = 3_600_000;

/** How far ahead of a receiver's clock `sentAt` may be, everywhere. */
export const SENT_AT_FUTURE_MS = 5 * 60_000;
/** How old `sentAt` may be when an agent sends a message to its own server (the client API). */
export const SEND_WINDOW_MS = 24 * HOUR_MS;
/** How old `sentAt` may be when another server delivers it: a day to send, then five days of retries. */
export const DELIVERY_WINDOW_MS = 144 * HOUR_MS;
/** How long a receiver recognises a delivery it accepted before, outlasting every retry. */
export const REPEAT_WINDOW_MS = 168 * HOUR_MS;

/**
 * An author's server stops delivering at the earlier of these (spec section 6.3): five days after it accepted
 * the message, and 143 hours after `sentAt`, an hour inside the receivers' 144, so no delivery arrives stale.
 */
export const DELIVERY_AFTER_ACCEPT_MS = 5 * 24 * HOUR_MS;
export const DELIVERY_AFTER_SENT_MS = 143 * HOUR_MS;

/** How long a resolver may cache each outcome (spec section 3): never `temporary` past a minute. */
export const TEMPORARY_CACHE_MS = 60_000;
export const SERVER_CACHE_MAX_MS = HOUR_MS;
export const NOT_FOUND_CACHE_MS = 10 * 60_000;

/** Documents may be cached this long; a server document is refetched for a failed signature at most once a minute. */
export const DOCUMENT_CACHE_MS = 10 * 60_000;
export const SERVER_DOCUMENT_REFETCH_MS = 60_000;

/** A key counts from 300 seconds before its `added`, since a signer's clock may run behind. */
export const KEY_ADDED_SKEW_MS = 300_000;

/** A signed request's timestamp is within this of the server's clock. */
export const REQUEST_SKEW_SECONDS = 300;
/** A signer does not reuse a nonce with the same key within this; the window's full width, both sides of now. */
export const NONCE_TTL_SECONDS = 600;
