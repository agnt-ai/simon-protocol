/**
 * The two documents a server publishes, fetched without authentication and cacheable (spec section 4):
 *
 *   GET /simon/server              { server, keys, algorithms, limits }
 *   GET /simon/agents/<address>    { address, keys, signature }         signed by the server, over SIMON-AGENT
 *                                 a retired address's adds `retired`, and `unpairing` when one retired it
 *
 * A reader takes a document's bytes: at most 131072 of them, JSON under the canonical rules (it need not be
 * canonical), with at most 32 total key entries, including retained revoked keys. Members a reader does not know are ignored; an agent document's
 * signature covers them all the same.
 */
import type { KeyObject } from 'node:crypto';
import { isJsonObject, parseStrict, signingBytes, type Json } from './canonical.ts';
import { isAddress } from './address.ts';
import {
  ALGORITHM_NAMES,
  isB64url,
  isImplemented,
  isPublicKey,
  parseKeyToken,
  sign,
  signedByAny,
  type KeyEntry,
} from './keys.ts';
import { MAX_DOCUMENT_BYTES, MAX_DOCUMENT_KEYS, MINIMUM_LIMITS, REVOCATION_AHEAD_MS, type Limits } from './limits.ts';
import { serverOrigin } from './resolve.ts';
import { parseTimestamp } from './time.ts';

export interface ServerDocument {
  server: string;
  keys: KeyEntry[];
  /** Every signature algorithm the server verifies, so an author can tell whether a recipient can verify its key. */
  algorithms: string[];
  limits: Limits;
  /** Present, and true, when the server answers lookups (discovery profile, section 2). */
  discovery?: true;
}

/** The algorithms version 1 defines (spec section 2.3). */
export const V1_ALGORITHMS: readonly string[] = Object.freeze(['ed25519', 'ml-dsa-65']);

/** The algorithms every server verifies, and so every server document lists; `ml-dsa-65` is optional and advertised. */
export const REQUIRED_ALGORITHMS: readonly string[] = Object.freeze(['ed25519']);

/**
 * What an agent is (spec section 2.2), fixed for the life of its address, as its own server records it:
 * `paired` speaks for one principal, whom its messages name in their `for` header; `solo` speaks for no one.
 * The agent document never says which: only the agent's messages do, with the evidence that backs them.
 */
export type AgentKind = 'paired' | 'solo';

export interface UnsignedAgentDocument {
  address: string;
  keys: KeyEntry[];
  /** Members this version does not define: ignored by readers, and signed. */
  [member: string]: unknown;
}

export interface AgentDocument extends UnsignedAgentDocument {
  signature: string;
}

export const serverDocument = (server: string, keys: KeyEntry[], limits: Limits = MINIMUM_LIMITS): ServerDocument => ({
  server,
  keys,
  algorithms: [...ALGORITHM_NAMES],
  limits: { ...limits },
});

export function signAgentDocument(doc: UnsignedAgentDocument, serverKey: string | KeyObject): AgentDocument {
  return { ...doc, signature: sign(serverKey, signingBytes('SIMON-AGENT', doc)) };
}

/**
 * At most 32 total published key entries, active and retained revoked entries together. Every entry is
 * parsed; entries of unknown algorithms are retained but never tried. Revocations may be ahead of the
 * reading clock by at most the ordinary 300-second tolerance, never deliberately scheduled.
 */
export function readKeys(value: Json | undefined, now: Date): KeyEntry[] | null {
  if (!Array.isArray(value) || value.length > MAX_DOCUMENT_KEYS) return null;
  const keys: KeyEntry[] = [];
  for (const k of value) {
    if (!isJsonObject(k) || !parseKeyToken(k.key) || parseTimestamp(k.added) === null) return null;
    const revoked = k.revoked === null ? null : parseTimestamp(k.revoked);
    if (k.revoked !== null && revoked === null) return null;
    if (revoked !== null && revoked > now.getTime() + REVOCATION_AHEAD_MS) return null;
    if (isImplemented(k.key) && !isPublicKey(k.key)) return null;
    keys.push({ key: k.key as string, added: k.added as string, revoked: k.revoked as string | null });
  }
  return keys;
}

/** A document's bytes as a JSON object, or null when they are too many or not JSON under the canonical rules. */
function readObject(body: Uint8Array): { [key: string]: Json } | null {
  if (body.length > MAX_DOCUMENT_BYTES) return null;
  try {
    const value = parseStrict(body);
    return isJsonObject(value) ? value : null;
  } catch {
    return null;
  }
}

/**
 * A fetched server document read at `now`, or null unless it is readable, its `server` is the origin it was
 * fetched from, and it has its `algorithms` and four `limits`. `discovery` is kept when it is `true`: the
 * server answers lookups (discovery profile, section 2).
 */
export function readServerDocument(body: Uint8Array, origin: string, now: Date): ServerDocument | null {
  const doc = readObject(body);
  if (!doc || serverOrigin(doc.server, true) !== origin || !isJsonObject(doc.limits)) return null;
  const keys = readKeys(doc.keys, now);
  const algorithms = readAlgorithms(doc.algorithms);
  const limits = readLimits(doc.limits);
  if (!keys || !algorithms || !limits) return null;
  // Members a reader does not know are ignored; `discovery` is read only when it is exactly true.
  return { server: origin, keys, algorithms, limits, ...(doc.discovery === true ? { discovery: true as const } : {}) };
}

/**
 * The algorithms a server document lists, or null: an array of algorithm names (lower-case letters, digits
 * and hyphens) that includes every required algorithm. Names this reader does not know are kept.
 */
function readAlgorithms(value: Json | undefined): string[] | null {
  if (!Array.isArray(value) || !value.every(a => typeof a === 'string' && /^[a-z0-9-]+$/.test(a))) return null;
  const names = value as string[];
  return REQUIRED_ALGORITHMS.every(a => names.includes(a)) ? names : null;
}

/** The four published limits, each a safe integer at least its minimum, or null. Other members are ignored. */
function readLimits(value: { [key: string]: Json }): Limits | null {
  const limits = { ...MINIMUM_LIMITS };
  for (const name of Object.keys(MINIMUM_LIMITS) as (keyof Limits)[]) {
    const n = value[name];
    if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < MINIMUM_LIMITS[name]) return null;
    limits[name] = n;
  }
  return limits;
}

/** An agent document as a reader reads it; `retired` and `unpairing` only on a retired document. */
export interface ReadAgentDocument {
  address: string;
  keys: KeyEntry[];
  /** When the address retired (spec section 4): it is ended for good, and no key is valid at or after this. */
  retired?: string;
  /** The key principal's unpairing that retired it, when one did: verify it with `verifyUnpairing`. */
  unpairing?: string;
}

/**
 * A fetched agent document, or null unless it is readable, its `address` is the address asked for, and its
 * signature verifies with one of the server's keys valid at `now`, the time of reading. It says nothing about
 * whom the agent speaks for: only its messages do, with the evidence that backs them (spec section 2.2).
 *
 * A **retired document** (spec section 4) also carries `retired`, a timestamp, and when an unpairing retired
 * the address, `unpairing`, a base64url string; every key in it is revoked, at or before `retired`. One that
 * breaks any of these is unreadable. It is read as an agent document is, so messages the agent signed before
 * it retired keep verifying against its keys.
 */
export function readAgentDocument(
  body: Uint8Array,
  address: string,
  serverKeys: readonly KeyEntry[],
  now: Date,
): ReadAgentDocument | null {
  const doc = readObject(body);
  if (!doc || !isAddress(address) || doc.address !== address) return null;
  const keys = readKeys(doc.keys, now);
  if (!keys || !signedByAny(serverKeys, now, signingBytes('SIMON-AGENT', doc), doc.signature)) return null;
  if (doc.retired === undefined) return { address, keys };
  const retired = parseTimestamp(doc.retired);
  if (retired === null || (doc.unpairing !== undefined && !isB64url(doc.unpairing))) return null;
  if (!keys.every(k => k.revoked !== null && parseTimestamp(k.revoked)! <= retired)) return null;
  return {
    address,
    keys,
    retired: doc.retired as string,
    ...(doc.unpairing !== undefined && { unpairing: doc.unpairing as string }),
  };
}
