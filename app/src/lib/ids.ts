/**
 * Record ids: a type prefix and a time-ordered random tail, such as `per_01J9Z...`. The prefix names the
 * record in logs; the time order makes an id a paging cursor. Message ids are not among them: a message's
 * id is the SHA-256 of its signed bytes.
 */
import crypto from 'node:crypto';
import { sha256Hex } from '@agnt-sdk/simon-protocol';

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32

const PREFIX = {
  person: 'per',
  attestation: 'att',
  entity: 'ent',
  edge: 'edg',
  intro: 'int',
  webhook: 'whk',
  delivery: 'dlv',
  bridge: 'brg',
  invite: 'inv',
  oauthClient: 'ocl',
  login: 'olg',
  token: 'otk',
  session: 'ses',
  request: 'req',
  activity: 'act',
} as const;

export type IdKind = keyof typeof PREFIX;

/** The id shape of one kind, for request validation. */
export const idPattern = (kind: IdKind) => new RegExp(`^${PREFIX[kind]}_[0-9A-Z]{26}$`);

let lastMs = 0;
let lastTail = new Uint8Array(10);

/** Monotonic within a process: ids minted in the same millisecond still sort in the order they were made. */
export function newId(kind: IdKind, now = Date.now()): string {
  if (now === lastMs) {
    // Add one to the tail, carrying past bytes that wrap to 0.
    for (let i = lastTail.length - 1; i >= 0; i--) {
      lastTail[i] = (lastTail[i] + 1) & 255;
      if (lastTail[i] !== 0) break;
    }
  } else {
    lastMs = now;
    lastTail = crypto.getRandomValues(new Uint8Array(10));
  }
  let time = '';
  for (let ms = now, i = 0; i < 10; i++, ms = Math.floor(ms / 32)) time = ALPHABET[ms % 32] + time;
  return `${PREFIX[kind]}_${time}${base32(lastTail)}`;
}

function base32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return out;
}

/** A retired agent where a record outlives it: only a hash of its address, which links it to nothing. */
export const retiredRef = (address: string) => `retired:${sha256Hex(address)}`;
