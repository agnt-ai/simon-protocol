/**
 * Signals: small, short-lived notes from one server to another about a message (spec section 6.4),
 * `POST /simon/signal`:
 *
 *   { type, from, to, about, at, server, signature }
 *
 * A signal's `type` is a registry name, such as `typing`, `collected` or `read`; a server never reads it, and
 * passes on a type it does not know. A signal is signed by the server of `from`'s domain, over `SIMON-SIGNAL`
 * and the canonical signal without `signature`, as an envelope is. It is never stored, so unlike a delivery
 * it has no repeat window: a replay inside its 300 seconds says again what was true. Any server may drop any
 * signal it receives. Members a receiver does not know are ignored, and signed.
 */
import type { KeyObject } from 'node:crypto';
import { isAddress } from './address.ts';
import { canonicalize, isJsonObject, signingBytes } from './canonical.ts';
import { bodyTooLarge, invalid } from './errors.ts';
import { isB64url, sign, signedByAny, type KeyEntry } from './keys.ts';
import { MAX_SIGNAL_BODY_BYTES, MAX_SIGNAL_BYTES, MINIMUM_LIMITS, SIGNAL_SKEW_MS, type Limits } from './limits.ts';
import { isHeaderName, parseJson } from './message.ts';
import { serverOrigin } from './resolve.ts';
import { parseTimestamp } from './time.ts';

/** The registry's first three signal types, each sent only by the one it is about. Servers never read a type. */
export const SIGNAL_TYPES = ['typing', 'collected', 'read'] as const;

export interface UnsignedSignal {
  type: string;
  /** The address the signal is about, on the signing server's domain. */
  from: string;
  /** Its recipients, all on the receiving server. */
  to: string[];
  /** The id of the message it is about. */
  about: string;
  /** When it was sent. */
  at: string;
  /** The origin of the receiving server, so a signal cannot be replayed to another. */
  server: string;
  [member: string]: unknown;
}

export interface Signal extends UnsignedSignal {
  signature: string;
}

const HEX64 = /^[0-9a-f]{64}$/;

export const signSignal = (s: UnsignedSignal, serverKey: string | KeyObject): Signal => ({
  ...s,
  signature: sign(serverKey, signingBytes('SIMON-SIGNAL', s)),
});

/** Whether one of the sending server's keys valid at `at` (when the signal arrives) signed it. */
export const verifySignal = (s: Signal, serverKeys: readonly KeyEntry[], at: Date) =>
  signedByAny(serverKeys, at, signingBytes('SIMON-SIGNAL', s), s.signature);

/**
 * Steps 1 to 3 of spec section 6.4: the body at most 16384 bytes (413), parsed, and the signal without its
 * signature at most 4096 canonical bytes; the signal's shape; and, given the receiver's origin, that `server`
 * names it. Steps 4 on need the network.
 */
export function parseSignal(
  body: Uint8Array,
  receiver?: { origin: string; allowHttp?: boolean },
  limits: Limits = MINIMUM_LIMITS,
): Signal {
  if (body.length > MAX_SIGNAL_BODY_BYTES) throw bodyTooLarge(MAX_SIGNAL_BODY_BYTES);
  const value = parseJson(body);
  if (!isJsonObject(value)) throw invalid('A signal is a JSON object.', { field: 'signal' });
  const { signature: _, ...unsigned } = value;
  if (Buffer.byteLength(canonicalize(unsigned)) > MAX_SIGNAL_BYTES) {
    throw invalid(`A signal without its signature is at most ${MAX_SIGNAL_BYTES} canonical bytes.`, {
      field: 'signal',
    });
  }
  const field = (name: string, ok: boolean, what: string) => {
    if (!ok) throw invalid(`${name} must be ${what}.`, { field: name });
  };
  field('type', isHeaderName(value.type), 'a signal type: lower-case letters and digits joined by hyphens');
  field('from', isAddress(value.from), 'an address in lower case');
  const { to } = value;
  field(
    'to',
    Array.isArray(to) &&
      to.length > 0 &&
      to.length <= limits.recipients &&
      to.every(isAddress) &&
      new Set(to).size === to.length,
    `a non-empty array of at most ${limits.recipients} distinct addresses`,
  );
  field('about', typeof value.about === 'string' && HEX64.test(value.about), 'a message id');
  field('at', parseTimestamp(value.at) !== null, 'a UTC timestamp');
  field('server', serverOrigin(value.server, receiver?.allowHttp) !== null, 'the origin of the receiving server');
  field('signature', isB64url(value.signature), 'canonical base64url');
  const signal = value as unknown as Signal;
  if (receiver && serverOrigin(signal.server, true) !== serverOrigin(receiver.origin, true)) {
    throw invalid(`This signal is for ${signal.server}, not this server.`, { field: 'server' });
  }
  return signal;
}

/** Step 7: `at` within 300 seconds of the receiver's clock, either way, or `400 invalid` on `at`. */
export function checkSignalFreshness(s: Pick<Signal, 'at'>, now: Date): void {
  const t = parseTimestamp(s.at);
  if (t === null || Math.abs(t - now.getTime()) > SIGNAL_SKEW_MS) {
    throw invalid('A signal is at most 300 seconds old or ahead.', { field: 'at' });
  }
}
