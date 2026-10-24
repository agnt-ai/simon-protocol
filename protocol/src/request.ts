/**
 * Signed requests (spec section 8): agents sign their calls to their own server, and servers sign the few
 * calls they make to each other that are not deliveries.
 *
 *   simon-key:        <key token of the signing key>
 *   simon-timestamp:  <unix seconds: 1 to 12 ASCII digits>
 *   simon-nonce:      <8 to 128 characters from U+0021 to U+007E>
 *   simon-signature:  <base64url signature over the signing string>
 *   simon-agent:      <the acting agent's address; on agent requests>
 *   simon-server:     <the requesting server's origin, serialised; on server requests>
 *
 * A request carries one of `simon-agent` and `simon-server`, naming who it acts as. The signing string is
 * eight lines joined by single newlines, with no trailing newline:
 *
 *   SIMON-REQUEST
 *   <METHOD, in upper case>
 *   <the origin of the server being asked, serialised as section 3 says>
 *   <the acting identity: the value of simon-agent or of simon-server>
 *   <the request target exactly as sent: the path and query of the request line, before any decoding>
 *   <simon-timestamp>
 *   <simon-nonce>
 *   <hex SHA-256 of the exact body bytes (of nothing, for no body)>
 *
 * The origin line, and a `simon-server` value, are the serialised origin (lower-case scheme and host, no
 * default port, no trailing `/`), so signer and verifier write the same line. A verifier checks the target it
 * received, before any decoding. An address in a path is written as `addressSegment` writes it.
 *
 * The origin line binds a request to one server: a request signed for one cannot be replayed to another. The
 * identity line binds it to who it acts as, so changing the header that names the actor breaks the signature.
 * Every refusal is a 401, whose `WWW-Authenticate: SIMON` the error's `headers` carry.
 */
import crypto, { type KeyObject } from 'node:crypto';
import { unauthorized } from './errors.ts';
import {
  isB64url,
  keyToken,
  parseKeyToken,
  privateKeyObject,
  sha256Hex,
  sign,
  validAt,
  verify,
  type KeyEntry,
} from './keys.ts';
import { isAddress } from './address.ts';
import { REQUEST_SKEW_SECONDS } from './limits.ts';
import { serverOrigin } from './resolve.ts';

export interface RequestParts {
  method: string;
  /** The origin of the server being asked. */
  origin: string;
  /** Who the request acts as: the `simon-agent` or `simon-server` value exactly as sent, or empty for neither. */
  actor: string;
  /** The path and query of the request line, exactly as sent. */
  target: string;
  timestamp: string;
  nonce: string;
  body: Uint8Array | string;
}

const upper = (s: string) => s.replace(/[a-z]/g, c => c.toUpperCase());

export function requestSigningString(r: RequestParts): string {
  const origin = serverOrigin(r.origin, true);
  if (!origin) throw new Error('A request signing origin must be a server origin.');
  return ['SIMON-REQUEST', upper(r.method), origin, r.actor, r.target, r.timestamp, r.nonce, sha256Hex(r.body)].join(
    '\n',
  );
}

/** The add-key proof's bytes: what a new key signs, so no agent can list a key it does not hold (CLIENT.md). */
export const addKeyProofString = (address: string, key: string) => `SIMON-ADD-KEY\n${address}\n${key}`;

/** A type, not an interface, so it passes as a plain record of header values (to fetch, for one). */
export type SignedHeaders = {
  'simon-key': string;
  'simon-timestamp': string;
  'simon-nonce': string;
  'simon-signature': string;
  'simon-agent'?: string;
  'simon-server'?: string;
};

/**
 * The origin and the request target of an absolute URL, the target as Node's HTTP clients send it: the
 * path and query as the URL standard writes them (percent-encoded where it requires, `@` left literal).
 */
export function splitUrl(url: string): { origin: string; target: string } {
  const u = new URL(url);
  return { origin: u.origin, target: u.pathname + u.search };
}

/**
 * Sign a request to an absolute URL, as `agent` (the acting agent's address) or as `server` (the requesting
 * server's origin). With neither, the identity line is empty: only a call authorised by what it carries,
 * such as a register that leases an address, goes without an actor (CLIENT.md).
 */
export function signRequest(
  key: string | KeyObject,
  r: {
    method: string;
    url: string;
    body?: Uint8Array | string;
    now?: number;
    nonce?: string;
    agent?: string;
    server?: string;
  },
): SignedHeaders {
  if (r.agent !== undefined && r.server !== undefined) throw new Error('A request acts as an agent or a server.');
  const privateKey = privateKeyObject(key);
  const timestamp = String(Math.floor((r.now ?? Date.now()) / 1000));
  const nonce = r.nonce ?? crypto.randomBytes(16).toString('base64url');
  // simon-server carries the serialised origin, as the origin line does (spec section 8).
  const server = r.server === undefined ? undefined : (serverOrigin(r.server, true) ?? r.server);
  const actor = r.agent ?? server ?? '';
  const signing = requestSigningString({
    method: r.method,
    ...splitUrl(r.url),
    actor,
    timestamp,
    nonce,
    body: r.body ?? '',
  });
  return {
    'simon-key': keyToken(privateKey),
    'simon-timestamp': timestamp,
    'simon-nonce': nonce,
    'simon-signature': sign(privateKey, signing),
    ...(r.agent === undefined ? {} : { 'simon-agent': r.agent }),
    ...(server === undefined ? {} : { 'simon-server': server }),
  };
}

/** Request headers as Node gives them: lower-case names, a repeated header as an array. */
export type HeaderValues = Record<string, string | string[] | undefined>;

/** The grammar of each signature header; the actor headers are read by `readSignedHeaders` itself. */
const HEADER_GRAMMAR: Record<
  Exclude<keyof SignedHeaders, 'simon-server' | 'simon-agent'>,
  (value: string) => boolean
> = {
  'simon-key': v => parseKeyToken(v) !== null,
  'simon-timestamp': v => /^[0-9]{1,12}$/.test(v),
  'simon-nonce': v => /^[\x21-\x7e]{8,128}$/.test(v),
  'simon-signature': isB64url,
};

export interface ReadHeadersOptions {
  /** A server request: `simon-server` is required too. */
  server?: boolean;
  /**
   * An agent request: `simon-agent` is required too, unless `optionalAgent` (a call authorised by what it
   * carries, which may come before the agent has an address).
   */
  agent?: boolean;
  optionalAgent?: boolean;
  /**
   * Local development only: accept a `simon-server` origin that is `http:` or names a local host, as
   * spec section 3 allows "for local development, never on a network". A server on a network leaves it off.
   */
  allowHttp?: boolean;
}

/**
 * The signature headers of a request, or `401 signature_required` naming the first one missing or malformed.
 * A server request (`options.server`) also needs `simon-server`, a serialised origin (lower-case scheme and
 * host, no default port, no trailing `/`), as the identity line signs it;
 * an agent request (`options.agent`) needs `simon-agent`, an address. A request carries at most one of them.
 */
export function readSignedHeaders(headers: HeaderValues, now: Date, options: ReadHeadersOptions = {}): SignedHeaders {
  const refuse = (name: string) =>
    unauthorized('signature_required', `This request needs a well-formed ${name} header.`, now, { header: name });
  const found: Record<string, string> = {};
  for (const name of Object.keys(HEADER_GRAMMAR) as (keyof typeof HEADER_GRAMMAR)[]) {
    const value = headers[name];
    if (typeof value !== 'string' || !HEADER_GRAMMAR[name](value)) throw refuse(name);
    found[name] = value;
  }
  if (headers['simon-agent'] !== undefined && headers['simon-server'] !== undefined) throw refuse('simon-agent');
  if (options.server) {
    const origin = serverOrigin(headers['simon-server'], options.allowHttp ?? false);
    if (!origin || origin !== headers['simon-server']) throw refuse('simon-server');
    found['simon-server'] = origin;
  }
  if (options.agent) {
    if (headers['simon-server'] !== undefined) throw refuse('simon-agent');
    const agent = headers['simon-agent'];
    if (agent === undefined && options.optionalAgent) return found as unknown as SignedHeaders;
    if (typeof agent !== 'string' || !isAddress(agent)) throw refuse('simon-agent');
    found['simon-agent'] = agent;
  }
  return found as unknown as SignedHeaders;
}

/** The identity line of a request: its `simon-agent` or `simon-server` value exactly as sent, or empty. */
export function actorOf(headers: HeaderValues): string {
  const value = headers['simon-agent'] ?? headers['simon-server'];
  return typeof value === 'string' ? value : '';
}

/**
 * Check a request whose headers `readSignedHeaders` read, in the order of spec section 8:
 *
 *   1. the timestamp within 300 seconds of `now`, in whole seconds (`stale_request`);
 *   2. the key known (`unknown_key`): `entry` is the agent's entry for `simon-key`, or for a server request
 *      the entry in the `simon-server` origin's server document, or null;
 *   3. the key valid now (`key_revoked`);
 *   4. the signature (`bad_signature`, carrying the signing string the server expected);
 *   5. the nonce not used by this key while its timestamp is in the window (`replayed_request`).
 *
 * `nonceSeen` only reads, and is asked only once the signature verifies. The caller records the nonce
 * after this returns (`NonceCache.record`), so a request nobody could sign never uses one up.
 */
export async function checkSignedRequest(
  r: Omit<RequestParts, 'timestamp' | 'nonce'>,
  headers: SignedHeaders,
  ctx: {
    now: Date;
    entry: KeyEntry | null;
    nonceSeen: (key: string, nonce: string) => boolean | Promise<boolean>;
  },
): Promise<void> {
  const { now, entry } = ctx;
  const skew = Math.abs(Number(headers['simon-timestamp']) - Math.floor(now.getTime() / 1000));
  if (skew > REQUEST_SKEW_SECONDS) {
    throw unauthorized(
      'stale_request',
      `simon-timestamp is more than ${REQUEST_SKEW_SECONDS} s from this server's clock.`,
      now,
    );
  }
  if (!entry) throw unauthorized('unknown_key', 'This server does not know this key.', now);
  if (!validAt(entry, now)) throw unauthorized('key_revoked', 'This key is not valid now.', now);
  const signingString = requestSigningString({
    ...r,
    timestamp: headers['simon-timestamp'],
    nonce: headers['simon-nonce'],
  });
  if (!verify(entry.key, signingString, headers['simon-signature'])) {
    throw unauthorized('bad_signature', 'The signature does not verify over the signing string.', now, {
      signingString,
    });
  }
  if (await ctx.nonceSeen(headers['simon-key'], headers['simon-nonce'])) {
    throw unauthorized('replayed_request', 'This key already used this nonce inside the window.', now);
  }
}

/**
 * The first moment, in milliseconds, at which a request with this `simon-timestamp` is stale: the window is
 * checked in whole seconds, so it is open until 301 seconds after the timestamp. A server keeps a nonce until
 * then (spec section 8), and no choice of `>` or `>=` at the boundary reopens a replay.
 */
export const nonceExpiry = (timestamp: string | number) => (Number(timestamp) + REQUEST_SKEW_SECONDS + 1) * 1000;

/**
 * The nonces each key used while their requests' timestamps are inside the window, in memory: `seen` is the
 * read `checkSignedRequest` asks, and `record` is called once a request is accepted. A server spread over
 * several processes keeps the same two operations in a shared store instead.
 */
export class NonceCache {
  readonly #expires = new Map<string, number>();

  seen(key: string, nonce: string, now: Date): boolean {
    return (this.#expires.get(`${key}\n${nonce}`) ?? 0) > now.getTime();
  }

  /** Remember a nonce until its request's `simon-timestamp` leaves the window. */
  record(key: string, nonce: string, timestamp: string, now: Date): void {
    // Expiries follow timestamps, which arrive up to 600 s out of order, so this sweep is lazy, never wrong.
    for (const [id, expires] of this.#expires) {
      if (expires > now.getTime()) break;
      this.#expires.delete(id);
    }
    const id = `${key}\n${nonce}`;
    this.#expires.delete(id);
    this.#expires.set(id, nonceExpiry(timestamp));
  }
}
