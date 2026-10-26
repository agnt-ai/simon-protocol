/**
 * Keys and signatures (spec section 2.3). A key is written as one string, its key token: the algorithm name,
 * a colon, and the raw public key in base64url (`ed25519:11qY...`). Version 1 defines `ed25519` and
 * `ml-dsa-65`. A token naming any other algorithm is unknown to this reader, never an error.
 *
 * Signatures do not name their algorithm: a verifier tries each of the signer's keys valid at the moment
 * whose algorithm it implements, against signatures that algorithm calls well formed. base64url is strict:
 * unpadded, and only the one spelling that decodes back to itself.
 */
import crypto, { type KeyObject } from 'node:crypto';
import { KEY_ADDED_SKEW_MS } from './limits.ts';
import { parseTimestamp } from './time.ts';

export const b64url = (buf: Uint8Array | string) => Buffer.from(buf).toString('base64url');

/** Strict base64url (no padding, canonical trailing bits), or null. */
export function fromB64url(s: unknown): Buffer | null {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) return null;
  const buf = Buffer.from(s, 'base64url');
  return buf.toString('base64url') === s ? buf : null;
}

/** Whether a value is a non-empty canonical base64url string, as every signature is written. */
export const isB64url = (value: unknown): value is string => (fromB64url(value)?.length ?? 0) > 0;

export const sha256Hex = (data: Uint8Array | string) => crypto.createHash('sha256').update(data).digest('hex');

// Ed25519 arithmetic, only as much as deciding what is a key needs. Node's key import checks none of it.

const P = 2n ** 255n - 19n;
/** The order of the prime subgroup. */
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

const mod = (n: bigint) => ((n % P) + P) % P;

function pow(base: bigint, exp: bigint): bigint {
  let result = 1n;
  for (let b = mod(base), e = exp; e > 0n; e >>= 1n, b = (b * b) % P) if (e & 1n) result = (result * b) % P;
  return result;
}

const D = mod(-121665n * pow(121666n, P - 2n));

const littleEndian = (bytes: Uint8Array) => BigInt(`0x${Buffer.from(bytes).reverse().toString('hex')}`);

/**
 * Whether 32 bytes decode to a point, as RFC 8032 section 5.1.3 decodes: y below p, then an x with
 * x² = (y² − 1) / (d·y² + 1). That x exists exactly when the quotient is 0 or a square (Euler's criterion),
 * and x = 0 cannot carry the sign bit of an odd x.
 */
function isOnCurve(bytes: Uint8Array): boolean {
  const y = littleEndian(bytes) & (2n ** 255n - 1n);
  if (y >= P) return false;
  const x2 = mod((y * y - 1n) * pow(D * y * y + 1n, P - 2n));
  return x2 === 0n ? bytes[31] >> 7 === 0 : pow(x2, (P - 1n) / 2n) === 1n;
}

/**
 * Encodings of the curve's points of small order, compared without the sign bit. A public key that is one
 * of them verifies signatures it never made, so it is never a key; a signature whose R is one of them is
 * never a signature, which keeps every verifier's verdict the same.
 */
const SMALL_ORDER = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
];

function isSmallOrder(bytes: Uint8Array): boolean {
  const unsigned = Buffer.from(bytes);
  unsigned[31] &= 0x7f;
  return SMALL_ORDER.includes(unsigned.toString('hex'));
}

/** One signature algorithm, saying which keys and which signatures are well formed (spec section 2.3). */
interface Algorithm {
  keyBytes: number;
  /** Whether raw bytes of the right length are a key. */
  isKey(raw: Buffer): boolean;
  /** Whether bytes are a well-formed signature, before the crypto library checks the equation. */
  isSignature(signature: Buffer): boolean;
  /** The JWK Node imports a public key from, less the member holding the raw key. */
  jwk: crypto.JsonWebKey;
  jwkMember: 'x' | 'pub';
  /** The start of a PKCS #8 private key holding only a 32-byte seed. */
  seedPrefix: Buffer;
}

/** A Map, so an algorithm name such as `constructor` never finds a prototype member. */
const ALGORITHMS = new Map<string, Algorithm>([
  [
    'ed25519',
    {
      keyBytes: 32,
      isKey: raw => isOnCurve(raw) && !isSmallOrder(raw),
      // 64 bytes, S below the group order, R not of small order. The library then checks [S]B − [k]A against
      // the exact bytes of R, without the cofactor (RFC 8032 5.1.7).
      isSignature: sig => sig.length === 64 && littleEndian(sig.subarray(32)) < L && !isSmallOrder(sig.subarray(0, 32)),
      jwk: { kty: 'OKP', crv: 'Ed25519' },
      jwkMember: 'x',
      seedPrefix: Buffer.from('302e020100300506032b657004220420', 'hex'),
    },
  ],
  [
    'ml-dsa-65',
    {
      keyBytes: 1952,
      // FIPS 204's pkDecode reads any 1952 bytes as a key.
      isKey: () => true,
      isSignature: sig => sig.length === 3309,
      jwk: { kty: 'AKP', alg: 'ML-DSA-65' },
      jwkMember: 'pub',
      seedPrefix: Buffer.from('3034020100300b060960864801650304031204228020', 'hex'),
    },
  ],
]);

/** The algorithms this implementation signs and verifies with, as a server document's `algorithms` lists them. */
export const ALGORITHM_NAMES = [...ALGORITHMS.keys()];

/** A key token's algorithm name and raw key, when it is written as one (`alg:base64url`), whatever the algorithm. */
export function parseKeyToken(token: unknown): { alg: string; raw: Buffer } | null {
  const m = typeof token === 'string' ? /^([a-z0-9-]+):(.*)$/s.exec(token) : null;
  const raw = m ? fromB64url(m[2]) : null;
  return m && raw?.length ? { alg: m[1], raw } : null;
}

/** Whether a token names an algorithm this implementation implements. */
export const isImplemented = (token: unknown) => ALGORITHMS.has(parseKeyToken(token)?.alg ?? '');

/** A key token as a public KeyObject, or null when it is not a key of an algorithm implemented here. */
function publicKeyObject(token: unknown): KeyObject | null {
  const t = parseKeyToken(token);
  const alg = t && ALGORITHMS.get(t.alg);
  if (!t || !alg || t.raw.length !== alg.keyBytes || !alg.isKey(t.raw)) return null;
  return crypto.createPublicKey({ key: { ...alg.jwk, [alg.jwkMember]: b64url(t.raw) }, format: 'jwk' });
}

/** Whether a token is a key of an algorithm implemented here: the right length, and for Ed25519 a usable point. */
export const isPublicKey = (token: unknown): token is string => publicKeyObject(token) !== null;

/** The key token of a private or public key. */
export function keyToken(key: KeyObject): string {
  const pub = key.type === 'private' ? crypto.createPublicKey(key) : key;
  const name = pub.asymmetricKeyType ?? '';
  const alg = ALGORITHMS.get(name);
  if (!alg) throw new Error(`No key token for a ${name} key.`);
  return `${name}:${pub.export({ format: 'jwk' })[alg.jwkMember]}`;
}

/** A private key from PKCS #8 PEM, or the KeyObject itself. */
export const privateKeyObject = (key: string | KeyObject): KeyObject =>
  typeof key === 'string' ? crypto.createPrivateKey(key) : key;

/** A private key from a 32-byte seed: deterministic keys, for test vectors. */
export function privateKeyFromSeed(algName: string, seed: Uint8Array): KeyObject {
  const alg = ALGORITHMS.get(algName);
  if (!alg || seed.length !== 32) throw new Error(`No ${algName} key from a ${seed.length}-byte seed.`);
  return crypto.createPrivateKey({ key: Buffer.concat([alg.seedPrefix, seed]), format: 'der', type: 'pkcs8' });
}

export function generateKey(alg: 'ed25519' | 'ml-dsa-65' = 'ed25519') {
  const { privateKey } =
    alg === 'ed25519' ? crypto.generateKeyPairSync('ed25519') : crypto.generateKeyPairSync('ml-dsa-65');
  return {
    privateKey,
    key: keyToken(privateKey),
    privateKeyPem: String(privateKey.export({ type: 'pkcs8', format: 'pem' })),
  };
}

/** A signature in base64url. Ed25519 signatures are deterministic; ML-DSA ones, as Node makes them, are not. */
export const sign = (key: string | KeyObject, data: Uint8Array | string) =>
  b64url(crypto.sign(null, Buffer.from(data), privateKeyObject(key)));

/** Whether a signature verifies with a key token. False for any algorithm not implemented here. */
export function verify(token: string, data: Uint8Array | string, signature: unknown): boolean {
  const alg = ALGORITHMS.get(parseKeyToken(token)?.alg ?? '');
  const sig = fromB64url(signature);
  if (!alg || !sig || !alg.isSignature(sig)) return false;
  const key = publicKeyObject(token);
  return key !== null && crypto.verify(null, Buffer.from(data), key, sig);
}

/** A key as documents list it (spec section 2.4). Revoking marks a key; it need not delete it. */
export interface KeyEntry {
  key: string;
  added: string;
  revoked: string | null;
}

/**
 * Whether a key is valid at a moment: added at most 300 seconds after it (a signer's clock may run behind),
 * and not revoked, or revoked after it.
 */
export function validAt(k: KeyEntry, at: Date): boolean {
  const added = parseTimestamp(k.added);
  if (added === null || added - KEY_ADDED_SKEW_MS > at.getTime()) return false;
  if (k.revoked === null) return true;
  const revoked = parseTimestamp(k.revoked);
  return revoked !== null && at.getTime() < revoked;
}

/** Whether a key was valid at some moment from `from` to `to`: the window in which a carrier signed a message's claims. */
export function validDuring(k: KeyEntry, from: Date, to: Date): boolean {
  const added = parseTimestamp(k.added);
  if (added === null || added - KEY_ADDED_SKEW_MS > to.getTime()) return false;
  if (k.revoked === null) return true;
  const revoked = parseTimestamp(k.revoked);
  return revoked !== null && from.getTime() < revoked;
}

/**
 * What a signer's keys say of a signature (spec sections 2.3 and 6.3): `verified` when one valid at `at`
 * signed these bytes; `unsupported_algorithm` when keys valid at `at` exist but none is of an algorithm
 * implemented here, so nothing could be tried; otherwise `bad_signature`, which includes having no key
 * valid at `at` at all.
 */
export type SignatureVerdict = 'verified' | 'unsupported_algorithm' | 'bad_signature';

export function signatureVerdict(
  keys: readonly KeyEntry[],
  at: Date,
  data: Uint8Array | string,
  signature: unknown,
): SignatureVerdict {
  const valid = keys.filter(k => validAt(k, at));
  const usable = valid.filter(k => isImplemented(k.key));
  if (usable.length === 0) return valid.length ? 'unsupported_algorithm' : 'bad_signature';
  return usable.some(k => verify(k.key, data, signature)) ? 'verified' : 'bad_signature';
}

/** Whether one of the keys valid at `at` signed these bytes. */
export const signedByAny = (keys: readonly KeyEntry[], at: Date, data: Uint8Array | string, signature: unknown) =>
  signatureVerdict(keys, at, data, signature) === 'verified';
