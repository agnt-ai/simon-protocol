/**
 * Just enough Ed25519 arithmetic (RFC 8032), in BigInt, to build the vectors no honest signer makes:
 * points off the curve, keys of mixed order, and signatures that satisfy the bare equation but not the
 * protocol's rules. Test code only; the protocol itself needs none of it beyond deciding what is a key.
 */
import crypto from 'node:crypto';

export const P = 2n ** 255n - 19n;
/** The order of the prime subgroup. */
export const L = 2n ** 252n + 27742317777372353535851937790883648493n;

const mod = (n: bigint, m = P) => ((n % m) + m) % m;

function pow(base: bigint, exp: bigint): bigint {
  let result = 1n;
  for (let b = mod(base), e = exp; e > 0n; e >>= 1n, b = (b * b) % P) if (e & 1n) result = (result * b) % P;
  return result;
}

const inv = (n: bigint) => pow(n, P - 2n);
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);

export const toLE = (n: bigint) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex').reverse();
export const fromLE = (b: Uint8Array) => BigInt(`0x${Buffer.from(b).reverse().toString('hex')}`);

export interface Point {
  x: bigint;
  y: bigint;
}

/** RFC 8032 section 5.1.3, step by step: the point 32 bytes encode, or null. */
export function decode(bytes: Uint8Array): Point | null {
  const y = fromLE(bytes) & (2n ** 255n - 1n);
  const sign = BigInt(bytes[31] >> 7);
  if (y >= P) return null;
  const u = mod(y * y - 1n);
  const v = mod(D * y * y + 1n);
  let x = mod(u * pow(v, 3n) * pow(u * pow(v, 7n), (P - 5n) / 8n));
  if (mod(v * x * x) !== u) {
    if (mod(v * x * x) !== mod(-u)) return null;
    x = mod(x * SQRT_M1);
  }
  if (x === 0n && sign === 1n) return null;
  return { x: x % 2n === sign ? x : P - x, y };
}

export function encode(p: Point): Buffer {
  const out = toLE(p.y);
  out[31] |= Number(p.x & 1n) << 7;
  return out;
}

export function add(a: Point, b: Point): Point {
  const t = mod(D * a.x * b.x * a.y * b.y);
  return {
    x: mod((a.x * b.y + b.x * a.y) * inv(1n + t)),
    y: mod((a.y * b.y + a.x * b.x) * inv(1n - t)),
  };
}

/** The secret scalar of a seed: the clamped low half of its SHA-512. */
export function scalarOf(seed: Uint8Array): bigint {
  const h = crypto.createHash('sha512').update(seed).digest().subarray(0, 32);
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;
  return fromLE(h);
}

/** The challenge k = SHA-512(R || A || M) mod L. */
export const challenge = (r: Uint8Array, a: Uint8Array, m: Uint8Array) =>
  fromLE(
    crypto
      .createHash('sha512')
      .update(Buffer.concat([r, a, m]))
      .digest(),
  ) % L;

/** A signature from its parts. */
export const signature = (r: Uint8Array, s: bigint) => Buffer.concat([r, toLE(mod(s, L))]);
