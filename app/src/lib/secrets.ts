/**
 * Secrets this application hands out (codes, tokens), how it keeps them (hashed, or sealed when it must
 * read them again), webhook signatures and PKCE. The protocol's own cryptography is @agnt-protocol/protocol's.
 */
import crypto from 'node:crypto';
import { b64url, sha256Hex } from '@agnt-protocol/protocol';

export const randomToken = (bytes = 32) => b64url(crypto.randomBytes(bytes));

/** An eight-digit code, as the core's: a hundred million, so a few guesses an hour come to almost nothing in a year. */
export const randomCode = () => String(crypto.randomInt(0, 100_000_000)).padStart(8, '0');

/** The hash a secret is stored and looked up by. */
export const hashSecret = (secret: string) => sha256Hex(`agnt-app:${secret.trim()}`);

export function sameSecret(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length > 0 && x.length === y.length && crypto.timingSafeEqual(x, y);
}

/** A key's fingerprint a person can compare by eye: 8 groups of 4 hex characters of its SHA-256. */
export const fingerprint = (key: string) => sha256Hex(key).slice(0, 32).toUpperCase().match(/.{4}/g)!.join(' ');

export const webhookSignature = (secret: string, timestamp: string, body: string) =>
  crypto.createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');

export const pkceS256 = (verifier: string) => b64url(crypto.createHash('sha256').update(verifier).digest());

/** AES-256-GCM: the 12-byte IV, the 16-byte tag and the ciphertext, in base64url. */
export function seal(key: Buffer, plaintext: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const sealed = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return b64url(Buffer.concat([iv, cipher.getAuthTag(), sealed]));
}

export function unseal(key: Buffer, sealed: string): string {
  const bytes = Buffer.from(sealed, 'base64url');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
  decipher.setAuthTag(bytes.subarray(12, 28));
  return Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString('utf8');
}
