/**
 * Principals (spec section 2.2): whom a paired agent speaks for, named by one identifier. An identifier is a
 * labelled string written exactly as one of these. The labels look like URI schemes, but identifiers are not
 * URIs: nothing is percent-encoded, and no URI parser applies.
 *
 *   mailto:<an address as version 2 writes one>
 *   tel:+<a digit from 1 to 9><1 to 14 more digits>
 *   simon-key:<key token>
 *
 * A key principal approves a pairing by signing `SIMON-PAIR\n<agent address>\n<identifier>\n<until>`, where
 * `until` is when the pairing lapses. Every message the agent sends carries `<until> <signature>` as its
 * `pairing` header, so any recipient can check the pairing without trusting a server. A pairing counts at a
 * moment before its `until` and at most 366 days before it; the principal renews it by signing a later one. It ends the pairing by signing `SIMON-UNPAIR\n<agent address>\n<identifier>`,
 * the unpairing, which retires the address whatever the agent's keys say. It recovers the agent at once by
 * signing `SIMON-RECOVER\n<agent address>\n<new key token>\n<timestamp>` (CLIENT.md dedicated recovery).
 */
import type { KeyObject } from 'node:crypto';
import { isV1Address } from './address.ts';
import { isB64url, parseKeyToken, sign, verify } from './keys.ts';
import { parseTimestamp, timestamp } from './time.ts';

const TEL = /^tel:\+[1-9][0-9]{1,14}$/;
const KEY_PREFIX = 'simon-key:';

/** Whether a value is a principal's identifier, and so a well-formed `for` header. Labels are matched exactly. */
export function isPrincipal(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  if (value.startsWith('mailto:')) return isV1Address(value.slice('mailto:'.length));
  if (value.startsWith(KEY_PREFIX)) return parseKeyToken(value.slice(KEY_PREFIX.length)) !== null;
  return TEL.test(value);
}

/** The key token a key principal names, or null for any other identifier. */
export const principalKey = (principal: string): string | null =>
  principal.startsWith(KEY_PREFIX) && isPrincipal(principal) ? principal.slice(KEY_PREFIX.length) : null;

/** The longest a pairing may last from any moment it counts at: 366 days, so no pairing is for good. */
export const PAIRING_MAX_MS = 366 * 24 * 60 * 60 * 1000;

/** How long `signPairing` makes a pairing last when given no `until`: 365 days. */
export const PAIRING_DEFAULT_MS = 365 * 24 * 60 * 60 * 1000;

/** The bytes a key principal signs to pair with an agent until `until`, a wire timestamp. */
export const pairingBytes = (agent: string, principal: string, until: string) =>
  `SIMON-PAIR\n${agent}\n${principal}\n${until}`;

/**
 * The `pairing` header: `<until> <signature>`, the principal's signature, with its own private key, pairing it
 * with `agent` until `until` (a year from now by default).
 */
export function signPairing(
  principalPrivateKey: string | KeyObject,
  agent: string,
  principal: string,
  until: string = timestamp(Date.now() + PAIRING_DEFAULT_MS),
): string {
  return `${until} ${sign(principalPrivateKey, pairingBytes(agent, principal, until))}`;
}

/** A `pairing` value's parts: a wire timestamp, one space and canonical base64url; otherwise null. */
export function parsePairing(pairing: unknown): { until: string; signature: string } | null {
  if (typeof pairing !== 'string') return null;
  const [until, signature, ...rest] = pairing.split(' ');
  if (rest.length > 0 || signature === undefined) return null;
  return parseTimestamp(until) !== null && isB64url(signature) ? { until, signature } : null;
}

/**
 * Whether `pairing` pairs `agent` with the key `principal` names, at `at` (now by default): its signature
 * verifies, and `at` is before its `until` by at most PAIRING_MAX_MS. A reader acting on a message asks for
 * now; one showing an old message may ask for its `sentAt`.
 */
export function verifyPairing(agent: string, principal: string, pairing: unknown, at: Date | number = Date.now()) {
  const key = principalKey(principal);
  const parsed = parsePairing(pairing);
  if (key === null || parsed === null) return false;
  const until = parseTimestamp(parsed.until)!;
  const t = new Date(at).getTime();
  if (!(t < until && until - t <= PAIRING_MAX_MS)) return false;
  return verify(key, pairingBytes(agent, principal, parsed.until), parsed.signature);
}

/** The bytes a key principal signs to end its pairing with an agent. */
export const unpairingBytes = (agent: string, principal: string) => `SIMON-UNPAIR\n${agent}\n${principal}`;

export const signUnpairing = (principalPrivateKey: string | KeyObject, agent: string, principal: string) =>
  sign(principalPrivateKey, unpairingBytes(agent, principal));

/** Whether `unpairing` is the signature of the key `principal` names, ending its pairing with `agent`. */
export function verifyUnpairing(agent: string, principal: string, unpairing: unknown): boolean {
  const key = principalKey(principal);
  return key !== null && verify(key, unpairingBytes(agent, principal), unpairing);
}

/**
 * The bytes a key principal signs to recover its agent at once (CLIENT.md dedicated recovery, the protocol's Appendix A
 * `recover-signed`): the new key replaces every old one. `at` is when it was signed, a timestamp; a server
 * takes it only while it is at most 24 hours old and at most 5 minutes ahead, so a signed recovery never used
 * is never a standing key to the agent.
 */
export const recoverBytes = (agent: string, newKey: string, at: string) => `SIMON-RECOVER\n${agent}\n${newKey}\n${at}`;

/** Compatibility name for the same recovery signing bytes. */
export const recoveryBytes = recoverBytes;

export const signRecovery = (principalPrivateKey: string | KeyObject, agent: string, newKey: string, at: string) =>
  sign(principalPrivateKey, recoverBytes(agent, newKey, at));

/** Whether `recover` is the signature of the key `principal` names, recovering `agent` to `newKey` at `at`. */
export function verifyRecovery(agent: string, principal: string, newKey: string, at: string, recover: unknown) {
  const key = principalKey(principal);
  return key !== null && verify(key, recoverBytes(agent, newKey, at), recover);
}
