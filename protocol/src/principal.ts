/**
 * Principals (spec section 2.2): whom a paired agent speaks for, named by one identifier. An identifier is a
 * labelled string written exactly as one of these. The labels look like URI schemes, but identifiers are not
 * URIs: nothing is percent-encoded, and no URI parser applies.
 *
 *   mailto:<an address as version 1 writes one>
 *   tel:+<a digit from 1 to 9><1 to 14 more digits>
 *   agnt-key:<key token>
 *
 * A key principal approves a pairing by signing `AGNT-PAIR\n<agent address>\n<identifier>`. Every message
 * the agent sends carries that signature as its `pairing` header, so any recipient can check the pairing
 * without trusting a server. It ends the pairing by signing `AGNT-UNPAIR\n<agent address>\n<identifier>`,
 * the unpairing, which retires the address whatever the agent's keys say. It recovers the agent at once by
 * signing `AGNT-RECOVER\n<agent address>\n<new key token>\n<timestamp>` (CLIENT.md dedicated recovery).
 */
import type { KeyObject } from 'node:crypto';
import { isV1Address } from './address.ts';
import { parseKeyToken, sign, verify } from './keys.ts';

const TEL = /^tel:\+[1-9][0-9]{1,14}$/;
const KEY_PREFIX = 'agnt-key:';

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

/** The bytes a key principal signs to pair with an agent. */
export const pairingBytes = (agent: string, principal: string) => `AGNT-PAIR\n${agent}\n${principal}`;

/** The `pairing` header: the principal's signature, with its own private key, pairing it with `agent`. */
export const signPairing = (principalPrivateKey: string | KeyObject, agent: string, principal: string) =>
  sign(principalPrivateKey, pairingBytes(agent, principal));

/** Whether `pairing` is the signature of the key `principal` names over its pairing with `agent`. */
export function verifyPairing(agent: string, principal: string, pairing: unknown): boolean {
  const key = principalKey(principal);
  return key !== null && verify(key, pairingBytes(agent, principal), pairing);
}

/** The bytes a key principal signs to end its pairing with an agent. */
export const unpairingBytes = (agent: string, principal: string) => `AGNT-UNPAIR\n${agent}\n${principal}`;

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
export const recoverBytes = (agent: string, newKey: string, at: string) => `AGNT-RECOVER\n${agent}\n${newKey}\n${at}`;

/** Compatibility name for the same recovery signing bytes. */
export const recoveryBytes = recoverBytes;

export const signRecovery = (principalPrivateKey: string | KeyObject, agent: string, newKey: string, at: string) =>
  sign(principalPrivateKey, recoverBytes(agent, newKey, at));

/** Whether `recover` is the signature of the key `principal` names, recovering `agent` to `newKey` at `at`. */
export function verifyRecovery(agent: string, principal: string, newKey: string, at: string, recover: unknown) {
  const key = principalKey(principal);
  return key !== null && verify(key, recoverBytes(agent, newKey, at), recover);
}
