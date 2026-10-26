/**
 * Deterministic keys and messages for tests and the published vectors. Each private key's seed is the
 * SHA-256 of a label, so anyone can rebuild it.
 *
 * Ed25519 signatures are deterministic. ML-DSA signatures, as Node makes them, are hedged with fresh
 * randomness, so each one the vectors need is made once and kept in ml-dsa-signatures.json, keyed by the
 * key and the signed bytes. `npm run vectors` adds any new one and drops those no longer used.
 */
import crypto, { type KeyObject } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  keyToken,
  pairingBytes,
  privateKeyFromSeed,
  sha256Hex,
  sign,
  signingBytes,
  successionBytes,
  type AnyMessage,
  type KeyEntry,
  type Message,
  type Unsigned,
  VERSION,
} from '../src/index.ts';

export interface FixedKey {
  label: string;
  alg: string;
  seed: string;
  privateKey: KeyObject;
  key: string;
}

export function fixedKey(label: string, alg = 'ed25519'): FixedKey {
  const seed = crypto.createHash('sha256').update(label).digest();
  const privateKey = privateKeyFromSeed(alg, seed);
  return { label, alg, seed: seed.toString('hex'), privateKey, key: keyToken(privateKey) };
}

export const ada = fixedKey('ada@example.com');
export const bob = fixedKey('bob@example.net');
/** An agent whose key is post-quantum. */
export const carol = fixedKey('carol@example.org', 'ml-dsa-65');
export const exampleCom = fixedKey('server https://simon.example.com');
/** Principals who pair with agents by key. */
export const erin = fixedKey('principal erin');
export const frank = fixedKey('principal frank', 'ml-dsa-65');
export const gwen = fixedKey('principal gwen');

const SIGNATURES_FILE = path.resolve(import.meta.dirname, 'ml-dsa-signatures.json');
const kept: Record<string, string> = JSON.parse(fs.readFileSync(SIGNATURES_FILE, 'utf8'));
const used: Record<string, string> = {};

/** A signature that is the same on every run: Ed25519's as made, ML-DSA's as first made and kept. */
export function fixedSign(k: FixedKey, data: Uint8Array | string): string {
  if (k.alg === 'ed25519') return sign(k.privateKey, data);
  const id = sha256Hex(Buffer.concat([Buffer.from(`${k.key}\n`), Buffer.from(data)]));
  used[id] ??= kept[id] ?? sign(k.privateKey, data);
  return used[id];
}

/** Write the ML-DSA signatures the last build used, sorted, so the file only changes when they do. */
export function saveFixedSignatures() {
  const sorted = Object.fromEntries(Object.entries(used).sort(([a], [b]) => (a < b ? -1 : 1)));
  fs.writeFileSync(SIGNATURES_FILE, `${JSON.stringify(sorted, null, 2)}\n`);
}

/** When the fixtures' pairings lapse: 365 days after the question's sentAt. */
export const PAIRED_UNTIL = '2027-10-14T21:00:00Z';

/** A `succession` step that is the same on every run: `old` succeeded by `fresh`, signed by `signers`. */
export const fixedStep = (old: FixedKey, fresh: FixedKey, signers: [FixedKey, FixedKey] = [old, fresh]) => {
  const bytes = successionBytes(`simon-key:${old.key}`, `simon-key:${fresh.key}`);
  return `${old.key} ${fixedSign(signers[0], bytes)} ${fixedSign(signers[1], bytes)}`;
};

/** A `pairing` value that is the same on every run: `<until> <signature>` by `k` over the pairing bytes. */
export const fixedPairing = (k: FixedKey, agent: string, principal: string, until = PAIRED_UNTIL) =>
  `${until} ${fixedSign(k, pairingBytes(agent, principal, until))}`;

export function fixedSignMessage<M extends AnyMessage>(m: Unsigned<M>, k: FixedKey): M {
  return { ...m, signature: fixedSign(k, signingBytes('SIMON-MESSAGE', m)) } as M;
}

export const keyEntry = (key: string, added = '2026-10-01T00:00:00Z', revoked: string | null = null): KeyEntry => ({
  key,
  added,
  revoked,
});

export const question: Unsigned<Message> = {
  v: VERSION,
  from: 'ada@example.com',
  to: ['bob@example.net'],
  inReplyTo: null,
  parts: [{ type: 'text/plain', data: 'Does 3pm work?' }],
  headers: { for: 'mailto:alice@example.org', subject: 'Thursday' },
  sentAt: '2026-10-14T21:00:00Z',
};

export const signedQuestion = fixedSignMessage<Message>(question, ada);
