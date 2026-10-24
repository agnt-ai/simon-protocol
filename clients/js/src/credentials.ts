/**
 * An agent's key and address on disk, shared by the CLI and the MCP server:
 *
 *   <home>              mode 700: SIMON_HOME, or ~/.config/simon
 *     key.pem           the private key, PKCS #8 PEM, mode 600, created once and never overwritten
 *     address.json      {"server","address","for"?,"pairing"?} once registered, mode 600
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateKey } from '@agnt-sdk/simon-protocol';
import { Agent } from './agent.ts';
import { invalid, originArg } from './errors.ts';
import type { Transport } from './http.ts';

/** What the address file holds. */
export interface AddressRecord {
  server: string;
  address: string;
  for?: string;
  pairing?: string;
}

export const defaultHome = (env: NodeJS.ProcessEnv = process.env) =>
  env.SIMON_HOME ?? path.join(os.homedir(), '.config', 'simon');

export const keyFile = (home: string) => path.join(home, 'key.pem');
export const addressFile = (home: string) => path.join(home, 'address.json');

/**
 * The private key in `file`, made if the file does not exist. The key is written to a fresh file opened
 * exclusively (`wx`, mode 600), then linked into place, which fails with EEXIST if another process got
 * there first; the key that won is then read back. Every concurrent caller gets the same key, and no
 * reader ever sees a partly written file.
 */
export function ensureKeyFile(file: string, alg: 'ed25519' | 'ml-dsa-65' = 'ed25519'): string {
  const existing = readIfExists(file);
  if (existing !== null) return existing;
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const fresh = `${file}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(fresh, generateKey(alg).privateKeyPem, { flag: 'wx', mode: 0o600 });
  try {
    fs.linkSync(fresh, file);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
  } finally {
    fs.rmSync(fresh, { force: true });
  }
  return fs.readFileSync(file, 'utf8');
}

/**
 * A new key for recovery, after every old key is lost. The old key file, if any, is kept beside it as
 * `key.pem.replaced-<time>`.
 */
export function replaceKeyFile(home: string, now = new Date()): string {
  const file = keyFile(home);
  if (fs.existsSync(file)) fs.renameSync(file, `${file}.replaced-${now.toISOString().replace(/[:.]/g, '-')}`);
  return ensureKeyFile(file);
}

export function readAddressFile(home: string): AddressRecord | null {
  const text = readIfExists(addressFile(home));
  if (text === null) return null;
  let r: Partial<Record<keyof AddressRecord, unknown>> | null = null;
  try {
    r = JSON.parse(text);
  } catch {
    // Described below.
  }
  const strings = r && [r.server, r.address].every(v => typeof v === 'string');
  if (!r || !strings || ![r.for, r.pairing].every(v => v === undefined || typeof v === 'string')) {
    throw invalid('address.json', 'The address file in the agent home is not {"server","address","for"?,"pairing"?}.');
  }
  return r as AddressRecord;
}

/** Save a registered agent's address, replacing the file whole: mode 600, never half written. */
export function saveAddress(home: string, agent: Agent): AddressRecord {
  if (agent.address === null) throw invalid('address', 'Only a registered agent has an address to save.');
  const record: AddressRecord = {
    server: agent.server,
    address: agent.address,
    for: agent.for,
    pairing: agent.pairing,
  };
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  const fresh = `${addressFile(home)}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(fresh, `${JSON.stringify(record, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  fs.renameSync(fresh, addressFile(home));
  return record;
}

/**
 * The agent whose key and address live in `home`, its key made on first use. Its server is the one in the
 * address file, or `server` before the agent is registered.
 */
export function openAgent(home: string, opts: Transport & { server?: string } = {}): Agent {
  const record = readAddressFile(home);
  if (record && opts.server !== undefined && originArg('server', opts.server) !== record.server) {
    throw invalid('server', `${record.address} is registered at ${record.server}, not ${opts.server}.`);
  }
  const server = record?.server ?? opts.server;
  if (server === undefined) throw invalid('server', 'No server: name the server to register with.');
  return new Agent({ ...opts, ...record, server, key: ensureKeyFile(keyFile(home)) });
}

function readIfExists(file: string): string | null {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw e;
  }
}
