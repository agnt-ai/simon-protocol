/** The key file and the address file: one key however many processes race to make it, and mode 600 throughout. */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { generateKey, keyToken, privateKeyObject } from '@agnt-protocol/protocol';
import {
  addressFile,
  ensureKeyFile,
  keyFile,
  openAgent,
  readAddressFile,
  replaceKeyFile,
  saveAddress,
} from '../src/credentials.ts';
import { fakeServer } from './fake-server.ts';

const run = promisify(execFile);
const tempHome = () => fs.mkdtempSync(path.join(os.tmpdir(), 'simon-credentials-'));
const mode = (file: string) => fs.statSync(file).mode & 0o777;
const CREDENTIALS = path.resolve(import.meta.dirname, '../src/credentials.ts');

describe('the key file', () => {
  it('is made once, mode 600, in a directory of mode 700, and read back after', () => {
    const home = path.join(tempHome(), 'simon');
    const pem = ensureKeyFile(keyFile(home));
    assert.equal(ensureKeyFile(keyFile(home)), pem);
    assert.equal(mode(keyFile(home)), 0o600);
    assert.equal(mode(home), 0o700);
    assert.match(keyToken(privateKeyObject(pem)), /^ed25519:/);
    assert.deepEqual(fs.readdirSync(home), ['key.pem']);
  });

  it('gives every one of many racing processes the same key, and leaves no stray file', async () => {
    const file = keyFile(tempHome());
    const script = `import { ensureKeyFile } from ${JSON.stringify(CREDENTIALS)}; process.stdout.write(ensureKeyFile(process.argv[1]));`;
    const outputs = await Promise.all(
      Array.from({ length: 16 }, () => run(process.execPath, ['--input-type=module', '-e', script, file])),
    );
    const keys = new Set(outputs.map(o => o.stdout));
    assert.equal(keys.size, 1);
    assert.equal([...keys][0], fs.readFileSync(file, 'utf8'));
    assert.deepEqual(fs.readdirSync(path.dirname(file)), ['key.pem']);
    assert.equal(mode(file), 0o600);
  });

  it('never overwrites a key already there', () => {
    const home = tempHome();
    const { privateKeyPem } = generateKey();
    fs.writeFileSync(keyFile(home), privateKeyPem, { mode: 0o600 });
    assert.equal(ensureKeyFile(keyFile(home)), privateKeyPem);
  });

  it('is replaced for recovery, the old one kept aside', () => {
    const home = tempHome();
    const old = ensureKeyFile(keyFile(home));
    const fresh = replaceKeyFile(home, new Date('2026-10-15T12:00:00.000Z'));
    assert.notEqual(fresh, old);
    assert.equal(fs.readFileSync(path.join(home, 'key.pem.replaced-2026-10-15T12-00-00-000Z'), 'utf8'), old);
  });
});

describe('the address file', () => {
  it('holds a registered agent, mode 600, and opens it again with its server and pairing', async () => {
    const home = tempHome();
    const fake = fakeServer();
    const a = openAgent(home, { server: fake.origin, fetch: fake.fetch });
    await a.register();
    const record = saveAddress(home, a);
    assert.deepEqual(readAddressFile(home), JSON.parse(JSON.stringify(record)));
    assert.equal(mode(addressFile(home)), 0o600);
    const again = openAgent(home, { fetch: fake.fetch });
    assert.deepEqual([again.server, again.address, again.key], [fake.origin, a.address, a.key]);
    assert.throws(() => openAgent(home, { server: 'https://elsewhere.test' }), { code: 'invalid' });
  });

  it('says what is missing or malformed', () => {
    const home = tempHome();
    assert.throws(() => openAgent(home), { code: 'invalid', details: { field: 'server' } });
    fs.writeFileSync(addressFile(home), '{"address": 1}');
    assert.throws(() => readAddressFile(home), { code: 'invalid', details: { field: 'address.json' } });
  });
});
