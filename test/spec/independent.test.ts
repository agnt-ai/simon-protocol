/**
 * spec/vectors/independent.json holds up on its own: every digest, signature, id and signing string in it
 * checks with Node's crypto (OpenSSL) alone. This file imports nothing from the protocol library, so it fails
 * if the file is wrong, never because the library is.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const file = path.resolve(import.meta.dirname, '../../spec/vectors/independent.json');
const v = JSON.parse(fs.readFileSync(file, 'utf8'));

const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex');
const verifies = (token: string, data: Buffer | string, signature: string) =>
  crypto.verify(
    null,
    Buffer.from(data),
    {
      key: Buffer.concat([SPKI_ED25519, Buffer.from(token.slice('ed25519:'.length), 'base64url')]),
      format: 'der',
      type: 'spki',
    },
    Buffer.from(signature, 'base64url'),
  );
const sha = (data: Buffer | string) => crypto.createHash('sha256').update(data).digest('hex');

describe('spec/vectors/independent.json', () => {
  it('has the digests it says', () => {
    for (const c of v.sha256.cases) {
      const input = 'utf8' in c.input ? c.input.utf8 : c.input.repeat.repeat(c.input.times);
      assert.equal(sha(input), c.digest, c.name);
    }
  });

  it('has Ed25519 keys and signatures that OpenSSL accepts, and tokens that spell the public key', () => {
    assert.equal(v.ed25519.cases.length, 5);
    for (const c of v.ed25519.cases) {
      const priv = crypto.createPrivateKey({
        key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(c.secret, 'hex')]),
        format: 'der',
        type: 'pkcs8',
      });
      const pub = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32);
      assert.equal(pub.toString('hex'), c.public, c.name);
      assert.equal(c.token, `ed25519:${pub.toString('base64url')}`, c.name);
      assert.equal(crypto.sign(null, Buffer.from(c.message, 'hex'), priv).toString('base64url'), c.signature, c.name);
      assert.ok(verifies(c.token, Buffer.from(c.message, 'hex'), c.signature), c.name);
    }
  });

  it('encodes base64url as Node does, and refuses what is not the one spelling', () => {
    for (const c of v.base64url.cases) assert.equal(Buffer.from(c.bytes, 'hex').toString('base64url'), c.encoded);
    for (const s of v.base64url.refused) {
      // Node's decoder is lenient: the spelling is refused because it is not what the decoded bytes encode to.
      assert.notEqual(Buffer.from(s, 'base64url').toString('base64url'), s, JSON.stringify(s));
    }
  });

  it('has canonical texts that mean their values', () => {
    for (const c of v.canonical.cases) assert.deepEqual(JSON.parse(c.canonical), c.value, c.name);
  });

  it('has message ids, signing bytes and signatures that follow from the canonical text', () => {
    for (const c of v.messages.cases) {
      assert.deepEqual(JSON.parse(c.canonical), c.unsigned, c.name);
      assert.equal(c.id, sha(c.canonical), c.name);
      assert.equal(c.signingBytes, `SIMON-MESSAGE\n${c.canonical}`, c.name);
      assert.ok(verifies(c.signer, c.signingBytes, c.signature), c.name);
      assert.deepEqual(c.message, { ...c.unsigned, signature: c.signature }, c.name);
    }
  });

  it('has request signing strings of eight lines that follow from their parts', () => {
    for (const c of v.requests.cases) {
      assert.equal(
        c.signingString,
        ['SIMON-REQUEST', c.method, c.origin, c.actor, c.target, c.timestamp, c.nonce, sha(c.body)].join('\n'),
        c.name,
      );
      assert.ok(verifies(c.key, c.signingString, c.signature), c.name);
    }
  });
});
