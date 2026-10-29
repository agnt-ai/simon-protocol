/**
 * The library against spec/vectors/independent.json, which was derived apart from it (spec/vectors/independent.md).
 * A failure here means the library disagrees with OpenSSL, hashlib, an RFC or a rule written out by hand.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  canonicalize,
  fromB64url,
  keyToken,
  messageId,
  parseKeyToken,
  parseMessage,
  privateKeyFromSeed,
  requestSigningString,
  sha256Hex,
  sign,
  verify,
  verifyMessage,
  b64url,
  MINIMUM_LIMITS,
} from '../src/index.ts';

const v = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, '../../spec/vectors/independent.json'), 'utf8'));

describe('the independent vectors', () => {
  it('hashes as SHA-256 does', () => {
    for (const c of v.sha256.cases) {
      const input = 'utf8' in c.input ? c.input.utf8 : c.input.repeat.repeat(c.input.times);
      assert.equal(sha256Hex(input), c.digest, c.name);
    }
  });

  it('derives, signs and verifies the keys of RFC 8032 section 7.1', () => {
    for (const c of v.ed25519.cases) {
      const key = privateKeyFromSeed('ed25519', Buffer.from(c.secret, 'hex'));
      assert.equal(keyToken(key), c.token, c.name);
      assert.deepEqual(parseKeyToken(c.token)?.raw.toString('hex'), c.public, c.name);
      const message = Buffer.from(c.message, 'hex');
      assert.equal(sign(key, message), c.signature, c.name);
      assert.ok(verify(c.token, message, c.signature), c.name);
      assert.ok(
        !verify(c.token, Buffer.concat([message, Buffer.from('x')]), c.signature),
        `${c.name}: another message`,
      );
    }
  });

  it('writes and reads base64url as RFC 4648 section 10 does, and refuses every other spelling', () => {
    for (const c of v.base64url.cases) {
      const bytes = Buffer.from(c.bytes, 'hex');
      assert.equal(b64url(bytes), c.encoded);
      // An empty string is no signature or key, but it is the empty byte string; fromB64url reads non-empty ones.
      if (bytes.length) assert.deepEqual(fromB64url(c.encoded), bytes);
    }
    for (const s of v.base64url.refused) assert.equal(fromB64url(s), null, JSON.stringify(s));
  });

  it('writes canonical JSON as the hand-written texts do', () => {
    for (const c of v.canonical.cases) assert.equal(canonicalize(c.value), c.canonical, c.name);
  });

  it('gives the messages the ids, signing bytes and signatures derived apart', () => {
    for (const c of v.messages.cases) {
      assert.equal(messageId(c.message), c.id, c.name);
      assert.equal(canonicalize(c.unsigned), c.canonical, c.name);
      assert.ok(verify(c.signer, c.signingBytes, c.signature), c.name);
      const m = parseMessage(Buffer.from(canonicalize(c.message)), MINIMUM_LIMITS);
      assert.equal(verifyMessage(m, [{ key: c.signer, added: '2026-01-01T00:00:00Z', revoked: null }]), true, c.name);
    }
  });

  it('builds the signing strings of requests the way they were derived', () => {
    for (const c of v.requests.cases) {
      const s = requestSigningString({
        method: c.method,
        origin: c.origin,
        actor: c.actor,
        target: c.target,
        timestamp: c.timestamp,
        nonce: c.nonce,
        body: c.body,
      });
      assert.equal(s, c.signingString, c.name);
      assert.ok(verify(c.key, s, c.signature), c.name);
    }
  });
});
