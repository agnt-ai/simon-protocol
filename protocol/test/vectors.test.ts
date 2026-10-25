/** The published test vectors, checked the way another implementation would use them. */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  addKeyProofString,
  addressSegment,
  canonicalize,
  checkAuthorSignature,
  checkEnvelopeSignature,
  deliveryState,
  deliveryWindow,
  isAuthoritative,
  MINIMUM_LIMITS,
  nonceExpiry,
  resolutionCacheMs,
  type Envelope,
  type Resolution,
  checkFreshness,
  checkPrincipal,
  checkServed,
  checkSignalFreshness,
  checkSignedRequest,
  claimedPrincipal,
  claimsBytes,
  forbidden,
  isUnderstood,
  parseSignal,
  readsAs,
  unpairingBytes,
  verifyClaims,
  verifySignal,
  verifyUnpairing,
  claimsAbout,
  isAddress,
  isCriticalValue,
  isListedValue,
  isPrincipal,
  pairingBytes,
  currentVersion,
  isSuccessionValue,
  pairingStanding,
  predecessors,
  readSuccession,
  parsePairing,
  verifyPairing,
  verifyRecovery,
  isFresh,
  isPublicKey,
  keyToken,
  messageId,
  normalizeAddress,
  parseEnvelope,
  parseMessage,
  parseStrict,
  parseTimestamp,
  privateKeyFromSeed,
  readAgentDocument,
  readKeys,
  readServerDocument,
  recoverBytes,
  readSignedHeaders,
  requestSigningString,
  SEND_WINDOW_MS,
  serverOrigin,
  signingBytes,
  verify,
  verifyEnvelope,
  verifyMessage,
  withinRepeatWindow,
  WireError,
  type AnyMessage,
  type KeyEntry,
} from '../src/index.ts';
import { buildVectors, resolveCase } from './vectors.ts';

const file = path.resolve(import.meta.dirname, '../../spec/vectors/v2.json');
const vectors = JSON.parse(fs.readFileSync(file, 'utf8'));
const bytes = (s: string) => Buffer.from(s);

/** A check's answer in the vectors' terms. */
function answer(check: () => unknown) {
  try {
    check();
    return { accepted: true };
  } catch (e) {
    if (!(e instanceof WireError)) throw e;
    const { field, canonical } = (e.details ?? {}) as { field?: string; canonical?: string };
    return { status: e.status, code: e.code, ...(field && { field }), ...(canonical && { canonical }) };
  }
}
const expected = ({ accepted, status, code, field, canonical }: Record<string, unknown>) =>
  accepted ? { accepted } : { status, code, ...(field ? { field } : {}), ...(canonical ? { canonical } : {}) };

describe('the published vectors', () => {
  it('are what the reference code produces (rerun npm run vectors after a change)', async () => {
    assert.deepEqual(vectors, JSON.parse(JSON.stringify(await buildVectors())));
  });

  // Everything below reads only the published file, the way another implementation would use it.

  it('keys come from their seeds', () => {
    for (const k of Object.values(vectors.keys).filter(k => typeof k === 'object') as Record<string, string>[]) {
      assert.equal(keyToken(privateKeyFromSeed(k.alg, Buffer.from(k.seed, 'hex'))), k.key);
    }
  });

  it('canonical forms and refusals', () => {
    for (const c of vectors.canonical.cases) {
      const input = c.inputHex ? Buffer.from(c.inputHex, 'hex') : c.input;
      if (c.refused) assert.throws(() => parseStrict(input), `${c.input ?? c.inputHex} (${c.refused})`);
      else assert.equal(canonicalize(parseStrict(input)), c.canonical);
    }
  });

  it('addresses, in their wire form and under the invariant grammar', () => {
    for (const a of vectors.addresses.cases) {
      assert.equal(normalizeAddress(a.input), a.wire, a.input);
      assert.equal(isAddress(a.input), a.anyVersion, a.input);
    }
  });

  it('timestamps', () => {
    for (const t of vectors.timestamps.cases) assert.equal(parseTimestamp(t.input), t.ms, t.input);
  });

  it('key tokens and key lists', () => {
    for (const c of vectors.keyTokens.cases) assert.equal(isPublicKey(c.token), c.key, c.why);
    for (const c of vectors.keyLists.cases) {
      assert.deepEqual(readKeys(c.keys, new Date(vectors.keyLists.now)), c.read, c.why);
    }
  });

  it('messages: signing bytes, ids, transmitted bytes and signatures', () => {
    for (const m of vectors.messages.cases) {
      assert.equal(signingBytes('SIMON-MESSAGE', m.message).toString('utf8'), m.signingBytes, m.name);
      assert.equal(canonicalize(m.message), m.transmitted, m.name);
      assert.deepEqual(parseMessage(bytes(m.transmitted)), m.message, m.name);
      assert.equal(messageId(m.message), m.id, m.name);
      assert.equal(verifyMessage(m.message, [{ key: m.signer, added: m.message.sentAt, revoked: null }]), true, m.name);
    }
  });

  it('message checks, in the order of section 6.3', () => {
    for (const c of vectors.messageChecks.cases) {
      assert.deepEqual(
        answer(() => parseMessage(bytes(c.bytes))),
        expected(c),
        c.name,
      );
    }
  });

  it('header values and pairings', () => {
    for (const c of vectors.headerValues.cases) {
      const check = {
        for: isPrincipal,
        critical: isCriticalValue,
        pairing: (v: unknown) => parsePairing(v) !== null,
        succession: isSuccessionValue,
        listed: isListedValue,
      }[c.header as string]!;
      assert.equal(check(c.value), c.valid, `${c.header}: ${c.value}`);
    }
    for (const c of vectors.pairings.cases) {
      assert.equal(pairingBytes(c.agent, c.principal, parsePairing(c.pairing)!.until), c.bytes, c.why);
      assert.equal(verifyPairing(c.agent, c.principal, c.pairing, Date.parse(c.at)), c.verifies, c.why);
    }
    for (const c of vectors.successions.cases) {
      assert.deepEqual(readSuccession(c.succession, c.principal), c.steps, c.why);
    }
  });

  it('signatures: key validity, refused signatures, and keys of mixed order', () => {
    const s = vectors.signatures;
    const target = vectors.messages.cases.find((m: { name: string }) => m.name === s.message).message as AnyMessage;
    for (const c of s.keyValidAt) assert.equal(verifyMessage(target, c.keys), c.verifies, c.why);
    for (const c of s.refused) {
      assert.equal(verifyMessage({ ...target, signature: c.signature }, [s.keyValidAt[0].keys[0]]), false, c.why);
    }
    const data = signingBytes('SIMON-MESSAGE', target);
    for (const c of s.mixedOrder.cases) assert.equal(verify(s.mixedOrder.key, data, c.signature), c.verifies, c.why);
  });

  it('requests: signing strings, the checks a server makes in order, and add-key proofs', async () => {
    for (const r of vectors.requests.signed) {
      assert.equal(requestSigningString(r), r.signingString);
      assert.equal(verify(r.headers['simon-key'], r.signingString, r.headers['simon-signature']), true);
    }
    for (const c of vectors.requests.checks) {
      const now = new Date(c.now);
      let got: Record<string, unknown> = { accepted: true };
      try {
        const headers = readSignedHeaders(c.request.headers, now, { server: c.server, agent: c.agent });
        await checkSignedRequest(c.request, headers, { now, entry: c.entry, nonceSeen: () => c.nonceSeen });
      } catch (e) {
        if (!(e instanceof WireError)) throw e;
        got = { status: e.status, code: e.code, details: e.details };
      }
      const { accepted, status, code, details } = c;
      assert.deepEqual(got, accepted ? { accepted } : { status, code, details }, c.name);
    }
    for (const n of vectors.requests.nonces)
      assert.equal(new Date(nonceExpiry(n.timestamp)).toISOString(), n.keptUntil);
    for (const o of vectors.requests.signedFor) assert.equal(serverOrigin(o.written), o.origin, o.written);
    for (const a of vectors.requests.addressSegments) assert.equal(addressSegment(a.address), a.segment, a.address);
    for (const p of vectors.requests.addKeyProofs) {
      assert.equal(addKeyProofString(p.address, p.key), p.string);
      assert.equal(verify(p.key, p.string, p.proof), true);
    }
  });

  it('documents', () => {
    const d = vectors.documents;
    for (const c of d.server)
      assert.deepEqual(readServerDocument(bytes(c.body), c.origin, new Date(d.now)), c.read, c.name);
    for (const c of d.agent) {
      assert.deepEqual(readAgentDocument(bytes(c.body), c.address, c.serverKeys, new Date(d.now)), c.read, c.name);
      if (c.signingBytes)
        assert.equal(signingBytes('SIMON-AGENT', JSON.parse(c.body)).toString('utf8'), c.signingBytes);
    }
  });

  it('envelopes, the send rule for paired and solo agents, and the claims a receiver considers', () => {
    const e = vectors.envelopes;
    const keys: KeyEntry[] = e.serverKeys;
    const parse = (b: string) => {
      const envelope = parseEnvelope(bytes(b), MINIMUM_LIMITS, { origin: e.receiver.origin });
      checkEnvelopeSignature(envelope, keys, new Date(e.now));
      checkServed(envelope.recipients, (d: string) => e.receiver.serves.includes(d));
      return envelope;
    };
    for (const c of e.accepted) {
      const envelope = parse(c.bytes);
      assert.equal(signingBytes('SIMON-ENVELOPE', envelope).toString('utf8'), c.signingBytes, c.name);
      if (envelope.claims) {
        const claims = claimsBytes(envelope.claims, messageId(envelope.message)).toString('utf8');
        assert.equal(claims, c.claimsSigningBytes, c.name);
      }
      assert.equal(verifyEnvelope(envelope, keys, new Date(e.now)), true, c.name);
    }
    for (const c of e.refused)
      assert.deepEqual(
        answer(() => parse(c.bytes)),
        expected(c),
        c.name,
      );
    for (const p of vectors.principals.cases) {
      const got = answer(() => {
        parseMessage(bytes(canonicalize(p.message)));
        checkPrincipal(p.message, p.agent);
      });
      assert.deepEqual(got, expected(p), p.name);
    }
    const c = vectors.claimsConsidered;
    const message = vectors.messages.cases.find((m: { name: string }) => m.name === c.message).message;
    assert.deepEqual(claimsAbout(message, c.claims), c.considered);
  });

  it('signatures at deliver are 403, and an author with no key to try is unsupported_algorithm', () => {
    const d = vectors.deliverSignatures;
    const message = vectors.messages.cases.find((m: { name: string }) => m.name === d.message).message;
    for (const c of d.author)
      assert.deepEqual(
        answer(() => checkAuthorSignature(message, c.keys)),
        expected(c),
        c.name,
      );
    const envelope = JSON.parse(d.envelope.bytes) as Envelope;
    for (const c of d.envelope.cases) {
      assert.deepEqual(
        answer(() => checkEnvelopeSignature(envelope, c.keys, new Date(d.now))),
        expected(c),
        c.name,
      );
    }
  });

  it('errors are problem details', () => {
    for (const c of vectors.problems.cases) {
      const e = new WireError(c.status, c.body.code, c.body.detail, c.body.details);
      assert.deepEqual({ headers: e.headers, body: e.toProblem() }, { headers: c.headers, body: c.body }, c.name);
      assert.equal(c.body.retryable, c.status === 429 || c.status >= 500, c.name);
    }
  });

  it('acts-for authority', async () => {
    const a = vectors.authority;
    const resolve = async (d: string): Promise<Resolution> => a.resolutions[d] ?? { outcome: 'not_found' };
    for (const c of a.cases) {
      assert.equal(await isAuthoritative(c, a.carrier, resolve), c.authoritative, c.name);
    }
  });

  it('claims signed for their message, checked by anyone holding the carrier keys', () => {
    const c = vectors.claimsSignatures;
    const message = vectors.messages.cases.find((m: { name: string }) => m.name === c.message).message;
    assert.equal(claimsBytes(c.cases[0].claims, messageId(message)).toString('utf8'), c.signingBytes);
    for (const k of c.cases) {
      assert.equal(verifyClaims({ claims: k.claims, signature: c.signature }, message, k.keys), k.verifies, k.name);
    }
  });

  it("signals: signing bytes, the receiver's checks in order, and which pass within a thread", () => {
    const s = vectors.signals;
    const now = new Date(s.now);
    const check = (b: string) => {
      const signal = parseSignal(bytes(b), { origin: s.receiver.origin });
      if (!verifySignal(signal, s.serverKeys, now)) throw forbidden('bad_signature', 'The signal does not verify.');
      checkServed(signal.to, (d: string) => s.receiver.serves.includes(d), 'to');
      checkSignalFreshness(signal, now);
      return signal;
    };
    for (const c of s.accepted)
      assert.equal(signingBytes('SIMON-SIGNAL', check(c.bytes)).toString('utf8'), c.signingBytes, c.name);
    for (const c of s.refused)
      assert.deepEqual(
        answer(() => check(c.bytes)),
        expected(c),
        c.name,
      );
  });

  it('publication claims bind the published original', () => {
    const { post, carrierKeys } = vectors.publications;
    const r = post.response;
    assert.equal(post.id, messageId(r.message));
    assert.equal(verifyMessage(r.message, post.authorKeys), true);
    assert.equal('keys' in r, false, 'a published message is served without unsigned keys');
    assert.equal(verifyClaims({ claims: r.claims, signature: r.claimsSignature }, r.message, carrierKeys), true);
    assert.equal(
      verifyClaims(
        { claims: r.claims, signature: r.claimsSignature },
        { ...r.message, to: ['someone@example.net'] },
        carrierKeys,
      ),
      false,
    );
  });

  it('unpairings', () => {
    for (const c of vectors.unpairings.cases) {
      assert.equal(unpairingBytes(c.agent, c.principal), c.bytes, c.why);
      assert.equal(verifyUnpairing(c.agent, c.principal, c.unpairing), c.verifies, c.why);
    }
  });

  it("a key principal's recoveries", () => {
    for (const c of vectors.recoveries.cases) {
      assert.equal(recoverBytes(c.agent, c.key, c.at), c.bytes, c.why);
      assert.equal(verifyRecovery(c.agent, c.principal, c.key, c.at, c.recover), c.verifies, c.why);
    }
  });

  it('what a reader may make of a message: understood, its principal, its relation', () => {
    const r = vectors.reading;
    for (const c of r.understood)
      assert.equal(isUnderstood(c.message, new Set(r.understoodHeaders)), c.understood, c.name);
    for (const c of r.principals) assert.equal(claimedPrincipal(c.message), c.principal, c.name);
    for (const c of r.pairings) assert.equal(pairingStanding(c.message, Date.parse(c.now)), c.standing, c.name);
    for (const c of r.predecessors) assert.deepEqual(predecessors(c.message), c.predecessors, c.name);
    for (const c of r.versions) {
      const { message, retracted } = currentVersion(r.versionsOf, c.relations);
      assert.deepEqual([messageId(message), retracted], [c.current, c.retracted], c.name);
    }
    for (const c of r.relations)
      assert.equal(readsAs(c.message, c.target, new Set(r.knownRelations)), c.readsAs, c.name);
  });

  it('delivery timing', () => {
    const d = vectors.delivery;
    for (const c of d.cases) {
      const { earliest, deadline } = deliveryWindow(d, new Date(c.acceptedAt));
      assert.deepEqual([earliest.toISOString(), deadline.toISOString()], [c.earliest, c.deadline], c.name);
      assert.equal(deliveryState(d, new Date(c.acceptedAt), new Date(c.now)), c.state, c.name);
    }
  });

  it('resolution outcomes and origins', async () => {
    for (const c of vectors.resolution.cases) assert.deepEqual(await resolveCase(c), c.result, JSON.stringify(c));
    for (const o of vectors.resolution.origins) assert.equal(serverOrigin(o.input), o.origin, o.input);
    for (const c of vectors.resolution.cacheMs) assert.equal(resolutionCacheMs(c.result, c.sourceTtlMs), c.cacheMs);
  });

  it('clock-dependent rules, each at its own now', () => {
    const m = { sentAt: vectors.clock.sentAt };
    for (const c of vectors.clock.cases) {
      const now = new Date(c.now);
      assert.equal(isFresh(m, now, SEND_WINDOW_MS), c.send, c.name);
      assert.equal(answer(() => checkFreshness(m, now)).accepted === true, c.deliver, c.name);
      assert.equal(withinRepeatWindow(m, now), c.repeat, c.name);
    }
  });
});
