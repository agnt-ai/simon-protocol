/** Around the message: keys, envelopes and claims, documents, resolution, and signed requests. */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalize,
  checkEnvelopeBeside,
  checkEnvelopeShape,
  checkServed,
  messageId,
  claimsBytes,
  verifyClaims,
  checkFreshness,
  checkPrincipal,
  checkSignedRequest,
  claimsAbout,
  generateKey,
  isPublicKey,
  keyToken,
  MAX_ENVELOPE_BESIDE_MESSAGE_BYTES,
  MINIMUM_LIMITS,
  parseEnvelope,
  parseKeyToken,
  parseTimestamp,
  readAgentDocument,
  readKeys,
  readServerDocument,
  readSignedHeaders,
  requestSigningString,
  actorOf,
  resolveDomain,
  serverDocument,
  serverOrigin,
  serversInTxt,
  sign,
  signAgentDocument,
  signEnvelope,
  signingBytes,
  signRequest,
  splitUrl,
  timestamp,
  verify,
  verifyEnvelope,
  wellKnownOutcome,
  withinRepeatWindow,
  WireError,
  unauthorized,
  checkMessage,
  isPrincipal,
  NonceCache,
  pairingBytes,
  principalKey,
  signPairing,
  verifyPairing,
  checkAuthorSignature,
  checkEnvelopeSignature,
  deliveryState,
  deliveryWindow,
  destinations,
  envelopeFor,
  forbidden,
  isAuthoritative,
  isRepeat,
  judgeClaims,
  nonceExpiry,
  parseProblem,
  REPEAT_WINDOW_MS,
  resolutionCacheMs,
  signatureVerdict,
  unsupportedVersion,
  type ActsForClaim,
  type KeyEntry,
  type Receiver,
  type Resolve,
  type Principal,
  type AnyMessage,
  type Json,
  type Message,
  type ResolverIO,
} from '../src/index.ts';
import { ada, bob, carol, erin, exampleCom, frank, keyEntry, signedQuestion } from './fixtures.ts';

const actsFor: ActsForClaim = {
  type: 'acts-for',
  agent: 'ada@example.com',
  for: 'mailto:alice@example.org',
  scope: ['converse', 'schedule'],
  verifiedAt: '2026-09-01T00:00:00Z',
};
const NOW = new Date('2026-10-14T21:00:00Z');
/** Where the question goes: bob@example.net, at the server example.net resolves to. */
const to = { server: 'https://simon.example.net', recipients: ['bob@example.net'] };
const receiver: Receiver = { origin: 'https://simon.example.net' };
/** A resolver over a fixed table; a domain not in it is not_found, and `flaky.example` is temporary. */
const resolver =
  (table: Record<string, string>): Resolve =>
  async domain =>
    domain in table
      ? { outcome: 'server', server: table[domain], via: 'dns' }
      : { outcome: domain === 'flaky.example' ? 'temporary' : 'not_found' };
const serverKeys = [keyEntry(exampleCom.key)];
const body = (v: unknown) => Buffer.from(typeof v === 'string' ? v : canonicalize(v));
const code = (fn: () => unknown) => {
  try {
    fn();
  } catch (e) {
    return e instanceof WireError ? `${e.status} ${e.code}${e.details?.field ? ` ${e.details.field}` : ''}` : String(e);
  }
  return 'accepted';
};

const codeOf = async (fn: () => Promise<unknown>) => {
  try {
    await fn();
  } catch (e) {
    return e instanceof WireError ? `${e.status} ${e.code}` : String(e);
  }
  return 'accepted';
};

describe('keys', () => {
  it('a key token is the algorithm, a colon, and the raw key in canonical base64url', () => {
    assert.match(ada.key, /^ed25519:[A-Za-z0-9_-]{43}$/);
    assert.equal(parseKeyToken(carol.key)?.raw.length, 1952);
    for (const bad of ['ed25519', 'ed25519:', 'Ed25519:AAAA', 'ed_25519:AAAA', 'ed25519:AAAA=', 'ed25519:AB']) {
      assert.equal(parseKeyToken(bad), null, bad);
    }
    assert.deepEqual(parseKeyToken('x-later:AAAA')?.alg, 'x-later', 'any algorithm name is a token');
  });

  it('Ed25519 keys are on the curve, below p, and not of small order', () => {
    assert.equal(isPublicKey(ada.key), true);
    for (const hex of [
      '0100000000000000000000000000000000000000000000000000000000000000',
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      '0000000000000000000000000000000000000000000000000000000000000080',
      'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      '0200000000000000000000000000000000000000000000000000000000000000',
    ]) {
      assert.equal(isPublicKey(`ed25519:${Buffer.from(hex, 'hex').toString('base64url')}`), false, hex);
    }
  });

  it('every random key either algorithm makes is a key, and signs and verifies', () => {
    for (const alg of ['ed25519', 'ml-dsa-65'] as const) {
      const k = generateKey(alg);
      assert.equal(isPublicKey(k.key), true, alg);
      assert.equal(verify(k.key, 'data', sign(k.privateKeyPem, 'data')), true, alg);
      assert.equal(verify(k.key, 'other', sign(k.privateKey, 'data')), false, alg);
      assert.equal(keyToken(k.privateKey), k.key);
    }
  });

  it('a signature is tried only with keys whose algorithm calls it well formed', () => {
    const edSig = sign(ada.privateKey, 'data');
    assert.equal(verify(carol.key, 'data', edSig), false);
    assert.equal(verify(ada.key, 'data', sign(carol.privateKey, 'data')), false);
    assert.equal(verify('x-later:AAAA', 'data', edSig), false, 'an algorithm not implemented here');
    assert.equal(verify('constructor:AAAA', 'data', edSig), false, 'no prototype member is an algorithm');
    assert.equal(verify(ada.key, 'data', `${edSig}=`), false);
  });

  it('key lists keep unknown algorithms untried, refuse malformed entries, and hold at most 32', () => {
    const later = { key: 'x-later:AAAA', added: '2026-10-01T00:00:00Z', revoked: null };
    assert.deepEqual(readKeys([later], NOW), [later]);
    assert.equal(signatureVerdict(readKeys([later], NOW)!, NOW, 'x', 'AA'), 'unsupported_algorithm');
    assert.equal(readKeys([{ key: ada.key, added: '2026-10-01T00:00:00Z' }], NOW), null);
    assert.equal(readKeys(Array.from({ length: 33 }, () => keyEntry(ada.key)) as unknown as Json, NOW), null);
    const revoked: Json = {
      key: ada.key,
      added: '2026-10-01T00:00:00Z',
      revoked: '2026-10-10T00:00:00Z',
    };
    const active: Json = { key: ada.key, added: '2026-10-01T00:00:00Z', revoked: null };
    const history: Json[] = Array.from({ length: 32 }, () => revoked);
    assert.equal(readKeys(history, NOW)?.length, 32, 'retained revoked entries are readable within the total cap');
    assert.equal(readKeys([...history, revoked], NOW), null, 'revoked entries also count against the CPU bound');
    assert.equal(readKeys([...history.slice(1), active], NOW)?.length, 32, 'mixed history shares one cap');

    assert.equal(readKeys({} as Json, NOW), null);
  });

  it('timestamps cover every year a wire timestamp can write, and no other', () => {
    assert.equal(parseTimestamp('0000-01-01T00:00:00Z'), -62167219200000);
    assert.equal(parseTimestamp('9999-12-31T23:59:59.999Z'), Date.parse('9999-12-31T23:59:59.999Z'));
    assert.equal(timestamp(Date.parse('9999-12-31T23:59:59.999Z')), '9999-12-31T23:59:59.999Z');
    assert.throws(() => timestamp(Date.parse('9999-12-31T23:59:59.999Z') + 1), RangeError);
    assert.throws(() => timestamp(Date.parse('0000-01-01T00:00:00Z') - 1), RangeError);
  });
});

describe('envelopes', () => {
  it('the carrying server signs SIMON-ENVELOPE and the envelope; claims and hints ride under its signature', () => {
    const envelope = signEnvelope(
      { message: signedQuestion, ...to, claims: [actsFor], hints: { 'bob@example.net': { invite: '7KQ2' } } },
      exampleCom.privateKey,
    );
    assert.equal(verifyEnvelope(envelope, serverKeys, NOW), true);
    assert.equal(verifyEnvelope({ ...envelope, server: 'https://simon.example.org' }, serverKeys, NOW), false);
    assert.equal(
      verifyEnvelope({ ...envelope, recipients: ['bob@example.net', 'x@example.net'] }, serverKeys, NOW),
      false,
    );
    assert.equal(verifyEnvelope(envelope, [keyEntry(ada.key)], NOW), false);
    assert.equal(verifyEnvelope({ ...envelope, claims: [] }, serverKeys, NOW), false);
    assert.equal(verifyEnvelope({ ...envelope, hints: {} }, serverKeys, NOW), false);
    assert.equal(signingBytes('SIMON-ENVELOPE', envelope).subarray(0, 15).toString(), 'SIMON-ENVELOPE\n');
    assert.deepEqual(parseEnvelope(body(envelope)), envelope);
  });

  it("is checked with the server keys valid when it arrives, not at the message's sentAt", () => {
    const envelope = signEnvelope({ message: signedQuestion, ...to }, exampleCom.privateKey);
    const addedLater = keyEntry(exampleCom.key, '2026-10-20T00:00:00Z');
    assert.equal(verifyEnvelope(envelope, [addedLater], new Date('2026-10-21T00:00:00Z')), true);
    assert.equal(verifyEnvelope(envelope, [addedLater], new Date('2026-10-19T00:00:00Z')), false);
  });

  it('members it does not define are kept, and signed', () => {
    const envelope = signEnvelope({ message: signedQuestion, ...to, route: ['x'] }, exampleCom.privateKey);
    const parsed = parseEnvelope(body(envelope));
    assert.deepEqual(parsed.route, ['x']);
    assert.equal(verifyEnvelope(parsed, serverKeys, NOW), true);
    assert.equal(verifyEnvelope({ ...parsed, route: [] }, serverKeys, NOW), false);
  });

  it('claims and hints, when present, are the right type: null is not absent', () => {
    const shape = (patch: Record<string, Json>) =>
      code(() => checkEnvelopeShape({ message: signedQuestion as unknown as Json, signature: 'AA', ...to, ...patch }));
    const signed = { claimsSignature: 'AA' };
    assert.equal(shape({}), 'accepted');
    assert.equal(shape({ claims: [], ...signed, hints: {} }), 'accepted');
    assert.equal(shape({ claims: null }), '400 invalid claims');
    assert.equal(shape({ hints: null }), '400 invalid hints');
    assert.equal(shape({ claims: [{ agent: 'x' }], ...signed }), '400 invalid claims');
    assert.equal(shape({ claims: [actsFor] as unknown as Json }), '400 invalid claimsSignature', 'claims are signed');
    assert.equal(shape({ ...signed }), '400 invalid claimsSignature', 'no claims, no signature over them');
    assert.equal(shape({ claims: [], claimsSignature: 'A=' }), '400 invalid claimsSignature');
    assert.equal(
      shape({ claims: Array.from({ length: 16 }, () => actsFor) as unknown as Json, ...signed }),
      'accepted',
    );
    assert.equal(
      shape({ claims: Array.from({ length: 17 }, () => actsFor) as unknown as Json, ...signed }),
      '400 invalid claims',
    );
    assert.equal(shape({ hints: { 'carol@example.net': { invite: 'x' } } }), '400 invalid hints');
    assert.equal(shape({ hints: { 'bob@example.net': { invite: 1 } } }), '400 invalid hints');
    const empty = canonicalize({ claims: [], hints: { 'bob@example.net': { pad: '' } } }).length;
    const pad = (n: number) => ({ 'bob@example.net': { pad: 'x'.repeat(n - empty) } });
    assert.equal(shape({ hints: pad(16384) }), 'accepted');
    assert.equal(shape({ hints: pad(16385) }), '400 invalid claims');
    assert.equal(shape({ signature: 1 }), '400 invalid signature');
    assert.equal(shape({ message: 'x' }), '400 invalid message');
    const beside = canonicalize({ signature: 'AA', ...to, extra: '' }).length;
    assert.equal(shape({ extra: 'x'.repeat(32769 - beside) }), 'accepted', 'no protocol bound beside the message');
    const padded = (n: number) =>
      checkEnvelopeShape({
        message: signedQuestion as unknown as Json,
        signature: 'AA',
        ...to,
        extra: 'x'.repeat(n - beside),
      });
    const bound = MAX_ENVELOPE_BESIDE_MESSAGE_BYTES;
    assert.equal(
      code(() => checkEnvelopeBeside(padded(bound))),
      'accepted',
      "the reference server's default",
    );
    assert.equal(
      code(() => checkEnvelopeBeside(padded(bound + 1))),
      '400 invalid envelope',
      'and past it',
    );
    assert.equal(
      code(() => checkEnvelopeBeside(padded(bound + 1), bound + 10)),
      'accepted',
      'a server may set its own',
    );
    assert.equal(
      code(() => checkEnvelopeShape([])),
      '400 invalid envelope',
    );
  });

  it('server is an origin, and recipients a non-empty list of distinct addresses that hints are keyed by', () => {
    const shape = (patch: Record<string, Json>) =>
      code(() => checkEnvelopeShape({ message: signedQuestion as unknown as Json, signature: 'AA', ...to, ...patch }));
    assert.equal(shape({ server: 'https://SIMON.example.net:443/' }), 'accepted', 'any spelling of the origin');
    for (const server of [undefined, 'simon.example.net', 'http://simon.example.net', 'https://simon.example.net/x']) {
      assert.equal(shape({ server: server as Json }), '400 invalid server', String(server));
    }
    for (const recipients of [
      undefined,
      [],
      'bob@example.net',
      ['bob@example.net', 'bob@example.net'],
      ['Bob@x.net'],
    ]) {
      assert.equal(shape({ recipients: recipients as Json }), '400 invalid recipients', String(recipients));
    }
    const two = { recipients: ['bob@example.net', 'carol@example.net'] };
    assert.equal(shape({ ...two, hints: { 'carol@example.net': { invite: 'x' } } }), 'accepted');
    assert.equal(shape({ hints: { 'carol@example.net': { invite: 'x' } } }), '400 invalid hints', 'not a recipient');
    assert.equal(
      code(() => checkEnvelopeShape({ message: {}, signature: 'AA', ...to, server: 'http://localhost:8080' }, true)),
      'accepted',
      'local development',
    );
  });

  it('the destination is this server, and recipients in to (step 5); served domains come after the signature (step 8)', () => {
    const deliver = (e: Record<string, unknown>, message: object = signedQuestion) =>
      code(() =>
        parseEnvelope(
          body(signEnvelope({ message, ...to, ...e } as never, exampleCom.privateKey)),
          MINIMUM_LIMITS,
          receiver,
        ),
      );
    assert.equal(deliver({}), 'accepted');
    assert.equal(deliver({ server: 'https://SIMON.example.net/' }), 'accepted');
    assert.equal(deliver({ server: 'https://simon.example.org' }), '400 invalid server');
    assert.equal(deliver({ recipients: ['carol@example.net'] }), '400 invalid recipients', 'not in to');
    const toTwo = { ...signedQuestion, to: ['bob@example.net', 'dan@example.org'] };
    assert.equal(deliver({ recipients: ['dan@example.org'] }, toTwo), 'accepted', 'not resolved before the signature');
    assert.equal(deliver({ recipients: ['bob@example.net'] }, toTwo), 'accepted', 'a part of to');
    const served = (recipients: string[]) => code(() => checkServed(recipients, d => d === 'example.net'));
    assert.equal(served(['bob@example.net']), 'accepted');
    assert.equal(served(['bob@example.net', 'dan@example.org']), '400 invalid recipients', 'not served here');
  });

  it("carries the carrier's claims signed for the message, checkable by anyone in the delivery window", () => {
    const envelope = signEnvelope({ message: signedQuestion, ...to, claims: [actsFor] }, exampleCom.privateKey);
    assert.equal(typeof envelope.claimsSignature, 'string');
    assert.equal(verifyEnvelope(envelope, serverKeys, NOW), true);
    assert.equal(verifyEnvelope({ ...envelope, claims: [{ ...actsFor, scope: ['commit'] }] }, serverKeys, NOW), false);
    const signed = { claims: envelope.claims!, signature: envelope.claimsSignature! };
    assert.equal(claimsBytes([actsFor], messageId(signedQuestion)).subarray(0, 13).toString(), 'SIMON-CLAIMS\n');
    assert.equal(verifyClaims(signed, signedQuestion, serverKeys), true);
    assert.equal(verifyClaims({ ...signed, claims: [] }, signedQuestion, serverKeys), false, 'other claims');
    const other = { ...signedQuestion, sentAt: '2026-10-14T21:00:01Z' };
    assert.equal(verifyClaims(signed, other, serverKeys), false, 'another message');
    assert.equal(verifyClaims(signed, signedQuestion, [keyEntry(ada.key)]), false, "not the carrier's key");
    const window = (added: string, revoked: string | null) =>
      verifyClaims(signed, signedQuestion, [keyEntry(exampleCom.key, added, revoked)]);
    assert.equal(window('2026-10-20T20:59:00Z', null), true, 'a key added within 144 hours of sentAt');
    assert.equal(window('2026-10-20T21:05:01Z', null), false, 'a key added after the window');
    assert.equal(window('2026-10-01T00:00:00Z', '2026-10-14T21:00:01Z'), true, 'revoked after sentAt');
    assert.equal(window('2026-10-01T00:00:00Z', '2026-10-14T21:00:00Z'), false, 'revoked by sentAt');
  });

  it('a repeat is per recipient: 202 only when every recipient in the envelope was accepted before', () => {
    const e = { message: signedQuestion, recipients: ['bob@example.net', 'carol@example.net'] };
    assert.equal(isRepeat(e, new Set(['bob@example.net', 'carol@example.net']), NOW), true);
    assert.equal(isRepeat(e, new Set(['bob@example.net']), NOW), false);
    assert.equal(
      isRepeat(e, new Set(e.recipients), new Date(Date.parse(signedQuestion.sentAt) + REPEAT_WINDOW_MS + 1)),
      false,
    );
  });

  it("a message's to splits into one envelope per server, each with only its recipients' hints", async () => {
    const message = {
      ...signedQuestion,
      to: ['bob@example.net', 'x@nowhere.example', 'eve@example.org', 'dan@example.net', 'y@flaky.example'],
    };
    const resolve = resolver({
      'example.net': 'https://simon.example.net',
      'example.org': 'https://simon.example.net',
    });
    const split = await destinations(message.to, resolve);
    assert.deepEqual(split, [
      {
        outcome: 'server',
        server: 'https://simon.example.net',
        recipients: ['bob@example.net', 'eve@example.org', 'dan@example.net'],
      },
      { outcome: 'not_found', server: null, recipients: ['x@nowhere.example'] },
      { outcome: 'temporary', server: null, recipients: ['y@flaky.example'] },
    ]);
    const hints = { 'bob@example.net': { invite: 'a' }, 'x@nowhere.example': { invite: 'b' } };
    const envelope = envelopeFor(message, split[0] as { server: string; recipients: string[] }, {
      claims: [actsFor],
      hints,
    });
    assert.deepEqual(envelope, {
      message,
      server: 'https://simon.example.net',
      recipients: ['bob@example.net', 'eve@example.org', 'dan@example.net'],
      claims: [actsFor],
      hints: { 'bob@example.net': { invite: 'a' } },
    });
    assert.equal(
      'hints' in envelopeFor(message, { server: 'https://a.example', recipients: ['eve@example.org'] }, { hints }),
      false,
    );
  });

  it('acts-for is authoritative when its for is a mailto: on a domain whose TXT record names the carrier', async () => {
    const table = resolver({ 'example.org': 'https://simon.example.com', 'example.net': 'https://simon.example.net' });
    const resolve: Resolve = async domain =>
      domain === 'web.example'
        ? { outcome: 'server', server: 'https://simon.example.com', via: 'well-known' }
        : table(domain);
    const carrier = 'https://simon.example.com';
    const judge = (forValue: string, c = carrier) => isAuthoritative({ for: forValue }, c, resolve);
    assert.equal(await judge('mailto:alice@example.org'), true);
    assert.equal(await judge('mailto:alice@web.example'), false, 'named only by its well-known answer');
    assert.equal(await judge('mailto:alice@example.org', 'https://SIMON.example.com/'), true);
    assert.equal(await judge('mailto:alice@example.net'), false, "another server's domain");
    assert.equal(await judge('mailto:alice@nowhere.example'), false);
    assert.equal(await judge('mailto:alice@flaky.example'), false);
    assert.equal(await judge('tel:+14155550100'), false, 'never for a phone number');
    assert.equal(await judge(`simon-key:${erin.key}`), false);
    assert.deepEqual(await judgeClaims(signedQuestion, [actsFor, { type: 'x-other' }], 'paired', carrier, resolve), [
      { ...actsFor, authoritative: true },
      { type: 'x-other' },
    ]);
    const unknown = ['custom', 'toString', 'constructor', '__proto__', 'hasOwnProperty'].map(type => ({ type }));
    assert.deepEqual(
      await judgeClaims(signedQuestion, unknown, 'paired', carrier, async () => {
        throw new Error('unknown types must not resolve');
      }),
      unknown,
    );
    const selfJudged = [{ type: 'operator', agent: 'ada@example.com', operator: 'Big Bank', authoritative: true }];
    assert.deepEqual(
      await judgeClaims(signedQuestion, selfJudged, 'paired', carrier, resolve),
      [{ type: 'operator', agent: 'ada@example.com', operator: 'Big Bank' }],
      "a carrier's own authoritative member means nothing",
    );
  });

  it('accepts legacy authority calls without resolving or aligning the author domain', async () => {
    const calls: string[] = [];
    const resolve: Resolve = async domain => {
      calls.push(domain);
      assert.equal(domain, 'example.org', 'only the claimed mail domain may be resolved');
      return { outcome: 'server', server: 'https://carrier.example', via: 'dns' };
    };
    const claim = { for: 'mailto:alice@example.org' };
    assert.equal(await isAuthoritative(claim, 'https://carrier.example', resolve), true);
    assert.equal(await isAuthoritative(claim, 'https://carrier.example', resolve, 'reader@unrelated.test'), true);
    assert.equal(await isAuthoritative(claim, 'https://other.example', resolve, 'reader@example.org'), false);
    assert.deepEqual(calls, ['example.org', 'example.org', 'example.org']);
  });

  it('delivery runs from sentAt to the earlier of five days after acceptance and 143 hours after sentAt', () => {
    const sent = Date.parse(signedQuestion.sentAt);
    const h = (n: number, ms = 0) => new Date(sent + n * 3_600_000 + ms);
    assert.deepEqual(deliveryWindow(signedQuestion, h(0)), { earliest: h(0), deadline: h(120) });
    assert.deepEqual(deliveryWindow(signedQuestion, h(24)), { earliest: h(0), deadline: h(143) });
    assert.equal(deliveryState(signedQuestion, h(0, -60_000), h(0, -1)), 'early');
    assert.equal(deliveryState(signedQuestion, h(0, -60_000), h(0)), 'due');
    assert.equal(deliveryState(signedQuestion, h(24), h(143, -1)), 'due');
    assert.equal(deliveryState(signedQuestion, h(24), h(143)), 'expired');
  });

  it('checks run in the order of section 6.3: size, parse, shape, canonical form, then the message', () => {
    const limits = { ...MINIMUM_LIMITS, requestBodyBytes: 100 };
    assert.equal(
      code(() => parseEnvelope(Buffer.from(`{${' '.repeat(100)}}`), limits)),
      '413 body_too_large',
    );
    assert.equal(
      code(() => parseEnvelope(body('{"a":1,"a":1}'))),
      '400 invalid',
    );
    const bad = { ...signedQuestion, id: 'x' };
    const spaced = (e: Record<string, unknown>) =>
      body(canonicalize(e).replace('"from":', '"from" :').replace('"sentAt"', ' "sentAt"'));
    assert.equal(
      code(() => parseEnvelope(spaced({ message: bad, ...to, claims: null, signature: 'AA' }))),
      '400 invalid claims',
    );
    assert.equal(
      code(() => parseEnvelope(spaced({ message: bad, ...to, signature: 'AA' }))),
      '400 invalid',
    );
    assert.equal(
      code(() => parseEnvelope(body({ message: bad, ...to, signature: 'AA' }))),
      '400 invalid id',
    );
    const elsewhere = { ...to, server: 'https://simon.example.org' };
    assert.equal(
      code(() => parseEnvelope(body({ message: bad, ...elsewhere, signature: 'AA' }), MINIMUM_LIMITS, receiver)),
      '400 invalid id',
      'the message before the destination',
    );
    const later = { ...signedQuestion, v: 4, extra: { anything: true } };
    assert.equal(
      code(() => parseEnvelope(body({ message: later, ...to, signature: 'AA' }))),
      'accepted',
    );
  });

  it('the canonical form of the message is checked as it arrived, and the refusal carries it', () => {
    const envelope = canonicalize(signEnvelope({ message: signedQuestion, ...to }, exampleCom.privateKey));
    try {
      parseEnvelope(body(envelope.replace('"to":', '"to":  ')));
      assert.fail('accepted a message that is not canonical');
    } catch (e) {
      assert.ok(e instanceof WireError);
      assert.equal(e.details?.canonical, canonicalize(signedQuestion));
    }
    assert.equal(
      code(() => parseEnvelope(body(envelope.replace('{"message":', '{\n"message" : ')))),
      'accepted',
    );
  });

  it('repeats are recognised for 168 hours, and deliveries are fresh for 144', () => {
    const at = (h: number, ms = 0) => new Date(Date.parse(signedQuestion.sentAt) + h * 3_600_000 + ms);
    assert.equal(withinRepeatWindow(signedQuestion, at(168)), true);
    assert.equal(withinRepeatWindow(signedQuestion, at(168, 1)), false);
    assert.equal(withinRepeatWindow(signedQuestion, at(-1)), true, 'a sentAt ahead of the clock is recent');
    assert.equal(
      code(() => checkFreshness(signedQuestion, at(144))),
      'accepted',
    );
    assert.equal(
      code(() => checkFreshness(signedQuestion, at(144, 1))),
      '400 invalid sentAt',
    );
    assert.equal(
      code(() => checkFreshness(signedQuestion, at(0, -300_000))),
      'accepted',
    );
    assert.equal(
      code(() => checkFreshness(signedQuestion, at(0, -300_001))),
      '400 invalid sentAt',
    );
  });

  it("an acts-for claim counts only for the message's own author and for header, and when well formed", () => {
    const other = { ...actsFor, agent: 'mallory@example.com' };
    const ceo = { ...actsFor, for: 'mailto:ceo@example.org' };
    const undated = { ...actsFor, verifiedAt: '2026-09-01' };
    const unscoped = { ...actsFor, scope: 'converse' };
    assert.deepEqual(
      claimsAbout(signedQuestion, [actsFor, other, ceo, undated, unscoped, { type: 'something-else' }], 'paired'),
      [actsFor, { type: 'something-else' }],
    );
    const { for: _, ...headers } = signedQuestion.headers;
    assert.deepEqual(
      claimsAbout({ ...signedQuestion, headers } as Message, [actsFor, { ...actsFor, for: undefined }], 'paired'),
      [],
    );
    const later = { ...signedQuestion, v: 2 } as AnyMessage;
    assert.deepEqual(claimsAbout(later, [actsFor], 'paired'), [], "a later version's headers are not read");
    assert.deepEqual(claimsAbout(signedQuestion, [actsFor], 'solo'), [], 'a solo agent speaks for no one');
    assert.deepEqual(claimsAbout(signedQuestion, [], 'paired'), []);
  });
});

describe('paired and solo agents', () => {
  const erinPrincipal = `simon-key:${erin.key}`;
  const fromBob = (headers: Record<string, string>) =>
    ({ ...signedQuestion, from: 'bob@example.net', headers }) as Message;
  const pairing = signPairing(erin.privateKey, 'bob@example.net', erinPrincipal);

  it('a principal is mailto:, tel: or simon-key:, written exactly, nothing percent-encoded', () => {
    for (const ok of [
      'mailto:alice@example.org',
      'tel:+12',
      'tel:+123456789012345',
      erinPrincipal,
      'simon-key:x-later:AAAA',
    ]) {
      assert.equal(isPrincipal(ok), true, ok);
    }
    for (const bad of [
      'mailto:Alice@example.org',
      'mailto:alice%40example.org',
      'Mailto:alice@example.org',
      'tel:+1',
      'tel:+1234567890123456',
      'tel:+01',
      'tel:+1%2023',
      `simon-key:${erin.key}=`,
      'simon-key:',
      'alice@example.org',
      1,
    ]) {
      assert.equal(isPrincipal(bad), false, String(bad));
    }
    assert.equal(principalKey(erinPrincipal), erin.key);
    assert.equal(principalKey('mailto:alice@example.org'), null);
  });

  it('a key principal pairs by signing SIMON-PAIR, the agent and itself, with either algorithm', () => {
    assert.equal(pairingBytes('bob@example.net', erinPrincipal), `SIMON-PAIR\nbob@example.net\n${erinPrincipal}`);
    assert.equal(verifyPairing('bob@example.net', erinPrincipal, pairing), true);
    assert.equal(verifyPairing('ada@example.com', erinPrincipal, pairing), false, 'another agent');
    assert.equal(verifyPairing('bob@example.net', `simon-key:${frank.key}`, pairing), false, 'another principal');
    assert.equal(verifyPairing('bob@example.net', 'mailto:erin@example.org', pairing), false, 'not a key principal');
    const pq = `simon-key:${frank.key}`;
    assert.equal(verifyPairing('bob@example.net', pq, signPairing(frank.privateKey, 'bob@example.net', pq)), true);
  });

  it("a paired agent's messages carry its principal, and a pairing exactly when it is a key; a solo agent's carry neither", () => {
    const paired = { kind: 'paired', for: 'mailto:alice@example.org' } as const;
    const byKey = { kind: 'paired', for: erinPrincipal } as const;
    const solo = { kind: 'solo' } as const;
    const check = (m: AnyMessage, agent: Principal) => code(() => checkPrincipal(m, agent));
    assert.equal(check(signedQuestion, paired), 'accepted');
    assert.equal(check(signedQuestion, { ...paired, for: 'tel:+14155550100' }), '400 invalid headers');
    assert.equal(check({ ...signedQuestion, headers: {} } as Message, paired), '400 invalid headers');
    assert.equal(
      check({ ...signedQuestion, headers: { ...signedQuestion.headers, pairing } } as Message, paired),
      '400 invalid headers',
    );
    assert.equal(check(fromBob({ for: erinPrincipal, pairing }), byKey), 'accepted');
    assert.equal(check(fromBob({ for: erinPrincipal }), byKey), '400 invalid headers');
    assert.equal(
      check(
        fromBob({ for: erinPrincipal, pairing: signPairing(erin.privateKey, 'ada@example.com', erinPrincipal) }),
        byKey,
      ),
      '400 invalid headers',
    );
    assert.equal(check(signedQuestion, solo), '400 invalid headers');
    assert.equal(check(fromBob({ pairing }), solo), '400 invalid headers');
    assert.equal(check(fromBob({}), solo), 'accepted');
    assert.equal(check({ ...signedQuestion, v: 2 } as AnyMessage, solo), 'accepted', "a later version's headers");
  });

  it('a routing server checks that pairing is present exactly with a key for, and its grammar, not its signature', () => {
    const m = (headers: Record<string, string>) => code(() => checkMessage({ ...signedQuestion, headers }));
    assert.equal(m({ for: erinPrincipal, pairing: 'AAAA' }), 'accepted');
    assert.equal(m({ for: erinPrincipal, pairing: 'AA==' }), '400 invalid headers');
    assert.equal(m({ for: erinPrincipal }), '400 invalid headers');
    assert.equal(m({ pairing }), '400 invalid headers');
    assert.equal(m({ for: 'mailto:alice@example.org', pairing }), '400 invalid headers');
    assert.equal(m({ for: 'tel:+14155550100' }), 'accepted');
  });
});

describe('documents', () => {
  const agent = (doc: Record<string, unknown>, k = exampleCom) =>
    Buffer.from(JSON.stringify(signAgentDocument(doc as never, k.privateKey)));
  const ada1 = { address: 'ada@example.com', kind: 'paired', keys: [keyEntry(ada.key)] };

  it('agent documents are signed over SIMON-AGENT by a server key valid at the time of reading', () => {
    const read = (b: Buffer, address = 'ada@example.com', keys = serverKeys) =>
      readAgentDocument(b, address, keys, NOW);
    assert.deepEqual(read(agent(ada1)), { address: 'ada@example.com', kind: 'paired', keys: [keyEntry(ada.key)] });
    assert.equal(read(agent(ada1), 'bob@example.net'), null);
    assert.equal(read(agent(ada1), 'ADA@example.com'), null, 'the address asked for, as written');
    assert.equal(read(agent(ada1, ada)), null);
    assert.equal(
      read(agent(ada1), 'ada@example.com', [keyEntry(exampleCom.key, '2026-10-01T00:00:00Z', '2026-10-02T00:00:00Z')]),
      null,
    );
    const bare = Buffer.from(canonicalize(ada1));
    const signature = sign(exampleCom.privateKey, bare);
    assert.equal(read(Buffer.from(JSON.stringify({ ...ada1, signature }))), null, 'the context line is signed');
  });

  it('an agent document names its kind; a kind a reader does not know reads as unknown', () => {
    const kind = (k: unknown) =>
      readAgentDocument(agent({ ...ada1, kind: k }), 'ada@example.com', serverKeys, NOW)?.kind ?? null;
    assert.equal(kind('paired'), 'paired');
    assert.equal(kind('solo'), 'solo');
    assert.equal(kind('group'), 'unknown');
    assert.equal(kind(1), null);
    assert.equal(
      readAgentDocument(agent({ address: ada1.address, keys: ada1.keys }), 'ada@example.com', serverKeys, NOW),
      null,
    );
  });

  it('a server document lists the algorithms it verifies, both of version 1 among them', () => {
    const doc = serverDocument('https://simon.example.com', serverKeys);
    assert.deepEqual(doc.algorithms, ['ed25519', 'ml-dsa-65']);
    const read = (algorithms: unknown) =>
      readServerDocument(body(JSON.stringify({ ...doc, algorithms })), 'https://simon.example.com', NOW)?.algorithms ??
      null;
    assert.deepEqual(read(['ml-dsa-65', 'x-later', 'ed25519']), ['ml-dsa-65', 'x-later', 'ed25519']);
    for (const bad of [undefined, [], ['ed25519'], 'ed25519,ml-dsa-65', ['ed25519', 'ml-dsa-65', 'X']]) {
      assert.equal(read(bad), null, String(bad));
    }
  });

  it('a server document is read by its origin as the URL standard writes it, with its four limits', () => {
    const doc = serverDocument('https://simon.example.com', serverKeys);
    const read = (v: unknown, origin = 'https://simon.example.com') =>
      readServerDocument(body(JSON.stringify(v)), origin, NOW);
    for (const server of ['https://simon.example.com', 'https://SIMON.example.com/', 'https://simon.example.com:443']) {
      assert.deepEqual(read({ ...doc, server }), doc, server);
    }
    assert.equal(read({ ...doc, server: 'https://x.example.com' }), null);
    assert.equal(read(doc, 'https://x.example.com'), null);
    assert.deepEqual(read({ ...doc, v: 1, extra: true, limits: { ...doc.limits, other: 1 } }), doc, 'unknown members');
    assert.equal(read({ ...doc, limits: { ...doc.limits, partBytes: 26214399 } }), null);
    assert.equal(read({ ...doc, limits: { messageBytes: 262144 } }), null);
    const raised = { ...doc, limits: { ...doc.limits, messageBytes: 2 ** 20 } };
    assert.deepEqual(read(raised), raised);
  });

  it('a document is at most 131072 bytes of strict JSON', () => {
    const doc = serverDocument('https://simon.example.com', serverKeys);
    const padded = (n: number) => {
      const s = JSON.stringify({ ...doc, pad: '' });
      return JSON.stringify({ ...doc, pad: 'x'.repeat(n - s.length) });
    };
    assert.ok(readServerDocument(body(padded(131072)), 'https://simon.example.com', NOW));
    assert.equal(readServerDocument(body(padded(131073)), 'https://simon.example.com', NOW), null);
    const repeated = JSON.stringify(doc).replace('{', '{"keys":[],');
    assert.equal(
      readServerDocument(body(repeated), 'https://simon.example.com', NOW),
      null,
      'JSON.parse would take the last',
    );
  });
});

describe('resolution', () => {
  const io = (txt: Record<string, string[][]>, wellKnown: Record<string, unknown> = {}): ResolverIO => ({
    txt: async name => txt[name] ?? [],
    get: async url => (url in wellKnown ? { status: 200, body: body(wellKnown[url]) } : null),
  });
  const record = (s: string) => ({ '_simon.example.com': [[s]] });
  const dns = (server: string) => ({ outcome: 'server', server, via: 'dns' });

  it('DNS first, the well-known answer only when there is no simon record', async () => {
    assert.deepEqual(
      await resolveDomain('example.com', io(record('v=simon1; server=https://simon.example.com'))),
      dns('https://simon.example.com'),
    );
    assert.deepEqual(
      await resolveDomain(
        'Example.COM',
        io({ '_simon.example.com': [['v=simon1;server=https://si', 'mon.example.com;'], ['x=y']] }),
      ),
      dns('https://simon.example.com'),
    );
    assert.deepEqual(
      await resolveDomain('example.com', io(record('v=simon1; ttl=3600; server=HTTPS://SIMON.example.com/'))),
      dns('https://simon.example.com'),
    );
    assert.deepEqual(
      await resolveDomain(
        'example.com',
        io({
          '_simon.example.com': [
            ['v=simon1; server=https://a.example.com'],
            ['v=simon1; server=https://b.example.com'],
          ],
        }),
      ),
      { outcome: 'conflict' },
    );
    const wk = { 'https://example.com/.well-known/simon': { server: 'https://simon.example.com' } };
    for (const bad of [
      'v=simon1',
      'v=simon1; server=https://x.example.com/path',
      'v=simon1; server=http://x.example.com',
      'v=simon1; server=https://10.0.0.1',
    ]) {
      assert.deepEqual(await resolveDomain('example.com', io(record(bad), wk)), { outcome: 'invalid_record' }, bad);
    }
    assert.deepEqual(await resolveDomain('example.com', io(record('V=SIMON1; server=https://a.example.com'), wk)), {
      outcome: 'server',
      server: 'https://simon.example.com',
      via: 'well-known',
    });
    assert.deepEqual(await resolveDomain('example.org', io({})), { outcome: 'not_found' });
    assert.deepEqual(await resolveDomain('localhost', io({})), { outcome: 'invalid_domain' });
  });

  it('a failure that may pass is temporary, never an absence', async () => {
    const failing = (where: 'txt' | 'get'): ResolverIO => ({
      txt: async () => {
        if (where === 'txt') throw new Error('SERVFAIL');
        return [];
      },
      get: async () => {
        throw new Error('TLS');
      },
    });
    assert.deepEqual(await resolveDomain('example.org', failing('txt')), { outcome: 'temporary' });
    assert.deepEqual(await resolveDomain('example.org', failing('get')), { outcome: 'temporary' });
  });

  it('does not make a well-known request after a temporary TXT failure, even when it could succeed', async () => {
    let calls = 0;
    assert.deepEqual(
      await resolveDomain('example.org', {
        txt: async () => {
          throw new Error('SERVFAIL');
        },
        get: async () => {
          calls++;
          return { status: 200, body: Buffer.from('{"server":"https://attacker.example"}') };
        },
      }),
      { outcome: 'temporary' },
    );
    assert.equal(calls, 0, 'a failed TXT authority lookup is terminal for this attempt');
  });

  it('caching: a server for its source TTL up to an hour, not_found ten minutes, temporary a minute', () => {
    const server = { outcome: 'server', server: 'https://simon.example.com', via: 'dns' } as const;
    assert.equal(resolutionCacheMs(server, 300_000), 300_000);
    assert.equal(resolutionCacheMs(server, 86_400_000), 3_600_000);
    assert.equal(resolutionCacheMs(server), 0);
    assert.equal(resolutionCacheMs({ outcome: 'not_found' }), 600_000);
    assert.equal(resolutionCacheMs({ outcome: 'temporary' }), 60_000);
    assert.equal(resolutionCacheMs({ outcome: 'conflict' }), 0);
  });

  it('the well-known answer: 200 with a server, 429 and 5xx temporary, anything else not found', () => {
    const answer = (status: number, b: unknown = { server: 'https://simon.example.org' }) =>
      wellKnownOutcome({ status, body: body(JSON.stringify(b)) }).outcome;
    assert.equal(answer(200), 'server');
    assert.equal(answer(200, { v: 2, server: 'https://simon.example.org', more: 1 }), 'server');
    assert.equal(answer(200, { server: 'https://simon.example.org/x' }), 'not_found');
    assert.equal(answer(201), 'not_found');
    assert.equal(answer(301), 'not_found');
    assert.equal(answer(404), 'not_found');
    assert.equal(answer(429), 'temporary');
    assert.equal(answer(500), 'temporary');
    assert.equal(answer(599), 'temporary');
    assert.equal(answer(600), 'not_found');
    assert.equal(wellKnownOutcome({ status: 200, body: body('{"server":1,"server":2}') }).outcome, 'not_found');
    assert.equal(wellKnownOutcome(null).outcome, 'not_found');
  });

  it('origins are https, a domain, an optional port of 1 to 65535, and nothing else', () => {
    assert.equal(serverOrigin('HTTPS://SIMON.example.com:08443/'), 'https://simon.example.com:8443');
    assert.equal(serverOrigin('https://simon.example.com:00443'), 'https://simon.example.com');
    assert.equal(serverOrigin('https://xn--zz.example'), 'https://xn--zz.example', 'A-labels are not checked');
    for (const bad of [
      'https://simon.example.com:',
      'https://simon.example.com:0',
      'https://simon.example.com:65536',
      'https://simon.example.com:123456',
      'https://bücher.example',
      'https://a.example.com/x',
      'https://u@a.example.com',
      'https://a.example.com?',
      'http://a.example.com',
    ]) {
      assert.equal(serverOrigin(bad), null, bad);
    }
    assert.equal(serverOrigin(`https://${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(62)}`), null);
    assert.equal(serverOrigin('http://localhost:8080', true), 'http://localhost:8080');
    assert.equal(serverOrigin('http://127.0.0.1:80/', true), 'http://127.0.0.1');
    assert.deepEqual(serversInTxt([['v=simon1; server=https://x.example.com?']]), 'invalid');
  });
});

describe('signed requests', () => {
  const url = 'https://simon.example.com/simon/inbox?after=0&limit=5';
  const now = Date.parse('2026-10-14T21:00:00Z');

  it('are signed over SIMON-REQUEST, the method, the server, the actor, the target as sent, the time, the nonce and the body hash', () => {
    const headers = signRequest(bob.privateKey, { method: 'get', url, body: '{"a":1}', now, agent: 'bob@example.net' });
    assert.equal(headers['simon-key'], bob.key);
    assert.equal(headers['simon-agent'], 'bob@example.net');
    assert.equal(headers['simon-timestamp'], '1792011600');
    const signing = requestSigningString({
      method: 'GET',
      origin: 'https://simon.example.com',
      actor: 'bob@example.net',
      target: '/simon/inbox?after=0&limit=5',
      timestamp: headers['simon-timestamp'],
      nonce: headers['simon-nonce'],
      body: '{"a":1}',
    });
    assert.deepEqual(signing.split('\n').slice(0, 5), [
      'SIMON-REQUEST',
      'GET',
      'https://simon.example.com',
      'bob@example.net',
      '/simon/inbox?after=0&limit=5',
    ]);
    assert.equal(signing.split('\n').length, 8);
    assert.equal(verify(bob.key, signing, headers['simon-signature']), true);
    assert.equal(
      verify(bob.key, signing.replace('simon.example.com', 'other.example.com'), headers['simon-signature']),
      false,
    );
    assert.equal(
      verify(bob.key, signing.replace('bob@example.net', 'eve@example.net'), headers['simon-signature']),
      false,
      'naming another actor breaks the signature',
    );
    assert.throws(() =>
      signRequest(bob.privateKey, { method: 'GET', url, agent: 'bob@example.net', server: 'https://x.example' }),
    );
  });

  it('the target is the path and query as Node sends them', () => {
    assert.deepEqual(splitUrl('https://simon.example.com:443/simon/agents/ada@example.com'), {
      origin: 'https://simon.example.com',
      target: '/simon/agents/ada@example.com',
    });
    assert.equal(splitUrl('https://simon.example.com/a b?q=x y#frag').target, '/a%20b?q=x%20y');
    const raw = {
      method: 'GET',
      origin: 'HTTPS://SIMON.EXAMPLE.COM:443/',
      actor: 'ada@example.com',
      target: '/simon/agents/ada%2Fops@example.com?q=%2f%2F',
      timestamp: '1',
      nonce: 'unique-nonce',
      body: '',
    };
    const signing = requestSigningString(raw);
    assert.equal(signing.split('\n')[2], 'https://simon.example.com');
    assert.equal(signing.split('\n')[4], raw.target);
    assert.notEqual(requestSigningString({ ...raw, target: raw.target.replace('%2f', '%2F') }), signing);
    assert.equal(splitUrl('https://simon.example.com').target, '/');
    assert.equal(splitUrl('https://simon.example.com/a?').target, '/a');
  });

  it('header grammar: anything missing or malformed is signature_required', () => {
    const ok = signRequest(ada.privateKey, { method: 'GET', url, now });
    const read = (h: Record<string, unknown>, server = false) =>
      code(() => readSignedHeaders(h as Record<string, string>, new Date(now), { server }));
    assert.equal(read(ok), 'accepted');
    for (const [name, value] of [
      ['simon-key', undefined],
      ['simon-key', ['a', 'b']],
      ['simon-key', raw(ada.key)],
      ['simon-timestamp', '1234567890123'],
      ['simon-timestamp', '-1'],
      ['simon-timestamp', ''],
      ['simon-nonce', '1234567'],
      ['simon-nonce', 'x'.repeat(129)],
      ['simon-nonce', 'abcédefgh'],
      ['simon-signature', 'AB'],
    ] as const) {
      assert.equal(read({ ...ok, [name]: value }), '401 signature_required', `${name}: ${value}`);
    }
    assert.equal(read({ ...ok, 'simon-timestamp': '000000000001' }), 'accepted');
    assert.equal(read({ ...ok, 'simon-nonce': '~'.repeat(128) }), 'accepted');
    assert.equal(read(ok, true), '401 signature_required', 'a server request names its server');
    // simon-server carries the serialised origin, the identity line it signs.
    const fromServer = readSignedHeaders({ ...ok, 'simon-server': 'https://simon.example.net' }, new Date(now), {
      server: true,
    });
    assert.equal(fromServer['simon-server'], 'https://simon.example.net');
    for (const written of [
      'HTTPS://Simon.Example.net/',
      'https://simon.example.net:443',
      'https://simon.example.net/',
    ]) {
      assert.equal(read({ ...ok, 'simon-server': written }, true), '401 signature_required', written);
    }
    const signedAs = signRequest(ada.privateKey, { method: 'GET', url, now, server: 'HTTPS://Simon.Example.net:443/' });
    assert.equal(signedAs['simon-server'], 'https://simon.example.net', 'a signer sends the serialised origin');
    const asAgent = signRequest(ada.privateKey, { method: 'GET', url, now, agent: 'ada@example.com' });
    const agentRead = (h: Record<string, unknown>, o = {}) =>
      code(() => readSignedHeaders(h as Record<string, string>, new Date(now), { agent: true, ...o }));
    assert.equal(agentRead(asAgent), 'accepted');
    assert.equal(agentRead(ok), '401 signature_required', 'an agent request names its agent');
    assert.equal(agentRead(ok, { optionalAgent: true }), 'accepted', 'unless the call may come before an address');
    assert.equal(agentRead({ ...asAgent, 'simon-agent': 'Ada@Example.com' }), '401 signature_required');
    assert.equal(agentRead({ ...asAgent, 'simon-agent': 'ada' }), '401 signature_required');
    assert.equal(
      agentRead({ ...asAgent, 'simon-server': 'https://simon.example.com' }),
      '401 signature_required',
      'one actor, never two',
    );
    assert.equal(actorOf(asAgent), 'ada@example.com');
    assert.equal(actorOf(ok), '');
    try {
      readSignedHeaders({}, new Date(now));
    } catch (e) {
      assert.ok(e instanceof WireError);
      assert.deepEqual(e.details, { serverTime: 1792011600, header: 'simon-key' });
    }
  });

  it('then the window, the key, its validity, the signature and only then the nonce', async () => {
    const headers = readSignedHeaders(signRequest(ada.privateKey, { method: 'GET', url, now }), new Date(now));
    const r = {
      method: 'GET',
      origin: 'https://simon.example.com',
      actor: '',
      target: '/simon/inbox?after=0&limit=5',
      body: '',
    };
    const check = async (o: { at?: number; entry?: KeyEntry | null; nonceSeen?: boolean; target?: string }) => {
      let asked = false;
      const answer = await codeOf(() =>
        checkSignedRequest({ ...r, target: o.target ?? r.target }, headers, {
          now: new Date(o.at ?? now),
          entry: o.entry === undefined ? keyEntry(ada.key) : o.entry,
          nonceSeen: () => (asked = true) && (o.nonceSeen ?? false),
        }),
      );
      return `${answer}${asked ? ' (nonce read)' : ''}`;
    };
    assert.equal(await check({}), 'accepted (nonce read)');
    assert.equal(await check({ at: now + 300_999 }), 'accepted (nonce read)', 'whole seconds');
    assert.equal(await check({ at: now + 301_000 }), '401 stale_request');
    assert.equal(await check({ at: now - 301_000 }), '401 stale_request');
    assert.equal(await check({ at: now + 301_000, target: '/x' }), '401 stale_request');
    assert.equal(await check({ entry: null, nonceSeen: true }), '401 unknown_key');
    const revoked = keyEntry(ada.key, '2026-10-01T00:00:00Z', '2026-10-14T00:00:00Z');
    assert.equal(await check({ entry: revoked }), '401 key_revoked');
    assert.equal(
      await check({ target: '/simon/inbox', nonceSeen: true }),
      '401 bad_signature',
      'a forger reads no nonce',
    );
    assert.equal(await check({ nonceSeen: true }), '401 replayed_request (nonce read)');
    await assert.rejects(
      checkSignedRequest({ ...r, target: '/x' }, headers, {
        now: new Date(now),
        entry: keyEntry(ada.key),
        nonceSeen: () => false,
      }),
      (e: unknown) =>
        e instanceof WireError &&
        e.details?.serverTime === 1792011600 &&
        e.details?.signingString ===
          requestSigningString({
            ...r,
            target: '/x',
            timestamp: headers['simon-timestamp'],
            nonce: headers['simon-nonce'],
          }),
    );
  });

  it('a nonce is kept until its timestamp leaves the window, so the boundary never reopens a replay', async () => {
    const cache = new NonceCache();
    const t = String(now / 1000);
    const at = (ms: number) => new Date(now + ms);
    assert.equal(nonceExpiry(t), now + 301_000);
    assert.equal(cache.seen(ada.key, 'n0nce-01', at(0)), false);
    cache.record(ada.key, 'n0nce-01', t, at(0));
    assert.equal(cache.seen(bob.key, 'n0nce-01', at(1)), false, 'per key');
    // The last moment the timestamp passes the window, the nonce is still remembered; the next, it is stale.
    const headers = readSignedHeaders(
      signRequest(ada.privateKey, { method: 'GET', url, now, nonce: 'n0nce-01' }),
      at(0),
    );
    const r = {
      method: 'GET',
      origin: 'https://simon.example.com',
      actor: '',
      target: '/simon/inbox?after=0&limit=5',
      body: '',
    };
    const replay = (ms: number) =>
      codeOf(() =>
        checkSignedRequest(r, headers, {
          now: at(ms),
          entry: keyEntry(ada.key),
          nonceSeen: (k, n) => cache.seen(k, n, at(ms)),
        }),
      );
    assert.equal(await replay(300_999), '401 replayed_request');
    assert.equal(await replay(301_000), '401 stale_request');
    assert.equal(await replay(-300_000), '401 replayed_request', 'early, too');
    cache.record(ada.key, 'n0nce-02', String(now / 1000 + 300), at(0));
    assert.equal(cache.seen(ada.key, 'n0nce-02', at(600_999)), true, 'a timestamp ahead keeps its nonce longer');
    assert.equal(cache.seen(ada.key, 'n0nce-02', at(601_000)), false);
  });

  it('a server request is signed by a key of the server it names, and an ML-DSA key signs requests too', async () => {
    const headers = signRequest(exampleCom.privateKey, {
      method: 'GET',
      url,
      now,
      server: 'https://simon.example.com',
    });
    const read = readSignedHeaders(headers, new Date(now), { server: true });
    const r = {
      method: 'GET',
      origin: 'https://simon.example.com',
      actor: 'https://simon.example.com',
      target: '/simon/inbox?after=0&limit=5',
      body: '',
    };
    assert.equal(
      await codeOf(() =>
        checkSignedRequest(r, read, { now: new Date(now), entry: keyEntry(exampleCom.key), nonceSeen: () => false }),
      ),
      'accepted',
    );
    const pq = readSignedHeaders(signRequest(carol.privateKey, { method: 'GET', url, now }), new Date(now));
    assert.equal(
      await codeOf(() =>
        checkSignedRequest({ ...r, actor: '' }, pq, {
          now: new Date(now),
          entry: keyEntry(carol.key),
          nonceSeen: () => false,
        }),
      ),
      'accepted',
    );
  });
});

describe('errors and signature verdicts', () => {
  it('errors are RFC 9457 problems, retryable exactly for 429 and 5xx', () => {
    const e = new WireError(400, 'invalid', 'sentAt is more than 144 hours old.', { field: 'sentAt' });
    assert.deepEqual(JSON.parse(JSON.stringify(e)), {
      type: 'about:blank',
      title: 'Invalid',
      status: 400,
      code: 'invalid',
      retryable: false,
      detail: 'sentAt is more than 144 hours old.',
      details: { field: 'sentAt' },
    });
    assert.deepEqual(e.headers, { 'content-type': 'application/problem+json' });
    for (const [status, retryable] of [
      [429, true],
      [500, true],
      [503, true],
      [599, true],
      [404, false],
      [600, false],
    ] as const) {
      assert.equal(new WireError(status, 'x', 'x').retryable, retryable, String(status));
    }
    assert.deepEqual(new WireError(503, 'unavailable', 'x', true, { a: 1 }).details, { a: 1 }, 'the older form');
    const u = unauthorized('bad_signature', 'x', NOW);
    assert.equal(u.headers['www-authenticate'], 'SIMON');
    assert.equal(forbidden('bad_signature', 'x').headers['www-authenticate'], undefined, '403 carries no challenge');
    assert.deepEqual(unsupportedVersion(7).toProblem().details, { field: 'v' });
  });

  it('a client reads a problem by its code, and acts on the HTTP status', () => {
    const p = parseProblem(
      503,
      JSON.stringify({ ...new WireError(503, 'unavailable', 'Try later.').toProblem(), status: 200, retryable: false }),
    );
    assert.deepEqual(p, {
      type: 'about:blank',
      title: 'Unavailable',
      status: 503,
      code: 'unavailable',
      retryable: true,
      detail: 'Try later.',
    });
    assert.equal(parseProblem(400, '{"error":{"code":"invalid"}}'), null, 'the old shape is no problem');
    assert.equal(parseProblem(502, '<html>'), null);
    assert.deepEqual(parseProblem(400, '{"code":"x-new","details":[]}'), {
      type: 'about:blank',
      title: 'X-new',
      status: 400,
      code: 'x-new',
      retryable: false,
      detail: '',
    });
  });

  it('a message signature at deliver is 403: bad_signature, or unsupported_algorithm when every valid key is of an unknown algorithm', () => {
    const later = { key: 'x-later:AAAA', added: '2026-10-01T00:00:00Z', revoked: null };
    const verdict = (keys: KeyEntry[]) => code(() => checkAuthorSignature(signedQuestion, keys));
    assert.equal(verdict([keyEntry(ada.key)]), 'accepted');
    assert.equal(verdict([later, keyEntry(ada.key)]), 'accepted');
    assert.equal(verdict([keyEntry(bob.key)]), '403 bad_signature');
    assert.equal(verdict([keyEntry(carol.key)]), '403 bad_signature', 'a key to try, of another algorithm');
    assert.equal(verdict([later]), '403 unsupported_algorithm');
    assert.equal(
      verdict([later, keyEntry(ada.key, '2026-10-01T00:00:00Z', '2026-10-02T00:00:00Z')]),
      '403 unsupported_algorithm',
    );
    assert.equal(
      signatureVerdict([], NOW, 'x', 'AA'),
      'bad_signature',
      'no key valid at all is not an algorithm question',
    );
    assert.equal(
      verdict([keyEntry(ada.key, '2026-10-01T00:00:00Z', '2026-10-02T00:00:00Z')]),
      '403 bad_signature',
      'only a revoked key',
    );
    const envelope = signEnvelope({ message: signedQuestion, ...to }, exampleCom.privateKey);
    assert.equal(
      code(() => checkEnvelopeSignature(envelope, serverKeys, NOW)),
      'accepted',
    );
    assert.equal(
      code(() => checkEnvelopeSignature(envelope, [keyEntry(ada.key)], NOW)),
      '403 bad_signature',
    );
  });
});

const raw = (token: string) => token.slice(token.indexOf(':') + 1);
