/**
 * The published test vectors (spec/vectors/v1.json), built from the reference code. An implementation in
 * any language should reproduce every canonical form, id, signature and verdict here byte for byte.
 */
import {
  addKeyProofString,
  addressSegment,
  b64url,
  bodyTooLarge,
  checkAuthorSignature,
  checkEnvelopeSignature,
  claimsAbout,
  deliveryState,
  deliveryWindow,
  forbidden,
  invalid,
  isAuthoritative,
  judgeClaims,
  nonceExpiry,
  resolutionCacheMs,
  unauthorized,
  unsupportedVersion,
  type Claim,
  type Resolution,
  type Resolve,
  canonicalize,
  isFresh,
  messageId,
  MINIMUM_LIMITS,
  normalizeAddress,
  isAddress,
  parseEnvelope,
  parseMessage,
  parseStrict,
  parseTimestamp,
  readAgentDocument,
  readKeys,
  readServerDocument,
  recoverBytes,
  requestSigningString,
  actorOf,
  resolveDomain,
  SEND_WINDOW_MS,
  serverDocument,
  serverOrigin,
  signAgentDocument,
  signEnvelope,
  signingBytes,
  signRequest,
  withinRepeatWindow,
  WireError,
  isPrincipal,
  isB64url,
  pairingBytes,
  signPairing,
  verifyPairing,
  verifyRecovery,
  isCriticalValue,
  isListedValue,
  isPublicKey,
  readSignedHeaders,
  checkSignedRequest,
  checkFreshness,
  checkPrincipal,
  checkServed,
  checkSignalFreshness,
  claimedPrincipal,
  claimsBytes,
  isUnderstood,
  parseSignal,
  readsAs,
  sign,
  unpairingBytes,
  verifyClaims,
  verifySignal,
  verifyUnpairing,
  type UnsignedSignal,
  type ActsForClaim,
  type Principal,
  type AnyMessage,
  type Json,
  type KeyEntry,
  type Message,
  type ResolverIO,
  type SignedHeaders,
  type UnsignedAgentDocument,
  type Unsigned,
} from '../src/index.ts';
import { add, challenge, decode, encode, fromLE, L, P, scalarOf, signature, toLE } from './ed25519.ts';
import {
  ada,
  bob,
  carol,
  erin,
  exampleCom,
  frank,
  fixedKey,
  fixedSign,
  fixedSignMessage,
  keyEntry,
  question,
  signedQuestion,
  type FixedKey,
} from './fixtures.ts';

const ORIGIN = 'https://agnt.example.com';
const NOW = '2026-10-14T21:00:00Z';
const many = <T>(n: number, f: (i: number) => T) => Array.from({ length: n }, (_, i) => f(i));
const at = (iso: string, deltaMs: number) => new Date(Date.parse(iso) + deltaMs).toISOString();
const text = (v: unknown) => JSON.stringify(v);
const without = (o: object, member: string) => Object.fromEntries(Object.entries(o).filter(([k]) => k !== member));
const raw = (token: string) => Buffer.from(token.slice(token.indexOf(':') + 1), 'base64url');
const ed25519 = (bytes: Uint8Array) => `ed25519:${b64url(bytes)}`;

/** The same base64url bytes spelled with non-zero trailing bits: decodes alike, but is not canonical. */
function withTrailingBits(s: string) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  return s.slice(0, -1) + alphabet[alphabet.indexOf(s.at(-1)!) | 1];
}

/** The answer a check gives: accepted, or the refusal's status, code and the details that matter. */
function outcome(check: () => unknown) {
  try {
    check();
    return { accepted: true };
  } catch (e) {
    if (!(e instanceof WireError)) throw e;
    const { field, canonical } = (e.details ?? {}) as { field?: string; canonical?: string };
    return { status: e.status, code: e.code, ...(field && { field }), ...(canonical && { canonical }) };
  }
}

const canonical = {
  about:
    'Canonical JSON (section 5.1): each input, parsed under the strict rules, has the canonical form given, or is refused for the reason given. inputHex is raw bytes.',
  cases: [
    ...[
      '{ "b": 1, "a": [3, 1, 2], "A": true }',
      '{"\\u20ac":1,"\\u00e9":2,"\\ufb01":3,"\\ud83d\\ude00":4}',
      '"tab\\there \\u001f \\u007f \\/ \\u00e9 \\u00C9"',
      '"\\b \\f \\n \\r \\t \\u0000 \\u001F \\" \\\\"',
      '"\\u007f \\u2028 \\u2029 <>& \\u003c\\u003e\\u0026"',
      '[0, -1, 9007199254740991, -9007199254740991, null, false]',
      '{"z":{"y":[{}],"x":""}}',
      ' \t\r\n{"a" : 1}\n',
      '{"__proto__":1}',
      `${'['.repeat(63)}{"deepest":1}${']'.repeat(63)}`,
    ].map(input => ({ input, canonical: canonicalize(parseStrict(input)) })),
    ...[
      ['1.0', 'fraction'],
      ['1e3', 'exponent'],
      ['-0', 'negative zero'],
      ['01', 'leading zero'],
      ['9007199254740992', 'outside the safe integer range'],
      ['{"a":1,"a":2}', 'duplicate key'],
      ['{"a":1,"\\u0061":2}', 'duplicate key, once unescaped'],
      [`${'['.repeat(65)}${']'.repeat(65)}`, 'nested too deep'],
      ['"\\ud800"', 'lone surrogate'],
      ['"\\x"', 'not an escape'],
      ['"a\tb"', 'a raw control character in a string'],
      ['[1,]', 'trailing comma'],
      ['{} {}', 'text after the value'],
    ].map(([input, refused]) => ({ input, refused })),
    { inputHex: '22ff22', refused: 'invalid UTF-8' },
    { inputHex: 'efbbbf7b7d', refused: 'byte order mark' },
    { inputHex: '22eda08022', refused: 'a surrogate written raw (invalid UTF-8)' },
  ],
};

const addresses = {
  about:
    'Addresses (section 2.1). wire: the version 1 wire form of the input from any case, or null. anyVersion: whether the input as written is an address a message of any version may carry: the invariant local part (1 to 64 bytes of UTF-8 with no @, no space, no ASCII capital and no character of category Cc), and a domain. Routers do not judge normalisation, so a local part not in NFC, or holding a mark assigned only in a recent Unicode version, is an address to every router.',
  cases: [
    'ada@example.com',
    'Ada@Example.COM',
    'ada.lovelace+notes@agents.example.com',
    'ada..x@example.com',
    '.ada@example.com',
    'ada@localhost',
    'ada@1.2.3.4',
    'ada@ex_ample.com',
    'ada@example.com.',
    `${String.fromCodePoint(0x212a)}@example.com`,
    'josé@example.com',
    'Josà@example.com',
    'a b@example.com',
    'a\u0085b@example.com',
    'a\u007fb@example.com',
    'jose\u0301@example.com',
    'x\u{1acf}y@example.com',
    'a@b@example.com',
    `${'a'.repeat(64)}@example.com`,
    `${'a'.repeat(65)}@example.com`,
    `${'é'.repeat(32)}@example.com`,
    `${'é'.repeat(32)}a@example.com`,
    `ada@${'a'.repeat(63)}.com`,
    `ada@${'a'.repeat(64)}.com`,
    `ada@${['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)].join('.')}`,
    `ada@${['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(62)].join('.')}`,
    'ada@-example.com',
    'ada@example-.com',
    'ada@example.123',
    'ada@xn--bcher-kva.example',
  ].map(input => ({ input, wire: normalizeAddress(input), anyVersion: isAddress(input) })),
};

const timestamps = {
  about:
    'Timestamps (section 2.5): the instant each names in milliseconds since 1970 (negative before it), or null when it is not a wire timestamp.',
  cases: [
    '2026-10-14T21:00:00Z',
    '2026-10-14T21:00:00.123Z',
    '0000-01-01T00:00:00Z',
    '9999-12-31T23:59:59.999Z',
    '2024-02-29T00:00:00Z',
    '2026-02-29T00:00:00Z',
    '2026-02-30T00:00:00Z',
    '2026-10-14T24:00:00Z',
    '2026-12-31T23:59:60Z',
    '2026-10-14T21:00:00.5Z',
    '2026-10-14T21:00:00.0000Z',
    '2026-10-14T21:00:00+00:00',
    '2026-10-14 21:00:00Z',
    '2026-10-14t21:00:00z',
    '+02026-10-14T21:00:00Z',
  ].map(input => ({ input, ms: parseTimestamp(input) })),
};

/** An order-8 point, from the encodings of small order. */
const ORDER_8 = Buffer.from('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05', 'hex');
/** Ada's key plus a point of order 8: on the curve, not of small order, but not in the prime subgroup. */
const mixedOrderKey = ed25519(encode(add(decode(raw(ada.key))!, decode(ORDER_8)!)));

function offCurve() {
  for (let y = 2n; ; y++) if (!decode(toLE(y))) return toLE(y);
}

const keyTokens = {
  about:
    'Key tokens (section 2.3): whether each is a key of an algorithm version 1 defines. An algorithm a reader does not implement is never a key to it.',
  cases: [
    { token: ada.key, why: 'an Ed25519 key' },
    { token: carol.key, why: 'an ML-DSA-65 key' },
    { token: `ml-dsa-65:${b64url(Buffer.alloc(1952))}`, why: 'any 1952 bytes are an ML-DSA-65 key' },
    { token: mixedOrderKey, why: 'a point of mixed order is on the curve and not of small order' },
    { token: ed25519(toLE(1n)), why: 'the identity, a point of small order' },
    { token: ed25519(ORDER_8), why: 'a point of order 8' },
    { token: ed25519(toLE(P - 1n)), why: 'the point of order 2 (y = p - 1)' },
    { token: ed25519(toLE(P + 1n)), why: 'the identity written non-canonically (y = p + 1)' },
    { token: ed25519(toLE(P)), why: 'y = p: not below p' },
    {
      token: ed25519(Buffer.concat([toLE(1n).subarray(0, 31), Buffer.from([0x80])])),
      why: 'x = 0 with the sign bit set',
    },
    { token: ed25519(offCurve()), why: 'the smallest y with no x: not on the curve' },
    {
      token: `ed25519:${withTrailingBits(raw(ada.key).toString('base64url'))}`,
      why: 'base64url with non-zero trailing bits',
    },
    { token: ed25519(raw(ada.key).subarray(0, 31)), why: '31 bytes' },
    { token: `ml-dsa-65:${b64url(raw(carol.key).subarray(1))}`, why: '1951 bytes' },
    { token: `${ada.key}=`, why: 'padded base64url' },
    { token: `ED25519:${raw(ada.key).toString('base64url')}`, why: 'an algorithm name in upper case' },
    { token: raw(ada.key).toString('base64url'), why: 'no algorithm' },
    { token: 'ed25519:', why: 'no key' },
    { token: 'x-later:AAAA', why: 'an algorithm version 1 does not define' },
  ].map(({ token, why }) => ({ token, key: isPublicKey(token), why })),
};

const keyLists = {
  about:
    'Key lists as documents carry them (section 4), read at now: read is the entries a reader implementing both algorithms keeps, or null when the list makes the document unreadable. At most 32 total entries may be published, including retained revoked entries. An entry revoked more than 300 seconds after now makes the list unreadable.',
  now: NOW,
  cases: (
    [
      [[keyEntry(ada.key), keyEntry(carol.key)], 'one key of each algorithm'],
      [[], 'no keys'],
      [
        [{ key: 'x-later:AAAA', added: NOW, revoked: null }, keyEntry(ada.key)],
        'an algorithm not implemented is skipped',
      ],
      [[keyEntry(ada.key, '2026-10-01T00:00:00Z', '2026-10-10T00:00:00.000Z')], 'a revoked key is listed'],
      [many(32, () => keyEntry(ada.key)), '32 entries'],
      [many(33, () => keyEntry(ada.key)), '33 entries'],
      [
        [keyEntry(carol.key, '2026-10-01T00:00:00Z', at(NOW, -1000)), ...many(32, () => keyEntry(ada.key))],
        '33 entries, one revoked before now: all 33 count',
      ],
      [
        [keyEntry(carol.key, '2026-10-01T00:00:00Z', NOW), ...many(32, () => keyEntry(ada.key))],
        '33 entries, one revoked exactly at now: all 33 count',
      ],
      [
        [keyEntry(carol.key, '2026-10-01T00:00:00Z', at(NOW, 1000)), ...many(32, () => keyEntry(ada.key))],
        '33 entries, one revoked 1 s after now and so not yet revoked: 33 count',
      ],
      [
        [
          ...many(40, i => keyEntry(carol.key, '2026-10-01T00:00:00Z', at(NOW, -1000 * (i + 1)))),
          ...many(32, () => keyEntry(ada.key)),
        ],
        '72 entries, 40 revoked before now: history also exceeds the cap',
      ],
      [[keyEntry(ada.key, '2026-10-01T00:00:00Z', at(NOW, 300_000))], 'revoked exactly 300 s after now: readable'],
      [[keyEntry(ada.key, '2026-10-01T00:00:00Z', at(NOW, 300_001))], 'revoked more than 300 s after now'],
      [[keyEntry(ada.key, '2026-10-01T00:00:00Z', '2099-01-01T00:00:00Z')], 'revoked far in the future'],
      [[{ key: ada.key, added: NOW }], 'revoked missing'],
      [[{ key: ada.key, revoked: null }], 'added missing'],
      [[{ added: NOW, revoked: null }], 'key missing'],
      [[ada.key], 'an entry that is not an object'],
      [[{ ...keyEntry(ada.key), added: '2026-10-01' }], 'added not a timestamp'],
      [[{ ...keyEntry(ada.key), revoked: false }], 'revoked neither a timestamp nor null'],
      [[{ key: 'x-later:AAAA', added: 'soon', revoked: null }], 'an unknown algorithm with a malformed added'],
      [[keyEntry('ada')], 'a key that is not a key token'],
      [[keyEntry(ed25519(toLE(1n))), keyEntry(ada.key)], 'an Ed25519 key of small order'],
      [[keyEntry(`ml-dsa-65:${b64url(Buffer.alloc(1951))}`)], 'an ML-DSA-65 key of the wrong length'],
      [[{ ...keyEntry(ada.key), alg: 'ed25519' }], 'a member readers do not know, inside an entry'],
    ] as [Json[], string][]
  ).map(([keys, why]) => ({ keys, read: readKeys(keys, new Date(NOW)), why })),
};

/** A version 1 message whose transmitted form is exactly `size` bytes, padded in a text part. */
function messageOfSize(size: number): Message {
  const base = (data: string): Unsigned<Message> => ({ ...question, parts: [{ type: 'text/plain', data }] });
  const empty = canonicalize(fixedSignMessage<Message>(base(''), ada)).length;
  return fixedSignMessage<Message>(base('x'.repeat(size - empty)), ada);
}

/** A version 7 message: invariants, plus fields version 1 does not have. */
const version7 = fixedSignMessage<AnyMessage>(
  {
    v: 7,
    from: 'ada@example.com',
    to: ['bob@example.net'],
    sentAt: NOW,
    body: { text: 'Fields of a later version ride along unread.' },
    priority: 3,
  } as Unsigned<AnyMessage>,
  ada,
);

/** Bob, paired with the key principal erin, who signed the pairing. */
const erinPrincipal = `agnt-key:${erin.key}`;
const keyPaired = fixedSignMessage<Message>(
  {
    ...question,
    from: 'bob@example.net',
    to: ['ada@example.com'],
    headers: { for: erinPrincipal, pairing: fixedSign(erin, pairingBytes('bob@example.net', erinPrincipal)) },
  },
  bob,
);

function messageCase(name: string, unsigned: Unsigned<Message> | Unsigned<AnyMessage>, signer: FixedKey = ada) {
  const signed = fixedSignMessage<AnyMessage>(unsigned as Unsigned<AnyMessage>, signer);
  return {
    name,
    signer: signer.key,
    signingBytes: signingBytes('AGNT-MESSAGE', signed).toString('utf8'),
    id: messageId(signed),
    message: signed,
    transmitted: canonicalize(signed),
  };
}

const post = {
  ...question,
  to: [],
  headers: { subject: 'Hello, AGNT' },
  parts: [{ type: 'text/plain', data: 'First post.' }],
};

const messages = {
  about:
    'Signed messages (sections 1 and 5): signingBytes is AGNT-MESSAGE, a newline, and the canonical message without signature; id is the SHA-256 of those canonical bytes without the prefix; signer is the key that verifies the signature.',
  cases: [
    messageCase('question with a for header', question),
    messageCase('reply carrying a content-addressed part', {
      ...question,
      inReplyTo: messageId(question),
      parts: [
        { type: 'text/plain', data: 'The agenda.' },
        {
          type: 'application/pdf',
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          size: 0,
        },
      ],
      headers: {},
    }),
    messageCase('Markdown, a named file with its alt, and a structured block naming its schema', {
      ...question,
      parts: [
        { type: 'text/markdown; variant=GFM', data: 'Does **3pm** work? The agenda is attached.' },
        {
          type: 'application/pdf',
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          size: 0,
          name: 'agenda.pdf',
          alt: "Thursday's agenda",
        },
        { type: 'application/json; schema="https://example.org/schemas/slots"', data: 'eyJzbG90cyI6WyIxNTowMCJdfQ==' },
      ],
    }),
    messageCase(
      'a reaction to the question, by bob',
      {
        ...question,
        from: 'bob@example.net',
        to: ['ada@example.com'],
        inReplyTo: messageId(question),
        headers: { rel: 'reaction' },
        parts: [{ type: 'text/plain', data: String.fromCodePoint(0x1f44d) }],
      },
      bob,
    ),
    messageCase('a published post in two feeds, for an audience', {
      ...question,
      to: [],
      headers: { feed: 'posts,travel', audience: 'followers' },
      parts: [{ type: 'text/markdown; variant=GFM', data: 'Landed in *Lisbon*.' }],
    }),
    messageCase('public post (empty to)', post),
    messageCase('media type parameters, one quoted', {
      ...question,
      parts: [
        { type: 'text/plain; charset=utf-8', data: 'See the attached.' },
        { type: 'application/octet-stream; name="a b.bin"', data: 'AAEC' },
      ],
    }),
    messageCase(
      'reply to the public post, by bob',
      {
        ...question,
        from: 'bob@example.net',
        to: ['ada@example.com'],
        inReplyTo: messageId(post),
        headers: {},
        parts: [{ type: 'text/plain', data: String.fromCodePoint(0x1f44d) }],
      },
      bob,
    ),
    messageCase(
      'signed with ML-DSA-65, speaking for a phone number',
      {
        ...question,
        from: 'carol@example.org',
        headers: { for: 'tel:+14155550100', critical: 'for' },
        parts: [{ type: 'text/plain', data: 'Post-quantum from day one.' }],
      },
      carol,
    ),
    messageCase('from an agent paired with a key principal', keyPaired, bob),
    messageCase('version 7, with fields version 1 does not define', version7 as Unsigned<AnyMessage>),
  ],
};

/** Each case is the exact body sent; the answer is `parseMessage` with the minimum limits (section 6.3 steps 1, 3 and 4). */
function messageChecks() {
  const m = signedQuestion as unknown as Record<string, Json>;
  const v1 = (patch: Record<string, Json>) =>
    canonicalize(fixedSignMessage({ ...question, ...patch } as Unsigned<Message>, ada));
  const v7 = (patch: Record<string, Json>) => canonicalize({ ...version7, ...patch });
  const domain253 = ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)].join('.');
  const TEXT = { type: 'text/plain', data: 'See below.' };
  const file = (size: number) => ({ type: 'application/pdf', sha256: 'a'.repeat(64), size });
  /** A part carrying a message inline whose parts are `parts`; nothing checks a carried message's signature. */
  const carry = (parts: Json[]) => ({
    type: 'application/agnt-message',
    data: Buffer.from(canonicalize({ ...signedQuestion, parts } as unknown as Json)).toString('base64'),
  });
  const forward = (parts: Json[]) => v1({ inReplyTo: messageId(question), headers: { rel: 'forward' }, parts });
  /** A part carrying exactly these bytes, whatever they are, in canonical base64. */
  const carryRaw = (text: string) => ({ type: 'application/agnt-message', data: Buffer.from(text).toString('base64') });
  /** The carried message of one file of size 1, its bytes changed by `edit`. */
  const carryEdited = (edit: (canonical: string) => string) =>
    carryRaw(edit(canonicalize({ ...signedQuestion, parts: [file(1)] } as unknown as Json)));
  /** A carried message of one file of size 1 with `patch` over its members. */
  const carryWith = (patch: Record<string, Json | undefined>) => {
    const m = { ...signedQuestion, parts: [file(1)], ...patch } as Record<string, Json | undefined>;
    return carryRaw(canonicalize(Object.fromEntries(Object.entries(m).filter(([, v]) => v !== undefined))));
  };
  /** Parts carrying a message `depth` deep, whose parts are `bottom`. */
  const nested = (depth: number, bottom: Json[] | number): Json[] =>
    depth === 0 ? (typeof bottom === 'number' ? [file(bottom)] : bottom) : [carry(nested(depth - 1, bottom))];
  /** A carried part whose data is base64url rather than base64: a message whose base64 holds + or /. */
  const urlSafe = (() => {
    for (let i = 0; ; i++) {
      const { data } = carry([file(1), { type: 'text/plain', data: `${i} ~~~???>>>` }]);
      if (/[+/]/.test(data))
        return { type: 'application/agnt-message', data: data.replace(/\+/g, '-').replace(/\//g, '_') };
    }
  })();
  const cases: [string, string][] = [
    ...[
      ['carried message with a media-type parameter', canonicalize({ ...signedQuestion, parts: [file(1)] })],
      [
        'oversized carried file with a media-type parameter',
        canonicalize({ ...signedQuestion, parts: [file(MINIMUM_LIMITS.partBytes + 1)] }),
      ],
      ['unparseable carried bytes are refused', 'not JSON'],
      [
        'a boolean carried version is refused',
        '{\"v\":true,\"parts\":[{\"sha256\":\"' + 'a'.repeat(64) + '\",\"size\":26214401}]}',
      ],
      ['a carried JSON array is refused', '[]'],
      [
        'an unknown carried version names no files',
        canonicalize({ ...signedQuestion, v: 7, parts: [file(MINIMUM_LIMITS.partBytes + 1)] }),
      ],
      [
        'duplicate carried members are refused',
        '{"v":1,"v":1,"parts":[{"sha256":"' + 'a'.repeat(64) + '","size":26214401}]}',
      ],
      [
        'fractional carried numbers are refused',
        '{"v":1,"extra":1.5,"parts":[{"sha256":"' + 'a'.repeat(64) + '","size":26214401}]}',
      ],
    ].map(
      ([name, body]) =>
        [
          name,
          forward([{ type: 'application/agnt-message; profile=forward', data: Buffer.from(body).toString('base64') }]),
        ] as [string, string],
    ),
    [
      'invalid UTF-8 carried bytes are refused',
      forward([
        {
          type: 'application/agnt-message',
          data: Buffer.concat([
            Buffer.from('{"v":1,"extra":"'),
            Buffer.from([0xff]),
            Buffer.from('","parts":[{"sha256":"' + 'a'.repeat(64) + '","size":26214401}]}'),
          ]).toString('base64'),
        },
      ]),
    ],
    [
      'nested carrier media-type matching is case-insensitive and ignores parameters',
      forward([
        carry([
          {
            type: ' APPLICATION/AGNT-MESSAGE ; opaque-parameter',
            data: Buffer.from(
              canonicalize({ ...signedQuestion, parts: [file(MINIMUM_LIMITS.partBytes + 1)] }),
            ).toString('base64'),
          },
        ]),
      ]),
    ],
    [
      'noncanonical nested base64 is refused',
      forward([
        carry([
          {
            type: 'application/agnt-message',
            data:
              Buffer.from(canonicalize({ ...signedQuestion, parts: [file(MINIMUM_LIMITS.partBytes + 1)] })).toString(
                'base64',
              ) + '!',
          },
        ]),
      ]),
    ],
    ['carried file at depth eight', forward(nested(8, 1))],
    ['carried file at depth nine', forward(nested(9, 1))],
    ['oversized carried file at depth eight', forward(nested(8, MINIMUM_LIMITS.partBytes + 1))],
    ['oversized carried file at depth nine', forward(nested(9, MINIMUM_LIMITS.partBytes + 1))],
    ['version 1', canonicalize(signedQuestion)],
    ['version 7 with fields version 1 does not define', canonicalize(version7)],
    ['version 7 from a local part that is not ASCII', v7({ from: 'josé@example.com' })],
    ['version 7 to an address version 1 refuses (a dot at the start)', v7({ to: ['.bob@example.net'] })],
    ['version 7 naming one recipient twice', v7({ to: ['bob@example.net', 'bob@example.net'] })],
    ['version 7 with a signature of any length', v7({ signature: 'AAAA' })],
    ['exactly 262144 bytes', canonicalize(messageOfSize(262144))],
    ['100 recipients', v1({ to: many(100, i => `r${i}@example.net`) })],
    ['32 parts', v1({ parts: many(32, () => ({ type: 'text/plain', data: 'x' })) })],
    ['32 headers', v1({ headers: Object.fromEntries(many(32, i => [`h${i}`, 'x'])) })],
    ['a header name of 64 characters', v1({ headers: { ['h'.repeat(64)]: 'x' } })],
    [
      'a media type of 200 characters',
      v1({ parts: [TEXT, { type: `${'a'.repeat(127)}/${'b'.repeat(72)}`, data: '' }] }),
    ],
    ['Markdown as the only text', v1({ parts: [{ type: 'text/markdown; variant=CommonMark', data: '*Yes.*' }] })],
    ['no parts: a message need carry nothing', v1({ parts: [] })],
    ['only a file, with no text', v1({ parts: [file(1)] })],
    ['only HTML', v1({ parts: [{ type: 'text/html', data: '<p>Yes.</p>' }] })],
    ['text by content address', v1({ parts: [{ type: 'text/plain', sha256: 'a'.repeat(64), size: 1 }] })],
    [
      'a sealed message: its block is ciphertext, carried unchanged',
      v1({
        parts: [{ type: 'application/agnt-sealed', data: Buffer.from('opaque ciphertext').toString('base64') }],
      }),
    ],
    [
      'a forward of a message of 32 parts: the original keeps its parts inside it',
      v1({
        inReplyTo: messageId(question),
        headers: { rel: 'forward' },
        parts: [
          TEXT,
          {
            type: 'application/agnt-message',
            data: Buffer.from(
              canonicalize(fixedSignMessage({ ...question, parts: many(32, () => file(1)) } as Unsigned<Message>, ada)),
            ).toString('base64'),
          },
        ],
      }),
    ],
    ['exactly 1024 files in all, carried inline', forward(many(32, () => carry(many(32, () => file(1)))))],
    [
      'more than 1024 files in all, counting those carried inside carried messages',
      forward([
        ...many(31, () => carry(many(32, () => file(1)))),
        carry([...many(31, () => file(1)), carry(many(32, () => file(1)))]),
      ]),
    ],
    ['a carried file of exactly partBytes', forward([carry([file(MINIMUM_LIMITS.partBytes)])])],
    [
      'files adding up to exactly 32 times partBytes, own and carried',
      forward([file(MINIMUM_LIMITS.partBytes), carry(many(31, () => file(MINIMUM_LIMITS.partBytes)))]),
    ],
    [
      'files adding up to one byte over 32 times partBytes',
      forward([
        file(MINIMUM_LIMITS.partBytes),
        carry(many(31, () => file(MINIMUM_LIMITS.partBytes))),
        carry([file(1)]),
      ]),
    ],
    ['a carried file over partBytes', forward([carry([file(MINIMUM_LIMITS.partBytes + 1)])])],
    ['a carried file with a negative size', forward([carry([file(-5)])])],
    [
      'a carried file with a size that is not a whole number',
      forward([
        {
          type: 'application/agnt-message',
          data: Buffer.from(
            canonicalize({ ...signedQuestion, parts: [file(1)] } as unknown as Json).replace('"size":1', '"size":1.5'),
          ).toString('base64'),
        },
      ]),
    ],
    [
      'a carried file whose sha256 is not 64 lower-case hex',
      forward([carry([{ type: 'application/pdf', sha256: '../../agnt/sync?since=0#', size: 1 }])]),
    ],
    [
      'a carried file over partBytes, two messages deep',
      forward([carry([carry([file(MINIMUM_LIMITS.partBytes + 1)])])]),
    ],
    ['a carried file whose size is written 1.0', forward([carryEdited(t => t.replace('"size":1', '"size":1.0'))])],
    ['a carried file whose size is written 1e3', forward([carryEdited(t => t.replace('"size":1', '"size":1e3'))])],
    [
      'a carried file whose size is NaN, beside one far over partBytes',
      forward([carryEdited(t => t.replace('"size":1', '"size":NaN')), carry([file(99_999_999_999)])]),
    ],
    ['a carried message repeating a key', forward([carryEdited(t => t.replace('"size":1', '"size":1,"size":1'))])],
    ['a carried message not in canonical form', forward([carryEdited(t => t.replace('"size":1', '"size": 1'))])],
    ['a carried message that is not JSON', forward([carryRaw('not json')])],
    ['a carried message that is not an object', forward([carryRaw('[1]')])],
    ['a message carried inside a carried one in base64url', forward([carry([urlSafe])])],
    ['a carried message with no signature', forward([carryWith({ signature: undefined })])],
    ['a carried message whose v is "1"', forward([carryWith({ v: '1' })])],
    ['a carried message whose from is not an address', forward([carryWith({ from: 'ada' })])],
    ['a carried message whose to is not an array', forward([carryWith({ to: 'bob@example.net' })])],
    ['a carried message whose sentAt is not a timestamp', forward([carryWith({ sentAt: 'yesterday' })])],
    ['a carried message of version 7, well formed, naming nothing', forward([carryWith({ v: 7, x: 'later' })])],
    ['messages carried 8 deep, a file within partBytes at the bottom', forward(nested(8, [file(1)]))],
    [
      'messages carried 8 deep, a file over partBytes at the bottom',
      forward(nested(8, [file(MINIMUM_LIMITS.partBytes + 1)])),
    ],
    ['messages carried 9 deep', forward(nested(9, [file(1)]))],
    ['the text after a file', v1({ parts: [file(1), TEXT] })],
    ['a part of exactly partBytes', v1({ parts: [TEXT, file(MINIMUM_LIMITS.partBytes)] })],
    [
      'a name of 255 bytes and an alt of 1024',
      v1({ parts: [{ ...TEXT, name: 'n'.repeat(255), alt: 'a'.repeat(1024) }] }),
    ],
    ['a name in any script', v1({ parts: [TEXT, { ...file(1), name: 'résumé 2026.pdf' }] })],
    ['a part member the reader does not know, ignored', v1({ parts: [{ ...TEXT, lang: 'en' }] })],
    ['a relation', v1({ inReplyTo: messageId(question), headers: { rel: 'reaction' } })],
    ['a relation the registry does not know', v1({ inReplyTo: messageId(question), headers: { rel: 'x-poke' } })],
    [
      'a relation its writer marked listed',
      v1({ inReplyTo: messageId(question), headers: { rel: 'comment', listed: 'yes' } }),
    ],
    [
      'a published message in feeds, with an audience',
      v1({ to: [], headers: { feed: 'posts,travel', audience: 'x' } }),
    ],
    ['a local part of 64 bytes', v1({ to: [`${'b'.repeat(64)}@example.net`] })],
    ['a domain of 253 bytes', v1({ to: [`bob@${domain253}`] })],
    ['a for header naming a phone number', v1({ headers: { for: 'tel:+14155550100' } })],
    ['a critical header', v1({ headers: { critical: 'for,x-thing', 'x-thing': '1' } })],
    ['a key principal with its pairing', canonicalize(keyPaired)],
    [
      'a pairing header a routing server does not verify',
      v1({ headers: { for: `agnt-key:${erin.key}`, pairing: 'AAAA' } }),
    ],
    ['a sentAt in year 0000 (freshness is a later check)', v1({ sentAt: '0000-01-01T00:00:00Z' })],
    [
      'an empty text part, and padded base64',
      v1({
        parts: [
          { type: 'text/plain', data: '' },
          { type: 'image/png', data: 'iVBORw0KGgo=' },
        ],
      }),
    ],

    ['v 0', v7({ v: 0 })],
    ['v -1', v7({ v: -1 })],
    ['v as a string', v7({ v: '1' })],
    ['no v', canonicalize(without(m, 'v'))],
    ['version 7 from an address in upper case', v7({ from: 'Ada@example.com' })],
    ['version 7 from a local part with a space', v7({ from: 'a b@example.com' })],
    ['version 7 with to not an array', v7({ to: 'bob@example.net' })],
    ['version 7 with no signature', canonicalize(without(version7, 'signature'))],
    ['version 7 with an empty signature', v7({ signature: '' })],
    ['version 7 with a sentAt that is not a timestamp', v7({ sentAt: '2026-10-14' })],
    ['version 7 to 101 recipients', v7({ to: many(101, i => `r${i}@example.net`) })],
    [
      'version 7 of 262145 bytes',
      v7({ body: { text: 'x'.repeat(262145 - canonicalize({ ...version7, body: { text: '' } }).length) } }),
    ],
    ['a field version 1 does not define', canonicalize({ ...m, id: 'x' })],
    ['262145 bytes', canonicalize(messageOfSize(262145))],
    ['from a local part that is not ASCII', v1({ from: 'josé@example.com' })],
    ['an address twice in to', v1({ to: ['bob@example.net', 'bob@example.net'] })],
    ['an upper-case address', v1({ to: ['Bob@example.net'] })],
    ['101 recipients', v1({ to: many(101, i => `r${i}@example.net`) })],
    ['a local part of 65 bytes', v1({ to: [`${'b'.repeat(65)}@example.net`] })],
    ['a domain of 254 bytes', v1({ to: [`bob@${domain253}a`] })],
    ['inReplyTo in upper case', v1({ inReplyTo: messageId(question).toUpperCase() })],
    ['a header name with a capital', v1({ headers: { Subject: 'x' } })],
    ['a header name of 65 characters', v1({ headers: { ['h'.repeat(65)]: 'x' } })],
    ['a header value that is not a string', v1({ headers: { subject: 1 } })],
    ['33 headers', v1({ headers: Object.fromEntries(many(33, i => [`h${i}`, 'x'])) })],
    ['a for header without a label', v1({ headers: { for: 'alice@example.org' } })],
    ['a for header with a number that is not E.164', v1({ headers: { for: 'tel:4155550100' } })],
    ['a for header percent-encoded', v1({ headers: { for: 'mailto:alice%40example.org' } })],
    ['a for header naming a key in upper case', v1({ headers: { for: `agnt-key:${erin.key.toUpperCase()}` } })],
    ['a pairing that is not base64url', v1({ headers: { for: `agnt-key:${erin.key}`, pairing: 'AA==' } })],
    ['a key for without a pairing', v1({ headers: { for: `agnt-key:${erin.key}` } })],
    ['a pairing without a for', v1({ headers: { pairing: keyPaired.headers.pairing } })],
    ['a pairing beside a mailto for', v1({ headers: { ...question.headers, pairing: keyPaired.headers.pairing } })],
    ['a critical header with a space', v1({ headers: { critical: 'for, subject' } })],
    ['30 February', v1({ sentAt: '2026-02-30T00:00:00Z' })],
    ['an upper-case media type', v1({ parts: [{ type: 'Text/Plain', data: 'x' }] })],
    ['an upper-case parameter name', v1({ parts: [{ type: 'text/plain; Charset=utf-8', data: 'x' }] })],
    [
      'a media type of 201 characters',
      v1({ parts: [TEXT, { type: `${'a'.repeat(127)}/${'b'.repeat(73)}`, data: '' }] }),
    ],
    ['a subtype of 128 characters', v1({ parts: [TEXT, { type: `text/${'b'.repeat(128)}`, data: '' }] })],
    ['a part one byte over partBytes', v1({ parts: [TEXT, file(MINIMUM_LIMITS.partBytes + 1)] })],
    ['a name of 256 bytes', v1({ parts: [{ ...TEXT, name: 'n'.repeat(256) }] })],
    ['a name that is a path', v1({ parts: [{ ...TEXT, name: '../agenda.pdf' }] })],
    ['a name with a right-to-left override', v1({ parts: [{ ...TEXT, name: 'invoice\u202efdp.exe' }] })],
    ['a name that is ..', v1({ parts: [{ ...TEXT, name: '..' }] })],
    ['an alt of two lines', v1({ parts: [{ ...TEXT, alt: 'two\nlines' }] })],
    ['an empty alt', v1({ parts: [{ ...TEXT, alt: '' }] })],
    ['an alt with a right-to-left override', v1({ parts: [{ ...TEXT, alt: 'agenda\u202efdp.exe' }] })],
    ['a relation to nothing', v1({ headers: { rel: 'reaction' } })],
    ['a relation name in upper case', v1({ inReplyTo: messageId(question), headers: { rel: 'Reaction' } })],
    ['a feed on a message with recipients', v1({ headers: { feed: 'posts' } })],
    ['an audience on a message with recipients', v1({ headers: { audience: 'followers' } })],
    ['feed names with a space', v1({ to: [], headers: { feed: 'posts, travel' } })],
    ['listed on a plain reply, with no rel', v1({ inReplyTo: messageId(question), headers: { listed: 'yes' } })],
    [
      'listed on a relation with an empty to',
      v1({ to: [], inReplyTo: messageId(question), headers: { rel: 'comment', listed: 'yes' } }),
    ],
    ['listed in upper case', v1({ inReplyTo: messageId(question), headers: { rel: 'comment', listed: 'Yes' } })],
    ['listed with another value', v1({ inReplyTo: messageId(question), headers: { rel: 'comment', listed: 'true' } })],
    ['listed empty', v1({ inReplyTo: messageId(question), headers: { rel: 'comment', listed: '' } })],
    ['33 parts', v1({ parts: many(33, () => ({ type: 'text/plain', data: 'x' })) })],
    ['unpadded base64', v1({ parts: [{ type: 'image/png', data: 'QQ' }] })],
    ['base64 with non-zero trailing bits', v1({ parts: [{ type: 'image/png', data: 'QR==' }] })],
    [
      'a part with both data and sha256',
      v1({ parts: [{ type: 'text/plain', data: 'x', sha256: 'a'.repeat(64), size: 1 }] }),
    ],
    ['a part with neither data nor sha256', v1({ parts: [{ type: 'text/plain' }] })],
    ['a negative size', v1({ parts: [{ type: 'application/pdf', sha256: 'a'.repeat(64), size: -1 }] })],
    [
      'a signature with non-zero trailing bits',
      canonicalize({ ...m, signature: withTrailingBits(signedQuestion.signature) }),
    ],
    [
      'a fractional size (no JSON this protocol parses)',
      JSON.stringify({ ...m, parts: [{ type: 'application/pdf', sha256: 'a'.repeat(64), size: 1.5 }] }),
    ],
    ['not in canonical form (the refusal carries the canonical form)', JSON.stringify(signedQuestion, null, 1)],
    [
      'not in canonical form and invalid: the canonical form is checked first',
      JSON.stringify({ ...m, id: 'x' }, null, 1),
    ],
  ];
  return {
    about:
      'Message bodies as sent, and the answer to each under the minimum limits: section 6.3 steps 1, 3 and 4 (parse, canonical form, then the invariants, size, recipients and, for version 1, its own rules: 0 to 32 parts, part members, part sizes within partBytes, and the grammar and placement of the headers the protocol names). field is details.field; canonical is details.canonical.',
    cases: cases.map(([name, bytes]) => ({ name, bytes, ...outcome(() => parseMessage(Buffer.from(bytes))) })),
  };
}

const headerValues = {
  about:
    'The values of four headers the protocol names (section 5.4), and whether each is well formed: for, critical, pairing, and listed, whose only value is yes (placement is in messageChecks). A for header is a principal (section 2.2), written exactly, with nothing percent-encoded.',
  cases: [
    ...[
      'mailto:alice@example.org',
      'mailto:alice+agents@mail.example.org',
      'mailto:a/b?c#d%e@example.org',
      'mailto:alice%40example.org',
      'mailto:alice@example.org?subject=x',
      'mailto:Alice@example.org',
      'mailto:alice@EXAMPLE.org',
      'mailto:alice',
      'mailto:',
      'MAILTO:alice@example.org',
      'alice@example.org',
      'tel:+14155550100',
      'tel:+12',
      'tel:+1',
      'tel:+123456789012345',
      'tel:+1234567890123456',
      'tel:+0123',
      'tel:14155550100',
      'tel:+1-415-555-0100',
      'tel:%2B14155550100',
      'tel:+1%20415',
      `agnt-key:${erin.key}`,
      `agnt-key:${frank.key}`,
      'agnt-key:x-later:AAAA',
      `agnt-key:${erin.key.toUpperCase()}`,
      `AGNT-KEY:${erin.key}`,
      `agnt-key:${erin.key}=`,
      `agnt-key:${erin.key.replace(':', '%3A')}`,
      'agnt-key:',
      'https://example.org',
    ].map(value => ({ header: 'for', value, valid: isPrincipal(value) })),
    ...['for', 'for,x-thing', 'for, x-thing', 'for,', ',for', 'For', ''].map(value => ({
      header: 'critical',
      value,
      valid: isCriticalValue(value),
    })),
    ...[signPairing(erin.privateKey, 'bob@example.net', `agnt-key:${erin.key}`), 'AA', 'AB', 'AA==', ''].map(value => ({
      header: 'pairing',
      value,
      valid: isB64url(value),
    })),
    ...['yes', 'Yes', 'YES', 'yes ', 'true', 'no', ''].map(value => ({
      header: 'listed',
      value,
      valid: isListedValue(value),
    })),
  ],
};

/** Pairings by key principals (sections 2.2 and 5.4), for both algorithms. */
function pairings() {
  const pair = (agent: string, k: FixedKey, signedAgent = agent, signedPrincipal = `agnt-key:${k.key}`) => {
    const principal = `agnt-key:${k.key}`;
    const pairing = fixedSign(k, pairingBytes(signedAgent, signedPrincipal));
    return {
      agent,
      principal,
      bytes: pairingBytes(agent, principal),
      pairing,
      verifies: verifyPairing(agent, principal, pairing),
    };
  };
  return {
    about:
      "Pairings (sections 2.2 and 5.4): bytes is AGNT-PAIR, the agent address and the principal, joined by newlines; pairing is the principal key's signature, the value of the pairing header; verifies is whether it verifies for this agent and principal.",
    cases: [
      { why: 'an Ed25519 principal', ...pair('bob@example.net', erin) },
      { why: 'an ML-DSA-65 principal', ...pair('bob@example.net', frank) },
      { why: 'signed for another agent', ...pair('bob@example.net', erin, 'ada@example.com') },
      {
        why: 'signed for another principal',
        ...pair('bob@example.net', erin, 'bob@example.net', 'mailto:erin@example.org'),
      },
    ],
  };
}

/**
 * Signatures over the question that a verifier must refuse though the bare equation can be made to hold, and
 * the verdicts a key of mixed order gets.
 */
function signatures() {
  const bytes = signingBytes('AGNT-MESSAGE', signedQuestion);
  const sig = Buffer.from(signedQuestion.signature, 'base64url');
  const A = raw(ada.key);
  const a = scalarOf(Buffer.from(ada.seed, 'hex'));
  /** R chosen freely, with S making [S]B − [k]A the identity, whose encoding is 01 00 ... 00. */
  const toIdentity = (r: Buffer) => b64url(signature(r, challenge(r, A, bytes) * a));
  const identity = toLE(1n);
  const signedIdentity = Buffer.from(identity);
  signedIdentity[31] |= 0x80;

  // Mixed order: A' = A + T with T of order 8, so [S]B − [k]A' = R − [k]T, which is R exactly when 8 divides k.
  const mixed = raw(mixedOrderKey);
  const mixedSignature = (wantDivisible: boolean) => {
    for (let i = 0; ; i++) {
      const nonce = fixedKey(`mixed-order nonce ${i}`);
      const R = raw(nonce.key);
      const k = challenge(R, mixed, bytes);
      if ((k % 8n === 0n) === wantDivisible) {
        return b64url(signature(R, scalarOf(Buffer.from(nonce.seed, 'hex')) + k * a));
      }
    }
  };
  const sentAt = question.sentAt;
  return {
    about:
      'Signature verification (sections 2.3 and 2.4), over the signingBytes of the message named. keyValidAt: the verdict with the key entries given. refused: signatures every verifier refuses with the author key, though [S]B - [k]A = R holds as points or holds after multiplying by the cofactor. mixedOrder: verdicts with a key of mixed order, which must agree across verifiers.',
    message: 'question with a for header',
    keyValidAt: [
      { keys: [keyEntry(ada.key)], verifies: true },
      { keys: [keyEntry(carol.key), keyEntry(ada.key)], verifies: true, why: 'each key of the signer is tried' },
      {
        keys: [keyEntry(ada.key, at(sentAt, 300_000))],
        verifies: true,
        why: 'added 300 s after sentAt: inside the clock tolerance',
      },
      { keys: [keyEntry(ada.key, at(sentAt, 301_000))], verifies: false, why: 'added more than 300 s after sentAt' },
      {
        keys: [keyEntry(ada.key, '2026-10-01T00:00:00Z', at(sentAt, 1))],
        verifies: true,
        why: 'revoked one millisecond after sentAt',
      },
      { keys: [keyEntry(ada.key, '2026-10-01T00:00:00Z', sentAt)], verifies: false, why: 'revoked at sentAt exactly' },
      { keys: [keyEntry(bob.key)], verifies: false, why: 'another key' },
      { keys: [keyEntry(carol.key)], verifies: false, why: 'a key whose signatures are another length' },
    ],
    refused: [
      {
        signature: b64url(Buffer.concat([sig.subarray(0, 32), toLE(fromLE(sig.subarray(32)) + L)])),
        why: 'S is not below the group order',
      },
      {
        signature: toIdentity(identity),
        why: 'R is the identity, a point of small order, and the equation holds exactly',
      },
      { signature: toIdentity(toLE(P + 1n)), why: 'R is the identity written non-canonically (y = p + 1)' },
      { signature: toIdentity(signedIdentity), why: 'R is the identity with the sign bit set' },
      { signature: b64url(sig.subarray(0, 63)), why: '63 bytes' },
    ],
    mixedOrder: {
      key: mixedOrderKey,
      cases: [
        { signature: mixedSignature(true), verifies: true, why: '8 divides k, so [S]B - [k]A equals R exactly' },
        {
          signature: mixedSignature(false),
          verifies: false,
          why: '8 does not divide k: a verifier that multiplies by the cofactor would accept, and must not',
        },
      ],
    },
  };
}

/** Requests: signing strings, and what a server answers to each header and window. */
async function requests() {
  const now = Date.parse(NOW);
  const timestamp = String(now / 1000);
  const nonce = 'n0nce-0123456789';
  const sendBody = canonicalize(signedQuestion);
  /** A request signed by `k`, acting as `as`: an agent's address, or with `server` a server's origin. */
  const signed = (
    method: string,
    target: string,
    body: string,
    k: FixedKey,
    as: string,
    server = false,
    origin = ORIGIN,
  ) => {
    const signingString = requestSigningString({ method, origin, actor: as, target, timestamp, nonce, body });
    const headers: SignedHeaders = {
      'agnt-key': k.key,
      'agnt-timestamp': timestamp,
      'agnt-nonce': nonce,
      'agnt-signature': fixedSign(k, signingString),
      ...(server ? { 'agnt-server': as } : { 'agnt-agent': as }),
    };
    return { method, origin, actor: as, target, timestamp, nonce, body, signingString, headers };
  };

  const sync = '/agnt/sync?since=0';
  /** A version 1 address holding every character that is not a pchar, and so is percent-encoded in a path. */
  const oddAddress = 'a#b%c/d?e^f`g{h|i}j@example.com';
  const asAda = 'ada@example.com';
  const ok = signRequest(ada.privateKey, { method: 'GET', url: ORIGIN + sync, now, nonce, agent: asAda });
  const twelve = `00${timestamp}`;
  const twelveDigits = {
    ...ok,
    'agnt-timestamp': twelve,
    'agnt-signature': fixedSign(
      ada,
      requestSigningString({
        method: 'GET',
        origin: ORIGIN,
        actor: asAda,
        target: sync,
        timestamp: twelve,
        nonce,
        body: '',
      }),
    ),
  };
  const withNonce = (n: string) =>
    signRequest(ada.privateKey, { method: 'GET', url: ORIGIN + sync, now, nonce: n, agent: asAda });
  const peer = 'https://agnt.example.net';
  const peerKey = fixedKey('server https://agnt.example.net');
  const partTarget = `/agnt/parts/${'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}`;
  const serverRequest = signRequest(peerKey.privateKey, {
    method: 'GET',
    url: ORIGIN + partTarget,
    now,
    nonce,
    server: peer,
  });
  type Case = {
    name: string;
    headers: Record<string, string>;
    target?: string;
    server?: boolean;
    now?: string;
    entry?: KeyEntry | null;
    nonceSeen?: boolean;
  };
  const cases: Case[] = [
    { name: 'well formed', headers: { ...ok } },
    { name: 'the timestamp 300 s behind', headers: { ...ok }, now: at(NOW, 300_000) },
    { name: 'the timestamp 300 s ahead', headers: { ...ok }, now: at(NOW, -300_000) },
    { name: 'a nonce of 8 characters', headers: { ...withNonce('!1234567') } },
    { name: 'a nonce of 128 characters', headers: { ...withNonce('~'.repeat(128)) } },
    {
      name: 'a server request',
      headers: { ...serverRequest },
      target: partTarget,
      server: true,
      entry: keyEntry(peerKey.key),
    },
    { name: 'no agnt-key', headers: { ...ok, 'agnt-key': undefined as never } },
    { name: 'agnt-key not a key token', headers: { ...ok, 'agnt-key': raw(ada.key).toString('base64url') } },
    { name: 'a timestamp of 12 digits, with leading zeros', headers: { ...twelveDigits } },
    { name: 'a timestamp of 13 digits', headers: { ...ok, 'agnt-timestamp': `000${timestamp}` } },
    { name: 'a timestamp with a sign', headers: { ...ok, 'agnt-timestamp': `+${timestamp}` } },
    { name: 'a nonce of 7 characters', headers: { ...ok, 'agnt-nonce': '1234567' } },
    { name: 'a nonce of 129 characters', headers: { ...ok, 'agnt-nonce': '~'.repeat(129) } },
    { name: 'a nonce with a space', headers: { ...ok, 'agnt-nonce': 'n0nce 0123456789' } },
    { name: 'a signature in padded base64', headers: { ...ok, 'agnt-signature': `${ok['agnt-signature']}==` } },
    {
      name: 'a server request without agnt-server',
      headers: { ...ok, 'agnt-agent': undefined as never },
      server: true,
    },
    { name: 'an agent request without agnt-agent', headers: { ...ok, 'agnt-agent': undefined as never } },
    { name: 'agnt-agent not an address', headers: { ...ok, 'agnt-agent': 'ada' } },
    { name: 'agnt-agent in upper case', headers: { ...ok, 'agnt-agent': 'Ada@example.com' } },
    { name: 'both agnt-agent and agnt-server', headers: { ...ok, 'agnt-server': 'https://agnt.example.net' } },
    { name: 'a signature made as another agent', headers: { ...ok, 'agnt-agent': 'bob@example.com' } },
    {
      name: 'agnt-server not an origin',
      headers: { ...serverRequest, 'agnt-server': `${peer}/x` },
      target: partTarget,
      server: true,
    },
    {
      name: 'agnt-server an origin not serialised: upper case and a trailing slash',
      headers: { ...serverRequest, 'agnt-server': 'HTTPS://AGNT.example.net/' },
      target: partTarget,
      server: true,
    },
    {
      name: 'agnt-server an origin not serialised: the default port',
      headers: { ...serverRequest, 'agnt-server': `${peer}:443` },
      target: partTarget,
      server: true,
    },
    { name: 'the timestamp 301 s behind', headers: { ...ok }, now: at(NOW, 301_000) },
    { name: 'the timestamp 301 s ahead', headers: { ...ok }, now: at(NOW, -301_000) },
    { name: 'a nonce used before', headers: { ...ok }, nonceSeen: true },
    {
      name: 'stale and replayed: the window is checked first',
      headers: { ...ok },
      now: at(NOW, 301_000),
      nonceSeen: true,
    },
    {
      name: 'stale and badly signed: the window is checked first',
      headers: { ...ok },
      target: '/agnt/sync?since=1',
      now: at(NOW, 301_000),
    },
    {
      name: 'replayed and badly signed: the signature is checked before the nonce',
      headers: { ...ok },
      target: '/agnt/sync?since=1',
      nonceSeen: true,
    },
    {
      name: 'replayed by an unknown key: the key is checked before the nonce',
      headers: { ...ok },
      entry: null,
      nonceSeen: true,
    },
    { name: 'a key the server does not know', headers: { ...ok }, entry: null },
    {
      name: 'a key revoked before now',
      headers: { ...ok },
      entry: keyEntry(ada.key, '2026-10-01T00:00:00Z', '2026-10-14T20:00:00Z'),
    },
    { name: 'a key added after now', headers: { ...ok }, entry: keyEntry(ada.key, at(NOW, 301_000)) },
    { name: 'a signature over another target', headers: { ...ok }, target: '/agnt/sync?since=1' },
  ];
  const checked = cases.map(async c => {
    const target = c.target ?? sync;
    const when = new Date(c.now ?? NOW);
    const entry = c.entry === undefined ? keyEntry(ada.key) : c.entry;
    const nonceSeen = c.nonceSeen ?? false;
    const headers = Object.fromEntries(Object.entries(c.headers).filter(([, v]) => v !== undefined));
    let answer: Record<string, unknown> = { accepted: true };
    try {
      const h = readSignedHeaders(headers, when, { server: c.server ?? false, agent: !c.server });
      await checkSignedRequest({ method: 'GET', origin: ORIGIN, actor: actorOf(headers), target, body: '' }, h, {
        now: when,
        entry,
        nonceSeen: () => nonceSeen,
      });
    } catch (e) {
      if (!(e instanceof WireError)) throw e;
      answer = { status: e.status, code: e.code, details: e.details };
    }
    return {
      name: c.name,
      request: { method: 'GET', origin: ORIGIN, actor: actorOf(headers), target, body: '', headers },
      server: c.server ?? false,
      agent: !c.server,
      now: when.toISOString(),
      entry,
      nonceSeen,
      ...answer,
    };
  });

  const proof = (address: string, k: FixedKey) => {
    const string = addKeyProofString(address, k.key);
    return { address, key: k.key, string, proof: fixedSign(k, string) };
  };
  return {
    about:
      'Signed requests (section 8). signed: requests, the eight-line signing string the server rebuilds (its fourth line is actor, the value of agnt-agent or agnt-server), and headers whose signature verifies with agnt-key. checks: what a server answers to each request at now, given the key entry it holds for agnt-key (null: none), whether it holds the nonce from this key (a server keeps a nonce until the timestamp of its request leaves the window), and whether it is a server request (server: agnt-server required) or an agent request (agent: agnt-agent required); request.actor is the identity line the server signs over. The refusals come in the order of section 8: headers, window, key, validity, signature, and only then the nonce. details are as the server sends them. nonces: until when a server keeps a nonce, given the agnt-timestamp of its request: the first moment that timestamp is outside the window, checked in whole seconds. addKeyProofs: the proof a new key signs (CLIENT.md, register). signedFor: the origin line a request to a server whose origin is written as given signs, the serialised origin (section 3); agnt-server carries the same form, and any other is refused. addressSegments: an address as one path segment: every byte that is not an RFC 3986 pchar percent-encoded with upper-case hex, @ literal; a server reads the target exactly as sent, before any decoding.',
    signed: [
      signed('POST', '/agnt/send', sendBody, ada, asAda),
      signed('GET', sync, '', ada, asAda),
      signed(
        'GET',
        '/agnt/agents/ada%2Fops@example.com?q=%2f%2F',
        '',
        ada,
        asAda,
        false,
        'HTTPS://AGNT.EXAMPLE.COM:443/',
      ),
      signed('GET', `/agnt/sent/${messageId(question)}`, '', carol, 'carol@example.org'),
      signed('GET', partTarget, '', peerKey, peer, true),
      signed('GET', `/agnt/feeds/${addressSegment(oddAddress)}/posts`, '', ada, asAda),
    ],
    signedFor: [
      'HTTPS://AGNT.Example.COM/',
      'https://agnt.example.com:443',
      'https://agnt.example.com',
      'https://agnt.example.com:8443/',
      'HTTPS://agnt.example.com:08443',
    ].map(written => ({ written, origin: serverOrigin(written) })),
    addressSegments: [
      'ada@example.com',
      oddAddress,
      "!$&'*+=~.-_@example.com",
      'a.b@example.com',
      `${'x'.repeat(64)}@example.com`,
    ].map(address => ({ address, segment: addressSegment(address) })),
    checks: await Promise.all(checked),
    nonces: [timestamp, '1', '000000000001'].map(t => ({
      timestamp: t,
      keptUntil: new Date(nonceExpiry(t)).toISOString(),
    })),
    addKeyProofs: [proof('ada@example.com', bob), proof('ada@example.com', carol)],
  };
}

const serverKeys = [keyEntry(exampleCom.key)];

function documents() {
  const doc = serverDocument(ORIGIN, serverKeys);
  const padTo = (size: number) => {
    const empty = text({ ...doc, pad: '' }).length;
    return text({ ...doc, pad: 'x'.repeat(size - empty) });
  };
  const server: [string, string, string?][] = [
    ['as served', text(doc)],
    ['with members readers do not know, the old v among them', text({ v: 1, ...doc, contact: 'ops@example.com' })],
    [
      'naming its origin with a default port and a trailing slash',
      text({ ...doc, server: 'https://AGNT.example.com:443/' }),
    ],
    ['with whitespace, as JSON may have', JSON.stringify(doc, null, 2)],
    [
      'with raised limits, and a limit readers do not know',
      text({ ...doc, limits: { ...MINIMUM_LIMITS, messageBytes: 1048576, parts: 64 } }),
    ],
    [
      'with an ML-DSA-65 key and a key of a later algorithm',
      text({ ...doc, keys: [...serverKeys, keyEntry(carol.key), { key: 'x-later:AAAA', added: NOW, revoked: null }] }),
    ],
    ['of exactly 131072 bytes', padTo(131072)],
    ['naming another server', text({ ...doc, server: 'https://other.example.com' })],
    ['fetched from another origin', text(doc), 'https://agnt.example.net'],
    ['with no server', text(without(doc, 'server'))],
    ['with a limit below its minimum', text({ ...doc, limits: { ...MINIMUM_LIMITS, recipients: 99 } })],
    ['with a limit missing', text({ ...doc, limits: { messageBytes: 262144, recipients: 100, partBytes: 26214400 } })],
    ['with a limit written as a string', text({ ...doc, limits: { ...MINIMUM_LIMITS, partBytes: '26214400' } })],
    ['with no limits', text({ server: ORIGIN, keys: serverKeys, algorithms: doc.algorithms })],
    ['with no algorithms', text(without(doc, 'algorithms'))],
    [
      'listing algorithms in another order, and one readers do not know',
      text({ ...doc, algorithms: ['x-later', 'ml-dsa-65', 'ed25519'] }),
    ],
    ['listing only ed25519', text({ ...doc, algorithms: ['ed25519'] })],
    ['with algorithms as one string', text({ ...doc, algorithms: 'ed25519,ml-dsa-65' })],
    ['with an algorithm name in upper case', text({ ...doc, algorithms: ['ed25519', 'ML-DSA-65'] })],
    ['with 33 keys', text({ ...doc, keys: many(33, () => keyEntry(exampleCom.key)) })],
    [
      'with 33 keys, one revoked before now',
      text({ ...doc, keys: [...many(32, () => keyEntry(exampleCom.key)), keyEntry(carol.key, NOW, at(NOW, -1))] }),
    ],
    [
      'with 33 keys, one revoked within 300 s after now',
      text({ ...doc, keys: [...many(32, () => keyEntry(exampleCom.key)), keyEntry(carol.key, NOW, at(NOW, 299_000))] }),
    ],
    [
      'with a key revoked far in the future',
      text({ ...doc, keys: [...serverKeys, keyEntry(carol.key, NOW, '2099-01-01T00:00:00Z')] }),
    ],
    ['with a malformed key', text({ ...doc, keys: [keyEntry(ed25519(offCurve()))] })],
    ['of 131073 bytes', padTo(131073)],
    ['repeating a member', text(doc).replace('{', '{"server":"https://agnt.example.com",')],
    ['an array', text([doc])],
  ];

  const signedBy = (d: Record<string, unknown>, k: FixedKey = exampleCom) =>
    signAgentDocument(d as unknown as UnsignedAgentDocument, k.privateKey);
  const ada1 = { address: 'ada@example.com', kind: 'paired', keys: [keyEntry(ada.key)] };
  const agent = signedBy(ada1);
  const solo = { address: 'carol@example.org', kind: 'solo', keys: [keyEntry(carol.key)] };
  const revoked = [keyEntry(exampleCom.key, '2026-10-01T00:00:00Z', '2026-10-14T00:00:00Z')];
  const RETIRED = '2026-10-14T09:00:00Z';
  const retired = (extra: KeyEntry[] = []) => ({
    ...ada1,
    retired: RETIRED,
    keys: [...extra, keyEntry(ada.key, '2026-10-01T00:00:00Z', RETIRED)],
  });
  const retiredUnpairing = fixedSign(erin, unpairingBytes('ada@example.com', erinPrincipal));
  const agentCases: [string, string, string, KeyEntry[]?][] = [
    ['as served: a paired agent', text(agent), 'ada@example.com'],
    ['a solo agent with an ML-DSA-65 key', text(signedBy(solo)), 'carol@example.org'],
    ['of a kind readers do not know', text(signedBy({ ...ada1, kind: 'group' })), 'ada@example.com'],
    [
      'with a member readers do not know, under the signature',
      text(signedBy({ ...ada1, avatar: 'https://example.com/a.png' })),
      'ada@example.com',
    ],
    ['with no kind', text(signedBy({ address: ada1.address, keys: ada1.keys })), 'ada@example.com'],
    ['with a kind that is not a string', text(signedBy({ ...ada1, kind: 1 })), 'ada@example.com'],
    ['naming another address', text(agent), 'bob@example.net'],
    ['asked for in another case', text(agent), 'Ada@example.com'],
    ['with a member added after signing', text({ ...agent, note: 'x' }), 'ada@example.com'],
    ['signed by a key not the server’s', text(signedBy(ada1, ada)), 'ada@example.com'],
    ['signed by a server key revoked before now', text(agent), 'ada@example.com', revoked],
    ['with no signature', text(ada1), 'ada@example.com'],
    ['a retired document', text(signedBy(retired())), 'ada@example.com'],
    [
      'a retired document with the unpairing that retired it',
      text(signedBy({ ...retired(), unpairing: retiredUnpairing })),
      'ada@example.com',
    ],
    [
      'a retired document listing a key revoked before it retired',
      text(signedBy(retired([keyEntry(carol.key, '2026-10-01T00:00:00Z', '2026-10-05T00:00:00Z')]))),
      'ada@example.com',
    ],
    ['a retired document with a key not revoked', text(signedBy(retired([keyEntry(carol.key)]))), 'ada@example.com'],
    [
      'a retired document with a key revoked after it retired',
      text(signedBy(retired([keyEntry(carol.key, '2026-10-01T00:00:00Z', at(RETIRED, 1000))]))),
      'ada@example.com',
    ],
    [
      'a retired document whose retired is not a timestamp',
      text(signedBy({ ...retired(), retired: '2026-10-14' })),
      'ada@example.com',
    ],
    [
      'a retired document whose unpairing is not a string',
      text(signedBy({ ...retired(), unpairing: 1 })),
      'ada@example.com',
    ],
    [
      'a retired document whose unpairing is not base64url',
      text(signedBy({ ...retired(), unpairing: 'not base64url' })),
      'ada@example.com',
    ],
  ];
  return {
    about:
      'Documents (section 4) as fetched bytes. server: what a reader reads at now from each body fetched from origin, or null (its keys read as keyLists says); a server document needs its algorithms, every one it verifies and both of version 1 among them, and its four limits. agent: what a reader reads from each body when it asked for address, holding the server keys given, at now; null when it refuses the document. A kind the reader does not know reads as "unknown". A retired document (a retired address’s) reads with its retired and its unpairing when it has one; it is unreadable unless retired is a timestamp, unpairing when present a base64url string, and every key revoked at or before retired.',
    now: NOW,
    server: server.map(([name, body, origin = ORIGIN]) => ({
      name,
      origin,
      body,
      read: readServerDocument(Buffer.from(body), origin, new Date(NOW)),
    })),
    agent: agentCases.map(([name, body, address, keys = serverKeys]) => ({
      name,
      address,
      serverKeys: keys,
      body,
      ...(name.startsWith('as served') && { signingBytes: signingBytes('AGNT-AGENT', agent).toString('utf8') }),
      read: readAgentDocument(Buffer.from(body), address, keys, new Date(NOW)),
    })),
  };
}

const actsFor: ActsForClaim = {
  type: 'acts-for',
  agent: 'ada@example.com',
  for: 'mailto:alice@example.org',
  scope: ['converse', 'schedule'],
  verifiedAt: '2026-09-01T00:00:00Z',
};

/** The registry's identifier claim about an agent (ada@example.com by default), or about its principal. */
const identifierOf = (of: string, identifier: string, agent = 'ada@example.com'): Claim => ({
  type: 'identifier',
  agent,
  of,
  identifier,
  verifiedAt: '2026-09-01T00:00:00Z',
});

/** The server the envelopes are for: bob@example.net's. */
const RECEIVER = { origin: 'https://agnt.example.net', serves: ['example.net'] };
const receiver = { origin: RECEIVER.origin };
const forBob = { server: RECEIVER.origin, recipients: ['bob@example.net'] };

function envelopes() {
  const signed = (e: Record<string, unknown>) => canonicalize(signEnvelope(e as never, exampleCom.privateKey));
  const message = signedQuestion;
  const toTwo = fixedSignMessage<Message>({ ...question, to: ['bob@example.net', 'dan@example.org'] }, ada);
  const extrasBase = canonicalize({ claims: [], hints: { 'bob@example.net': { pad: '' } } }).length;
  const hintsOf = (n: number) => ({ 'bob@example.net': { pad: 'x'.repeat(n - extrasBase) } });
  /** Signed as an envelope, but with whatever claimsSignature it carries, or none. */
  const raw = (e: Record<string, unknown>) =>
    canonicalize({ ...e, signature: sign(exampleCom.privateKey, signingBytes('AGNT-ENVELOPE', e)) });
  const besideBase = canonicalize({ ...forBob, signature: 'x'.repeat(86), pad: '' }).length;
  const accepted: [string, string][] = [
    [
      'with claims and hints',
      signed({ message, ...forBob, claims: [actsFor], hints: { 'bob@example.net': { invite: '7KQ2-XK4P-M9DA' } } }),
    ],
    ['with neither (absent members are not signed)', signed({ message, ...forBob })],
    [
      'with claims and hints present and empty (they are signed)',
      signed({ message, ...forBob, claims: [], hints: {} }),
    ],
    [
      'with a member version 1 does not define (it is signed)',
      signed({ message, ...forBob, route: ['https://relay.example.com'] }),
    ],
    [
      'naming its server in another spelling of the same origin',
      signed({ message, ...forBob, server: 'https://AGNT.example.net:443/' }),
    ],
    ['for one of two servers the message goes to', signed({ message: toTwo, ...forBob })],
    ['carrying a version 7 message', signed({ message: version7, ...forBob })],
    ['with 16 claims', signed({ message, ...forBob, claims: many(16, () => actsFor) })],
    ['with claims and hints of exactly 16384 canonical bytes', signed({ message, ...forBob, hints: hintsOf(16384) })],
    [
      'with everything beside the message at exactly 32768 canonical bytes',
      signed({ message, ...forBob, pad: 'x'.repeat(32768 - besideBase) }),
    ],
    [
      'not itself canonical, around a canonical message',
      signed({ message, ...forBob }).replace('{"message":', '{ "message" :'),
    ],
  ];
  const refused: [string, string][] = [
    ['no server', signed({ message, recipients: forBob.recipients })],
    ['a server that is not an origin', signed({ message, ...forBob, server: 'https://agnt.example.net/deliver' })],
    ['a server over http', signed({ message, ...forBob, server: 'http://agnt.example.net' })],
    ['no recipients', signed({ message, server: forBob.server })],
    ['empty recipients', signed({ message, ...forBob, recipients: [] })],
    ['a recipient twice', signed({ message, ...forBob, recipients: ['bob@example.net', 'bob@example.net'] })],
    ['a recipient that is not an address', signed({ message, ...forBob, recipients: ['bob'] })],
    ['a recipient in upper case', signed({ message, ...forBob, recipients: ['Bob@example.net'] })],
    ['claims null', signed({ message, ...forBob, claims: null })],
    ['hints null', signed({ message, ...forBob, hints: null })],
    ['claims an object', signed({ message, ...forBob, claims: {} })],
    ['17 claims', signed({ message, ...forBob, claims: many(17, () => actsFor) })],
    ['a claim with an empty type', signed({ message, ...forBob, claims: [{ ...actsFor, type: '' }] })],
    ['a claim with no type', signed({ message, ...forBob, claims: [{ agent: 'ada@example.com' }] })],
    [
      'a hint for an address in to but not in recipients',
      signed({ message: toTwo, ...forBob, hints: { 'dan@example.org': { invite: 'x' } } }),
    ],
    ['a hint for an address not in to', signed({ message, ...forBob, hints: { 'eve@example.net': { invite: 'x' } } })],
    ['a hint keyed by another case', signed({ message, ...forBob, hints: { 'Bob@example.net': { invite: 'x' } } })],
    ['a hint value that is not a string', signed({ message, ...forBob, hints: { 'bob@example.net': { n: 1 } } })],
    ['claims and hints of 16385 canonical bytes', signed({ message, ...forBob, hints: hintsOf(16385) })],
    ['claims without their claimsSignature', raw({ message, ...forBob, claims: [actsFor] })],
    ['a claimsSignature without claims', raw({ message, ...forBob, claimsSignature: 'AAAA' })],
    ['a message that is not an object', signed({ message: canonicalize(message), ...forBob })],
    ['no signature', canonicalize({ message, ...forBob })],
    ['an envelope that is an array', canonicalize([signEnvelope({ message, ...forBob }, exampleCom.privateKey)])],
    ['a message not in canonical form', signed({ message, ...forBob }).replace('"from":', '"from" :')],
    ['a version 1 message with a field it does not define', signed({ message: { ...message, id: 'x' }, ...forBob })],
    ['a message of version 0', signed({ message: { ...version7, v: 0 }, ...forBob })],
    [
      'not JSON this protocol parses (a repeated member)',
      signed({ message, ...forBob }).replace('{"message":', '{"route":1,"route":2,"message":'),
    ],
    ['for another server (step 5)', signed({ message, ...forBob, server: 'https://agnt.example.org' })],
    ['a recipient not in to (step 5)', signed({ message, ...forBob, recipients: ['carol@example.net'] })],
    [
      'claims whose claimsSignature is over other claims (step 7)',
      raw({
        message,
        ...forBob,
        claims: [{ ...actsFor, scope: ['commit'] }],
        claimsSignature: sign(exampleCom.privateKey, claimsBytes([actsFor], messageId(message))),
      }),
    ],
    [
      'a recipient on a domain this server does not serve (step 8, after the signature)',
      signed({ message: toTwo, ...forBob, recipients: ['bob@example.net', 'dan@example.org'] }),
    ],
    [
      'for another server and with an invalid message: the message is checked first',
      signed({ message: { ...message, id: 'x' }, ...forBob, server: 'https://agnt.example.org' }),
    ],
  ];
  const parse = (bytes: string) => {
    const e = parseEnvelope(Buffer.from(bytes), MINIMUM_LIMITS, receiver);
    checkEnvelopeSignature(e, serverKeys, new Date(NOW));
    checkServed(e.recipients, d => RECEIVER.serves.includes(d));
    return e;
  };
  return {
    about:
      'Envelopes (section 6) as posted to receiver, the server at origin that serves the domains listed, from the carrier whose keys are serverKeys. accepted: each passes section 6.3 steps 1 to 5, 7 and 8 there at now; signingBytes is AGNT-ENVELOPE, a newline, and the canonical envelope without signature, and claimsSigningBytes, for an envelope with claims, is AGNT-CLAIMS, a newline, and the canonical {"claims","message":<id>}. refused: the answer to each, under the minimum limits, in the order of steps 1 to 5, 7 and 8 (step 6 resolves the carrier, which these vectors fix): field is details.field.',
    now: NOW,
    serverKeys,
    receiver: RECEIVER,
    accepted: accepted.map(([name, bytes]) => {
      const e = parse(bytes);
      return {
        name,
        bytes,
        signingBytes: signingBytes('AGNT-ENVELOPE', e).toString('utf8'),
        ...(e.claims && { claimsSigningBytes: claimsBytes(e.claims, messageId(e.message)).toString('utf8') }),
      };
    }),
    refused: refused.map(([name, bytes]) => ({ name, bytes, ...outcome(() => parse(bytes)) })),
  };
}

/** Steps 7 and 11 at deliver: signatures there are 403, unlike a request's (section 8), which are 401. */
function deliverSignatures() {
  const later = { key: 'x-later:AAAA', added: '2026-10-01T00:00:00Z', revoked: null };
  const authorCases: [string, KeyEntry[]][] = [
    ["the author's key", [keyEntry(ada.key)]],
    ["the author's key beside one of an algorithm not implemented", [later, keyEntry(ada.key)]],
    ['another Ed25519 key', [keyEntry(bob.key)]],
    ['only an ML-DSA-65 key: one to try, so the signature is bad', [keyEntry(carol.key)]],
    ['only a key of an algorithm not implemented', [later]],
    [
      "the author's key revoked before sentAt, beside one of an algorithm not implemented",
      [later, keyEntry(ada.key, '2026-10-01T00:00:00Z', '2026-10-02T00:00:00Z')],
    ],
    ["the author's key added more than 300 s after sentAt", [keyEntry(ada.key, at(question.sentAt, 301_000))]],
    ['no keys at all', []],
  ];
  const envelope = signEnvelope({ message: signedQuestion, ...forBob }, exampleCom.privateKey);
  const envelopeCases: [string, KeyEntry[]][] = [
    ["the carrier's key", serverKeys],
    ["a key that is not the carrier's", [keyEntry(ada.key)]],
    [
      "the carrier's key revoked before now",
      [keyEntry(exampleCom.key, '2026-10-01T00:00:00Z', '2026-10-14T00:00:00Z')],
    ],
  ];
  return {
    about:
      "Signature failures at deliver (section 6.3) are 403, where a request's (section 8) are 401. author: the answer to step 11 for the message named, given the author's key entries (an entry of an algorithm not implemented is skipped): 403 unsupported_algorithm when no key valid at sentAt is of an algorithm the server implements, so nothing could be tried, else 403 bad_signature unless one verifies. envelope: the answer to step 7 for the envelope given, with the carrier key entries given, at now.",
    message: 'question with a for header',
    now: NOW,
    author: authorCases.map(([name, keys]) => ({
      name,
      keys,
      ...outcome(() => checkAuthorSignature(signedQuestion, keys)),
    })),
    envelope: {
      bytes: canonicalize(envelope),
      cases: envelopeCases.map(([name, keys]) => ({
        name,
        keys,
        ...outcome(() => checkEnvelopeSignature(envelope, keys, new Date(NOW))),
      })),
    },
  };
}

/** Error answers as sent (section 9). */
function problems() {
  const now = new Date(NOW);
  const examples: [string, WireError][] = [
    ['a stale message at deliver', invalid('sentAt is more than 144 hours old.', { field: 'sentAt' })],
    [
      'a request signature that does not verify',
      unauthorized('bad_signature', 'The signature does not verify over the signing string.', now, {
        signingString:
          'AGNT-REQUEST\nGET\nhttps://agnt.example.com\nada@example.com\n/agnt/sync?since=0\n1792011600\nn0nce-0123456789\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      }),
    ],
    ['an envelope signature that does not verify', forbidden('bad_signature', 'The envelope does not verify.')],
    ['an author with no key this server can verify', forbidden('unsupported_algorithm', 'No key to try.')],
    ['send of a version the server does not implement', unsupportedVersion(7)],
    ['a body too large', bodyTooLarge(1048576)],
    ['rate limited', new WireError(429, 'rate_limited', 'Too many requests; retry in 30 s.', { retryAfter: 30 })],
    ['a lookup that failed just now', new WireError(503, 'unavailable', "The author's server did not answer.")],
  ];
  return {
    about:
      'Errors (section 9) as sent: RFC 9457 problem details, application/problem+json, with code, retryable (true exactly for 429 and 5xx) and optional details. title is the code in words, since the type is about:blank. Every 401 carries WWW-Authenticate: AGNT, and details.serverTime. A 429 carries Retry-After; this implementation also gives the seconds as details.retryAfter, a convention, not a rule. detail is English and may change; a reader acts on status, code and retryable.',
    cases: examples.map(([name, e]) => ({ name, status: e.status, headers: e.headers, body: e.toProblem() })),
  };
}

/** The send rule a paired or solo agent's own server applies (sections 2.2 and 5.4); the messages are all valid. */
function principals() {
  const sign = (m: Record<string, Json>, k: FixedKey) =>
    fixedSignMessage<AnyMessage>(m as unknown as Unsigned<AnyMessage>, k);
  const paired = { kind: 'paired', for: 'mailto:alice@example.org' } as const;
  const solo = { kind: 'solo' } as const;
  const fromCarol = { ...question, from: 'carol@example.org' } as unknown as Record<string, Json>;
  const byKey = { kind: 'paired', for: erinPrincipal } as const;
  const { signature: _, ...keyPairedFields } = keyPaired as unknown as Record<string, Json>;
  const withPairing = (k: FixedKey) => {
    const principal = `agnt-key:${k.key}`;
    return {
      ...keyPairedFields,
      headers: { for: principal, pairing: fixedSign(k, pairingBytes('bob@example.net', principal)) },
    };
  };
  const cases: [string, AnyMessage, Principal][] = [
    ['a paired agent naming its principal', signedQuestion, paired],
    ['a paired agent naming no one', sign({ ...question, headers: { subject: 'Thursday' } }, ada), paired],
    [
      'a paired agent naming another principal',
      sign({ ...question, headers: { for: 'tel:+14155550100' } }, ada),
      paired,
    ],
    ['a solo agent naming no one', sign({ ...fromCarol, headers: {} }, carol), solo],
    ['a solo agent carrying a for header', sign(fromCarol, carol), solo],
    ['a key-paired agent with its pairing', keyPaired, byKey],
    [
      'an agent paired with an ML-DSA-65 key',
      sign(withPairing(frank), bob),
      { kind: 'paired', for: `agnt-key:${frank.key}` },
    ],
    [
      'a key-paired agent with a pairing signed for another agent',
      sign(
        {
          ...keyPairedFields,
          headers: { for: erinPrincipal, pairing: fixedSign(erin, pairingBytes('ada@example.com', erinPrincipal)) },
        },
        bob,
      ),
      byKey,
    ],
    [
      'a key-paired agent with a pairing by another key',
      sign(
        {
          ...keyPairedFields,
          headers: { for: erinPrincipal, pairing: fixedSign(frank, pairingBytes('bob@example.net', erinPrincipal)) },
        },
        bob,
      ),
      byKey,
    ],
    ['a paired agent sending a version whose headers this server does not know', version7, paired],
  ];
  return {
    about:
      "What an agent's own server answers on send, given the agent's kind and, for a paired agent, its principal (sections 2.2 and 5.4, CLIENT.md send): for is the principal; pairing is present, and verifies, exactly when the principal is a key; a solo agent carries neither. Every message here is valid, pairing present exactly when for is a key; whether for is this agent's principal and whether its pairing verifies bind the sending agent, so only its server, and readers, check them.",
    cases: cases.map(([name, message, agent]) => ({
      name,
      agent,
      message,
      ...outcome(() => {
        parseMessage(Buffer.from(canonicalize(message)));
        checkPrincipal(message, agent);
      }),
    })),
  };
}

const consideredClaims: Claim[] = [
  actsFor,
  { ...actsFor, agent: 'eve@example.com' },
  { ...actsFor, for: 'mailto:someone@example.org' },
  { ...actsFor, verifiedAt: '2026-09-01' },
  { ...actsFor, scope: 'converse' },
  { ...actsFor, scope: ['converse', 1] },
  { type: 'x-member-since', year: 2019 },
  identifierOf('agent', 'mailto:ada.mail@example.org'),
  identifierOf('agent', 'tel:+14155550100'),
  identifierOf('principal', 'mailto:alice.work@example.org'),
  { ...identifierOf('agent', 'mailto:ada.mail@example.org'), agent: 'eve@example.com' },
  { ...identifierOf('agent', 'mailto:ada.mail@example.org'), of: 'pet' },
  identifierOf('agent', 'ada.mail@example.org'),
  identifierOf('agent', 'mailto:Ada.Mail@Example.ORG'),
  identifierOf('agent', 'mailto:ada.mail@example.org.'),
  identifierOf('agent', `agnt-key:${erin.key}`),
  { ...identifierOf('agent', 'mailto:ada.mail@example.org'), verifiedAt: '2026-09-01' },
];

const claimsConsidered = {
  about:
    "Which claims a receiver considers for the message named (section 6.2, and the registry's identifier): an acts-for claim only for the author and the message's for header, with a timestamp verifiedAt and a scope that is an array of strings; an identifier claim only for the author, of agent, or of principal on a message whose for header names a key (this message's names an email address, so none), with a mailto: or tel: identifier in the version 1 form, exactly as written, and a timestamp verifiedAt; other types pass through.",
  message: 'question with a for header',
  kind: 'paired',
  claims: consideredClaims,
  considered: claimsAbout(signedQuestion, consideredClaims, 'paired'),
};

/** Which acts-for claims a receiving server marks authoritative under its local policy (sections 2.2 and 6.2). */
async function authority() {
  const carrier = ORIGIN;
  const resolutions: Record<string, Resolution> = {
    'example.com': { outcome: 'server', server: ORIGIN, via: 'dns' },
    'txt.example': { outcome: 'server', server: ORIGIN, via: 'dns' },
    'hosted.example': { outcome: 'server', server: ORIGIN, via: 'well-known' },
    'example.org': { outcome: 'server', server: 'https://agnt.example.org', via: 'dns' },
    'nowhere.example': { outcome: 'not_found' },
    'flaky.example': { outcome: 'temporary' },
    'acme.example': { outcome: 'server', server: ORIGIN, via: 'dns' },
  };
  const resolve: Resolve = async d => resolutions[d] ?? { outcome: 'not_found' };
  const cases: [string, string, string][] = [
    ['an address on the carrier’s own domain', 'mailto:alice@example.com', 'ada@example.com'],
    ['an address on another domain whose TXT record names the carrier', 'mailto:alice@txt.example', 'ada@txt.example'],
    [
      'an address on a domain only its well-known answer names the carrier for',
      'mailto:alice@hosted.example',
      'ada@hosted.example',
    ],
    ['an address on a domain another server serves', 'mailto:alice@example.org', 'ada@example.org'],
    ['an address on a domain with no server', 'mailto:alice@nowhere.example', 'ada@nowhere.example'],
    ['an address on a domain that failed to resolve just now', 'mailto:alice@flaky.example', 'ada@flaky.example'],
    ['a phone number, never authoritative', 'tel:+14155550100', 'ada@example.com'],
    ['a key, which a pairing proves instead', `agnt-key:${erin.key}`, 'ada@example.com'],
    [
      'an address on a domain naming the carrier, for an agent on another of its domains',
      'mailto:alice@txt.example',
      'ada@example.com',
    ],
    ['an agent on a different domain: no alignment requirement', 'mailto:alice@acme.example', 'ada@example.com'],
    ['another agent on a different domain', 'mailto:alice@acme.example', 'ada@tenant.example.com'],
    ['an agent on a subdomain: no new DNS delegation field', 'mailto:alice@acme.example', 'ada@other.example.com'],
  ];
  return {
    about:
      'Authority (section 6.2): an acts-for claim about the agent named is authoritative exactly when its for is a mailto: identifier whose domain names the carrier by its _agnt TXT record (via dns), A domain named only by its well-known answer (via well-known) grants no authority. resolutions are the outcomes of resolving each domain; any domain not listed is not_found.',
    carrier,
    resolutions,
    cases: await Promise.all(
      cases.map(async ([name, forValue, agent]) => ({
        name,
        for: forValue,
        agent,
        authoritative: await isAuthoritative({ for: forValue }, carrier, resolve),
      })),
    ),
  };
}

/**
 * How a receiving server judges the claims it considers (section 6.2, and the registry's identifier): each
 * acts-for claim by its `for`, and each identifier claim by its `identifier`, authoritative exactly when that
 * is a mailto: identifier whose domain names the carrier by TXT record. Other types pass through unjudged,
 * stripped of any `authoritative` member the carrier gave them.
 */
async function claimsJudged() {
  const carrier = ORIGIN;
  const resolutions: Record<string, Resolution> = {
    'example.com': { outcome: 'server', server: ORIGIN, via: 'dns' },
    'example.org': { outcome: 'server', server: 'https://agnt.example.org', via: 'dns' },
  };
  const resolve: Resolve = async d => resolutions[d] ?? { outcome: 'not_found' };
  const cases: [string, AnyMessage, string, Claim[]][] = [
    [
      'question with a for header',
      signedQuestion,
      'paired',
      [
        actsFor,
        identifierOf('agent', 'mailto:ada.mail@example.com'),
        identifierOf('agent', 'mailto:ada.mail@example.org'),
        identifierOf('agent', 'tel:+14155550100'),
        { type: 'x-member-since', year: 2019 },
        { type: 'operator', agent: 'ada@example.com', operator: 'Big Bank', authoritative: true },
      ],
    ],
    [
      'from an agent paired with a key principal',
      keyPaired,
      'paired',
      [
        identifierOf('principal', 'mailto:erin@example.com', keyPaired.from),
        identifierOf('principal', 'mailto:erin@example.org', keyPaired.from),
      ],
    ],
    [
      'question with a for header',
      signedQuestion,
      'solo',
      [actsFor, identifierOf('agent', 'mailto:ada.mail@example.com')],
    ],
  ];
  return {
    about:
      'The claims a receiving server considers for each message named, from an author of the kind given (its agent document says paired or solo; a solo agent has no acts-for or principal claim that counts, whatever its message carries), as it passes them to its agents: each acts-for claim marked authoritative by its for, each identifier claim by its identifier, true exactly for a mailto: identifier whose domain names the carrier by TXT record; other types unmarked, and stripped of any authoritative member the carrier sent, which means nothing. resolutions are the outcomes of resolving each domain; any domain not listed is not_found.',
    carrier,
    resolutions,
    cases: await Promise.all(
      cases.map(async ([message, m, kind, claims]) => ({
        message,
        kind,
        claims,
        judged: await judgeClaims(m, claims, kind, carrier, resolve),
      })),
    ),
  };
}

/**
 * Claims a carrier signed for a message (section 6.2), checked later by anyone with the carrier's keys: a key
 * valid at some moment from the message's sentAt to 144 hours after.
 */
function claimsSignatures() {
  const claims = [actsFor];
  const signed = { claims, signature: fixedSign(exampleCom, claimsBytes(claims, messageId(signedQuestion))) };
  const keyed = (added: string, revoked: string | null = null) => [keyEntry(exampleCom.key, added, revoked)];
  const cases: [string, Claim[], KeyEntry[]][] = [
    ["the carrier's key, added before sentAt", claims, serverKeys],
    ['a key added 144 hours after sentAt, inside the 300 s skew', claims, keyed('2026-10-20T21:05:00Z')],
    ['a key added 144 hours and 301 s after sentAt', claims, keyed('2026-10-20T21:05:01Z')],
    ['a key revoked 1 s after sentAt', claims, keyed('2026-10-01T00:00:00Z', '2026-10-14T21:00:01Z')],
    ['a key revoked at sentAt', claims, keyed('2026-10-01T00:00:00Z', '2026-10-14T21:00:00Z')],
    ["a key that is not the carrier's", claims, [keyEntry(ada.key)]],
    ['other claims under the same signature', [{ ...actsFor, scope: ['commit'] }], serverKeys],
  ];
  return {
    about:
      'Claims as a carrier signed them for the message named (section 6.2), as an inbox entry carries them in signedClaims: signature is the carrier\'s over signingBytes, AGNT-CLAIMS, a newline, and the canonical {"claims","message":<id>}. verifies is whether a reader holding the keys given (the carrier\'s, read from the server the message\'s from domain resolves to) accepts the claims: one key valid at some moment from sentAt to 144 hours after signed them.',
    message: 'question with a for header',
    signature: signed.signature,
    signingBytes: claimsBytes(claims, messageId(signedQuestion)).toString('utf8'),
    cases: cases.map(([name, c, keys]) => ({
      name,
      claims: c,
      keys,
      verifies: verifyClaims({ claims: c, signature: signed.signature }, signedQuestion, keys),
    })),
  };
}

/** Signals (section 6.4): their signing bytes, and the receiver's answers in the order of its checks. */
function signals() {
  const now = '2026-10-14T21:03:00Z';
  const read: UnsignedSignal = {
    type: 'read',
    from: 'ada@example.com',
    to: ['bob@example.net'],
    about: messageId(question),
    at: now,
    server: RECEIVER.origin,
  };
  // The sending server holds an ed25519 key and a post-quantum one, whose signature alone passes 4096 bytes.
  const pqServer = fixedKey('server https://agnt.example.com ml-dsa-65', 'ml-dsa-65');
  const signalKeys = [...serverKeys, keyEntry(pqServer.key)];
  const signed = (s: Record<string, unknown>, k: FixedKey = exampleCom) =>
    canonicalize({ ...s, signature: fixedSign(k, signingBytes('AGNT-SIGNAL', s)) });
  const check = (bytes: string) => {
    const s = parseSignal(Buffer.from(bytes), receiver);
    if (!verifySignal(s, signalKeys, new Date(now))) throw forbidden('bad_signature', 'The signal does not verify.');
    checkServed(s.to, d => RECEIVER.serves.includes(d), 'to');
    checkSignalFreshness(s, new Date(now));
    return s;
  };
  const accepted: [string, string][] = [
    ['read', signed(read)],
    ['typing', signed({ ...read, type: 'typing' })],
    [
      'collected, for two recipients',
      signed({ ...read, type: 'collected', to: ['bob@example.net', 'dan@example.net'] }),
    ],
    [
      'a type the registry may add, with a member this version does not define',
      signed({ ...read, type: 'x-live', offer: 'x' }),
    ],
    ['sent 300 s ago', signed({ ...read, at: '2026-10-14T20:58:00Z' })],
    ['signed with ml-dsa-65: 4096 bytes bound the signal without its signature', signed(read, pqServer)],
    [
      'of 4096 bytes without its signature',
      signed({ ...read, pad: 'x'.repeat(4096 - canonicalize({ ...read, pad: '' }).length) }),
    ],
  ];
  const refused: [string, string][] = [
    ['a type in upper case', signed({ ...read, type: 'Read' })],
    ['no recipients', signed({ ...read, to: [] })],
    ['about that is not a message id', signed({ ...read, about: 'x' })],
    ['for another server', signed({ ...read, server: 'https://agnt.example.org' })],
    [
      'of 4097 bytes without its signature',
      signed({ ...read, pad: 'x'.repeat(4097 - canonicalize({ ...read, pad: '' }).length) }),
    ],
    ['a body of 16385 bytes', signed({ ...read, pad: 'x'.repeat(16385 - signed({ ...read, pad: '' }).length) })],
    [
      "signed by a key that is not the server's",
      canonicalize({ ...read, signature: fixedSign(ada, signingBytes('AGNT-SIGNAL', read)) }),
    ],
    ['changed after signing', signed(read).replace('"read"', '"typing"')],
    [
      'a recipient on a domain this server does not serve',
      signed({ ...read, to: ['bob@example.net', 'dan@example.org'] }),
    ],
    ['sent 301 s ago', signed({ ...read, at: '2026-10-14T20:57:59Z' })],
    ['sent 301 s ahead', signed({ ...read, at: '2026-10-14T21:08:01Z' })],
  ];
  return {
    about:
      "Signals (section 6.4) posted to receiver from the server whose keys are serverKeys, at now. signingBytes is AGNT-SIGNAL, a newline, and the canonical signal without signature. The body is at most 16384 bytes (413), and the signal without its signature at most 4096 canonical bytes (400), so a post-quantum signature fits. refused: the answer to each, in the order of the section's checks (step 4, resolution, is fixed by these vectors). Whether a signal reaches an agent is the receiving server's own policy; no vector fixes it.",
    now,
    serverKeys: signalKeys,
    receiver: RECEIVER,
    accepted: accepted.map(([name, bytes]) => ({
      name,
      bytes,
      signingBytes: signingBytes('AGNT-SIGNAL', check(bytes)).toString('utf8'),
    })),
    refused: refused.map(([name, bytes]) => ({ name, bytes, ...outcome(() => check(bytes)) })),
  };
}

/** Unpairings (section 2.2): a key principal ends its pairing. */
/** A key principal's recovery of its agent (CLIENT.md register, Appendix A `recover-signed`), both algorithms. */
function recoveries() {
  const at = '2026-10-14T20:00:00Z';
  const recovery = (agent: string, k: FixedKey, newKey: string, signed = { agent, newKey, at }) => {
    const principal = `agnt-key:${k.key}`;
    const recover = fixedSign(k, recoverBytes(signed.agent, signed.newKey, signed.at));
    return {
      agent,
      principal,
      key: newKey,
      at,
      bytes: recoverBytes(agent, newKey, at),
      recover,
      verifies: verifyRecovery(agent, principal, newKey, at, recover),
    };
  };
  return {
    about:
      "A key principal's recovery (CLIENT.md register): bytes is AGNT-RECOVER, the agent address, the new key token and at, joined by newlines (Appendix A recover-signed); recover is the principal key's signature; verifies is whether it recovers this agent to this key at this time for this principal. A server takes it only while at is at most 24 hours old and 5 minutes ahead.",
    cases: [
      { why: 'an Ed25519 principal', ...recovery('bob@example.net', erin, carol.key) },
      { why: 'an ML-DSA-65 principal', ...recovery('bob@example.net', frank, ada.key) },
      {
        why: 'signed for another key',
        ...recovery('bob@example.net', erin, carol.key, { agent: 'bob@example.net', newKey: ada.key, at }),
      },
      {
        why: 'signed at another time',
        ...recovery('bob@example.net', erin, carol.key, {
          agent: 'bob@example.net',
          newKey: carol.key,
          at: '2026-10-14T20:00:01Z',
        }),
      },
      {
        why: 'signed for another agent',
        ...recovery('bob@example.net', erin, carol.key, { agent: 'ada@example.com', newKey: carol.key, at }),
      },
    ],
  };
}

function unpairings() {
  const unpair = (agent: string, k: FixedKey, signedAgent = agent) => {
    const principal = `agnt-key:${k.key}`;
    const unpairing = fixedSign(k, unpairingBytes(signedAgent, principal));
    return {
      agent,
      principal,
      bytes: unpairingBytes(agent, principal),
      unpairing,
      verifies: verifyUnpairing(agent, principal, unpairing),
    };
  };
  return {
    about:
      "Unpairings (section 2.2): bytes is AGNT-UNPAIR, the agent address and the principal, joined by newlines; unpairing is the principal key's signature; verifies is whether it ends this agent's pairing with this principal. A pairing signature is never an unpairing.",
    cases: [
      { why: 'an Ed25519 principal', ...unpair('bob@example.net', erin) },
      { why: 'an ML-DSA-65 principal', ...unpair('bob@example.net', frank) },
      { why: 'signed for another agent', ...unpair('bob@example.net', erin, 'ada@example.com') },
      {
        why: 'a pairing signature offered as an unpairing',
        agent: 'bob@example.net',
        principal: erinPrincipal,
        bytes: unpairingBytes('bob@example.net', erinPrincipal),
        unpairing: keyPaired.headers.pairing,
        verifies: verifyUnpairing('bob@example.net', erinPrincipal, keyPaired.headers.pairing),
      },
    ],
  };
}

/** What a reader may make of a message it holds (sections 1, 2.2, 5.4 and 5.5): rules no server test can show. */
function reading() {
  const understood = ['for', 'pairing', 'critical', 'rel', 'subject'];
  const withCritical = (c: string) => ({ ...signedQuestion, headers: { ...signedQuestion.headers, critical: c } });
  const understoodCases: [string, AnyMessage][] = [
    ['version 1, nothing critical', signedQuestion],
    ['version 1, critical headers it understands', withCritical('for,subject')],
    ['version 1, an absent critical header is ignored', withCritical('binding')],
    [
      'version 1, a critical header it does not understand',
      { ...withCritical('binding'), headers: { critical: 'binding', binding: 'opaque' } },
    ],
    ['a version it does not implement', version7],
  ];
  const principalCases: [string, AnyMessage, string][] = [
    ['a paired agent', signedQuestion, 'paired'],
    ['a solo agent carrying a for header', signedQuestion, 'solo'],
    ['an agent of a kind the reader does not know', signedQuestion, 'robot'],
    ['a paired agent writing a version the reader does not implement', version7, 'paired'],
  ];
  const known = ['reaction', 'edit', 'retract', 'thread', 'comment'];
  const rel = (from: string, name: string | null): Message => ({
    ...signedQuestion,
    from,
    inReplyTo: messageId(question),
    headers: name ? { rel: name } : {},
  });
  const relationCases: [string, Message, { from: string } | null][] = [
    ['a reply', rel('bob@example.net', null), { from: 'ada@example.com' }],
    ['a reaction from anyone', rel('bob@example.net', 'reaction'), { from: 'ada@example.com' }],
    ['a relation the reader does not know', rel('bob@example.net', 'x-poke'), { from: 'ada@example.com' }],
    ['an edit by the original author', rel('ada@example.com', 'edit'), { from: 'ada@example.com' }],
    ['an edit by anyone else', rel('bob@example.net', 'edit'), { from: 'ada@example.com' }],
    ['a retraction by anyone else', rel('bob@example.net', 'retract'), { from: 'ada@example.com' }],
    ['an edit of a message the reader does not hold yet', rel('bob@example.net', 'edit'), null],
  ];
  return {
    about:
      "Rules that bind readers. understood: whether a reader that implements version 1 and understands the headers listed may act on the message, or must present it as not understood (an unknown version, or an unknown critical header). principals: the principal that may count, given the kind the author's agent document states: the for header of a version 1 message from a paired agent, else null; whether it is verified is a further question. relations: how a reader that knows the relations listed reads the message, given the from of the message its inReplyTo names (target, or null when it does not hold it): reply (no rel, an unknown rel, or an author-only relation, edit or retract, from anyone but the target's author), relation, or pending.",
    understoodHeaders: understood,
    understood: understoodCases.map(([name, message]) => ({
      name,
      message,
      understood: isUnderstood(message, new Set(understood)),
    })),
    principals: principalCases.map(([name, message, kind]) => ({
      name,
      message,
      kind,
      principal: claimedPrincipal(message, kind),
    })),
    knownRelations: known,
    relations: relationCases.map(([name, message, target]) => ({
      name,
      message,
      target,
      readsAs: readsAs(message, target, new Set(known)),
    })),
  };
}

/** Delivery limits and structural checks shared by readers and receiving servers. */
function delivery() {
  const sentAt = question.sentAt;
  const cases: [string, number, number][] = [
    ['accepted at sentAt, attempted then', 0, 0],
    ['accepted at sentAt, attempted 1 ms before the five days end', 0, 120 * 3600_000 - 1],
    ['accepted at sentAt, attempted when the five days end', 0, 120 * 3600_000],
    ['accepted 24 h after sentAt, attempted 1 ms before 143 h', 24 * 3600_000, 143 * 3600_000 - 1],
    ['accepted 24 h after sentAt, attempted at 143 h', 24 * 3600_000, 143 * 3600_000],
    ['accepted with sentAt 5 min ahead, attempted before sentAt', -300_000, -1],
    ['accepted with sentAt 5 min ahead, attempted at sentAt', -300_000, 0],
  ];
  return {
    about:
      'Delivery timing (section 6.3), for a message with the sentAt given: the author’s server attempts delivery no earlier than sentAt, and stops at deadline, the earlier of acceptedAt plus 5 days and sentAt plus 143 hours. state is early, due, or expired (at or after the deadline) for an attempt at now.',
    sentAt,
    cases: cases.map(([name, accepted, attempt]) => {
      const acceptedAt = new Date(Date.parse(sentAt) + accepted);
      const now = new Date(Date.parse(sentAt) + attempt);
      const { earliest, deadline } = deliveryWindow(question, acceptedAt);
      return {
        name,
        acceptedAt: acceptedAt.toISOString(),
        now: now.toISOString(),
        earliest: earliest.toISOString(),
        deadline: deadline.toISOString(),
        state: deliveryState(question, acceptedAt, now),
      };
    }),
  };
}

/** A well-known answer, or how the fetch failed: the first three are absences, the last two may pass. */
type WellKnown = { status: number; body: string } | 'nxdomain' | 'refused' | 'bad_certificate' | 'timeout' | 'dropped';
type ResolutionCase = {
  domain?: string;
  txt: string[][] | 'servfail' | 'dnssec_failure';
  wellKnown?: WellKnown;
  why?: string;
};

async function resolution() {
  const wellKnownBody = text({ server: 'https://agnt.example.org' });
  const cases: ResolutionCase[] = [
    { txt: [['v=agnt1; server=https://agnt.example.com']] },
    { txt: [['v=agnt1;server=https://ag', 'nt.example.com;'], ['google-site-verification=abc']] },
    { txt: [['v=agnt1; ttl=60; server=https://AGNT.example.com/']] },
    { txt: [['v=agnt1; server=HTTPS://agnt.example.com']], why: 'the scheme in any case' },
    { txt: [['v=agnt1; server=https://agnt.example.com:0443']], why: 'leading zeros in the port' },
    { txt: [['v=agnt1; server=https://agnt.example.com:08443']] },
    { txt: [['v=agnt1; server=https://agnt.example.com:65535']] },
    { txt: [['v=agnt1; server=https://a.example.com'], ['v=agnt1; server=https://b.example.com']] },
    { txt: [['v=agnt1; server=https://agnt.example.com/path']] },
    {
      txt: [['V=AGNT1; server=https://agnt.example.com']],
      wellKnown: 'nxdomain',
      why: 'not an agnt record, and no well-known host',
    },
    {
      txt: [['v=agnt1; server=https://agnt.example.com'], ['v=agnt1; server=https://AGNT.example.com:443']],
      why: 'two agnt records naming the same server',
    },
    {
      txt: [[' v=agnt1 ;; note; server=https://agnt.example.com ']],
      why: 'spaces around fields, an empty field and a field without = are ignored',
    },
    { txt: [['v=agnt1; ttl=60']], why: 'no server field' },
    { txt: [['v=agnt1; server']], why: 'a server field with no = has an empty value, which is no origin' },
    { txt: [['v=agnt1; server=https://agnt.example.com:0']], why: 'port 0' },
    { txt: [['v=agnt1; server=https://agnt.example.com:00000']], why: 'port 0, in five digits' },
    { txt: [['v=agnt1; server=https://agnt.example.com:000443']], why: 'six digits' },
    { txt: [['v=agnt1; server=https://agnt.example.com:65536']], why: 'port above 65535' },
    { txt: [['v=agnt1; server=https://a.example.com; server=https://a.example.com']], why: 'two server fields' },
    { txt: [['v=agnt1; server=http://agnt.example.com']], why: 'not https' },
    { txt: [['v=agnt1; server=https://agnt.example.com:']], why: 'empty port' },
    { txt: [['v=agnt1; server=https://10.0.0.1']], why: 'an IP address is not a domain' },
    { txt: [['v=agnt1; server=https://u@agnt.example.com']], why: 'user information' },
    { txt: [['v=agnt1; server=https://agnt.example.com?']], why: 'a query' },
    {
      txt: [['v=agnt1;\tserver=https://agnt.example.com']],
      why: 'only spaces are trimmed, so this record has no server field',
    },
    {
      txt: [['v=agnt1; server=https://a.example.com'], ['v=agnt1; server=https://b.example.com'], ['v=agnt1']],
      why: 'a malformed agnt record fails resolution before a conflict does',
    },
    { domain: 'localhost', txt: [] },
    {
      domain: `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(62)}`,
      txt: [],
      why: 'a domain of 254 bytes',
    },
    { txt: 'servfail', why: 'a DNS server error is temporary, never an absence' },
    {
      txt: 'servfail',
      wellKnown: { status: 200, body: wellKnownBody },
      why: 'a TXT lookup that ends temporary ends resolution: the well-known answer, though it would name a server, is not tried',
    },
    {
      txt: [['v=agnt1; server=https://agnt.example.com; agents=example.com,host.example']],
      why: 'an unknown agents field is ignored for routing and authority',
    },
    {
      txt: [['v=agnt1; agents=host.example; server=https://agnt.example.com; agents=host.example']],
      why: 'an agents field repeated in a record is ignored, and routing is unchanged',
    },
    {
      txt: [['v=agnt1; server=https://agnt.example.com; agents=Host.example']],
      why: 'an agents field naming a domain not in wire form is ignored',
    },
    {
      txt: [['v=agnt1; server=https://agnt.example.com; agents=host.example, other.example']],
      why: 'an agents field with a space is ignored',
    },
    { txt: [['v=agnt1; server=https://agnt.example.com; agents=']], why: 'an empty agents field is ignored' },
    {
      txt: [
        ['v=agnt1; server=https://agnt.example.com; agents=host.example'],
        ['v=agnt1; server=https://agnt.example.com'],
      ],
      why: 'agnt records that do not all carry the same agents field: all are ignored',
    },
    {
      txt: [
        ['v=agnt1; server=https://agnt.example.com; agents=host.example'],
        ['v=agnt1; server=https://agnt.example.com; agents=other.example'],
      ],
      why: 'agnt records whose agents fields differ: all are ignored',
    },
    {
      txt: [
        ['v=agnt1; server=https://agnt.example.com; agents=host.example'],
        ['v=agnt1; server=https://AGNT.example.com/; agents=host.example'],
      ],
      why: 'agnt records with the same agents field',
    },
    {
      txt: [['v=agnt1; agents=host.example']],
      why: 'an agents field does not make a record without a server well formed',
    },
    { txt: 'dnssec_failure', why: 'a DNSSEC validation failure is temporary, never an answer' },
    { txt: [], wellKnown: { status: 200, body: wellKnownBody } },
    {
      txt: [],
      wellKnown: { status: 200, body: text({ v: 1, server: 'https://agnt.example.org/', note: 'x' }) },
      why: 'other members are ignored',
    },
    { txt: [], wellKnown: { status: 200, body: text({ server: 'https://agnt.example.org/x' }) } },
    {
      txt: [],
      wellKnown: { status: 200, body: '{"server":"https://a.example.org","server":"https://b.example.org"}' },
      why: 'not JSON under the canonical rules',
    },
    { txt: [], wellKnown: { status: 200, body: text(['https://agnt.example.org']) } },
    { txt: [], wellKnown: { status: 302, body: '' }, why: 'redirects are not followed' },
    { txt: [], wellKnown: { status: 404, body: '' } },
    { txt: [], wellKnown: { status: 429, body: '' } },
    { txt: [], wellKnown: { status: 500, body: '' } },
    { txt: [], wellKnown: { status: 599, body: '' } },
    { txt: [], wellKnown: 'nxdomain' },
    { txt: [], wellKnown: 'refused', why: 'a refused connection is an absence' },
    { txt: [], wellKnown: 'bad_certificate', why: 'a certificate not valid for the domain is an absence' },
    { txt: [], wellKnown: 'timeout', why: 'a timeout may pass' },
    { txt: [], wellKnown: 'dropped', why: 'a dropped connection may pass' },
  ];
  return {
    about:
      'Resolution (section 3) of domain (example.com when absent). txt is the TXT records at _agnt.<domain>, each as its character strings, or "servfail" or "dnssec_failure". wellKnown is the answer to GET https://<domain>/.well-known/agnt: a status and body, or how the fetch failed: "nxdomain", "refused" or "bad_certificate" (absences, so not_found), or "timeout" or "dropped" (temporary); when absent it must not be fetched. origins: server origins as written, and as compared. cacheMs: the longest a resolver may cache each outcome, given the lifetime its source allows (sourceTtlMs: the DNS TTL, or the HTTP freshness lifetime).',
    cases: await Promise.all(cases.map(async c => ({ ...c, result: await resolveCase(c) }))),
    origins: [
      'https://agnt.example.com',
      'HTTPS://AGNT.Example.COM/',
      'https://agnt.example.com:443',
      'https://agnt.example.com:00443',
      'https://agnt.example.com:8443/',
      'https://agnt.example.com//',
      'https://agnt.example.com:',
      'https://bücher.example',
      'https://xn--bcher-kva.example',
      'https://agnt.example.com#x',
      'http://agnt.example.com',
    ].map(input => ({ input, origin: serverOrigin(input) })),
    cacheMs: (
      [
        [{ outcome: 'server', server: ORIGIN, via: 'dns' }, 300_000],
        [{ outcome: 'server', server: ORIGIN, via: 'well-known' }, 86_400_000],
        [{ outcome: 'not_found' }, 86_400_000],
        [{ outcome: 'temporary' }, 86_400_000],
      ] as [Resolution, number][]
    ).map(([result, sourceTtlMs]) => ({ result, sourceTtlMs, cacheMs: resolutionCacheMs(result, sourceTtlMs) })),
  };
}

/** Resolve a vector case with lookups that answer as it says. */
export function resolveCase(c: ResolutionCase) {
  const io: ResolverIO = {
    txt: async () => {
      if (typeof c.txt === 'string') throw new Error(c.txt);
      return c.txt;
    },
    get: async () => {
      const w = c.wellKnown;
      if (w === undefined) throw new Error('This case must not fetch the well-known answer.');
      if (w === 'timeout' || w === 'dropped') throw new Error(w);
      return typeof w === 'string' ? null : { status: w.status, body: Buffer.from(w.body) };
    },
  };
  return resolveDomain(c.domain ?? 'example.com', io);
}

const clock = {
  about:
    'Clock-dependent rules (sections 6.3 and CLIENT.md send), each at its own now: send is whether a server takes the message from its agent (24 h back, 5 min ahead), deliver whether a receiver accepts a delivery (144 h back, 5 min ahead), repeat whether a receiver still recognises a delivery it accepted before (168 h back, and any time ahead).',
  sentAt: question.sentAt,
  cases: [
    ['at sentAt', 0],
    ['24 h after', 24 * 3600_000],
    ['24 h and 1 ms after', 24 * 3600_000 + 1],
    ['144 h after', 144 * 3600_000],
    ['144 h and 1 ms after', 144 * 3600_000 + 1],
    ['168 h after', 168 * 3600_000],
    ['168 h and 1 ms after', 168 * 3600_000 + 1],
    ['5 min before', -300_000],
    ['5 min and 1 ms before', -300_001],
  ].map(([name, delta]) => {
    const now = new Date(Date.parse(question.sentAt) + (delta as number));
    return {
      name,
      now: now.toISOString(),
      send: isFresh(question, now, SEND_WINDOW_MS),
      deliver: outcome(() => checkFreshness(question, now)).accepted === true,
      repeat: withinRepeatWindow(question, now),
    };
  }),
};

/** Offline publication response fixtures; feed order is publication order, independent of sentAt. */
function publications() {
  const post = fixedSignMessage<Message>(
    { ...question, to: [], headers: { ...question.headers, feed: 'updates' } },
    ada,
  );
  const newer = fixedSignMessage<Message>(
    {
      ...question,
      to: [],
      headers: { ...question.headers, feed: 'updates' },
      parts: [{ type: 'text/plain', data: 'Published second.' }],
      sentAt: at(question.sentAt, -60_000),
    },
    ada,
  );
  const claims: Claim[] = [
    {
      type: 'acts-for',
      agent: post.from,
      for: post.headers.for,
      scope: ['converse'],
      verifiedAt: '2026-10-01T00:00:00Z',
    },
  ];
  return {
    about:
      'Published response and paged feed fixtures (sections 7.1 and 7.3). stored is insertion/publication order. Each page specifies its messages by id; cursors are implementation-defined opaque tokens, non-null iff more. Claims remain separately signed evidence for this exact post. These fixtures do not select a relation-publication consent rule or a reader reducer.',
    carrierKeys: [keyEntry(exampleCom.key)],
    post: {
      id: messageId(post),
      response: {
        message: post,
        keys: [keyEntry(ada.key)],
        claims,
        claimsSignature: fixedSign(exampleCom, claimsBytes(claims, messageId(post))),
      },
    },
    feed: {
      address: post.from,
      name: 'updates',
      stored: [post, newer],
      pages: [
        { limit: 1, messageIds: [messageId(newer)], more: true },
        { limit: 1, messageIds: [messageId(post)], more: false },
      ],
    },
  };
}

export async function buildVectors() {
  const key = (k: FixedKey) => ({ alg: k.alg, seed: k.seed, key: k.key });
  return {
    about:
      'AGNT Protocol version 1 test vectors (spec/PROTOCOL.md section 15). Each section says what its cases mean. Private keys are 32-byte seeds in hex (RFC 8032 for Ed25519, FIPS 204 ML-DSA.KeyGen for ML-DSA-65); every other byte string is as it appears on the wire. ML-DSA-65 signatures are hedged, so another implementation verifies them rather than reproducing them.',
    keys: {
      about:
        'The keys every section uses, from their seeds. erin and frank are principals who pair with agents by key.',
      ada: key(ada),
      bob: key(bob),
      carol: key(carol),
      erin: key(erin),
      frank: key(frank),
      server: { ...key(exampleCom), origin: ORIGIN },
    },
    canonical,
    addresses,
    timestamps,
    keyTokens,
    keyLists,
    messages,
    messageChecks: messageChecks(),
    headerValues,
    pairings: pairings(),
    signatures: signatures(),
    requests: await requests(),
    documents: documents(),
    envelopes: envelopes(),
    deliverSignatures: deliverSignatures(),
    problems: problems(),
    principals: principals(),
    claimsConsidered,
    authority: await authority(),
    claimsJudged: await claimsJudged(),
    claimsSignatures: claimsSignatures(),
    publications: publications(),
    signals: signals(),
    unpairings: unpairings(),
    recoveries: recoveries(),
    reading: reading(),
    resolution: await resolution(),
    clock,
    delivery: delivery(),
  };
}
