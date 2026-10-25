/** The message: its invariants, version 2's rules, its id, its signature, and its age. */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalize,
  carriedMessages,
  checkInvariants,
  checkMessage,
  header,
  isFresh,
  MINIMUM_LIMITS,
  messageId,
  namedFiles,
  parseMessage,
  SEND_WINDOW_MS,
  sign,
  signingBytes,
  signMessage,
  unsignedBytes,
  verifyMessage,
  WireError,
  type AnyMessage,
  type Json,
  type Message,
} from '../src/index.ts';
import { ada, bob, carol, keyEntry, question, signedQuestion } from './fixtures.ts';

const version7Like = { v: 7, from: 'ada@example.com', to: [], signature: 'AAAA' };

const bytes = (value: unknown) => Buffer.from(canonicalize(value));
const code = (fn: () => unknown) => {
  try {
    fn();
  } catch (e) {
    return e instanceof WireError ? `${e.status} ${e.code}${e.details?.field ? ` ${e.details.field}` : ''}` : String(e);
  }
  return 'accepted';
};
const m = signedQuestion as unknown as Record<string, Json>;
const variant = (patch: Record<string, Json>) => () => checkMessage({ ...m, ...patch });
const many = (n: number, f: (i: number) => Json) => Array.from({ length: n }, (_, i) => f(i));

describe('the message', () => {
  it('the id hashes the canonical message without its signature; the signature is over SIMON-MESSAGE and those bytes', () => {
    assert.equal(unsignedBytes(signedQuestion).toString(), canonicalize(question));
    assert.equal(messageId(signedQuestion), messageId(question));
    assert.match(messageId(question), /^[0-9a-f]{64}$/);
    assert.equal(signingBytes('SIMON-MESSAGE', signedQuestion).toString(), `SIMON-MESSAGE\n${canonicalize(question)}`);
  });

  it('a signature verifies with a key valid at sentAt, and only then', () => {
    assert.equal(verifyMessage(signedQuestion, [keyEntry(ada.key)]), true);
    assert.equal(verifyMessage(signedQuestion, [keyEntry(bob.key)]), false);
    // Added after the message was sent (beyond five minutes of clock tolerance): not valid for it.
    assert.equal(verifyMessage(signedQuestion, [keyEntry(ada.key, '2026-10-14T21:05:01Z')]), false);
    assert.equal(verifyMessage(signedQuestion, [keyEntry(ada.key, '2026-10-14T21:05:00Z')]), true);
    // Revoked later: the message still verifies.
    assert.equal(
      verifyMessage(signedQuestion, [keyEntry(ada.key, '2026-10-01T00:00:00Z', '2026-10-15T00:00:00Z')]),
      true,
    );
    // Revoked before it was sent: refused.
    assert.equal(
      verifyMessage(signedQuestion, [keyEntry(ada.key, '2026-10-01T00:00:00Z', '2026-10-14T20:00:00Z')]),
      false,
    );
    const tampered = { ...signedQuestion, parts: [{ type: 'text/plain', data: 'Does 4pm work?' }] };
    assert.equal(verifyMessage(tampered, [keyEntry(ada.key)]), false);
  });

  it('the signature covers the context line: one over the bare canonical bytes does not verify', () => {
    const bare = { ...signedQuestion, signature: sign(ada.privateKey, unsignedBytes(question)) };
    assert.equal(verifyMessage(bare, [keyEntry(ada.key)]), false);
  });

  it('ML-DSA-65 signs and verifies messages, and its signatures are never mistaken for Ed25519 ones', () => {
    const fromCarol = signMessage<Message>({ ...question, from: 'carol@example.org' }, carol.privateKey);
    assert.equal(Buffer.from(fromCarol.signature, 'base64url').length, 3309);
    assert.equal(verifyMessage(fromCarol, [keyEntry(ada.key), keyEntry(carol.key)]), true);
    assert.equal(verifyMessage(fromCarol, [keyEntry(ada.key)]), false);
    assert.equal(verifyMessage(signedQuestion, [keyEntry(carol.key)]), false);
  });

  it('a transmitted message must already be canonical, and the refusal carries the canonical form', () => {
    assert.deepEqual(parseMessage(bytes(signedQuestion)), signedQuestion);
    const spaced = Buffer.from(JSON.stringify(signedQuestion, null, 2));
    try {
      parseMessage(spaced);
      assert.fail('accepted a non-canonical message');
    } catch (e) {
      assert.ok(e instanceof WireError && e.status === 400);
      assert.equal(e.details?.canonical, canonicalize(signedQuestion));
    }
  });

  it('a body over requestBodyBytes is 413 body_too_large, before it is parsed', () => {
    const limits = { ...MINIMUM_LIMITS, requestBodyBytes: 10 };
    assert.equal(
      code(() => parseMessage(Buffer.from('x'.repeat(11)), limits)),
      '413 body_too_large',
    );
    assert.equal(
      code(() => parseMessage(Buffer.from('x'.repeat(10)), limits)),
      '400 invalid',
    );
  });

  it('a version this server does not know is routed on its invariants alone', () => {
    const later = { ...m, v: 9, inReplyTo: 'not an id', thread: { anything: [1, 2] } };
    assert.equal(
      code(() => checkMessage(later)),
      'accepted',
    );
    assert.equal(
      code(() => checkMessage({ v: 9, from: 'ada@example.com', to: [], sentAt: m.sentAt, signature: 'AA' })),
      'accepted',
    );
    assert.equal(
      code(() => checkMessage({ ...later, from: 'josé@example.com' })),
      'accepted',
      'any UTF-8 local part',
    );
    assert.equal(
      code(() => checkMessage({ ...later, from: 'José@example.com' })),
      '400 invalid from',
      'lower case',
    );
    assert.equal(
      code(() => checkMessage({ ...later, from: 'a\u0000b@example.com' })),
      '400 invalid from',
    );
    assert.equal(
      code(() => checkMessage({ ...later, from: `${'é'.repeat(33)}@example.com` })),
      '400 invalid from',
    );
    assert.equal(
      code(() => checkMessage({ ...later, to: ['bob@localhost'] })),
      '400 invalid to',
    );
    assert.equal(
      code(() => checkMessage({ ...later, sentAt: 1 })),
      '400 invalid sentAt',
    );
    assert.equal(
      code(() => checkMessage({ ...later, signature: 'AB' })),
      '400 invalid signature',
      'not canonical',
    );
    for (const v of [0, -1, '1', null]) assert.equal(code(variant({ v })), '400 invalid v', String(v));
    assert.equal(
      code(() => checkMessage([])),
      '400 invalid message',
    );
    assert.deepEqual(checkInvariants(later), later);
  });

  it("the size and recipients are checked against the server's limits, for every version", () => {
    const later = { ...m, v: 9, to: many(101, i => `r${i}@example.net`) };
    assert.equal(
      code(() => checkMessage(later)),
      '400 invalid to',
    );
    assert.equal(
      code(() => checkMessage(later, { ...MINIMUM_LIMITS, recipients: 101 })),
      'accepted',
    );
    const big = { ...m, v: 9, pad: 'x'.repeat(MINIMUM_LIMITS.messageBytes) };
    assert.equal(
      code(() => checkMessage(big)),
      '400 invalid message',
    );
    assert.equal(
      code(() => checkMessage(big, { ...MINIMUM_LIMITS, messageBytes: 2 ** 20 })),
      'accepted',
    );
  });

  it('this version has exactly its eight fields, each as section 5 says', () => {
    assert.equal(code(variant({})), 'accepted');
    assert.equal(code(variant({ id: 'x' })), '400 invalid id');
    assert.equal(code(variant({ from: 'josé@example.com' })), '400 invalid from', 'ASCII in this version');
    assert.equal(code(variant({ from: '.ada@example.com' })), '400 invalid from');
    assert.equal(code(variant({ to: ['bob@example.net', 'bob@example.net'] })), '400 invalid to');
    assert.equal(code(variant({ to: ['BOB@example.net'] })), '400 invalid to', 'addresses are lower case on the wire');
    assert.equal(code(variant({ to: [] })), 'accepted');
    assert.equal(code(variant({ inReplyTo: 'abc' })), '400 invalid inReplyTo');
    assert.equal(code(variant({ inReplyTo: messageId(question) })), 'accepted');
    assert.equal(code(variant({ headers: { Subject: 'x' } })), '400 invalid headers');
    assert.equal(code(variant({ headers: { subject: 1 } })), '400 invalid headers');
    assert.equal(code(variant({ headers: [] })), '400 invalid headers');
    for (const name of ['-x', 'x-', 'x--y', 'x_y', 'h'.repeat(129), '.x', 'x.', 'x..y', 'x.Y', 'x.-y']) {
      assert.equal(code(variant({ headers: { [name]: 'y' } })), '400 invalid headers', name);
    }
    assert.equal(
      code(variant({ headers: { ['h'.repeat(128)]: 'y', 'x-1-2': 'z', 'com.example.x-1': 'w' } })),
      'accepted',
    );
    // One encoding per type: a JSON value for a JSON type, the text for text/*, base64 for anything else.
    const part = (p: Json) => variant({ parts: [p] });
    assert.equal(code(part({ type: 'application/json', data: { a: [1, 'b', null] } })), 'accepted');
    assert.equal(
      code(part({ type: 'application/simon-ui+json; schema=x', data: 'a string is a JSON value' })),
      'accepted',
    );
    assert.equal(code(part({ type: 'application/pdf', data: { a: 1 } })), '400 invalid parts');
    assert.equal(code(part({ type: 'text/plain', data: 1 })), '400 invalid parts');
    for (const sentAt of [
      '2026-10-14 21:00:00',
      '2026-10-14T21:00:00+02:00',
      '2026-02-30T00:00:00Z',
      '2026-10-14T24:00:00Z',
      '2026-10-14T23:59:60Z',
      '2026-10-14T21:00:00.5Z',
      '2026-10-14T21:00:00.0000Z',
    ]) {
      assert.equal(code(variant({ sentAt })), '400 invalid sentAt', sentAt);
    }
    assert.equal(code(variant({ sentAt: '2026-10-14T21:00:00.500Z' })), 'accepted');
  });

  it('parts: a media type, then inline data or a content address; other members ignored', () => {
    const part = (p: Json) => code(variant({ parts: [{ type: 'text/plain', data: 'See below.' }, p] }));
    assert.equal(part({ type: 'TEXT/PLAIN', data: 'x' }), '400 invalid parts', 'media types are lower case');
    assert.equal(part({ type: 'text/plain; charset=UTF-8', data: 'x' }), 'accepted', 'parameter values in any case');
    assert.equal(part({ type: 'text/plain;charset="a b"', data: 'x' }), 'accepted');
    assert.equal(part({ type: 'text/plain;  charset=x', data: 'x' }), '400 invalid parts', 'at most one space');
    assert.equal(part({ type: 'text/plain; charset="a\\"b"', data: 'x' }), '400 invalid parts');
    assert.equal(part({ type: 'pdf', data: 'x' }), '400 invalid parts');
    assert.equal(part({ type: 'application/pdf', sha256: 'a'.repeat(64), size: '1' }), '400 invalid parts');
    assert.equal(part({ type: 'application/pdf', sha256: 'A'.repeat(64), size: 1 }), '400 invalid parts');
    assert.equal(part({ type: 'application/pdf', sha256: 'a'.repeat(64), size: 48213 }), 'accepted');
    assert.equal(part({ type: 'application/pdf', sha256: 'a'.repeat(64), size: 1, data: 'x' }), '400 invalid parts');
    assert.equal(part({ type: 'application/pdf', sha256: 'a'.repeat(64) }), '400 invalid parts');
    assert.equal(part({ type: 'image/png', data: 'iVBORw0KGgo' }), '400 invalid parts', 'base64 is padded');
    assert.equal(part({ type: 'image/png', data: 'not base64!' }), '400 invalid parts');
    assert.equal(part({ type: 'image/png', data: 'iVBORw0KGgo=' }), 'accepted');
    assert.equal(part({ type: 'text/plain', data: 'not base64!' }), 'accepted', 'text is itself');
    assert.equal(part({ type: 'text/plain', data: 1 }), '400 invalid parts');
    assert.equal(part('text/plain'), '400 invalid parts');
  });

  it('carry 0 to 32 parts of any type: no content rule', () => {
    const parts = (p: Json[]) => code(variant({ parts: p }));
    const pdf = { type: 'application/pdf', sha256: 'a'.repeat(64), size: 1 };
    assert.equal(parts([]), 'accepted', 'nothing at all');
    assert.equal(parts([pdf]), 'accepted', 'a file alone');
    assert.equal(parts([{ type: 'text/html', data: '<p>x</p>' }]), 'accepted', 'only HTML');
    assert.equal(parts(Array.from({ length: 32 }, () => pdf)), 'accepted');
    assert.equal(parts(Array.from({ length: 33 }, () => pdf)), '400 invalid parts', 'at most 32');
  });

  it('name the files of messages they carry whole as their own', () => {
    const pdf = (c: string) => ({ type: 'application/pdf', sha256: c.repeat(64), size: 1 });
    const original = signMessage<Message>({ ...question, parts: [pdf('a'), pdf('b')] }, ada.privateKey);
    const carry = (m: object) => ({
      type: 'application/simon-message',
      data: Buffer.from(canonicalize(m)).toString('base64'),
    });
    const forward = { ...signedQuestion, parts: [{ type: 'text/plain', data: 'FYI' }, pdf('c'), carry(original)] };
    assert.deepEqual(
      namedFiles(forward).map(f => f.sha256[0]),
      ['c', 'a', 'b'],
    );
    const twice = { ...signedQuestion, parts: [carry(forward)] };
    assert.deepEqual(
      namedFiles(twice).map(f => f.sha256[0]),
      ['c', 'a', 'b'],
      'a forward of a forward',
    );
    const broken = { ...signedQuestion, parts: [{ type: 'application/simon-message', data: 'bm90IGpzb24=' }] };
    assert.deepEqual(namedFiles(broken), [], 'a carried message that does not parse names nothing');
    assert.deepEqual(
      namedFiles({ ...version7Like, parts: [pdf('a')] } as unknown as AnyMessage),
      [],
      'another version names none here',
    );
  });

  it('refuses carried messages beyond eight levels instead of losing their files', () => {
    for (const size of [1, MINIMUM_LIMITS.partBytes + 1]) {
      let inner: Message = {
        ...signedQuestion,
        parts: [{ type: 'application/octet-stream', sha256: 'a'.repeat(64), size }],
      };
      for (let depth = 0; depth <= 9; depth++) {
        if (depth === 8) {
          assert.equal(
            code(() => checkMessage(inner)),
            size === 1 ? 'accepted' : '400 invalid parts',
          );
          assert.equal(namedFiles(inner).length, 1);
        }
        if (depth === 9) {
          assert.equal(
            code(() => checkMessage(inner)),
            '400 invalid parts',
          );
          assert.equal(
            code(() => namedFiles(inner)),
            '400 invalid parts',
          );
        }
        inner = {
          ...signedQuestion,
          parts: [
            {
              type: 'application/simon-message; profile=forward',
              data: Buffer.from(canonicalize(inner)).toString('base64'),
            },
          ],
        };
      }
    }
  });

  it('refuses malformed carried bytes while enumerating valid known versions and keeping future interiors opaque', () => {
    const file = '{"sha256":"' + 'a'.repeat(64) + '","size":1}';
    const carried = (body: Uint8Array | string) => ({
      ...signedQuestion,
      parts: [{ type: 'application/simon-message; profile=forward', data: Buffer.from(body).toString('base64') }],
    });
    for (const body of [
      'not JSON',
      '[]',
      '{"v":2,"v":2,"parts":[' + file + ']}',
      '{"v":2,"extra":1.5,"parts":[' + file + ']}',
      '{"v":true,"parts":[' + file + ']}',
      Buffer.concat([Buffer.from('{"v":2,"extra":"'), Buffer.from([0xff]), Buffer.from('","parts":[' + file + ']}')]),
    ]) {
      const m = carried(body);
      assert.equal(
        code(() => checkMessage(m)),
        '400 invalid parts',
      );
      assert.deepEqual(namedFiles(m), [], 'invalid or unknown carried JSON creates no file entitlement');
    }
    const valid = carried(canonicalize({ ...signedQuestion, parts: [JSON.parse(file)] }));
    assert.equal(
      code(() => checkMessage(valid)),
      'accepted',
    );
    assert.equal(namedFiles(valid).length, 1);
    const future = carried(canonicalize({ ...signedQuestion, v: 7, parts: [JSON.parse(file)] }));
    assert.equal(
      code(() => checkMessage(future)),
      'accepted',
    );
    assert.deepEqual(namedFiles(future), [], 'a valid unknown version has opaque interiors');
  });

  it('lists the messages carried whole inline, at every depth, and none it cannot read', () => {
    const wrap = (inner: object | string) => ({
      ...signedQuestion,
      parts: [
        {
          type: 'application/simon-message',
          data: Buffer.from(typeof inner === 'string' ? inner : canonicalize(inner as Json)).toString('base64'),
        },
      ],
    });
    const post = { ...signedQuestion, to: [], headers: { audience: 'followers' } };
    assert.deepEqual(carriedMessages(signedQuestion), []);
    assert.deepEqual(
      carriedMessages(wrap(post)).map(m => m.headers),
      [{ audience: 'followers' }],
    );
    const deeper = carriedMessages(wrap(wrap(post)));
    assert.equal(deeper.length, 2);
    assert.deepEqual(deeper[1].headers, { audience: 'followers' });
    assert.deepEqual(carriedMessages(wrap('not JSON')), []);
  });

  it('parts may carry a name and an alt, each safe to show', () => {
    const labelled = (labels: Record<string, Json>) =>
      code(variant({ parts: [{ type: 'text/plain', data: 'x', ...labels }] }));
    assert.equal(labelled({ name: 'agenda.pdf', alt: 'The agenda' }), 'accepted');
    assert.equal(labelled({ name: 'résumé 2026.pdf' }), 'accepted', 'any language');
    assert.equal(labelled({ name: 'n'.repeat(255) }), 'accepted');
    assert.equal(labelled({ name: 'n'.repeat(256) }), '400 invalid parts', 'at most 255 bytes');
    assert.equal(labelled({ name: 'é'.repeat(128) }), '400 invalid parts', 'counted in bytes');
    for (const name of ['', '.', '..', 'a/b', 'a\\b', 'a\nb', 'invoice\u202efdp.exe', 'x\u2066y']) {
      assert.equal(labelled({ name }), '400 invalid parts', JSON.stringify(name));
    }
    assert.equal(labelled({ name: 1 }), '400 invalid parts');
    assert.equal(labelled({ alt: 'a'.repeat(1024) }), 'accepted');
    assert.equal(labelled({ alt: 'a'.repeat(1025) }), '400 invalid parts');
    assert.equal(labelled({ alt: '' }), '400 invalid parts');
    assert.equal(labelled({ alt: 'two\nlines' }), '400 invalid parts', 'one line');
    assert.equal(labelled({ lang: 'en', x: [1] }), 'accepted', 'a member it does not know is ignored');
    assert.equal(labelled({ alt: 'a\u202eb' }), '400 invalid parts', 'no bidirectional override in alt');
  });

  it("a content-addressed part is within the receiving server's partBytes", () => {
    const sized = (size: number) =>
      code(
        variant({
          parts: [
            { type: 'text/plain', data: 'x' },
            { type: 'image/png', sha256: 'a'.repeat(64), size },
          ],
        }),
      );
    assert.equal(sized(MINIMUM_LIMITS.partBytes), 'accepted');
    assert.equal(sized(MINIMUM_LIMITS.partBytes + 1), '400 invalid parts');
  });

  it('rel names a relation on a message that points at another; feed and audience only on a published one', () => {
    const msg = (patch: Record<string, Json>) => code(variant(patch));
    const parent = 'a'.repeat(64);
    assert.equal(msg({ inReplyTo: parent, headers: { rel: 'reaction' } }), 'accepted');
    assert.equal(msg({ inReplyTo: parent, headers: { rel: 'x-vendor-thing' } }), 'accepted', 'any name');
    assert.equal(
      msg({ inReplyTo: null, headers: { rel: 'reaction' } }),
      '400 invalid headers',
      'a relation to nothing',
    );
    assert.equal(msg({ inReplyTo: parent, headers: { rel: 'Reaction' } }), '400 invalid headers');
    assert.equal(msg({ inReplyTo: parent, headers: { rel: '' } }), '400 invalid headers');
    assert.equal(msg({ to: [], headers: { feed: 'posts,photos', audience: 'followers' } }), 'accepted');
    assert.equal(msg({ to: [], headers: { audience: '' } }), 'accepted', 'the label is opaque');
    assert.equal(msg({ to: [], headers: { feed: 'posts, photos' } }), '400 invalid headers');
    assert.equal(msg({ headers: { feed: 'posts' } }), '400 invalid headers', 'a feed is for published messages');
    assert.equal(msg({ headers: { audience: 'followers' } }), '400 invalid headers');
  });

  it('the for and critical headers keep their grammar', () => {
    const headers = (h: Record<string, string>) => code(variant({ headers: h }));
    assert.equal(headers({ for: 'mailto:alice@example.org' }), 'accepted');
    assert.equal(headers({ for: 'tel:+442071838750' }), 'accepted');
    assert.equal(headers({ for: 'alice@example.org' }), '400 invalid headers');
    assert.equal(headers({ for: 'mailto:Alice@example.org' }), '400 invalid headers');
    assert.equal(headers({ for: 'tel:+44 20 7183 8750' }), '400 invalid headers');
    assert.equal(headers({ critical: 'for,subject' }), 'accepted');
    assert.equal(headers({ critical: 'for, subject' }), '400 invalid headers');
    assert.equal(headers({ critical: '' }), '400 invalid headers');
  });

  it('limits: parts, headers, recipients and size, accepted at the limit and refused past it', () => {
    assert.equal(code(variant({ to: many(100, i => `r${i}@example.net`) })), 'accepted');
    assert.equal(code(variant({ to: many(101, i => `r${i}@example.net`) })), '400 invalid to');
    assert.equal(code(variant({ parts: many(32, () => ({ type: 'text/plain', data: 'x' })) })), 'accepted');
    assert.equal(code(variant({ parts: many(33, () => ({ type: 'text/plain', data: 'x' })) })), '400 invalid parts');
    assert.equal(
      code(variant({ headers: Object.fromEntries(Array.from({ length: 32 }, (_, i) => [`h${i}`, 'x'])) })),
      'accepted',
    );
    assert.equal(
      code(variant({ headers: Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`h${i}`, 'x'])) })),
      '400 invalid headers',
    );
    const size = canonicalize({ ...m, parts: [{ type: 'text/plain', data: '' }] }).length;
    const padded = (n: number) => variant({ parts: [{ type: 'text/plain', data: 'x'.repeat(n - size) }] });
    assert.equal(code(padded(MINIMUM_LIMITS.messageBytes)), 'accepted');
    assert.equal(code(padded(MINIMUM_LIMITS.messageBytes + 1)), '400 invalid message');
  });

  it('sentAt is at most 24 hours old and 5 minutes ahead when an agent sends it', () => {
    const at = (iso: string) => new Date(iso);
    assert.equal(isFresh(signedQuestion, at('2026-10-15T21:00:00Z'), SEND_WINDOW_MS), true);
    assert.equal(isFresh(signedQuestion, at('2026-10-15T21:00:00.001Z'), SEND_WINDOW_MS), false);
    assert.equal(isFresh(signedQuestion, at('2026-10-14T20:55:00Z'), SEND_WINDOW_MS), true);
    assert.equal(isFresh(signedQuestion, at('2026-10-14T20:54:59.999Z'), SEND_WINDOW_MS), false);
  });

  it('headers are read as own members only', () => {
    assert.equal(header(signedQuestion, 'subject'), 'Thursday');
    assert.equal(header(signedQuestion, 'constructor'), null);
    assert.equal(header(signedQuestion, 'Subject'), null, 'names are lower case on the wire');
  });

  it('Ed25519 signing is deterministic', () => {
    assert.equal(signMessage(question, ada.privateKey).signature, signedQuestion.signature);
  });

  it('a message of any version is signed and verified the same way', () => {
    const later = signMessage<AnyMessage>(
      { v: 9, from: 'ada@example.com', to: [], sentAt: question.sentAt, extra: true } as Omit<AnyMessage, 'signature'>,
      ada.privateKey,
    );
    assert.equal(verifyMessage(later, [keyEntry(ada.key)]), true);
    assert.equal(verifyMessage({ ...later, extra: false } as AnyMessage, [keyEntry(ada.key)]), false);
  });
});
