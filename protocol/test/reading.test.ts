/** Signals (section 6.4), unpairing (section 2.2), a key principal's recovery (CLIENT.md) and the rules that bind readers (sections 1, 2.2, 5.4, 5.5). */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalize,
  checkSignalFreshness,
  claimedPrincipal,
  isUnderstood,
  parseSignal,
  readsAs,
  recoveryBytes,
  signRecovery,
  signSignal,
  signUnpairing,
  unpairingBytes,
  verifyPairing,
  verifyRecovery,
  verifySignal,
  verifyUnpairing,
  WireError,
  type Message,
  type UnsignedSignal,
} from '../src/index.ts';
import { ada, carol, erin, exampleCom, frank, keyEntry, signedQuestion } from './fixtures.ts';

const code = (fn: () => unknown) => {
  try {
    fn();
    return 'accepted';
  } catch (e) {
    if (!(e instanceof WireError)) throw e;
    return `${e.status} ${e.code}${e.details?.field ? ` ${e.details.field}` : ''}`;
  }
};

const NOW = new Date('2026-10-14T21:03:00Z');
const read: UnsignedSignal = {
  type: 'read',
  from: 'ada@example.com',
  to: ['bob@example.net'],
  about: 'a'.repeat(64),
  at: '2026-10-14T21:03:00Z',
  server: 'https://simon.example.net',
};
const receiver = { origin: 'https://simon.example.net' };

describe('signals', () => {
  it("are signed by the sender's server over SIMON-SIGNAL, and bound to the receiving server", () => {
    const signal = signSignal(read, exampleCom.privateKey);
    const keys = [keyEntry(exampleCom.key)];
    assert.equal(verifySignal(signal, keys, NOW), true);
    assert.equal(verifySignal({ ...signal, type: 'typing' }, keys, NOW), false);
    assert.equal(verifySignal({ ...signal, server: 'https://simon.example.org' }, keys, NOW), false);
    assert.equal(verifySignal(signal, [keyEntry(ada.key)], NOW), false);
    assert.deepEqual(parseSignal(Buffer.from(canonicalize(signal)), receiver), signal);
  });

  it('are checked for shape, size and destination before anything is looked up', () => {
    const parse = (patch: Record<string, unknown>) =>
      code(() => parseSignal(Buffer.from(JSON.stringify({ ...read, signature: 'AA', ...patch })), receiver));
    assert.equal(parse({}), 'accepted');
    assert.equal(parse({ type: 'x-live-offer', extra: [1] }), 'accepted', 'unknown types and members pass');
    assert.equal(parse({ type: 'Read' }), '400 invalid type');
    assert.equal(parse({ from: 'Ada@example.com' }), '400 invalid from');
    assert.equal(parse({ to: [] }), '400 invalid to');
    assert.equal(parse({ to: ['bob@example.net', 'bob@example.net'] }), '400 invalid to');
    assert.equal(parse({ about: 'A'.repeat(64) }), '400 invalid about');
    assert.equal(parse({ at: '2026-10-14' }), '400 invalid at');
    assert.equal(parse({ server: 'simon.example.net' }), '400 invalid server');
    assert.equal(parse({ signature: 'A=' }), '400 invalid signature');
    assert.equal(parse({ server: 'https://simon.example.org' }), '400 invalid server', 'for another server');
    assert.equal(
      code(() => parseSignal(Buffer.from('[]'))),
      '400 invalid signal',
    );
    const big = Buffer.from(JSON.stringify({ ...read, signature: 'AA', pad: 'x'.repeat(4096) }));
    assert.equal(
      code(() => parseSignal(big)),
      '400 invalid signal',
      'over 4096 without its signature',
    );
    const huge = Buffer.from(JSON.stringify({ ...read, signature: 'A'.repeat(16384) }));
    assert.equal(
      code(() => parseSignal(huge)),
      '413 body_too_large',
      'a body over 16384',
    );
  });

  it('carry a post-quantum signature: the 4096 bound leaves the signature out', () => {
    const signal = signSignal(read, carol.privateKey);
    assert.ok(signal.signature.length > 4096, 'an ML-DSA-65 signature alone is longer than 4096 characters');
    assert.deepEqual(parseSignal(Buffer.from(canonicalize(signal)), receiver), signal);
    assert.equal(verifySignal(signal, [keyEntry(carol.key)], NOW), true);
  });

  it("live five minutes either side of the receiver's clock", () => {
    const at = (iso: string) => code(() => checkSignalFreshness({ at: iso }, NOW));
    assert.equal(at('2026-10-14T20:58:00Z'), 'accepted');
    assert.equal(at('2026-10-14T20:57:59Z'), '400 invalid at');
    assert.equal(at('2026-10-14T21:08:00Z'), 'accepted');
    assert.equal(at('2026-10-14T21:08:01Z'), '400 invalid at');
  });
});

describe('unpairing', () => {
  it("is the key principal's signature over SIMON-UNPAIR, address and identifier", () => {
    const principal = `simon-key:${erin.key}`;
    const unpairing = signUnpairing(erin.privateKey, 'bob@example.net', principal);
    assert.equal(unpairingBytes('bob@example.net', principal), `SIMON-UNPAIR\nbob@example.net\n${principal}`);
    assert.equal(verifyUnpairing('bob@example.net', principal, unpairing), true);
    assert.equal(verifyUnpairing('ada@example.com', principal, unpairing), false, 'another address');
    assert.equal(verifyUnpairing('bob@example.net', `simon-key:${frank.key}`, unpairing), false, 'another key');
    assert.equal(verifyPairing('bob@example.net', principal, unpairing), false, 'never read as a pairing');
    assert.equal(verifyUnpairing('bob@example.net', 'mailto:erin@example.org', unpairing), false, 'keys only');
  });
});

describe("a key principal's recovery", () => {
  it('is the signature over SIMON-RECOVER, the address, the new key and the time', () => {
    const principal = `simon-key:${erin.key}`;
    const at = '2026-10-14T21:03:00Z';
    const recover = signRecovery(erin.privateKey, 'bob@example.net', ada.key, at);
    assert.equal(recoveryBytes('bob@example.net', ada.key, at), `SIMON-RECOVER\nbob@example.net\n${ada.key}\n${at}`);
    assert.equal(verifyRecovery('bob@example.net', principal, ada.key, at, recover), true);
    assert.equal(verifyRecovery('ada@example.com', principal, ada.key, at, recover), false, 'another address');
    assert.equal(verifyRecovery('bob@example.net', principal, carol.key, at, recover), false, 'another new key');
    assert.equal(
      verifyRecovery('bob@example.net', principal, ada.key, '2026-10-14T21:03:01Z', recover),
      false,
      'another time',
    );
    assert.equal(
      verifyRecovery('bob@example.net', `simon-key:${frank.key}`, ada.key, at, recover),
      false,
      'another key',
    );
    assert.equal(
      verifyRecovery('bob@example.net', 'mailto:erin@example.org', ada.key, at, recover),
      false,
      'keys only',
    );
  });
});

describe('readers', () => {
  const understood = new Set(['for', 'pairing', 'critical', 'rel', 'subject']);

  it('present an unknown version, or an unknown critical header, as not understood', () => {
    assert.equal(isUnderstood(signedQuestion, understood), true);
    assert.equal(isUnderstood({ ...signedQuestion, v: 9 }, understood), false);
    const critical = (c: string) => ({ ...signedQuestion, headers: { ...signedQuestion.headers, critical: c } });
    assert.equal(isUnderstood(critical('for,subject'), understood), true);
    assert.equal(isUnderstood(critical('binding'), understood), true, 'an absent critical header is ignored');
    assert.equal(
      isUnderstood(
        { ...critical('binding'), headers: { critical: 'binding', binding: 'opaque' } } as Message,
        understood,
      ),
      false,
    );
  });

  it('count a principal only for a paired agent', () => {
    assert.equal(claimedPrincipal(signedQuestion, 'paired'), 'mailto:alice@example.org');
    assert.equal(claimedPrincipal(signedQuestion, 'solo'), null, 'a solo agent speaks for no one');
    assert.equal(claimedPrincipal(signedQuestion, 'robot'), null, 'nor an agent of a kind the reader does not know');
    assert.equal(claimedPrincipal({ ...signedQuestion, v: 9 }, 'paired'), null);
  });

  it('show an unknown relation as a reply, and apply an author-only one only from the author', () => {
    const known = new Set(['reaction', 'edit', 'retract']);
    const original = { from: 'ada@example.com' };
    const rel = (from: string, name?: string): Message => ({
      ...signedQuestion,
      from,
      inReplyTo: 'a'.repeat(64),
      headers: name ? { rel: name } : {},
    });
    assert.equal(readsAs(rel('bob@example.net'), original, known), 'reply', 'no rel');
    assert.equal(readsAs(rel('bob@example.net', 'reaction'), original, known), 'relation', 'anyone reacts');
    assert.equal(readsAs(rel('bob@example.net', 'x-poke'), original, known), 'reply', 'unknown');
    assert.equal(readsAs(rel('ada@example.com', 'edit'), original, known), 'relation', 'the author edits');
    assert.equal(readsAs(rel('bob@example.net', 'edit'), original, known), 'reply', 'nobody else does');
    assert.equal(readsAs(rel('bob@example.net', 'retract'), original, known), 'reply');
    assert.equal(readsAs(rel('bob@example.net', 'edit'), null, known), 'pending', 'until the original arrives');
  });
});
