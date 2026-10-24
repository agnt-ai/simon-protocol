/** Exact declared-byte boundaries must agree with arbitrary-precision clients. */
import assert from 'node:assert/strict';
import { it } from 'node:test';
import { canonicalBytes, checkMessage, MINIMUM_LIMITS, WireError, type Message, type Part } from '../src/index.ts';
import { signedQuestion } from './fixtures.ts';

const file = (size: number, id: number): Part => ({
  type: 'application/octet-stream',
  sha256: id.toString(16).padStart(64, '0'),
  size,
});
const message = (parts: Part[]): Message => ({ ...signedQuestion, parts });
const carry = (parts: Part[]): Part => ({
  type: 'application/agnt-message',
  data: canonicalBytes(message(parts)).toString('base64'),
});
const invalidParts = (e: unknown) => e instanceof WireError && e.status === 400 && e.details?.field === 'parts';

it('rejects the exact one-byte-over total even when Number addition rounds it down', () => {
  const partBytes = 2 ** 48;
  const limits = { ...MINIMUM_LIMITS, partBytes };
  const inner = Array.from({ length: 32 }, (_, i) => file(partBytes, i + 1));
  assert.doesNotThrow(() => checkMessage(message([carry(inner)]), limits));
  assert.throws(() => checkMessage(message([file(1, 33), carry(inner)]), limits), invalidParts);
});

it('counts repeated declarations and rejects conflicting sizes, including zero', () => {
  assert.doesNotThrow(() => checkMessage(message([file(0, 1), carry([file(0, 1)])])));
  assert.throws(() => checkMessage(message([file(0, 1), carry([file(1, 1)])])), invalidParts);
  assert.throws(() => checkMessage(message([file(1, 1), carry([file(2, 1)])])), invalidParts);
  const partBytes = MINIMUM_LIMITS.partBytes;
  const repeated = Array.from({ length: 32 }, () => file(partBytes, 1));
  assert.doesNotThrow(() => checkMessage(message([carry(repeated)])));
  assert.throws(() => checkMessage(message([file(partBytes, 1), carry(repeated)])), invalidParts);
});

it('accepts the exact aggregate with maximum-safe individual declarations', () => {
  const partBytes = Number.MAX_SAFE_INTEGER;
  const parts = Array.from({ length: 32 }, (_, i) => file(partBytes, i + 1));
  assert.doesNotThrow(() => checkMessage(message([carry(parts)]), { ...MINIMUM_LIMITS, partBytes }));
});

const readerLimits = { ...MINIMUM_LIMITS, messageBytes: Infinity, recipients: Infinity, partBytes: Infinity };

it('accepts unrestricted reader part-byte limits for plain, own-file and carried messages', () => {
  assert.doesNotThrow(() => checkMessage(message([]), readerLimits));
  assert.doesNotThrow(() => checkMessage(signedQuestion, readerLimits));
  const large = file(Number.MAX_SAFE_INTEGER, 1);
  assert.doesNotThrow(() => checkMessage(message([large]), readerLimits));
  assert.doesNotThrow(() => checkMessage(message([large, carry([large])]), readerLimits));
});

it('keeps structural, hash-size and occurrence bounds for unrestricted readers', () => {
  assert.throws(() => checkMessage(message([file(0, 1), carry([file(1, 1)])]), readerLimits), invalidParts);
  for (const unsafe of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => checkMessage(message([file(unsafe, 1)]), readerLimits));
    assert.throws(() => checkMessage(message([carry([file(unsafe, 1)])]), readerLimits));
  }
  const files = Array.from({ length: 32 }, (_, i) => file(Number.MAX_SAFE_INTEGER, i + 1));
  const atLimit = Array.from({ length: 32 }, () => carry(files));
  assert.doesNotThrow(() => checkMessage(message(atLimit), readerLimits));
  // Keep each message's own parts within32 while adding a1025th file at one further carried level.
  const overLimit = [...atLimit.slice(0, 31), carry([...files.slice(0, 31), carry([files[31], file(1, 33)])])];
  assert.throws(() => checkMessage(message(overLimit), readerLimits), invalidParts);
});

it('does not treat NaN or negative infinity as an unrestricted part-byte limit', () => {
  for (const partBytes of [NaN, -Infinity]) {
    const limits = { ...readerLimits, partBytes };
    assert.throws(() => checkMessage(message([]), limits));
    assert.throws(() => checkMessage(message([file(0, 1), carry([file(0, 1)])]), limits));
  }
});
