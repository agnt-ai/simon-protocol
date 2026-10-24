/** Part success limits and bounded HTTP errors must not borrow one another's byte budget. */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateKey, sha256Hex } from '@agnt-protocol/protocol';
import { Agent } from '../src/index.ts';
import { exchange, failure, MAX_PROBLEM_BYTES } from '../src/http.ts';

const URL = 'https://simon.test/simon/parts/' + 'a'.repeat(64);
const NOW = new Date('2026-10-15T12:00:00.000Z');
const problem = JSON.stringify({ code: 'not_found', detail: 'No such part.', details: { what: 'part' } });

function partAgent(answer: () => Response) {
  return new Agent({
    server: 'https://simon.test',
    address: 'ada@simon.test',
    key: generateKey().privateKeyPem,
    fetch: async () => answer(),
    now: () => NOW,
  });
}

describe('separate error-body budget', () => {
  it('preserves a valid problem larger than a one-byte part, including HTTP retry metadata', async () => {
    for (const status of [404, 503]) {
      const agent = partAgent(() => new Response(problem, { status, headers: { 'retry-after': '7' } }));
      await assert.rejects(agent.fetchPart({ sha256: 'a'.repeat(64), size: 1 }), {
        code: 'not_found',
        status,
        retryable: status === 503,
        retryAfter: 7,
        details: { what: 'part' },
      });
    }
  });

  it('keeps successful part size and hash validation', async () => {
    const bytes = Uint8Array.of(7);
    const part = { sha256: sha256Hex(bytes), size: 1 };
    assert.deepEqual(await partAgent(() => new Response(bytes)).fetchPart(part), bytes);
    await assert.rejects(partAgent(() => new Response(Uint8Array.of(7, 8))).fetchPart(part), {
      code: 'hash_mismatch',
    });
    await assert.rejects(partAgent(() => new Response(Uint8Array.of(8))).fetchPart(part), {
      code: 'hash_mismatch',
    });
  });

  it('accepts a complete problem at the decoded error limit', async () => {
    const answer = await exchange(
      { fetch: async () => new Response(problem.padEnd(MAX_PROBLEM_BYTES), { status: 404 }) },
      URL,
      {},
      1,
    );
    assert.equal(answer.body.length, MAX_PROBLEM_BYTES);
    assert.deepEqual(failure(answer, NOW).details, { what: 'part' });
    assert.equal(failure(answer, NOW).code, 'not_found');
  });

  it('rejects an oversized parseable prefix, bounds retained bytes and never waits for cancellation', async () => {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(Buffer.from(problem.padEnd(MAX_PROBLEM_BYTES + 1024)));
      },
      cancel() {
        cancelled = true;
        return new Promise<void>(() => {});
      },
    });
    const answer = await exchange(
      {
        fetch: async () => new Response(stream, { status: 503, headers: { 'retry-after': '9' } }),
        timeoutMs: 500,
      },
      URL,
      {},
      1,
    );
    assert.equal(answer.body.length, MAX_PROBLEM_BYTES + 1);
    assert.equal(cancelled, true);
    const error = failure(answer, NOW);
    assert.deepEqual([error.code, error.status, error.retryable, error.retryAfter], ['bad_response', 503, true, 9]);
  });

  it('preserves caller cancellation during a stalled error body read', { timeout: 2000 }, async () => {
    const controller = new AbortController();
    const reason = new Error('caller stopped the error read');
    let started!: () => void;
    const reading = new Promise<void>(resolve => (started = resolve));
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>(
      {
        pull() {
          started();
          return new Promise<void>(() => {});
        },
        cancel() {
          cancelled = true;
          return new Promise<void>(() => {});
        },
      },
      { highWaterMark: 0 },
    );
    const pending = exchange(
      { fetch: async () => new Response(stream, { status: 404 }), timeoutMs: 1000 },
      URL,
      { signal: controller.signal },
      1,
    );
    const rejected = assert.rejects(pending, error => error === reason);
    await reading;
    controller.abort(reason);
    await rejected;
    assert.equal(cancelled, true);
  });

  it('bounds a stalled error body including unending cancellation cleanup', { timeout: 2000 }, async () => {
    let cancelled = false;
    let read = false;
    const stream = new ReadableStream<Uint8Array>(
      {
        pull() {
          read = true;
          return new Promise<void>(() => {});
        },
        cancel() {
          cancelled = true;
          return new Promise<void>(() => {});
        },
      },
      { highWaterMark: 0 },
    );
    await assert.rejects(
      exchange({ fetch: async () => new Response(stream, { status: 503 }), timeoutMs: 20 }, URL, {}, 1),
      { code: 'timeout', retryable: true },
    );
    assert.equal(read, true);
    assert.equal(cancelled, true);
  });
});
