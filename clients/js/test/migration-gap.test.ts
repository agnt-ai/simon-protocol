/** A migration gap reaches the caller; only an explicit subsequent request accepts its resume token. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { generateKey } from '@agnt-sdk/simon-protocol';
import { Agent, SimonError, type Fetch } from '../src/index.ts';
import { readWaitState, saveWaitState, waitFile, waitForMessage } from '../src/wait.ts';
import { fakeServer } from './fake-server.ts';

async function migration() {
  const fake = fakeServer();
  const key = generateKey();
  const owner = new Agent({ server: fake.origin, key: key.privateKey, fetch: fake.fetch });
  await owner.register();
  const resumeToken = (await owner.sync()).token;
  const author = new Agent({ server: fake.origin, key: generateKey().privateKey, fetch: fake.fetch });
  await author.register();
  const sent = await author.send({ to: [owner.address!], text: 'retained through migration' });
  const entry = (await owner.sync({ since: resumeToken })).messages[0];
  assert.equal(entry.id, sent.id);
  const details = { reason: 'history_migration', resumeToken };
  const calls: URL[] = [];
  const fetch: Fetch = async (url, init) => {
    const requested = new URL(url);
    if (requested.pathname === '/simon/sync') {
      calls.push(requested);
      if (!requested.searchParams.has('since'))
        return new Response(
          JSON.stringify({
            type: 'about:blank',
            title: 'Token expired',
            status: 410,
            code: 'token_expired',
            detail: 'Retained sent history may be incomplete. Explicitly accept this gap.',
            retryable: false,
            details,
          }),
          { status: 410, headers: { 'content-type': 'application/problem+json' } },
        );
    }
    return fake.fetch(url, init);
  };
  const agent = new Agent({ server: fake.origin, key: key.privateKey, address: owner.address, fetch });
  return { fake, key, agent, details, calls, fetch, entry };
}

const errorIsGap = (details: object) => (error: unknown) => {
  assert.ok(error instanceof SimonError);
  assert.deepEqual([error.status, error.code, error.retryable], [410, 'token_expired', false]);
  assert.deepEqual(error.details, details);
  assert.deepEqual(
    JSON.parse(JSON.stringify(error)).error.details,
    details,
    'SimonError JSON preserves the offered token',
  );
  return true;
};

describe('explicit migration-gap handoff', () => {
  it('surfaces the real SDK error without a second request, then reads retained messages only on explicit resume', async () => {
    const { agent, details, calls, entry } = await migration();
    await assert.rejects(agent.sync(), errorIsGap(details));
    assert.equal(calls.length, 1, 'the SDK must not automatically retry with resumeToken');
    assert.equal(calls[0].searchParams.has('since'), false);
    const retained = await agent.sync({ since: details.resumeToken });
    assert.equal(calls.length, 2);
    assert.equal(calls[1].searchParams.get('since'), details.resumeToken, 'opaque token is passed unchanged');
    assert.deepEqual(
      retained.messages.map(e => e.id),
      [entry.id],
    );
    await assert.rejects(agent.sync(), errorIsGap(details));
    assert.equal(
      calls.length,
      3,
      'explicit acceptance does not silently turn later initial requests into resumed ones',
    );
  });

  it('preserves shared wait bytes and unmatched buffered messages on 410', async () => {
    const { agent, details, calls, entry } = await migration();
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'simon-gap-wait-'));
    try {
      saveWaitState(home, { token: null, pending: [entry], seen: ['e'.repeat(64)] });
      const before = fs.readFileSync(waitFile(home));
      await assert.rejects(
        waitForMessage(agent, home, {
          from: 'wanted@agents.test',
          timeoutMs: 60_000,
          intervalMs: 1,
          sleep: async () => {
            throw new Error('a nonretryable migration gap must not sleep or retry');
          },
        }),
        errorIsGap(details),
      );
      assert.equal(calls.length, 1);
      assert.deepEqual(fs.readFileSync(waitFile(home)), before, 'no implicit checkpoint or buffer reset');
      assert.equal(fs.existsSync(path.join(home, 'wait.lock')), false, 'the failed wait releases its own lock');
      const buffered = await waitForMessage(agent, home, { timeoutMs: 0, intervalMs: 1 });
      assert.equal(buffered?.entry.id, entry.id, 'another correspondent remains readable offline');
      assert.equal(calls.length, 1, 'showing a buffered entry does not accept the migration token');
      assert.equal(readWaitState(home).token, null);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
