/** Actual MCP JSON-RPC preserves migration-gap details and requires explicit token acceptance. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { Agent, type Fetch } from '@agnt-protocol/client';
import { saveAddress } from '@agnt-protocol/client/credentials';
import { saveWaitState, waitFile } from '@agnt-protocol/client/wait';
import { generateKey } from '@agnt-protocol/protocol';
import { answer } from '../src/server.ts';
import { fakeServer } from '../../js/test/fake-server.ts';

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
    if (requested.pathname === '/agnt/sync') {
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

describe('explicit migration-gap handoff', () => {
  it('keeps migration details in actual MCP JSON-RPC errors and requires explicit sync arguments', async t => {
    const { agent, key, details, calls, fetch, entry } = await migration();
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'agnt-gap-mcp-'));
    t.mock.method(globalThis, 'fetch', fetch);
    try {
      fs.writeFileSync(path.join(home, 'key.pem'), key.privateKeyPem, { mode: 0o600 });
      saveAddress(home, agent);
      const invoke = async (name: string, args: object) => {
        const response = await answer(
          JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }),
          { home, timeoutMs: 1000 },
        );
        assert.ok(response && 'result' in response);
        return response.result as { isError?: boolean; content: { text: string }[] };
      };
      const rejected = await invoke('sync', {});
      assert.equal(rejected.isError, true);
      const error = JSON.parse(rejected.content[0].text).error;
      assert.deepEqual(
        [error.status, error.code, error.retryable, error.details],
        [410, 'token_expired', false, details],
      );
      assert.equal(calls.length, 1, 'MCP did not make an implicit acceptance request');
      const resumed = await invoke('sync', { since: details.resumeToken });
      assert.notEqual(resumed.isError, true);
      assert.deepEqual(
        JSON.parse(resumed.content[0].text).messages.map((e: { id: string }) => e.id),
        [entry.id],
      );
      assert.equal(calls.length, 2);
      assert.equal(calls[1].searchParams.get('since'), details.resumeToken);

      saveWaitState(home, { token: null, pending: [entry], seen: [] });
      const before = fs.readFileSync(waitFile(home));
      const waiting = await invoke('wait_for_message', { from: 'wanted@agents.test', timeoutSeconds: 1 });
      assert.equal(waiting.isError, true);
      assert.deepEqual(JSON.parse(waiting.content[0].text).error.details, details);
      assert.equal(calls.length, 3, 'MCP wait also surfaces the gap after exactly one request');
      assert.deepEqual(fs.readFileSync(waitFile(home)), before);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
