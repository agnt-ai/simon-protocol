/** External signed part requests must use the same pre-authentication lookup budget as deliveries/readers. */
import assert from 'node:assert/strict';
import { it } from 'node:test';
import { generateKey, signRequest } from '@agnt-protocol/protocol';
import { Federation, toRequest } from './harness.ts';

it('charges cold server-signed part lookups to the caller network and caches misses', async () => {
  const fed = new Federation();
  try {
    const home = await fed.server('home', { config: { rates: { lookup: { limit: 1, seconds: 3600 } } } });
    const key = generateKey().privateKey;
    const url = new URL(`${home.origin}/agnt/parts/${'a'.repeat(64)}`);
    const ask = async (server: string) =>
      home.server.handle(
        toRequest(
          'GET',
          url,
          signRequest(key, { method: 'GET', url: url.href, now: fed.clock.t, server }),
          Buffer.alloc(0),
          '203.0.113.10',
        ),
      );
    assert.equal((await ask('https://first.example')).status, 404);
    assert.equal(fed.net.sent.length, 1);
    assert.equal((await ask('https://first.example')).status, 404);
    assert.equal(fed.net.sent.length, 1, 'the cached negative answer needs no refetch');
    assert.equal((await ask('https://second.example')).status, 404);
    assert.equal(fed.net.sent.length, 1, 'new origins do not bypass the same client-network budget');
  } finally {
    await fed.close();
  }
});
