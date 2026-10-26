/**
 * The application's own agents send JSON details as an `application/json` block (spec section 5.3), whose
 * value is signed as canonical JSON: one it cannot carry is refused before signing, with a message that says
 * how to write it, rather than an encoding error from deep inside the signer.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';
import type { ServerApi } from '@agnt-sdk/simon-server';
import { SystemAgents } from '../src/system.ts';

describe('the application agents', () => {
  it('refuse details canonical JSON cannot carry, naming the problem and the way to write it', async () => {
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    let sent = 0;
    const api = {
      now: () => new Date('2026-10-25T00:00:00Z'),
      send: async () => {
        sent++;
        return { id: 'x' };
      },
    } as unknown as ServerApi;
    const system = new SystemAgents(privateKey, 'app.test', () => api);
    await assert.rejects(
      system.send('notices', { to: ['ada@app.test'], text: 'A price.', data: { price: 19.99 } }),
      /notices's message to ada@app\.test: A JSON block's data must fit canonical JSON.*"19\.99"/s,
    );
    assert.equal(sent, 0);
    assert.equal(
      await system.send('notices', { to: ['ada@app.test'], text: 'A price.', data: { price: '19.99' } }),
      'x',
    );
    assert.equal(sent, 1);
  });
});
