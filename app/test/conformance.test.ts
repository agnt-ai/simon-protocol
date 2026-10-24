/**
 * The black-box conformance suite, over real HTTP, against the application with every module running:
 * every `must` holds. The server under test resolves the suite's peer domain to its simulator.
 */
import assert from 'node:assert/strict';
import net from 'node:net';
import { after, before, describe, it } from 'node:test';
import { generateKey } from '@agnt-sdk/simon-protocol';
import { runConformance, type Report } from 'simon-conformance';
import { defineConfig } from 'simon-server';
import { createApp, type App } from '../src/app.ts';
import { loadAppConfig } from '../src/config.ts';
import { freshDb, stopMongo } from './mongo.ts';

const freePort = () =>
  new Promise<number>((resolve, reject) => {
    const s = net.createServer().once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address() as net.AddressInfo;
      s.close(() => resolve(port));
    });
  });

describe('conformance', { timeout: 600_000 }, () => {
  let app: App;
  let report: Report;

  before(async () => {
    const [port, peerPort, secondPeerPort] = [await freePort(), await freePort(), await freePort()];
    const origin = `http://127.0.0.1:${port}`;
    const loose = { limit: 1_000_000, seconds: 3600 };
    const server = defineConfig({
      origin,
      dev: true,
      port,
      hostedDomains: ['sut.test'],
      leaseDomain: 'lease.sut.test',
      serverKey: generateKey().privateKey,
      rates: {
        request: loose,
        register: loose,
        code: loose,
        codeClient: loose,
        send: loose,
        destinations: loose,
        upload: loose,
        deliver: loose,
        badSignature: loose,
      },
      devResolve: {
        'sut.test': origin,
        'lease.sut.test': origin,
        'peer.test': `http://127.0.0.1:${peerPort}`,
        'second.test': `http://127.0.0.1:${secondPeerPort}`,
      },
    });
    const env = {
      SIMON_INBOUND_PER_SENDER: '100000',
      SIMON_INBOUND_PER_DOMAIN: '100000',
      SIMON_INBOUND_FIRST_CONTACTS: '100000',
    };
    app = createApp({ config: loadAppConfig(env, server), db: await freshDb(), log: () => {} });
    await app.start();
    await app.server.listen(port, '127.0.0.1');
    report = await runConformance({
      server: origin,
      peerPort,
      secondPeerDomain: 'second.test',
      secondPeerPort,
      hostedDomain: 'sut.test',
      clockMarginSeconds: 2,
      deliveryWaitMs: 10_000,
      retryWaitMs: 150_000,
      prefetchWaitMs: 240_000,
    });
  });
  after(async () => {
    await app?.close();
    await stopMongo();
  });

  it('passes every must', () => {
    const failed = report.checks.filter(c => c.level === 'must' && c.status === 'fail');
    assert.deepEqual(
      failed.map(c => `${c.id}: ${c.observed}`),
      [],
    );
  });
});
