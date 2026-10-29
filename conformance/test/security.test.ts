/**
 * The transport checks against servers with planted faults. TLS needs a certificate; the test makes a
 * self-signed one with openssl (it skips without it) and lets the suite's process trust it through
 * NODE_EXTRA_CA_CERTS, as an operator would trust a private root.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { freePort } from '../src/context.ts';
import { runConformance } from '../src/suite.ts';
import { startToy } from './toy-server.ts';

const run = promisify(execFile);
const cli = path.resolve(import.meta.dirname, '../src/cli.ts');
const haveOpenssl = spawnSync('openssl', ['version']).status === 0;

describe('the TLS checks', { skip: !haveOpenssl && 'openssl is not installed' }, () => {
  let dir: string;
  const servers: https.Server[] = [];

  const listen = async (minVersion: 'TLSv1.2' | 'TLSv1.3') => {
    const server = https.createServer(
      { key: fs.readFileSync(`${dir}/key.pem`), cert: fs.readFileSync(`${dir}/cert.pem`), minVersion },
      (_, res) => res.writeHead(404, { 'content-type': 'application/problem+json' }).end('{}'),
    );
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    servers.push(server);
    return (server.address() as net.AddressInfo).port;
  };

  /** What the suite says about the TLS checks of an https server, in a process that trusts `trust`. */
  async function checks(port: number, trust: boolean) {
    const peerPort = await freePort('127.0.0.1');
    const env = { ...process.env, ...(trust ? { NODE_EXTRA_CA_CERTS: `${dir}/cert.pem` } : {}) };
    const out = await run(
      process.execPath,
      [
        cli,
        '--server',
        `https://localhost:${port}`,
        '--peer-port',
        String(peerPort),
        '--only',
        'security.tls-version,security.tls-certificate',
      ],
      { env },
    ).catch(e => e as { stdout: string });
    const report = JSON.parse(out.stdout);
    return Object.fromEntries(report.checks.map((c: { id: string; status: string }) => [c.id, c.status]));
  }

  before(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'simon-tls-'));
    const made = spawnSync(
      'openssl',
      ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '2']
        .concat(['-keyout', `${dir}/key.pem`, '-out', `${dir}/cert.pem`, '-subj', '/CN=localhost'])
        .concat(['-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1']),
    );
    assert.equal(made.status, 0, String(made.stderr));
  });
  after(async () => {
    for (const s of servers) await new Promise(resolve => s.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('passes a server that speaks TLS 1.3 only, with a certificate the process trusts', async () => {
    assert.deepEqual(await checks(await listen('TLSv1.3'), true), {
      'security.tls-version': 'pass',
      'security.tls-certificate': 'pass',
    });
  });

  it('fails a server that still speaks TLS 1.2', async () => {
    assert.deepEqual(await checks(await listen('TLSv1.2'), true), {
      'security.tls-version': 'fail',
      'security.tls-certificate': 'pass',
    });
  });

  it('fails a certificate the system does not trust', async () => {
    assert.deepEqual(await checks(await listen('TLSv1.3'), false), {
      'security.tls-version': 'pass',
      'security.tls-certificate': 'fail',
    });
  });
});

describe('the transport checks against the toy server', () => {
  it('skip the TLS checks of an http origin, and catch a server that follows a redirect', async () => {
    const port = await freePort('127.0.0.1');
    const toy = await startToy({ 'peer.test': `http://127.0.0.1:${port}` });
    try {
      const report = await runConformance({
        server: toy.origin,
        peerPort: port,
        only: [
          'security.tls-version',
          'security.tls-certificate',
          'security.no-redirect-agent-document',
          'webhooks.create',
        ],
        clockMarginSeconds: 2,
        deliveryWaitMs: 2000,
      });
      const status = Object.fromEntries(report.checks.map(c => [c.id, c.status]));
      assert.deepEqual(status, {
        'security.tls-version': 'skip',
        'security.tls-certificate': 'skip',
        // The toy fetches documents with fetch(), which follows a redirect unless told not to.
        'security.no-redirect-agent-document': 'fail',
        // The toy offers no webhooks (404), so their checks skip.
        'webhooks.create': 'skip',
      });
    } finally {
      await toy.close();
    }
  });
});
