/**
 * The suite tested against a toy server with planted faults: each must be caught by the check aimed at it,
 * what the toy does right must pass, and a failure must say what was sent, what came back and what was
 * expected.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import { catalog, catalogMarkdown, runConformance, type Report } from '../src/suite.ts';
import { freePort } from '../src/context.ts';
import { Peer } from '../src/peer.ts';
import { startToy, type ClientFaults } from './toy-server.ts';

describe('the conformance suite against a broken toy server', () => {
  let report: Report;
  let close: () => Promise<unknown>;
  const status = (id: string) => report.checks.find(c => c.id === id)?.status;

  before(async () => {
    const port = await freePort('127.0.0.1');
    const toy = await startToy({ 'peer.test': `http://127.0.0.1:${port}` });
    close = toy.close;
    report = await runConformance({
      server: toy.origin,
      peerPort: port,
      clockMarginSeconds: 2,
      deliveryWaitMs: 2000,
      retryWaitMs: 2000,
      prefetchWaitMs: 2000,
    });
  });
  after(() => close());

  it('catches every planted fault', () => {
    assert.equal(status('documents.server.limits'), 'fail', 'recipients: 50 is below the minimum');
    assert.equal(status('requests.nonce-after-bad-signature'), 'fail', 'a badly signed request uses up its nonce');
    assert.equal(status('deliver.order-envelope-before-freshness'), 'fail', 'freshness is checked before the envelope');
    assert.equal(status('deliver.order-repeat-before-freshness'), 'fail', 'freshness is checked before the repeat');
    assert.equal(status('deliver.silence'), 'fail', 'an unknown recipient is 404');
    assert.equal(status('documents.server.algorithms'), 'fail', 'the server document lists no algorithms');
    assert.equal(status('errors.content-type'), 'fail', 'errors go out as application/json');
    assert.equal(status('errors.www-authenticate'), 'fail', 'a 401 carries no WWW-Authenticate');
    assert.equal(status('deliver.destination-server'), 'fail', 'an envelope for another server is taken');
    assert.equal(status('deliver.repeat-new-recipient'), 'fail', 'a repeat is recognised by message id alone');
    assert.equal(
      status('deliver.author-unsupported-algorithm'),
      'fail',
      'an author with only unknown-algorithm keys is bad_signature',
    );
  });

  it('passes what the toy does right', () => {
    for (const id of [
      'documents.server.readable',
      'documents.server.origin',
      'documents.agent.served',
      'documents.agent.unknown',
      'requests.unsigned',
      'requests.malformed-header',
      'requests.bad-signature',
      'requests.binds-origin',
      'requests.replayed',
      'requests.nonce-after-unsigned',
      'requests.refusal-order',
      'deliver.accepted',
      'deliver.body-too-large',
      'deliver.parse',
      'deliver.claims-null',
      'deliver.shape-server',
      'deliver.shape-recipients',
      'deliver.shape-hints',
      'deliver.destination-recipients',
      'deliver.order-message-before-destination',
      'deliver.fan-out-recipients',
      'deliver.canonical',
      'deliver.order-canonical-before-signature',
      'deliver.version-1-rules',
      'deliver.carried-files',
      'deliver.unknown-version-stored',
      'deliver.envelope-covers-everything',
      'deliver.author-key-valid-at-sentAt',
      'deliver.author-strict-ed25519',
      'deliver.author-signature',
      'sync.shape',
      'sync.self',
      'sync.carrier-local',
      'sync.parameters',
      'sync.unknown-token',
      'sync.paging',
      'sync.sent',
      'errors.shape',
      'errors.retryable',
      'errors.server-time',
    ]) {
      assert.equal(status(id), 'pass', `${id}: ${report.checks.find(c => c.id === id)?.observed}`);
    }
  });

  it('says what was sent, what came back and what was expected', () => {
    const c = report.checks.find(x => x.id === 'deliver.silence')!;
    assert.match(c.section, /6\.3/);
    assert.equal(c.level, 'must');
    assert.ok(c.expected.length > 0);
    assert.match(c.observed!, /expected status 202, got 404 not_found/);
    const last = c.exchanges.find(e => e.label === 'an unknown name')!;
    assert.equal(last.request.method, 'POST');
    assert.match(last.request.url, /\/simon\/deliver$/);
    assert.equal(typeof last.request.body, 'string');
    assert.equal(last.response?.status, 404);
  });

  it('counts must failures for the exit code', () => {
    assert.ok(report.summary.mustFailed > 0);
    assert.equal(report.summary.total, report.checks.length);
    assert.equal(report.checks.length, catalog().length);
  });
});

describe('migrated sync checks catch planted client faults', () => {
  for (const [fault, id] of [
    ['numericToken', 'sync.shape'],
    ['unknownTokenEmpty', 'sync.unknown-token'],
    ['omitSent', 'sync.sent'],
    ['stalledToken', 'sync.paging'],
  ] as const) {
    it(`rejects ${fault} through ${id}`, async () => {
      const port = await freePort('127.0.0.1');
      const faults: ClientFaults = { [fault]: true };
      const toy = await startToy({ 'peer.test': `http://127.0.0.1:${port}` }, faults);
      try {
        const report = await runConformance({
          server: toy.origin,
          peerPort: port,
          only: [id],
          clockMarginSeconds: 2,
          deliveryWaitMs: 200,
          retryWaitMs: 200,
          prefetchWaitMs: 200,
        });
        assert.deepEqual(
          report.checks.map(c => [c.id, c.status]),
          [[id, 'fail']],
        );
        if (fault === 'numericToken') {
          assert.match(report.checks[0].observed ?? '', /opaque token|token is [0-9]+/);
        }
      } finally {
        await toy.close();
      }
    });
  }
});

describe('the simulator behind a tunnel', () => {
  /** A TCP forwarder to a local port, as a tunnel's connector is: its own port is the public origin's. */
  async function tunnelTo(port: number) {
    const sockets = new Set<net.Socket>();
    const server = net.createServer(socket => {
      const inner = net.connect(port, '127.0.0.1');
      for (const s of [socket, inner]) {
        sockets.add(s);
        s.on('close', () => sockets.delete(s));
        s.on('error', () => s.destroy());
      }
      socket.pipe(inner).pipe(socket);
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    let connections = 0;
    server.on('connection', () => connections++);
    return {
      origin: `http://127.0.0.1:${(server.address() as net.AddressInfo).port}`,
      connections: () => connections,
      close: () => {
        for (const s of sockets) s.destroy();
        return new Promise(resolve => server.close(resolve));
      },
    };
  }

  it('is reached at the origin given it, not where it listens', async () => {
    const port = await freePort('127.0.0.1');
    const tunnel = await tunnelTo(port);
    const toy = await startToy({ 'peer.test': tunnel.origin });
    try {
      const ids = ['deliver.accepted', 'deliver.envelope-covers-everything', 'deliver.author-key-valid-at-sentAt'];
      const report = await runConformance({
        server: toy.origin,
        peerPort: port,
        peerOrigin: tunnel.origin,
        only: ids,
        clockMarginSeconds: 2,
        deliveryWaitMs: 2000,
      });
      assert.equal(report.peer.origin, tunnel.origin);
      assert.deepEqual(
        report.checks.map(c => [c.id, c.status]),
        ids.map(id => [id, 'pass']),
      );
      assert.ok(tunnel.connections() > 0, 'the server under test reached the simulator through the tunnel');
    } finally {
      await toy.close();
      await tunnel.close();
    }
  });

  it("answers the well-known resolution for a domain that is its origin's host, and for no other", async () => {
    for (const [domain, wellKnown] of [
      ['quick-tunnel.example', 200],
      ['peer.test', 404],
    ] as const) {
      const port = await freePort('127.0.0.1');
      const peer = new Peer(domain, '127.0.0.1', port, 'run', 'https://quick-tunnel.example');
      const read = async (target: string) => {
        const res = await fetch(`http://127.0.0.1:${port}${target}`);
        return [res.status, await res.json()];
      };
      await peer.start();
      try {
        const [status, body] = await read('/.well-known/simon');
        assert.equal(status, wellKnown, domain);
        if (status === 200) assert.deepEqual(body, { server: 'https://quick-tunnel.example' });
        assert.equal((await read('/simon/server'))[1].server, 'https://quick-tunnel.example');
      } finally {
        await peer.stop();
      }
    }
  });
});

describe('the README', () => {
  it('lists the checks as the code declares them', () => {
    const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
    const start = readme.indexOf('<!-- checks:start -->');
    const end = readme.indexOf('<!-- checks:end -->');
    assert.ok(start >= 0 && end > start, 'README.md has the check markers');
    assert.equal(
      readme.slice(start + '<!-- checks:start -->'.length, end).trim(),
      catalogMarkdown().trim(),
      'run `node conformance/scripts/write-readme.ts` to regenerate the list',
    );
  });
});
