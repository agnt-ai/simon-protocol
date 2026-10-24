/**
 * Behind a tunnel or a load balancer: the client's address comes from the header the proxy sets, believed
 * only from this machine and from the proxy networks configured; the load balancer checks a health route
 * that says nothing else. A hosting service's own networks skip the per-client rates, by that same address.
 */
import assert from 'node:assert/strict';
import type { IncomingMessage } from 'node:http';
import { describe, it } from 'node:test';
import { defineConfig, DEFAULT_RATES, loadConfig } from '../src/config.ts';
import { clientIp } from '../src/http.ts';
import { parseNetwork, type Network } from '../src/net/ip.ts';
import { RateLimiter } from '../src/rate.ts';
import { createServer, type SimonServer } from '../src/server.ts';
import { SqliteStore } from '../src/store/sqlite.ts';
import { toRequest } from '../src/testing.ts';

const base = {
  SIMON_ORIGIN: 'https://simon.example.com',
  SIMON_SERVER_KEY: `ed25519:${Buffer.alloc(32, 7).toString('base64url')}`,
};
const request = (remoteAddress: string, headers: Record<string, string> = {}) =>
  ({ socket: { remoteAddress }, headers }) as unknown as IncomingMessage;

describe('behind a tunnel', () => {
  const tunnel = { clientIpHeader: 'cf-connecting-ip', trustedProxies: [] };

  it('reads the client address from the named header only on a connection from this machine', () => {
    const header = { 'cf-connecting-ip': '203.0.113.9' };
    assert.equal(clientIp(request('127.0.0.1', header), tunnel), '203.0.113.9');
    assert.equal(clientIp(request('::1', header), tunnel), '203.0.113.9');
    assert.equal(clientIp(request('::ffff:127.0.0.1', header), tunnel), '203.0.113.9');
    assert.equal(
      clientIp(request('198.51.100.4', header), tunnel),
      '198.51.100.4',
      'a remote client cannot name itself',
    );
    assert.equal(clientIp(request('127.0.0.1', { 'cf-connecting-ip': 'not an ip' }), tunnel), '127.0.0.1');
    assert.equal(
      clientIp(request('127.0.0.1', header), { clientIpHeader: null, trustedProxies: [] }),
      '127.0.0.1',
      'no header configured, none read',
    );
  });

  it('takes a listen address and a header name, and refuses anything else', () => {
    const config = loadConfig({ ...base, SIMON_LISTEN_HOST: '127.0.0.1', SIMON_CLIENT_IP_HEADER: 'CF-Connecting-IP' });
    assert.equal(config.listenHost, '127.0.0.1');
    assert.equal(config.clientIpHeader, 'cf-connecting-ip');
    assert.equal(loadConfig(base).listenHost, null);
    assert.throws(() => loadConfig({ ...base, SIMON_LISTEN_HOST: 'localhost.example' }), /listenHost/);
    assert.throws(() => loadConfig({ ...base, SIMON_CLIENT_IP_HEADER: 'x y' }), /clientIpHeader/);
  });
});

describe('behind a load balancer', () => {
  const subnets = ['10.0.0.0/16', 'fd00:ec2::/32'].map(cidr => parseNetwork(cidr) as Network);
  const balancer = { clientIpHeader: 'x-forwarded-for', trustedProxies: subnets };
  const from = (socket: string, xff: string) => clientIp(request(socket, { 'x-forwarded-for': xff }), balancer);

  it('takes the address the balancer appended', () => {
    assert.equal(from('10.0.1.5', '203.0.113.9'), '203.0.113.9');
    assert.equal(from('::ffff:10.0.1.5', '203.0.113.9'), '203.0.113.9', 'an IPv4 connection on a dual-stack socket');
    assert.equal(from('fd00:ec2::7', '2001:db8::1'), '2001:db8::1');
  });

  it('never reaches what the client wrote itself', () => {
    assert.equal(from('10.0.1.5', '198.51.100.1, 203.0.113.9'), '203.0.113.9', 'a forged entry on the left');
    assert.equal(from('10.0.1.5', '10.0.9.9, 203.0.113.9'), '203.0.113.9', 'a forged proxy address on the left');
    assert.equal(from('10.0.1.5', 'garbage, 203.0.113.9'), '203.0.113.9');
  });

  it('walks past every trusted hop, and no further', () => {
    assert.equal(from('10.0.1.5', '203.0.113.9, 10.0.2.7'), '203.0.113.9', 'a second proxy inside the network');
    assert.equal(from('10.0.1.5', '10.0.2.7'), '10.0.2.7', 'the list ran out at a proxy');
    assert.equal(from('10.0.1.5', '203.0.113.9, not an ip'), '10.0.1.5', 'a hop that is no address stops the walk');
    assert.equal(from('10.0.1.5', ''), '10.0.1.5');
    assert.equal(from('10.0.1.5', '203.0.113.9:51234'), '10.0.1.5', 'an entry with a port is no address');
  });

  it('believes nobody outside the proxy networks', () => {
    assert.equal(from('198.51.100.4', '203.0.113.9'), '198.51.100.4');
    assert.equal(from('10.1.0.1', '203.0.113.9'), '10.1.0.1', 'next to the network is not in it');
    assert.equal(clientIp(request('10.0.1.5'), balancer), '10.0.1.5', 'no header, the connection');
  });

  it('reads the proxy networks and the keep-alive timeout, and refuses anything else', () => {
    const c = loadConfig({
      ...base,
      SIMON_CLIENT_IP_HEADER: 'X-Forwarded-For',
      SIMON_TRUSTED_PROXIES: '10.0.0.0/16, fd00:ec2::/32',
      SIMON_KEEP_ALIVE_TIMEOUT: '65',
    });
    assert.deepEqual(
      c.trustedProxies.map(n => n.cidr),
      ['10.0.0.0/16', 'fd00:ec2:0:0:0:0:0:0/32'],
    );
    assert.equal(c.keepAliveSeconds, 65);
    assert.deepEqual([loadConfig(base).trustedProxies, loadConfig(base).keepAliveSeconds], [[], 5]);
    const header = { ...base, SIMON_CLIENT_IP_HEADER: 'x-forwarded-for' };
    assert.throws(() => loadConfig({ ...base, SIMON_TRUSTED_PROXIES: '10.0.0.0/16' }), /clientIpHeader/);
    assert.throws(() => loadConfig({ ...header, SIMON_TRUSTED_PROXIES: '0.0.0.0/0' }), /trustedProxies/);
    assert.throws(() => loadConfig({ ...header, SIMON_TRUSTED_PROXIES: '10.0.0.1' }), /trustedProxies/);
    assert.throws(() => loadConfig({ ...header, SIMON_TRUSTED_PROXIES: '::ffff:10.0.0.0/104' }), /as IPv4/);
    assert.throws(() => loadConfig({ ...base, SIMON_KEEP_ALIVE_TIMEOUT: '0' }), /keepAliveSeconds/);
  });

  it('limits each client by the address the balancer saw, over real HTTP', async () => {
    const config = defineConfig({
      origin: 'http://127.0.0.1',
      dev: true,
      database: ':memory:',
      clientIpHeader: 'x-forwarded-for',
      rates: { request: { limit: 2, seconds: 60 } },
      rateExemptNetworks: ['192.0.2.0/24'],
    });
    const store = new SqliteStore(config.database);
    const server = createServer({ config, store, worker: false });
    const port = await server.listen(0, '127.0.0.1');
    const health = (client: string) =>
      fetch(`http://127.0.0.1:${port}/health`, { headers: { 'x-forwarded-for': `198.51.100.1, ${client}` } });
    try {
      const statuses = [];
      for (const client of ['203.0.113.1', '203.0.113.1', '203.0.113.1', '203.0.113.2']) {
        statuses.push((await health(client)).status);
      }
      assert.deepEqual(statuses, [200, 200, 429, 200], 'the third request from one client is refused, not the next');
      for (let i = 0; i < 3; i++) assert.equal((await health('192.0.2.10')).status, 200, 'an exempt client');
    } finally {
      await server.close();
      await store.close();
    }
  });
});

describe("a hosting service's own networks", () => {
  const networks = (...cidrs: string[]) => cidrs.map(cidr => parseNetwork(cidr) as Network);
  const balancer = { clientIpHeader: 'x-forwarded-for', trustedProxies: networks('10.0.0.0/16') };
  const limiter = () =>
    new RateLimiter(
      { ...DEFAULT_RATES, request: { limit: 1, seconds: 60 }, register: { limit: 1, seconds: 60 } },
      () => new Date(),
      networks('192.0.2.0/24'),
    );

  it('skip the request and register rates', () => {
    const rate = limiter();
    for (let i = 0; i < 3; i++) {
      rate.hitClient('request', '192.0.2.10');
      rate.hitClient('register', '::ffff:192.0.2.10');
    }
    rate.hitClient('request', '203.0.113.9');
    assert.throws(() => rate.hitClient('request', '203.0.113.9'), { status: 429 }, 'everyone else is counted');
  });

  it('cannot be claimed by a client that writes their address into the header', () => {
    const rate = limiter();
    const header = { 'x-forwarded-for': '192.0.2.10' };
    const direct = clientIp(request('198.51.100.4', header), balancer);
    const forged = clientIp(request('10.0.1.5', { 'x-forwarded-for': '192.0.2.10, 198.51.100.4' }), balancer);
    assert.deepEqual([direct, forged], ['198.51.100.4', '198.51.100.4']);
    rate.hitClient('request', direct);
    assert.throws(() => rate.hitClient('request', forged), { status: 429 });
  });

  it('are read from the environment, each /8 or narrower', () => {
    const c = loadConfig({ ...base, SIMON_RATE_EXEMPT_NETWORKS: '192.0.2.0/24, 2001:db8::/32' });
    assert.deepEqual(
      c.rateExemptNetworks.map(n => n.cidr),
      ['192.0.2.0/24', '2001:db8:0:0:0:0:0:0/32'],
    );
    assert.deepEqual(loadConfig(base).rateExemptNetworks, []);
    assert.throws(() => loadConfig({ ...base, SIMON_RATE_EXEMPT_NETWORKS: '0.0.0.0/0' }), /rateExemptNetworks/);
  });
});

describe('the health check', () => {
  const config = defineConfig({ origin: 'https://simon.example.com', dev: true, database: ':memory:' });
  const check = (server: SimonServer) =>
    server.handle(toRequest('GET', new URL('/health', config.origin), {}, Buffer.alloc(0), '203.0.113.9'));

  it('answers ok, and nothing else, while the store answers', async () => {
    const store = new SqliteStore(config.database);
    const server = createServer({ config, store, worker: false });
    try {
      const reply = await check(server);
      assert.equal(reply.status, 200);
      assert.deepEqual(reply.json, { status: 'ok' });
    } finally {
      await server.close();
      await store.close();
    }
  });

  it('answers 503 when the store does not', async () => {
    const store = new SqliteStore(config.database);
    const logged: string[] = [];
    const server = createServer({ config, store, worker: false, log: (_, message) => logged.push(message) });
    await store.close();
    try {
      const reply = await check(server);
      assert.equal(reply.status, 503);
      assert.equal((reply.json as { code: string }).code, 'unavailable');
      assert.deepEqual(logged, ['health: the store does not answer']);
    } finally {
      await server.close();
    }
  });
});
