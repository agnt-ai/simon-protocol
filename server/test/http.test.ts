/**
 * Real sockets: two servers on localhost in development mode, with the real worker loop and the real
 * outbound HTTP client, exchanging messages both ways.
 */
import assert from 'node:assert/strict';
import net from 'node:net';
import { after, before, describe, it } from 'node:test';
import {
  canonicalBytes,
  generateKey,
  keyToken,
  signMessage,
  signRequest,
  timestamp,
  type Message,
} from '@agnt-protocol/protocol';
import { defineConfig } from '../src/config.ts';
import { createServer, type AgntServer } from '../src/server.ts';
import { SqliteStore } from '../src/store/sqlite.ts';

const freePort = () =>
  new Promise<number>(resolve => {
    const s = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = s.address() as net.AddressInfo;
      s.close(() => resolve(port));
    });
  });

class Agent {
  readonly key = generateKey().privateKey;
  address = '';
  readonly origin: string;
  constructor(origin: string) {
    this.origin = origin;
  }
  async call(method: string, target: string, body?: Uint8Array, agent = this.address || undefined) {
    const url = this.origin + target;
    const headers = signRequest(this.key, { method, url, body: body ?? '', agent });
    const res = await fetch(url, {
      method,
      headers: headers as Record<string, string>,
      body: body && new Uint8Array(body),
    });
    return { status: res.status, json: await res.json() };
  }
  async register(address: string) {
    const res = await this.call(
      'POST',
      '/agnt/register',
      Buffer.from(JSON.stringify({ key: keyToken(this.key), address })),
      address,
    );
    this.address = res.json.address;
    return res;
  }
  send(to: string, text: string) {
    const m = signMessage<Message>(
      {
        v: 1,
        from: this.address,
        to: [to],
        inReplyTo: null,
        parts: [{ type: 'text/plain', data: text }],
        headers: {},
        sentAt: timestamp(Date.now()),
      },
      this.key,
    );
    return this.call('POST', '/agnt/send', canonicalBytes(m));
  }
  async waitForInbox(count: number) {
    for (let i = 0; i < 200; i++) {
      const { json } = await this.call('GET', '/agnt/sync');
      const received = json.messages.filter((e: { message: { from: string } }) => e.message.from !== this.address);
      if (received.length >= count) return received;
      await new Promise(r => setTimeout(r, 25));
    }
    throw new Error(`${this.address} never received ${count} messages`);
  }
}

describe('over real HTTP on localhost', () => {
  const servers: { server: AgntServer; store: SqliteStore; origin: string }[] = [];

  before(async () => {
    const [pa, pb] = [await freePort(), await freePort()];
    const origins = { 'a.test': `http://127.0.0.1:${pa}`, 'b.test': `http://127.0.0.1:${pb}` };
    for (const [domain, origin] of Object.entries(origins)) {
      const config = defineConfig({ origin, dev: true, hostedDomains: [domain], devResolve: origins });
      const store = new SqliteStore();
      const server = createServer({ config, store, log: () => {} });
      await server.listen(Number(new URL(origin).port), '127.0.0.1');
      servers.push({ server, store, origin });
    }
  });
  after(async () => {
    for (const s of servers) {
      await s.server.close();
      await s.store.close();
    }
  });

  it('registers an agent on each server and delivers messages both ways', async () => {
    const ada = new Agent(servers[0].origin);
    const bob = new Agent(servers[1].origin);
    assert.equal((await ada.register('ada@a.test')).status, 200);
    assert.equal((await bob.register('bob@b.test')).status, 200);
    assert.equal((await ada.send('bob@b.test', 'Hello over a socket.')).status, 200);
    const [toBob] = await bob.waitForInbox(1);
    assert.equal(toBob.carrier, servers[0].origin);
    assert.equal((await bob.send('ada@a.test', 'And back.')).status, 200);
    const [toAda] = await ada.waitForInbox(1);
    assert.equal(toAda.message.parts[0].data, 'And back.');
  });

  it('refuses a body over its cap without reading it all', async () => {
    const res = await fetch(`${servers[0].origin}/agnt/deliver`, { method: 'POST', body: Buffer.alloc(2_000_000, 32) });
    assert.equal(res.status, 413);
    assert.equal((await res.json()).code, 'body_too_large');
  });

  it('answers errors as RFC 9457 problems, and a request 401 with WWW-Authenticate: AGNT', async () => {
    const res = await fetch(`${servers[0].origin}/agnt/sync`);
    assert.equal(res.status, 401);
    assert.equal(res.headers.get('content-type'), 'application/problem+json');
    assert.equal(res.headers.get('www-authenticate'), 'AGNT');
    const problem = await res.json();
    assert.deepEqual(
      [problem.type, problem.status, problem.code, problem.retryable],
      ['about:blank', 401, 'signature_required', false],
    );
    assert.equal(typeof problem.detail, 'string');
  });
});
