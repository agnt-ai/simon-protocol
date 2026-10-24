/** Host retirement disclosure uses the same policy in direct calls and the real listener. */
import assert from 'node:assert/strict';
import { it } from 'node:test';
import {
  generateKey,
  readAgentDocument,
  readServerDocument,
  signRequest,
  signUnpairing,
  verifyUnpairing,
} from '@agnt-protocol/protocol';
import { defineConfig, loadConfig, type Config } from '../src/config.ts';
import { createServer, type ServerOptions } from '../src/server.ts';
import { SqliteStore } from '../src/store/sqlite.ts';
import { replyBody, toRequest } from '../src/testing.ts';

interface SignedCall {
  key: ReturnType<typeof generateKey>;
  address: string;
  body?: string;
  invalidSignature?: boolean;
}

async function fixture(
  policy: ServerOptions['retiredAgentDocuments'],
  listener: boolean,
  missLimit = 100,
  configPolicy?: Config['retiredAgentDocuments'],
) {
  const now = new Date('2026-10-20T12:00:00.000Z');
  const config = defineConfig({
    origin: 'https://privacy.test',
    hostedDomains: ['privacy.test'],
    dev: true,
    rates: { agentMiss: { limit: missLimit, seconds: 3600 } },
    retiredAgentDocuments: configPolicy,
  });
  const store = new SqliteStore();
  const options: ServerOptions = {
    config,
    store,
    now: () => now,
    log: () => {},
    worker: false,
    retiredAgentDocuments: policy,
  };
  const server = createServer(options);
  const port = listener ? await server.listen(0, '127.0.0.1') : null;
  async function call(method: string, path: string, signed?: SignedCall) {
    const body = Buffer.from(signed?.body ?? '');
    const headers: Record<string, string> = signed
      ? signRequest(signed.key.privateKey, {
          method,
          url: config.origin + path,
          body,
          now: now.getTime(),
          agent: signed.address,
        })
      : {};
    if (signed?.invalidSignature) headers['agnt-signature'] = 'broken';
    if (port === null) {
      const request = toRequest(method, new URL(path, config.origin), headers, body, '192.0.2.7');
      const reply = await server.handle(request);
      const bytes = replyBody(reply);
      return {
        status: reply.status,
        bytes,
        json: JSON.parse(bytes.toString()),
        headers: reply.headers ?? {},
      };
    }
    const response = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers: headers as Record<string, string>,
      body: body.length ? new Uint8Array(body) : undefined,
    });
    const bytes = Buffer.from(await response.arrayBuffer());
    const protocolHeaders: Record<string, string> = {};
    for (const name of ['content-type', 'www-authenticate', 'retry-after']) {
      const value = response.headers.get(name);
      if (value !== null) protocolHeaders[name] = value;
    }
    return { status: response.status, bytes, json: JSON.parse(bytes.toString()), headers: protocolHeaders };
  }
  async function agent(local: string, principal: string | null = null) {
    const key = generateKey();
    const address = `${local}@privacy.test`;
    assert.equal(
      await store.createAgent({
        address,
        kind: principal ? 'paired' : 'solo',
        principal,
        keys: [{ key: key.key, added: '2026-10-19T00:00:00.000Z', revoked: null, label: 'Private device' }],
        mailbox: false,
        createdAt: '2026-10-19T00:00:00.000Z',
        retiredAt: null,
      }),
      'created',
    );
    return { key, address };
  }
  return {
    now,
    config,
    options,
    store,
    server,
    call,
    agent,
    async close() {
      await server.close();
      await store.close();
    },
  };
}

for (const listener of [false, true]) {
  for (const policy of [undefined, 'public', 'private'] as const) {
    it(`captures retirement disclosure=${policy}, real listener=${listener}`, async () => {
      const home = await fixture(policy, listener);
      try {
        const active = await home.agent('active');
        const solo = await home.agent('solo');
        const principal = generateKey();
        const forValue = `agnt-key:${principal.key}`;
        const paired = await home.agent('paired', forValue);
        const unpairing = signUnpairing(principal.privateKey, paired.address, forValue);
        const retire = () =>
          home.call('POST', '/agnt/unpair', {
            ...paired,
            body: JSON.stringify({ address: paired.address, unpairing }),
          });
        await home.server.api.retire(solo.address);
        assert.equal((await retire()).status, 200);
        home.options.retiredAgentDocuments = policy === 'public' ? 'private' : 'public';
        const serverResponse = await home.call('GET', '/agnt/server');
        const server = readServerDocument(serverResponse.bytes, home.config.origin, home.now)!;
        const visible = await home.call('GET', `/agnt/agents/${encodeURIComponent(active.address)}`);
        assert.equal(visible.status, 200);
        assert.ok(readAgentDocument(visible.bytes, active.address, server.keys, home.now));
        assert.ok(!visible.bytes.includes('Private device'));
        assert.deepEqual(await home.call('GET', `/agnt/agents/${active.address}`, active), visible);
        assert.deepEqual(
          await home.call('GET', `/agnt/agents/${active.address}`, { ...active, invalidSignature: true }),
          visible,
        );
        for (const agent of [solo, paired]) {
          const response = await home.call('GET', `/agnt/agents/${encodeURIComponent(agent.address)}`);
          assert.deepEqual(await home.call('GET', `/agnt/agents/${agent.address}`, active), response);
          assert.deepEqual(
            await home.call('GET', `/agnt/agents/${agent.address}`, { ...active, invalidSignature: true }),
            response,
          );
          if (policy !== 'public') {
            // Private is the default: an unset policy answers exactly as an explicit private one.
            const absent = await home.call('GET', '/agnt/agents/nobody%40privacy.test');
            assert.deepEqual(response, absent, 'private retirement has exactly the absent-address refusal');
          } else {
            assert.equal(response.status, 200);
            const document = readAgentDocument(response.bytes, agent.address, server.keys, home.now);
            assert.ok(document?.retired);
            assert.ok(document.keys.every(key => key.revoked === document.retired));
            if (agent === paired) {
              assert.equal(document.unpairing, unpairing);
              assert.ok(verifyUnpairing(paired.address, forValue, document.unpairing));
            }
          }
          const held = await home.store.agentByAddress(agent.address);
          assert.ok(held?.retiredAt);
          assert.equal((await home.store.agentByKey(agent.key.key))?.address, agent.address);
          const denied = await home.call('GET', '/agnt/account', agent);
          assert.deepEqual([denied.status, denied.json.code], [401, 'key_revoked']);
        }
        const before = await home.store.agentByAddress(paired.address);
        assert.equal(before?.unpairing, unpairing);
        assert.equal((await retire()).status, 200, 'the actual core unpairing retry remains idempotent');
        assert.deepEqual(await home.store.agentByAddress(paired.address), before);
        for (const path of ['/agnt/agents/%', '/agnt/agents/', '/agnt/agents/x/extra'])
          assert.equal((await home.call('GET', path)).status, 404);
      } finally {
        await home.close();
      }
    });
  }

  it(`charges private retired misses before lookup, real listener=${listener}`, async () => {
    const home = await fixture('private', listener, 2);
    try {
      const active = await home.agent('active');
      const retired = await home.agent('retired');
      await home.server.api.retire(retired.address);
      let lookups = 0;
      const lookup = home.store.agentByAddress.bind(home.store);
      home.store.agentByAddress = async address => {
        lookups++;
        const agent = await lookup(address);
        if (agent?.retiredAt)
          Object.defineProperty(agent, 'keys', {
            get() {
              throw new Error('private retirement keys must never be projected');
            },
          });
        return agent;
      };
      assert.equal((await home.call('GET', `/agnt/agents/${active.address}`)).status, 200);
      assert.equal((await home.call('GET', `/agnt/agents/${retired.address}`)).status, 404);
      assert.equal((await home.call('GET', '/agnt/agents/unknown@privacy.test')).status, 404);
      const before = lookups;
      const addresses = [active.address, retired.address, 'unknown@privacy.test'];
      const requests = addresses.map(address => home.call('GET', `/agnt/agents/${address}`));
      const responses = await Promise.all(requests);
      const statuses = responses.map(response => response.status);
      assert.deepEqual(statuses, [429, 429, 429]);
      assert.equal(lookups, before, 'over-budget refusal precedes every Store lookup');
    } finally {
      await home.close();
    }
  });
}

it('rejects invalid disclosure policy before reading other options or starting workers/listeners', () => {
  for (const policy of [null, false, true, '', 'PUBLIC', 'hidden', 0, {}]) {
    const invalid = { retiredAgentDocuments: policy } as unknown as ServerOptions;
    const options = new Proxy(invalid, {
      get(target, property, receiver) {
        if (property !== 'retiredAgentDocuments') throw new Error('startup must not continue');
        return Reflect.get(target, property, receiver);
      },
    });
    assert.throws(() => createServer(options), { name: 'TypeError', message: /retiredAgentDocuments/ });
  }
});

for (const [env, expected] of [
  [undefined, 'private'],
  ['private', 'private'],
  ['public', 'public'],
] as const) {
  it(`AGNT_RETIRED_AGENT_DOCUMENTS=${env} reaches the server as ${expected}`, async () => {
    const config = loadConfig({
      AGNT_ORIGIN: 'http://privacy.test',
      AGNT_DEV: '1',
      AGNT_HOSTED_DOMAINS: 'privacy.test',
      ...(env === undefined ? {} : { AGNT_RETIRED_AGENT_DOCUMENTS: env }),
    });
    assert.equal(config.retiredAgentDocuments, expected);
    const store = new SqliteStore();
    // As main.ts passes it, and with the option left out so the config alone decides.
    for (const options of [{ retiredAgentDocuments: config.retiredAgentDocuments }, {}]) {
      const server = createServer({ config, store, log: () => {}, worker: false, ...options });
      try {
        const local = `retired-${Object.keys(options).length}`;
        const key = generateKey();
        const address = `${local}@privacy.test`;
        await store.createAgent({
          address,
          kind: 'solo',
          principal: null,
          keys: [{ key: key.key, added: '2026-10-19T00:00:00.000Z', revoked: null }],
          mailbox: false,
          createdAt: '2026-10-19T00:00:00.000Z',
          retiredAt: null,
        });
        await server.api.retire(address);
        const url = new URL(`/agnt/agents/${encodeURIComponent(address)}`, config.origin);
        const reply = await server.handle(toRequest('GET', url, {}, Buffer.alloc(0), '192.0.2.7'));
        assert.equal(reply.status, expected === 'private' ? 404 : 200);
        if (expected === 'public') assert.ok(JSON.parse(replyBody(reply).toString()).retired);
      } finally {
        await server.close();
      }
    }
    await store.close();
  });
}

it('an explicit createServer option overrides the configured policy', async () => {
  const home = await fixture('private', false, 100, 'public');
  try {
    const agent = await home.agent('retired');
    await home.server.api.retire(agent.address);
    const response = await home.call('GET', `/agnt/agents/${encodeURIComponent(agent.address)}`);
    const absent = await home.call('GET', '/agnt/agents/nobody%40privacy.test');
    assert.deepEqual(response, absent);
  } finally {
    await home.close();
  }
});
