/** Repeated forwarding retains its own file source after older grants expire, on the app's real store. */
import assert from 'node:assert/strict';
import { it } from 'node:test';
import { generateKey, sha256Hex } from '@agnt-protocol/protocol';
import { createServer, defineConfig, type SimonServer } from '@agnt-protocol/server';
import { MongoStore } from '../src/store/mongo-store.ts';
import { World } from './harness.ts';
import { freshDb } from './mongo.ts';

it('Mongo-backed sends retain the final forward after source messages expire', async () => {
  const world = new World();
  let store: MongoStore | undefined;
  let server: SimonServer | undefined;
  try {
    store = await new MongoStore(await freshDb()).init();
    const origin = 'https://simon.mongo.test';
    server = createServer({
      config: defineConfig({ origin, hostedDomains: ['mongo.test'], serverKey: generateKey().privateKey }),
      store,
      dns: world.dns,
      http: world.net,
      now: world.clock.now,
      worker: false,
      log: () => {},
    });
    world.dns.point('mongo.test', origin);
    world.net.hosts.set(origin, req => server!.handle(req));
    const agents = [];
    for (const name of ['a', 'b', 'c', 'd', 'outsider']) agents.push(await world.agent(origin, `${name}@mongo.test`));
    const bytes = Buffer.from('forwarded file retained by the app');
    const part = { type: 'application/octet-stream', sha256: sha256Hex(bytes), size: bytes.length };
    await agents[0].uploadPart(bytes, part.type);
    for (let i = 0; i < 3; i++) {
      if (i > 0) world.clock.advance(86_400_000);
      const sent = await agents[i].send({ to: [agents[i + 1].address!], text: 'forward', parts: [part] });
      assert.match(sent.id, /^[0-9a-f]{64}$/);
      for (let round = 0; round < 3; round++) await server.work();
      assert.deepEqual(Buffer.from(await agents[i + 1].fetchPart(part)), bytes);
    }
    world.clock.advance(29 * 86_400_000);
    const now = new Date(world.clock.t).toISOString();
    await store.sweep(now, now);
    assert.equal(await store.part(part.sha256, { uploader: agents[0].address! }), null);
    assert.deepEqual(Buffer.from(await agents[3].fetchPart(part)), bytes);
    await assert.rejects(agents[4].fetchPart(part), { code: 'not_found', status: 404 });
  } finally {
    try {
      await server?.close();
    } finally {
      try {
        await store?.close();
      } finally {
        await world.close();
      }
    }
  }
});
