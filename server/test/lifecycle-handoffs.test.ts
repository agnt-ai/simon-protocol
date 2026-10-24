/** Router-to-worker regressions: these exercise the actual signed API and fake HTTP transport. */
import assert from 'node:assert/strict';
import type { KeyObject } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  addKeyProofString,
  canonicalBytes,
  checkSignedRequest,
  generateKey,
  messageId,
  readServerDocument,
  readSignedHeaders,
  sign,
  signMessage,
  signRequest,
  signRecovery,
  signPairing,
  verifyMessage,
  signSignal,
  timestamp,
  type Message,
} from '@agnt-protocol/protocol';
import { defineConfig } from '../src/config.ts';
import type { Request } from '../src/http.ts';
import { createServer, type SimonServer } from '../src/server.ts';
import { SqliteStore } from '../src/store/sqlite.ts';
import { StoreCapacityError } from '../src/store/store.ts';
import { Clock, FakeDns, FakeNet, replyBody, toRequest } from '../src/testing.ts';
import { Federation, Peer } from './harness.ts';

const DAY = 86_400_000;

/** Real router calls, also usable after the original server and database connection are closed. */
async function call(
  server: SimonServer,
  key: KeyObject,
  address: string,
  method: string,
  target: string,
  value?: object,
) {
  const url = new URL(target, server.api.config.origin);
  const body = value === undefined ? Buffer.alloc(0) : canonicalBytes(value);
  const headers = signRequest(key, {
    method,
    url: url.href,
    body,
    now: server.api.now().getTime(),
    ...(address ? { agent: address } : {}),
  });
  const res = await server.handle(
    toRequest(
      method,
      url,
      { ...(value === undefined ? {} : { 'content-type': 'application/json' }), ...headers },
      body,
      '192.0.2.50',
    ),
  );
  return { status: res.status, json: JSON.parse(replyBody(res).toString() || 'null'), headers: res.headers };
}

describe('lifecycle router handoffs', () => {
  it('verifies a signed webhook before waking it, enforces ownership, and stops after deletion', async () => {
    const fed = new Federation();
    try {
      const alpha = await fed.server('hooks');
      const owner = await alpha.agent('owner');
      const other = await alpha.agent('other');
      const captured: Request[] = [];
      const origin = 'https://hooks.example';
      fed.net.hosts.set(origin, async req => {
        captured.push({ ...req, headers: { ...req.headers }, body: Buffer.from(req.body) });
        return { status: 204 };
      });
      const created = await owner.request('POST', '/simon/webhooks', {
        body: JSON.stringify({ url: `${origin}/events?channel=one` }),
      });
      assert.equal(created.status, 201);
      assert.equal(typeof created.json.id, 'string');
      await fed.work();
      assert.equal(captured.length, 1);
      const verify = JSON.parse(captured[0].body.toString());
      assert.deepEqual(Object.keys(verify).sort(), ['code', 'type']);
      assert.equal(verify.type, 'verify');
      assert.equal(typeof verify.code, 'string');

      const document = readServerDocument(
        (await owner.request('GET', '/simon/server', { sign: false })).bytes,
        alpha.origin,
        fed.clock.now(),
      )!;
      assert.ok(document, 'the webhook signing authority is a readable server document');
      async function verifies(req: Request, body = req.body) {
        const headers = readSignedHeaders(req.headers, fed.clock.now(), { server: true });
        assert.equal(headers['simon-server'], alpha.origin);
        await checkSignedRequest(
          { method: req.method, origin, actor: headers['simon-server']!, target: req.target, body },
          headers,
          {
            now: fed.clock.now(),
            entry: document.keys.find(k => k.key === headers['simon-key']) ?? null,
            nonceSeen: () => false,
          },
        );
      }
      await verifies(captured[0]);
      await assert.rejects(verifies(captured[0], Buffer.from('{}')), { code: 'bad_signature' });
      await other.send(other.message([owner.address], 'before webhook verification'));
      await fed.work();
      assert.equal(captured.length, 1, 'an unverified endpoint receives no changed notification');
      const hook = `/simon/webhooks/${encodeURIComponent(created.json.id)}`;
      const confirm = (who: typeof owner, code: string) =>
        who.request('POST', `${hook}/verify`, {
          body: JSON.stringify({ code }),
        });
      assert.deepEqual(
        [(await confirm(other, verify.code)).status, (await other.request('DELETE', hook)).status],
        [404, 404],
        "neither operation reveals another owner's row",
      );
      const wrong = await confirm(owner, 'wrong');
      assert.deepEqual([wrong.status, wrong.json.details.field], [400, 'code']);
      assert.deepEqual((await confirm(owner, verify.code)).json, { id: created.json.id, verified: true });
      await fed.work();
      assert.equal(captured.length, 2, 'verification makes the first wake due');
      await verifies(captured[1]);
      assert.deepEqual(JSON.parse(captured[1].body.toString()), { type: 'changed', agent: owner.address });

      const before = (await owner.sync()).json.token;
      fed.clock.advance(1001);
      const sent = await other.send(other.message([owner.address], 'after verification'));
      assert.equal(sent.status, 200);
      await fed.work();
      assert.equal(captured.length, 3, 'admission schedules a signed wake through the leased poster');
      await verifies(captured[2]);
      assert.deepEqual(JSON.parse(captured[2].body.toString()), { type: 'changed', agent: owner.address });
      const synced = await owner.sync(before);
      assert.deepEqual(
        synced.json.messages.map((e: { id: string }) => e.id),
        [sent.json.id],
      );
      assert.deepEqual((await owner.request('DELETE', hook)).json, { deleted: true });
      assert.equal((await owner.request('DELETE', hook)).status, 404);
      fed.clock.advance(1001);
      await other.send(other.message([owner.address], 'after deletion'));
      await fed.work();
      assert.equal(captured.length, 3, 'deletion prevents subsequent wakeups');
    } finally {
      await fed.close();
    }
  });

  it('refuses a client signal when its author domain no longer names this server', async () => {
    const fed = new Federation();
    try {
      const alpha = await fed.server('signal-host');
      const beta = await fed.server('signal-moved');
      const author = await alpha.agent('author');
      const recipient = await alpha.agent('recipient');
      const sent = await author.send(author.message([recipient.address], 'held before the domain moves'));
      assert.equal(sent.status, 200);
      await fed.work();
      fed.dns.point(alpha.domain, beta.origin);
      fed.clock.advance(11 * 60_000);
      const response = await author.request('POST', '/simon/send-signal', {
        body: JSON.stringify({ type: 'typing', about: sent.json.id, to: [recipient.address] }),
      });
      assert.deepEqual([response.status, response.json.code], [409, 'address_not_served']);
      await fed.work();
      assert.deepEqual((await recipient.sync()).json.signals, [], 'a refused signal is never queued');
    } finally {
      await fed.close();
    }
  });

  it('retains an old but valid incoming signal for five minutes after receipt', async () => {
    const fed = new Federation();
    try {
      const alpha = await fed.server('signals');
      const recipient = await alpha.agent('recipient');
      const peer = new Peer(fed, 'signal-peer');
      const author = peer.agent('author');
      const message = peer.message(author, [recipient.address], 'the signal is about this held message');
      assert.equal((await peer.post(alpha, peer.envelope(message))).status, 202);
      await fed.work();
      const before = (await recipient.sync()).json.token;
      const at = timestamp(fed.clock.t - 299_000);
      const signal = signSignal(
        { type: 'typing', from: author, to: [recipient.address], about: messageId(message), at, server: alpha.origin },
        peer.key,
      );
      assert.equal(
        (
          await fed.net.request({
            method: 'POST',
            url: `${alpha.origin}/simon/signal`,
            body: canonicalBytes(signal),
            maxBytes: 1 << 20,
          })
        ).status,
        202,
      );
      await fed.work();
      const expected = [{ type: 'typing', from: author, about: messageId(message), at }];
      assert.deepEqual((await recipient.sync(before)).json.signals, expected);
      fed.clock.advance(299_999);
      assert.deepEqual(
        (await recipient.sync(before)).json.signals,
        expected,
        'wire at is now almost ten minutes old; retention still runs from receipt',
      );
      fed.clock.advance(1);
      assert.deepEqual(
        (await recipient.sync(before)).json.signals,
        [],
        'the signal expires at five minutes of residence',
      );
    } finally {
      await fed.close();
    }
  });

  it('keeps a delayed admission for a full sync window measured from admission', async () => {
    const fed = new Federation();
    try {
      const alpha = await fed.server('delayed', {
        config: { retentionDays: 7, syncDays: 7 },
        extensions: [{ name: 'hold', admit: () => 'later' }],
      });
      const recipient = await alpha.agent('recipient');
      const peer = new Peer(fed, 'delayed-peer');
      const author = peer.agent('author');
      const message = peer.message(author, [recipient.address], 'held until the recipient consents');
      const id = messageId(message);
      assert.equal((await peer.post(alpha, peer.envelope(message))).status, 202);
      await fed.work();
      assert.deepEqual((await recipient.sync()).json.messages, []);
      fed.clock.advance(6 * DAY);
      const before = (await recipient.sync()).json.token;
      const admittedAt = fed.clock.now().toISOString();
      assert.equal(await alpha.server.api.admit(recipient.address, id), true);
      await fed.work();
      fed.clock.advance(2 * DAY);
      await alpha.server.sweep();
      const read = await recipient.sync(before);
      assert.equal(read.status, 200);
      assert.deepEqual(
        read.json.messages.map((e: { id: string; receivedAt: string }) => [e.id, e.receivedAt]),
        [[id, admittedAt]],
      );
      assert.equal(
        read.json.messages[0].message.sentAt,
        message.sentAt,
        'admission changes residence time, never signed authorship',
      );
      fed.clock.advance(5 * DAY - 1);
      await alpha.server.sweep();
      assert.deepEqual(
        (await recipient.sync(before)).json.messages.map((e: { id: string }) => e.id),
        [id],
      );
      fed.clock.advance(2);
      await alpha.server.sweep();
      assert.equal(await alpha.store.message(id), null, 'the extended residence ends at admission plus syncDays');
      assert.equal(
        (await recipient.sync(before)).json.code,
        'token_expired',
        'the old checkpoint reports the retention gap',
      );
    } finally {
      await fed.close();
    }
  });

  it('rejects tampered, cross-account and cross-origin tokens and accepts a checkpoint after a database reopen', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'simon-checkpoint-'));
    const file = path.join(dir, 'simon.sqlite');
    const clock = new Clock(),
      dns = new FakeDns(),
      net = new FakeNet();
    const origin = 'https://simon.checkpoints.test';
    const config = defineConfig({ origin, hostedDomains: ['checkpoints.test'], serverKey: generateKey().privateKey });
    dns.point('checkpoints.test', origin);
    let store = new SqliteStore(file);
    let server = createServer({ config, store, dns, http: net, now: clock.now, worker: false });
    net.hosts.set(origin, req => server.handle(req));
    try {
      const a = generateKey(),
        b = generateKey();
      const address = 'a@checkpoints.test',
        other = 'b@checkpoints.test';
      assert.equal(
        (await call(server, a.privateKey, address, 'POST', '/simon/register', { key: a.key, address })).status,
        200,
      );
      assert.equal(
        (await call(server, b.privateKey, other, 'POST', '/simon/register', { key: b.key, address: other })).status,
        200,
      );
      const first = await call(server, a.privateKey, address, 'GET', '/simon/sync');
      assert.equal(first.status, 200);
      const token = first.json.token;
      assert.equal(typeof token, 'string');
      const sync = `/simon/sync?since=${encodeURIComponent(token)}`;
      const damaged = Buffer.from(token, 'base64url');
      damaged[13] ^= 1;
      assert.deepEqual(
        [
          (await call(server, a.privateKey, address, 'GET', `/simon/sync?since=${damaged.toString('base64url')}`))
            .status,
          (await call(server, b.privateKey, other, 'GET', sync)).status,
        ],
        [410, 410],
      );

      const foreignOrigin = 'https://simon.foreign.test';
      const shared = await store.value('sync-secret', origin, clock.now().toISOString());
      assert.ok(shared, 'the first checkpoint persisted its secret');
      await store.setValue('sync-secret', foreignOrigin, shared, null);
      const foreign = createServer({
        config: defineConfig({
          origin: foreignOrigin,
          hostedDomains: ['checkpoints.test'],
          serverKey: config.serverKey,
        }),
        store,
        dns,
        http: net,
        now: clock.now,
        worker: false,
      });
      try {
        const refused = await call(foreign, a.privateKey, address, 'GET', sync);
        assert.deepEqual(
          [refused.status, refused.json.code],
          [410, 'token_expired'],
          'origin binding survives an intentionally shared encryption key',
        );
      } finally {
        await foreign.close();
      }

      await server.close();
      await store.close();
      store = new SqliteStore(file);
      server = createServer({ config, store, dns, http: net, now: clock.now, worker: false });
      const message = signMessage<Message>(
        {
          v: 1,
          from: other,
          to: [address],
          inReplyTo: null,
          parts: [{ type: 'text/plain', data: 'after reopen' }],
          headers: {},
          sentAt: timestamp(clock.t),
        },
        b.privateKey,
      );
      assert.equal((await call(server, b.privateKey, other, 'POST', '/simon/send', message)).status, 200);
      await server.work();
      const resumed = await call(server, a.privateKey, address, 'GET', sync);
      assert.equal(resumed.status, 200);
      assert.deepEqual(
        resumed.json.messages.map((e: { id: string }) => e.id),
        [messageId(message)],
      );
    } finally {
      await server.close();
      await store.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('maps Store overload before acceptance to a generic retryable refusal', async () => {
    const fed = new Federation();
    let full = false,
      stored = 0;
    try {
      const host = await fed.server('capacity', {
        extensions: [
          {
            name: 'observe',
            on: {
              stored: () => {
                stored++;
              },
            },
          },
        ],
        wrapStore: store =>
          new Proxy(store, {
            get(target, property) {
              if (property === 'putMessage')
                return async (...args: Parameters<typeof store.putMessage>) => {
                  if (full) throw new StoreCapacityError();
                  return target.putMessage(...args);
                };
              const value = Reflect.get(target, property, target);
              return typeof value === 'function' ? value.bind(target) : value;
            },
          }),
      });
      const author = await host.agent('author'),
        recipient = await host.agent('recipient');
      const message = author.message([recipient.address], 'cannot be accepted');
      full = true;
      const rejected = await author.send(message);
      assert.deepEqual(
        [rejected.status, rejected.json.code, rejected.json.detail],
        [503, 'unavailable', 'The server is temporarily at capacity.'],
      );
      assert.equal(rejected.headers['retry-after'], '60');
      assert.deepEqual(rejected.json.details, { retryAfter: 60 });
      assert.equal(await host.store.message(messageId(message)), null);
      await fed.work();
      assert.equal(stored, 0);
      assert.deepEqual((await recipient.sync()).json.messages, []);
    } finally {
      await fed.close();
    }
  });

  it('discloses a migrated history gap to every device and resumes only by explicit token', async () => {
    const fed = new Federation();
    try {
      const host = await fed.server('migration');
      const owner = await host.agent('owner'),
        sender = await host.agent('sender');
      const ids: string[] = [];
      for (let i = 0; i < 3; i++)
        ids.push((await sender.send(sender.message([owner.address], `retained ${i}`))).json.id);
      await fed.work();
      await host.store.setValue('sync-history-gap', owner.address, true, null);
      const first = await owner.sync();
      assert.deepEqual(
        [first.status, first.json.code, first.json.details.reason],
        [410, 'token_expired', 'history_migration'],
      );
      const resume = first.json.details.resumeToken;
      assert.equal(typeof resume, 'string');
      const another = generateKey();
      assert.equal(
        (
          await owner.request('POST', '/simon/keys', {
            body: JSON.stringify({
              key: another.key,
              proof: sign(another.privateKey, addKeyProofString(owner.address, another.key)),
            }),
          })
        ).status,
        200,
      );
      assert.equal(
        (await owner.request('GET', '/simon/sync', { key: another.privateKey })).status,
        410,
        'one device never accepts the gap for another',
      );
      assert.equal((await sender.sync(resume)).status, 410, 'the offered resume remains account-bound');
      let token = resume;
      const got: string[] = [];
      for (let page = 0; page < 4; page++) {
        const read = await owner.sync(token, { limit: 1 });
        assert.equal(read.status, 200);
        got.push(...read.json.messages.map((entry: { id: string }) => entry.id));
        token = read.json.token;
        if (!read.json.more) break;
      }
      assert.deepEqual(got, ids, 'explicit resume paginates retained entries without skipping');
      assert.equal((await owner.sync()).status, 410, 'resuming never clears the account migration marker');
      fed.clock.advance(7 * DAY + 1);
      assert.deepEqual(
        [(await owner.sync(resume)).status, (await owner.sync(resume)).json.code],
        [410, 'token_expired'],
      );
    } finally {
      await fed.close();
    }
  });

  for (const by of ['mailbox', 'principal'] as const) {
    it(`ends an old future-revoked key immediately after ${by} recovery without rewriting history`, async () => {
      const fed = new Federation();
      try {
        const host = await fed.server(`recover-${by}`, { config: { recoveryWaitSeconds: 0 } });
        const domain = `mail-${by}.example`;
        fed.dns.point(domain, host.origin);
        const address = `owner@${domain}`,
          old = host.newAgent(),
          fresh = host.newAgent();
        const principal = generateKey(),
          forValue = `simon-key:${principal.key}`;
        const at = fed.clock.now().toISOString(),
          future = new Date(fed.clock.t + 60_000).toISOString();
        await host.store.createAgent({
          address,
          kind: by === 'principal' ? 'paired' : 'solo',
          principal: by === 'principal' ? forValue : null,
          mailbox: true,
          keys: [{ key: old.token, added: at, revoked: future }],
          createdAt: at,
          retiredAt: null,
        });
        old.address = address;
        const historic = old.message(
          [],
          'old history',
          by === 'principal'
            ? { headers: { for: forValue, pairing: signPairing(principal.privateKey, address, forValue) } }
            : {},
        );
        assert.equal((await old.request('GET', '/simon/account')).status, 200);
        if (by === 'principal') {
          assert.equal(
            (
              await fresh.recover({
                address,
                at,
                recover: signRecovery(principal.privateKey, address, fresh.token, at),
              })
            ).status,
            200,
          );
        } else {
          await fresh.recover({ address });
          assert.equal((await fresh.recover({ address, code: host.code(address) })).status, 200);
        }
        for (const route of ['/simon/account', '/simon/sync']) {
          assert.deepEqual(
            [(await old.request('GET', route)).status, (await old.request('GET', route)).json.code],
            [401, 'unknown_key'],
          );
          assert.equal((await fresh.request('GET', route)).status, 200);
        }
        const state = (await fresh.request('GET', '/simon/account')).json;
        assert.equal(state.authorizedKeys, undefined);
        const document = (await fresh.request('GET', `/simon/agents/${address}`, { sign: false })).json;
        assert.equal(document.authorizedKeys, undefined);
        assert.equal(document.keys.find((key: { key: string }) => key.key === old.token).revoked, future);
        assert.equal(verifyMessage(historic, document.keys), true, 'historical cryptographic validity is preserved');
      } finally {
        await fed.close();
      }
    });
  }

  it(
    'rechecks a long-poll signing key after revocation before returning newly admitted data',
    { timeout: 3000 },
    async () => {
      const fed = new Federation();
      let waiting!: () => void;
      const observed = new Promise<void>(resolve => {
        waiting = resolve;
      });
      let observe = false;
      try {
        const alpha = await fed.server('poll', {
          wrapStore: store =>
            new Proxy(store, {
              get(target, name) {
                if (name === 'sync')
                  return async (...args: Parameters<typeof store.sync>) => {
                    const page = await target.sync(...args);
                    if (observe) {
                      observe = false;
                      setImmediate(waiting);
                    }
                    return page;
                  };
                const value = Reflect.get(target, name, target);
                return typeof value === 'function' ? value.bind(target) : value;
              },
            }),
        });
        const owner = await alpha.agent('owner'),
          sender = await alpha.agent('sender');
        const device = generateKey();
        assert.equal(
          (
            await owner.request('POST', '/simon/keys', {
              body: JSON.stringify({
                key: device.key,
                proof: sign(device.privateKey, addKeyProofString(owner.address, device.key)),
              }),
            })
          ).status,
          200,
        );
        const token = (await owner.sync()).json.token;
        observe = true;
        let finished = false;
        const poll = owner
          .request('GET', `/simon/sync?since=${encodeURIComponent(token)}&wait=60`, { key: device.privateKey })
          .then(result => {
            finished = true;
            waiting();
            return result;
          });
        await observed;
        assert.equal(finished, false, 'the signed request reached an empty sync page and actually waited');
        assert.equal((await owner.request('DELETE', `/simon/keys/${encodeURIComponent(device.key)}`)).status, 200);
        await sender.send(sender.message([owner.address], 'must not reach the revoked device'));
        await fed.work();
        const res = await poll;
        assert.deepEqual([res.status, res.json.code], [401, 'bad_signature']);
        assert.equal(res.headers['www-authenticate'], 'SIMON');
        assert.equal(res.json.messages, undefined);
      } finally {
        await fed.close();
      }
    },
  );
});
