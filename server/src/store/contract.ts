/**
 * The Store contract as tests. Any store proves itself by running them:
 *
 *   import { storeContract } from 'simon-server/store-contract';
 *   storeContract('my store', () => new MyStore());
 *
 * `make` returns a fresh, empty store each time. Every rule in store.ts that the core relies on is here.
 */
import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import type { AnyMessage } from '@agnt-sdk/simon-protocol';
import { MAX_STORED_KEYS } from './store.ts';
import type { Agent, Delivery, QueuedArrival, Store, StoredMessage, Webhook, RetractionCapacity } from './store.ts';

const T0 = Date.parse('2026-10-15T00:00:00.000Z');
const at = (ms = 0) => new Date(T0 + ms).toISOString();
const HOUR = 3_600_000;
const sha = (c: string) => c.repeat(64);
const ids = (page: { messages: { id: string }[] }) => page.messages.map(e => e.id);

const agent = (address: string, ...keys: string[]): Agent => ({
  address,
  kind: 'solo',
  principal: null,
  keys: keys.map(key => ({ key, added: at(), revoked: null })),
  mailbox: false,
  createdAt: at(),
  retiredAt: null,
});

let n = 0;
function message(from: string, to: string[], extra: Record<string, unknown> = {}): StoredMessage {
  const m = {
    v: 1,
    from,
    to,
    inReplyTo: null,
    parts: [],
    headers: {},
    sentAt: at(),
    signature: 'AA',
    n: n++,
    ...extra,
  };
  return {
    id: String(n).padStart(64, '0'),
    message: m as unknown as AnyMessage,
    carrier: 'https://here.test',
    claims: [],
    signedClaims: null,
    receivedAt: at(),
    expiresAt: at(24 * HOUR),
  };
}

const delivery = (id: string, domain: string, extra: Partial<Delivery> = {}): Delivery => ({
  id,
  domain,
  recipients: [`bob@${domain}`],
  hints: {},
  server: null,
  status: 'pending',
  reason: null,
  attempts: 0,
  nextAttemptAt: at(),
  createdAt: at(),
  deadline: at(120 * HOUR),
  ...extra,
});

const arrival = (id: string, recipient: string, extra: Partial<QueuedArrival> = {}): QueuedArrival => ({
  id,
  recipient,
  hints: {},
  attempts: 0,
  dueAt: at(),
  ...extra,
});

const SELF = 'https://here.test';
const lease = (token: string, until = at(2 * 60_000)) => ({ token, until });

export function storeContract(name: string, make: () => Store | Promise<Store>) {
  describe(`Store contract: ${name}`, () => {
    let store: Store;
    beforeEach(async () => {
      store = await make();
    });
    afterEach(() => store.close());

    describe('agents', () => {
      it('gives an address and a key to one agent, forever', async () => {
        assert.equal(await store.createAgent(agent('ada@a.test', 'k1')), 'created');
        assert.equal(await store.createAgent(agent('ada@a.test', 'k2')), 'address_taken');
        assert.equal(await store.createAgent(agent('bob@a.test', 'k1')), 'key_in_use');
        assert.equal((await store.agentByKey('k1'))?.address, 'ada@a.test');
        assert.equal(await store.agentByAddress('bob@a.test'), null);
        await store.retireAgent('ada@a.test', at(1));
        const retired = await store.agentByAddress('ada@a.test');
        assert.equal(retired?.retiredAt, at(1));
        assert.equal(retired?.keys[0].revoked, at(1));
        assert.equal(retired?.unpairing ?? null, null);
        assert.equal(await store.createAgent(agent('ada@a.test', 'k3')), 'address_taken');
      });

      it('keeps the unpairing that retired an address, and only the first retirement', async () => {
        await store.createAgent(agent('ada@a.test', 'k1'));
        await store.retireAgent('ada@a.test', at(1), 'UNPAIRING');
        await store.retireAgent('ada@a.test', at(2), 'OTHER');
        await store.retireAgent('ada@a.test', at(3));
        const retired = await store.agentByAddress('ada@a.test');
        assert.deepEqual(
          [retired?.retiredAt, retired?.unpairing, retired?.keys[0].revoked],
          [at(1), 'UNPAIRING', at(1)],
        );
        // Racing retirements: one wins, whole.
        await store.createAgent(agent('bob@a.test', 'k2'));
        await Promise.all([at(4), at(5), at(6)].map((t, i) => store.retireAgent('bob@a.test', t, `U${i}`)));
        const bob = await store.agentByAddress('bob@a.test');
        assert.equal(bob?.keys[0].revoked, bob?.retiredAt);
        assert.equal(bob?.unpairing, `U${[at(4), at(5), at(6)].indexOf(bob!.retiredAt!)}`);
        await store.retireAgent('nobody@a.test', at(1));
        assert.equal(await store.agentByAddress('nobody@a.test'), null);
      });

      it('caps active keys atomically, even when adds race', async () => {
        await store.createAgent(agent('ada@a.test', 'k0'));
        const results = await Promise.all(
          ['k1', 'k2', 'k3', 'k4'].map(key => store.addKey('ada@a.test', { key, added: at(), revoked: null }, 3)),
        );
        assert.equal(results.filter(r => r === 'added').length, 2);
        assert.equal(results.filter(r => r === 'too_many_keys').length, 2);
        assert.equal(await store.addKey('ada@a.test', { key: 'k0', added: at(), revoked: null }, 9), 'key_in_use');
        assert.deepEqual((await store.agentByAddress('ada@a.test'))!.keys[0].key, 'k0');
      });

      it('checks final document admission inside concurrent additions and recovery, with no partial mutation', async () => {
        assert.equal(await store.createAgent(agent('ada@a.test', 'k0'), () => false), 'too_many_keys');
        assert.equal(await store.agentByAddress('ada@a.test'), null);
        await store.createAgent(agent('ada@a.test', 'k0'));
        const results = await Promise.all(
          ['k1', 'k2'].map(key =>
            store.addKey(
              'ada@a.test',
              { key, added: at(), revoked: null },
              32,
              a => a.keys.filter(k => k.revoked === null).length <= 2,
            ),
          ),
        );
        assert.deepEqual(results.sort(), ['added', 'too_many_keys']);
        const before = await store.agentByAddress('ada@a.test');
        assert.equal(
          await store.replaceKeys('ada@a.test', { key: 'recovery', added: at(2), revoked: null }, () => false),
          'too_many_keys',
        );
        assert.deepEqual(await store.agentByAddress('ada@a.test'), before);
        assert.equal(await store.agentByKey('recovery'), null);
      });

      it("keeps a key's label, and a key without one has none", async () => {
        await store.createAgent(agent('ada@a.test', 'k0'));
        await store.addKey('ada@a.test', { key: 'k1', added: at(), revoked: null, label: "Ada's phone" }, 9);
        assert.deepEqual((await store.agentByAddress('ada@a.test'))!.keys, [
          { key: 'k0', added: at(), revoked: null },
          { key: 'k1', added: at(), revoked: null, label: "Ada's phone" },
        ]);
      });

      it('revokes one key at a time, never the last, even when revocations race', async () => {
        await store.createAgent(agent('ada@a.test', 'k0', 'k1', 'k2'));
        await store.createAgent(agent('bob@a.test', 'kb'));
        assert.equal(await store.revokeKey('ada@a.test', 'k2', at(1)), 'revoked');
        assert.equal(await store.revokeKey('ada@a.test', 'k2', at(2)), 'not_found', 'already revoked');
        assert.equal(await store.revokeKey('ada@a.test', 'kb', at(2)), 'not_found', "another agent's");
        const results = await Promise.all(['k0', 'k1'].map(key => store.revokeKey('ada@a.test', key, at(3))));
        assert.deepEqual(results.toSorted(), ['last_key', 'revoked']);
        const keys = (await store.agentByAddress('ada@a.test'))!.keys;
        assert.equal(keys[2].revoked, at(1), 'a revocation never moves');
        assert.equal(keys.filter(k => k.revoked === null).length, 1);
        assert.equal(await store.revokeKey('bob@a.test', 'kb', at(4)), 'last_key');
      });

      it('replaces every key on recovery, keeping the old ones as revoked', async () => {
        await store.createAgent(agent('ada@a.test', 'k0', 'k1'));
        await store.createAgent(agent('bob@a.test', 'kb'));
        assert.equal(await store.replaceKeys('ada@a.test', { key: 'kb', added: at(5), revoked: null }), 'key_in_use');
        assert.equal(await store.replaceKeys('ada@a.test', { key: 'k2', added: at(5), revoked: null }), 'replaced');
        const keys = (await store.agentByAddress('ada@a.test'))!.keys;
        assert.deepEqual(
          keys.map(k => [k.key, k.revoked]),
          [
            ['k0', at(5)],
            ['k1', at(5)],
            ['k2', null],
          ],
        );
        assert.equal((await store.agentByKey('k0'))?.address, 'ada@a.test');
        // A retired address never has a key again, whichever call reaches it first.
        await store.retireAgent('ada@a.test', at(6));
        assert.equal(await store.replaceKeys('ada@a.test', { key: 'k3', added: at(7), revoked: null }), 'retired');
        assert.ok((await store.agentByAddress('ada@a.test'))!.keys.every(k => k.revoked !== null));
      });

      it('keeps only a key the agent holds, revoking every other, and nothing for a key it does not hold', async () => {
        await store.createAgent(agent('ada@a.test', 'k0', 'k1', 'k2'));
        await store.createAgent(agent('bob@a.test', 'kb'));
        assert.equal(await store.keepOnlyKey('ada@a.test', 'kb', at(5)), 'not_held');
        assert.equal(await store.keepOnlyKey('ada@a.test', 'k9', at(5)), 'not_held');
        assert.equal(await store.keepOnlyKey('ada@a.test', 'k1', at(5)), 'kept');
        const keys = (await store.agentByAddress('ada@a.test'))!.keys;
        assert.deepEqual(
          keys.map(k => [k.key, k.revoked]),
          [
            ['k0', at(5)],
            ['k1', null],
            ['k2', at(5)],
          ],
        );
        assert.equal(await store.keepOnlyKey('ada@a.test', 'k0', at(6)), 'not_held', 'a revoked key is not held');
        await store.retireAgent('bob@a.test', at(7));
        assert.equal(await store.keepOnlyKey('bob@a.test', 'kb', at(8)), 'not_held', 'nor a retired agent');
      });

      it('separates current recovery authority from future historical revocations', async () => {
        for (const mode of ['principal', 'mailbox', 'keep'] as const) {
          const address = `${mode}@a.test`,
            a = agent(address, `${mode}-old`, `${mode}-keep`);
          a.keys[0].revoked = at(100 * HOUR);
          await store.createAgent(a);
          if (mode === 'keep') assert.equal(await store.keepOnlyKey(address, `${mode}-keep`, at(1)), 'kept');
          else if (mode === 'principal')
            assert.equal(
              await store.replaceKeys(address, { key: `${mode}-new`, added: at(1), revoked: null }),
              'replaced',
            );
          else {
            const pending = { key: `${mode}-new`, hash: 'h', completesAt: at(1) };
            await store.beginRecovery(address, pending, at(2), at());
            assert.equal(
              await store.completeRecovery(address, { key: pending.key, added: at(1), revoked: null }, pending),
              'replaced',
            );
          }
          const current = (await store.agentByAddress(address))!;
          assert.equal(current.keys[0].revoked, at(100 * HOUR), 'historical revocation does not move');
          assert.deepEqual(current.authorizedKeys, [`${mode}-${mode === 'keep' ? 'keep' : 'new'}`]);
          assert.equal(
            await store.revokeKey(
              address,
              current.authorizedKeys![0],
              at(1),
              a => a.authorizedKeys?.includes(`${mode}-old`) ?? true,
            ),
            'not_found',
            'old signer cannot use preserved history as current authority',
          );
          await store.addKey(address, { key: `${mode}-added`, added: at(2), revoked: null }, 32);
          assert.ok((await store.agentByAddress(address))!.authorizedKeys!.includes(`${mode}-added`));
          await store.retireAgent(address, at(3));
          assert.deepEqual((await store.agentByAddress(address))!.authorizedKeys, []);
        }
      });

      it('returns copies', async () => {
        await store.createAgent(agent('ada@a.test', 'k0'));
        const a = (await store.agentByAddress('ada@a.test'))!;
        a.keys.push({ key: 'x', added: at(), revoked: null });
        assert.equal((await store.agentByAddress('ada@a.test'))!.keys.length, 1);
      });
    });

    describe('messages', () => {
      it('stores a message once, and the first record wins', async () => {
        const m = message('ada@a.test', ['bob@b.test']);
        assert.deepEqual(await store.putMessage(m), m);
        assert.deepEqual(await store.putMessage({ ...m, carrier: 'https://other.test' }), m);
        assert.deepEqual(await store.message(m.id), m);
        assert.equal(await store.message('f'.repeat(64)), null);
      });

      it('stores a message with its rows, and a repeat adds only the rows that are missing', async () => {
        const m = message('ada@a.test', ['bob@b.test', 'cat@c.test']);
        await store.putMessage(m, { deliveries: [delivery(m.id, 'b.test')] });
        await store.putMessage(m, {
          deliveries: [delivery(m.id, 'b.test', { recipients: ['changed@b.test'] }), delivery(m.id, 'c.test')],
        });
        assert.deepEqual(
          (await store.deliveries(m.id)).map(d => [d.domain, d.recipients]),
          [
            ['b.test', ['bob@b.test']],
            ['c.test', ['bob@c.test']],
          ],
        );
      });

      it('deletes a message with everything tied to it', async () => {
        const m = message('ada@a.test', ['bob@b.test'], { parts: [{ type: 'a/b', sha256: sha('a'), size: 1 }] });
        await store.putMessage(m, { arrivals: [arrival(m.id, 'bob@b.test')], deliveries: [delivery(m.id, 'b.test')] });
        await store.addToInbox('bob@b.test', m.id, at());
        await store.deleteMessage(m.id);
        assert.equal(await store.message(m.id), null);
        assert.deepEqual((await store.sync('bob@b.test', 0, 10, at())).messages, []);
        assert.deepEqual((await store.sync('ada@a.test', 0, 10, at())).messages, []);
        assert.deepEqual(await store.inboxEvents(10), []);
        assert.deepEqual(await store.deliveries(m.id), []);
        assert.deepEqual(await store.arrivals(at(), 10), []);
      });
    });

    describe('arrivals', () => {
      it('queues arrivals per recipient, due in order, each retried on its own', async () => {
        const a = message('ada@a.test', ['bob@b.test', 'cat@b.test']);
        const b = message('ada@a.test', ['bob@b.test']);
        await store.putMessage(a, {
          arrivals: [arrival(a.id, 'bob@b.test', { hints: { invite: 'x' } }), arrival(a.id, 'cat@b.test')],
        });
        await store.putMessage(b, { arrivals: [arrival(b.id, 'bob@b.test', { dueAt: at(1) })] });
        await store.putMessage(a, { arrivals: [arrival(a.id, 'bob@b.test', { hints: { changed: 'y' } })] });
        const due = await store.arrivals(at(1), 10);
        assert.deepEqual(
          due.map(d => [d.message.id, d.arrival.recipient]),
          [
            [a.id, 'bob@b.test'],
            [a.id, 'cat@b.test'],
            [b.id, 'bob@b.test'],
          ],
        );
        assert.deepEqual(due[0].arrival.hints, { invite: 'x' });
        assert.deepEqual(due[0].message, a);
        assert.equal((await store.arrivals(at(0), 10)).length, 2, 'b is not due yet');

        await store.arrivalRetry(a.id, 'bob@b.test', at(HOUR));
        const later = await store.arrivals(at(HOUR), 10);
        assert.deepEqual(
          later.map(d => [d.arrival.recipient, d.arrival.attempts]),
          [
            ['cat@b.test', 0],
            ['bob@b.test', 0],
            ['bob@b.test', 1],
          ],
        );
      });

      it('keeps a received message while an arrival waits or once one kept it, and drops it otherwise', async () => {
        const kept = message('eve@e.test', ['bob@b.test', 'cat@b.test']);
        await store.putMessage(kept, { arrivals: [arrival(kept.id, 'bob@b.test'), arrival(kept.id, 'cat@b.test')] });
        assert.equal(await store.arrivalDone(kept.id, 'bob@b.test', false), null, 'cat is still waiting');
        assert.ok(await store.message(kept.id));
        assert.equal(await store.arrivalDone(kept.id, 'cat@b.test', true), 'kept');
        assert.ok(await store.message(kept.id));

        const dropped = message('eve@e.test', ['bob@b.test']);
        await store.putMessage(dropped, { arrivals: [arrival(dropped.id, 'bob@b.test')] });
        assert.equal(await store.arrivalDone(dropped.id, 'bob@b.test', false), 'dropped');
        assert.equal(await store.message(dropped.id), null);

        const offered = message('eve@e.test', ['bob@b.test']);
        await store.putMessage(offered, { arrivals: [arrival(offered.id, 'bob@b.test')] });
        await store.addToInbox('dan@b.test', offered.id, at());
        assert.equal(await store.arrivalDone(offered.id, 'bob@b.test', false), null, 'an inbox holds it');
        assert.ok(await store.message(offered.id));

        const sent = message('ada@a.test', ['bob@b.test']);
        await store.putMessage(sent);
        await store.putMessage(sent, { arrivals: [arrival(sent.id, 'bob@b.test')] });
        assert.equal(await store.arrivalDone(sent.id, 'bob@b.test', false), null, 'a message written here stays');
        assert.ok(await store.message(sent.id));
      });
    });

    describe('atomic recovery authority', () => {
      const proof = (key: string) => ({ key, hash: 'proof-hash', completesAt: at(1) });
      const epoch = async (address: string) => (await store.agentByAddress(address))!.recoveryEpoch ?? 0;
      it('advances the recovery epoch when a recovery ends or authority resets, never for a key added or revoked', async () => {
        await store.createAgent(agent('ada@a.test', 'k0'));
        assert.equal(await epoch('ada@a.test'), 0);
        assert.equal(await store.addKey('ada@a.test', { key: 'k1', added: at(1), revoked: null }, 8), 'added');
        assert.equal(await store.revokeKey('ada@a.test', 'k1', at(2)), 'revoked');
        assert.equal(await epoch('ada@a.test'), 0, 'key churn leaves mailbox codes good');
        const pending = proof('k2');
        await store.beginRecovery('ada@a.test', pending, null, at(3));
        assert.equal(await epoch('ada@a.test'), 0, 'beginning one does not');
        assert.equal(await store.cancelRecovery('ada@a.test', pending, at(4)), true);
        assert.equal(await epoch('ada@a.test'), 1, 'cancelled');
        await store.beginRecovery('ada@a.test', pending, null, at(5));
        assert.equal(
          await store.completeRecovery('ada@a.test', { key: 'k2', added: at(6), revoked: null }, pending),
          'replaced',
        );
        assert.equal(await epoch('ada@a.test'), 2, 'completed');
        await store.beginRecovery('ada@a.test', proof('k3'), at(HOUR), at(7));
        await store.sweep(at(2 * HOUR), at(2 * HOUR));
        assert.equal(await store.value('recovery', 'ada@a.test', at(2 * HOUR)), null);
        assert.equal(await epoch('ada@a.test'), 3, 'lapsed');
        assert.equal(await store.keepOnlyKey('ada@a.test', 'k2', at(2 * HOUR)), 'kept');
        assert.equal(await epoch('ada@a.test'), 4, 'principal recovery keeping a key');
        assert.equal(
          await store.replaceKeys('ada@a.test', { key: 'k4', added: at(2 * HOUR), revoked: null }),
          'replaced',
        );
        assert.equal(await epoch('ada@a.test'), 5, 'principal recovery replacing keys');
        await store.retireAgent('ada@a.test', at(3 * HOUR));
        assert.equal(await epoch('ada@a.test'), 6, 'retired');
      });
      it('bounds stored key history for additions, never for recovery', async () => {
        await store.createAgent(agent('ada@a.test', 'k0'));
        for (let i = 1; i < MAX_STORED_KEYS; i++) {
          assert.equal(await store.addKey('ada@a.test', { key: `k${i}`, added: at(i), revoked: null }, 8), 'added');
          assert.equal(await store.revokeKey('ada@a.test', `k${i}`, at(i)), 'revoked');
        }
        assert.equal((await store.agentByAddress('ada@a.test'))!.keys.length, MAX_STORED_KEYS);
        assert.equal(
          await store.addKey('ada@a.test', { key: 'over', added: at(HOUR), revoked: null }, 8),
          'too_many_keys',
        );
        assert.equal(await store.agentByKey('over'), null);
        const pending = proof('mailbox');
        await store.beginRecovery('ada@a.test', pending, null, at(HOUR));
        assert.equal(
          await store.completeRecovery('ada@a.test', { key: 'mailbox', added: at(HOUR), revoked: null }, pending),
          'replaced',
        );
        assert.equal(
          await store.replaceKeys('ada@a.test', { key: 'principal', added: at(HOUR), revoked: null }),
          'replaced',
        );
        assert.equal((await store.agentByAddress('ada@a.test'))!.keys.length, MAX_STORED_KEYS + 2);
      });
      it('refuses replacing keys of a retired agent as retired, even with a key in use', async () => {
        await store.createAgent(agent('ada@a.test', 'k0'));
        await store.createAgent(agent('bob@a.test', 'b0'));
        await store.retireAgent('ada@a.test', at(1));
        assert.equal(await store.replaceKeys('ada@a.test', { key: 'b0', added: at(2), revoked: null }), 'retired');
        assert.equal(await store.replaceKeys('bob@a.test', { key: 'k0', added: at(2), revoked: null }), 'key_in_use');
      });
      it('rejects unsafe generic writes to the reserved recovery namespace', async () => {
        await store.createAgent(agent('ada@a.test', 'k0'));
        const pending = proof('k1');
        await store.beginRecovery('ada@a.test', pending, null, at());
        await assert.rejects(store.setValue('recovery', 'ada@a.test', proof('k2'), null), /reserved/);
        await assert.rejects(store.valueOnce('recovery', 'ada@a.test', proof('k2'), null, at()), /reserved/);
        await assert.rejects(store.releaseValue('recovery', 'ada@a.test', pending), /reserved/);
        await assert.rejects(store.renewValue('recovery', 'ada@a.test', pending, at(HOUR)), /reserved/);
        assert.deepEqual(await store.value('recovery', 'ada@a.test', at()), pending);
      });
      it('preserves pending proof on capacity failure and completes keys plus proof in one change', async () => {
        await store.createAgent(agent('ada@a.test', 'k0'));
        const pending = proof('k1');
        await store.beginRecovery('ada@a.test', pending, null, at());
        const before = await store.agentByAddress('ada@a.test');
        assert.equal(
          await store.completeRecovery('ada@a.test', { key: 'k1', added: at(2), revoked: null }, pending, () => false),
          'too_many_keys',
        );
        assert.deepEqual(await store.value('recovery', 'ada@a.test', at(2)), pending);
        assert.deepEqual(await store.agentByAddress('ada@a.test'), before);
        assert.equal(
          await store.completeRecovery('ada@a.test', { key: 'k1', added: at(2), revoked: null }, pending),
          'replaced',
        );
        assert.equal(await store.value('recovery', 'ada@a.test', at(2)), null);
        assert.equal((await store.agentByAddress('ada@a.test'))!.keys.find(k => k.key === 'k1')!.revoked, null);
        assert.equal(
          await store.completeRecovery('ada@a.test', { key: 'k1', added: at(3), revoked: null }, pending),
          'not_pending',
        );
      });
      it('cannot complete explicitly undefended recovery, even after its waiting time, until exact activation', async () => {
        await store.createAgent(agent('ada@a.test', 'k0'));
        const pending = { ...proof('k1'), defended: false, nonce: 'unchanged', cancel: { binding: 'same' } };
        await store.beginRecovery('ada@a.test', pending, null, at());
        const entry = { key: 'k1', added: at(HOUR), revoked: null };
        assert.equal(await store.completeRecovery('ada@a.test', entry, pending), 'not_pending');
        assert.deepEqual(await store.value('recovery', 'ada@a.test', at(HOUR)), pending);
        assert.equal(await store.agentByKey('k1'), null);
        assert.equal(await store.activateRecovery('ada@a.test', { ...pending, hash: 'wrong' }, at(HOUR)), false);
        const activated = { ...pending, defended: true };
        const results = await Promise.all([
          store.activateRecovery('ada@a.test', pending, at(HOUR)),
          store.activateRecovery('ada@a.test', pending, at(HOUR)),
        ]);
        assert.deepEqual(results.sort(), [false, true]);
        assert.deepEqual(await store.value('recovery', 'ada@a.test', at(HOUR)), activated);
        assert.equal(await store.completeRecovery('ada@a.test', entry, pending), 'not_pending');
        await assert.rejects(
          store.completeRecovery('ada@a.test', entry, activated, () => {
            throw new Error('admission unavailable');
          }),
          /admission unavailable/,
        );
        assert.deepEqual(await store.value('recovery', 'ada@a.test', at(HOUR)), activated);
        assert.equal(await store.agentByKey('k1'), null);
        assert.equal(await store.completeRecovery('ada@a.test', entry, activated), 'replaced');
      });
      it('cannot activate expired, cancelled or principal-cleared recovery and preserves legacy completion', async () => {
        for (const mode of ['expired', 'cancelled', 'principal', 'retired'] as const) {
          const address = `${mode}@a.test`;
          await store.createAgent(agent(address, `${mode}-old`));
          const pending = { ...proof(`${mode}-new`), defended: false };
          await store.beginRecovery(address, pending, mode === 'expired' ? at(2) : null, at());
          if (mode === 'cancelled') assert.equal(await store.cancelRecovery(address, pending, at(2)), true);
          if (mode === 'principal') assert.equal(await store.keepOnlyKey(address, `${mode}-old`, at(2)), 'kept');
          if (mode === 'retired') await store.retireAgent(address, at(2));
          assert.equal(await store.activateRecovery(address, pending, at(2)), false);
        }
        await store.createAgent(agent('legacy@a.test', 'legacy-old'));
        const pending = proof('legacy-new');
        await store.beginRecovery('legacy@a.test', pending, null, at());
        assert.equal(
          await store.completeRecovery('legacy@a.test', { key: 'legacy-new', added: at(2), revoked: null }, pending),
          'replaced',
        );
      });

      it('fences a delayed begin even when principal recovery keeps the already-only key', async () => {
        await store.createAgent(agent('ada@a.test', 'k0'));
        const old = await store.agentByAddress('ada@a.test');
        const pending = proof('k1');
        await store.beginRecovery('ada@a.test', pending, null, at());
        assert.equal(await store.keepOnlyKey('ada@a.test', 'k0', at(2)), 'kept');
        assert.equal(await store.value('recovery', 'ada@a.test', at(2)), null);
        assert.equal(
          await store.beginRecovery(
            'ada@a.test',
            proof('k2'),
            null,
            at(2),
            a => (a.authorityVersion ?? 0) === (old!.authorityVersion ?? 0),
          ),
          null,
        );
        assert.equal(
          await store.completeRecovery('ada@a.test', { key: 'k1', added: at(3), revoked: null }, pending),
          'not_pending',
        );
        assert.deepEqual((await store.agentByAddress('ada@a.test'))!.keys, old!.keys);
      });
      it('atomically persists key-cancellation history and invalidates stale begin authority', async () => {
        await store.createAgent(agent('ada@a.test', 'k0'));
        const captured = await store.agentByAddress('ada@a.test');
        const pending = proof('k1');
        await store.beginRecovery('ada@a.test', pending, null, at());
        assert.equal(await store.cancelRecovery('ada@a.test', pending, at(2), () => false, at(2)), false);
        assert.equal(await store.cancelRecovery('ada@a.test', pending, at(2), () => true, at(2)), true);
        const current = (await store.agentByAddress('ada@a.test'))!;
        assert.equal(current.recoveryKeyCancelledAt, at(2));
        assert.ok((current.authorityVersion ?? 0) > (captured!.authorityVersion ?? 0));
        assert.equal(
          await store.beginRecovery(
            'ada@a.test',
            proof('k2'),
            null,
            at(3),
            a => (a.authorityVersion ?? 0) === (captured!.authorityVersion ?? 0),
          ),
          null,
        );
        const next = proof('k2');
        assert.deepEqual(await store.beginRecovery('ada@a.test', next, null, at(3)), next);
        assert.equal(await store.cancelRecovery('ada@a.test', pending, at(4), () => true, at(4)), false);
        assert.deepEqual(await store.value('recovery', 'ada@a.test', at(4)), next);
      });
    });

    describe('sync streams', () => {
      it('never applies a late arrival decision to a recreated message incarnation', async () => {
        const old = { ...message('eve@e.test', ['ada@a.test']), carrier: 'https://e.test' };
        await store.putMessage(old, { arrivals: [arrival(old.id, 'ada@a.test')] });
        const [snapshot] = await store.arrivals(at(), 1);
        await store.deleteMessage(old.id);
        await store.putMessage({ ...old, carrier: 'https://new.test' }, { arrivals: [arrival(old.id, 'ada@a.test')] });
        const [fresh] = await store.arrivals(at(), 1);
        assert.notEqual(fresh.generation, snapshot.generation);
        await store.arrivalRetry(old.id, 'ada@a.test', at(HOUR), snapshot.generation);
        assert.equal(await store.arrivalDone(old.id, 'ada@a.test', true, snapshot.generation), null);
        assert.equal(await store.addToInbox('ada@a.test', old.id, at(), snapshot.generation), false);
        const [stillWaiting] = await store.arrivals(at(), 1);
        assert.equal(stillWaiting.arrival.attempts, 0);
        assert.equal(stillWaiting.generation, fresh.generation);
        assert.equal(await store.addToInbox('ada@a.test', old.id, at(), fresh.generation), true);
      });

      it('keeps one inbox entry per address and message, paged by position and limit', async () => {
        const ms = [1, 2, 3].map(() => message('ada@a.test', ['bob@b.test']));
        for (const m of ms) await store.putMessage(m);
        for (const m of ms) assert.equal(await store.addToInbox('bob@b.test', m.id, at(1)), true);
        assert.equal(await store.addToInbox('bob@b.test', ms[0].id, at(2)), false);
        const all = await store.sync('bob@b.test', 0, 10, at());
        assert.deepEqual(
          ids(all),
          ms.map(m => m.id),
        );
        assert.equal(all.more, false);
        const [first, second, third] = all.messages;
        assert.ok(first.cursor < second.cursor && second.cursor < third.cursor);
        assert.deepEqual([first.address, first.receivedAt, first.message], ['bob@b.test', at(1), ms[0].message]);
        const page = await store.sync('bob@b.test', first.cursor, 1, at());
        assert.deepEqual([ids(page), page.cursor, page.more], [[ms[1].id], second.cursor, true]);
        const rest = await store.sync('bob@b.test', page.cursor, 5, at());
        assert.deepEqual([ids(rest), rest.more], [[ms[2].id], false]);
        assert.deepEqual(ids(await store.sync('eve@b.test', 0, 10, at())), []);
      });

      it('holds what an agent wrote here beside what it received, in the order the store took them', async () => {
        const wrote = message('ada@a.test', ['bob@b.test']);
        const received = { ...message('bob@b.test', ['ada@a.test']), carrier: 'https://b.test' };
        const published = message('ada@a.test', []);
        await store.putMessage(wrote);
        await store.putMessage(received, { arrivals: [arrival(received.id, 'ada@a.test')] });
        assert.deepEqual(ids(await store.sync('ada@a.test', 0, 10, at())), [wrote.id], 'not yet taken');
        await store.addToInbox('ada@a.test', received.id, at(5));
        await store.putMessage(published);
        await store.putMessage(wrote, { deliveries: [delivery(wrote.id, 'b.test')] });
        const page = await store.sync('ada@a.test', 0, 10, at());
        assert.deepEqual(ids(page), [wrote.id, received.id, published.id], 'a repeat takes no new place');
        assert.deepEqual(
          page.messages.map(e => [e.address, e.receivedAt]),
          [
            ['ada@a.test', wrote.receivedAt],
            ['ada@a.test', at(5)],
            ['ada@a.test', published.receivedAt],
          ],
        );
        assert.deepEqual(ids(await store.sync('bob@b.test', 0, 10, at())), [], 'the author of a received message');
      });

      it('starts from the messages that entered a stream at or after a time', async () => {
        const [old, recent] = [1, 2].map(() => message('ada@a.test', ['bob@b.test']));
        for (const m of [old, recent]) await store.putMessage(m);
        await store.addToInbox('bob@b.test', old.id, at(1));
        await store.addToInbox('bob@b.test', recent.id, at(HOUR));
        assert.deepEqual(ids(await store.sync('bob@b.test', 0, 10, at(), at(HOUR))), [recent.id]);
        assert.deepEqual(ids(await store.sync('bob@b.test', 0, 10, at(), at(HOUR + 1))), []);
      });

      it("covers every position taken so far, other agents' too, once nothing more is there", async () => {
        const m = message('ada@a.test', ['bob@b.test']);
        await store.putMessage(m);
        await store.addToInbox('bob@b.test', m.id, at());
        const bob = await store.sync('bob@b.test', 0, 10, at());
        const cat = await store.sync('cat@b.test', 0, 10, at());
        assert.equal(cat.cursor, bob.cursor);
        assert.equal(cat.cursor, bob.messages[0].cursor);
        const later = await store.sync('cat@b.test', cat.cursor, 10, at());
        assert.deepEqual([later.messages, later.cursor, later.more], [[], cat.cursor, false]);
        assert.ok((await store.sync('cat@b.test', cat.cursor + 5, 10, at())).cursor < cat.cursor + 5);
      });

      it('retains a late-admitted message for the complete promised sync window', async () => {
        const day = 24 * HOUR;
        const m = { ...message('eve@e.test', ['ada@a.test']), expiresAt: at(30 * day) };
        await store.putMessage(m, { arrivals: [arrival(m.id, 'ada@a.test')] });
        const [arrivalSnapshot] = await store.arrivals(at(), 1);
        assert.equal(
          await store.addToInbox('ada@a.test', m.id, at(29 * day), arrivalSnapshot.generation, at(36 * day)),
          true,
        );
        await store.sweep(at(30 * day), at());
        assert.deepEqual(ids(await store.sync('ada@a.test', 0, 10, at(35 * day))), [m.id]);
        await store.sweep(at(36 * day), at());
        assert.equal(await store.message(m.id), null);
      });

      it('shows a held signal in its place until it expires, and forgets it', async () => {
        const [m1, m2] = [1, 2].map(() => message('ada@a.test', ['bob@b.test']));
        for (const m of [m1, m2]) await store.putMessage(m);
        const signal = { type: 'read', from: 'ada@a.test', about: m1.id, at: at() };
        await store.addToInbox('bob@b.test', m1.id, at());
        await store.holdSignal('bob@b.test', signal, at(300_000), at());
        await store.holdSignal('cat@b.test', { ...signal, type: 'typing' }, at(300_000), at());
        await store.addToInbox('bob@b.test', m2.id, at());
        const all = await store.sync('bob@b.test', 0, 10, at(1));
        assert.deepEqual(
          all.signals.map(({ cursor: _, ...held }) => held),
          [signal],
        );
        const [e1, e2] = all.messages;
        assert.ok(e1.cursor < all.signals[0].cursor && all.signals[0].cursor < e2.cursor);
        assert.deepEqual(
          (await store.sync('bob@b.test', 0, 1, at(1))).signals,
          [],
          'not on a page that ends before it',
        );
        assert.equal((await store.sync('bob@b.test', e1.cursor, 1, at(1))).signals.length, 1);
        assert.deepEqual((await store.sync('bob@b.test', all.signals[0].cursor, 10, at(1))).signals, []);
        assert.deepEqual((await store.sync('bob@b.test', 0, 10, at(300_000))).signals, [], 'expired');

        await store.holdSignal('bob@b.test', { ...signal, type: 'typing' }, at(600_000), at(300_000));
        assert.deepEqual(
          (await store.sync('bob@b.test', 0, 10, at(299_999))).signals.map(s => s.type),
          ['typing'],
          'the expired ones are forgotten',
        );
        assert.equal((await store.sweep(at(600_000), at())).signals, 1);
        assert.deepEqual((await store.sync('bob@b.test', 0, 10, at())).signals, []);
      });

      it('queues one inbox event with each new entry, until it is told', async () => {
        const [m1, m2] = [1, 2].map(() => message('ada@a.test', ['bob@b.test', 'cat@b.test']));
        for (const m of [m1, m2]) await store.putMessage(m);
        await store.addToInbox('bob@b.test', m1.id, at());
        await store.addToInbox('cat@b.test', m1.id, at());
        await store.addToInbox('bob@b.test', m1.id, at());
        await store.addToInbox('bob@b.test', m2.id, at());
        const events = await store.inboxEvents(10);
        assert.deepEqual(
          events.map(e => [e.address, e.id]),
          [
            ['bob@b.test', m1.id],
            ['cat@b.test', m1.id],
            ['bob@b.test', m2.id],
          ],
        );
        assert.deepEqual(events[0].message, m1.message);
        await store.inboxEventDone(events[1].cursor);
        assert.deepEqual(
          (await store.inboxEvents(1)).map(e => e.cursor),
          [events[0].cursor],
        );
        assert.equal((await store.inboxEvents(10)).length, 2);
      });

      it('never lets a reader following the cursor skip an entry that concurrent writers add', async () => {
        const ms = Array.from({ length: 120 }, () => message('ada@a.test', ['bob@b.test']));
        for (const m of ms) await store.putMessage(m);
        const seen = new Set<string>();
        let writing = true;
        const reader = (async () => {
          for (let cursor = 0; ; ) {
            const last = !writing;
            const page = await store.sync('bob@b.test', cursor, 7, at());
            for (const e of page.messages) seen.add(e.id);
            cursor = page.cursor;
            if (last && !page.more) return;
          }
        })();
        await Promise.all(
          ms.map((m, i) =>
            i % 3
              ? store.addToInbox('bob@b.test', m.id, at())
              : store.holdSignal(
                  'bob@b.test',
                  { type: 'typing', from: 'ada@a.test', about: m.id, at: at() },
                  at(1),
                  at(),
                ),
          ),
        );
        writing = false;
        await reader;
        assert.equal(seen.size, ms.filter((_, i) => i % 3).length);
      });
    });

    describe('webhooks', () => {
      const hook = (id: string, address = 'ada@a.test', extra: Partial<Webhook> = {}): Webhook => ({
        id,
        address,
        url: `https://hooks.test/${id}`,
        codeHash: sha('c'),
        verified: false,
        createdAt: at(),
        failingSince: null,
        ...extra,
      });
      const claimed = async (now: number, quiet = now + 1000) =>
        (await store.claimWebhooks(at(now), 10, at(quiet), lease(`w${now}`, at(now + 30_000)))).map(w => w.id).sort();

      it('keeps at most so many per agent, even when adds race', async () => {
        const added = await Promise.all(['w1', 'w2', 'w3', 'w4'].map(id => store.addWebhook(hook(id), 2)));
        assert.equal(added.filter(Boolean).length, 2);
        assert.equal(await store.addWebhook(hook('w5', 'bob@a.test'), 2), true);
        assert.deepEqual(await store.webhook('w5'), hook('w5', 'bob@a.test'));
        assert.equal(await store.webhook('nope'), null);
        const [kept] = ['w1', 'w2', 'w3', 'w4'].filter((_, i) => added[i]);
        await store.deleteWebhook(kept);
        assert.equal(await store.webhook(kept), null);
        assert.equal(await store.addWebhook(hook('w6'), 2), true, 'a deleted one frees its place');
      });

      it('wakes only verified webhooks, each claimed once and then quiet for a while', async () => {
        await store.addWebhook(hook('w1'), 5);
        await store.addWebhook(hook('w2'), 5);
        await store.addWebhook(hook('w3', 'bob@a.test'), 5);
        await store.wakeWebhooks('ada@a.test', at());
        assert.deepEqual(await claimed(0), [], 'none verified');
        for (const id of ['w1', 'w3']) await store.verifyWebhook(id);
        assert.equal((await store.webhook('w1'))?.verified, true);
        await store.wakeWebhooks('ada@a.test', at(10));
        assert.deepEqual(await claimed(9), [], 'not due yet');
        const racing = await Promise.all(
          [1, 2, 3].map(i => store.claimWebhooks(at(10), 10, at(1010), lease(`race${i}`, at(30_010)))),
        );
        assert.deepEqual(
          racing.flat().map(w => w.id),
          ['w1'],
        );
        await store.wakeWebhooks('ada@a.test', at(20));
        await store.wakeWebhooks('ada@a.test', at(30));
        assert.deepEqual(await claimed(1009), [], 'quiet until 1010');
        const won = racing.findIndex(a => a.length > 0) + 1;
        assert.equal(await store.settleWebhook('w1', null, null, `race${won}`), true);
        assert.deepEqual(await claimed(1010, 2010), ['w1'], 'one post for both wakes');
        await store.settleWebhook('w1', null, null, 'w1010');
        assert.deepEqual(await claimed(5000), []);
      });

      it('replays a crashed post and fences its stale settlement after a new lease', async () => {
        await store.addWebhook(hook('w1', 'ada@a.test', { verified: true }), 2);
        await store.wakeWebhooks('ada@a.test', at());
        assert.equal((await store.claimWebhooks(at(), 1, at(1), lease('old', at(10)))).length, 1);
        assert.deepEqual(await store.claimWebhooks(at(9), 1, at(10), lease('early', at(20))), []);
        assert.equal((await store.claimWebhooks(at(10), 1, at(11), lease('new', at(20)))).length, 1);
        assert.equal(await store.settleWebhook('w1', at(), at(HOUR), 'old'), false);
        await store.wakeWebhooks('ada@a.test', at(12));
        assert.equal(await store.settleWebhook('w1', null, null, 'new'), true);
        assert.equal((await store.claimWebhooks(at(12), 1, at(13), lease('wake', at(22)))).length, 1);
      });

      it('disables a permanently failing webhook only for the current claim token', async () => {
        await store.addWebhook(hook('w1', 'ada@a.test', { verified: true }), 1);
        await store.wakeWebhooks('ada@a.test', at());
        await store.claimWebhooks(at(), 1, at(1), lease('old', at(10)));
        await store.claimWebhooks(at(10), 1, at(11), lease('new', at(20)));
        assert.equal(await store.settleWebhook('w1', at(), null, 'old', true), false);
        assert.ok(await store.webhook('w1'));
        assert.equal(await store.settleWebhook('w1', at(), null, 'new', true), true);
        assert.equal(await store.webhook('w1'), null);
      });

      it('keeps when a webhook began failing, and a retry, unless a post is due anyway', async () => {
        await store.addWebhook(hook('w1'), 5);
        await store.verifyWebhook('w1');
        await store.wakeWebhooks('ada@a.test', at());
        await claimed(0);
        await store.settleWebhook('w1', at(), at(60_000), 'w0');
        assert.equal((await store.webhook('w1'))?.failingSince, at());
        assert.deepEqual(await claimed(59_999), []);
        assert.deepEqual(await claimed(60_000), ['w1']);
        await store.wakeWebhooks('ada@a.test', at(61_000));
        await store.settleWebhook('w1', at(), at(HOUR), 'w60000');
        assert.deepEqual(await claimed(61_000), ['w1'], 'the wake stands');
        await store.settleWebhook('w1', null, null, 'w61000');
        assert.equal((await store.webhook('w1'))?.failingSince, null);
        assert.deepEqual(await claimed(2 * HOUR), []);
      });
    });

    describe('deliveries', () => {
      it('claims due rows earliest first, skipping servers, and never the same row twice', async () => {
        const m = message('ada@a.test', ['bob@b.test']);
        await store.putMessage(m, {
          deliveries: [
            delivery(m.id, 'b.test', { nextAttemptAt: at(2) }),
            delivery(m.id, 'c.test', { nextAttemptAt: at(1), server: 'https://c.test' }),
            delivery(m.id, 'd.test', { nextAttemptAt: at(HOUR) }),
          ],
        });
        assert.deepEqual(
          (await store.claimDeliveries(at(10), 10, ['https://c.test'], lease('t1'))).map(d => d.domain),
          ['b.test'],
        );
        const racing = await Promise.all(['t2', 't3', 't4'].map(t => store.claimDeliveries(at(10), 10, [], lease(t))));
        assert.deepEqual(
          racing.flat().map(d => d.domain),
          ['c.test'],
          'b.test is leased, d.test not due, c.test claimed once',
        );
        const expired = await store.claimDeliveries(at(HOUR), 10, [], lease('t5', at(HOUR + 60_000)));
        assert.deepEqual(
          expired.map(d => d.domain).sort(),
          ['b.test', 'c.test', 'd.test'],
          'a lease that ran out frees its row',
        );
        assert.ok(expired.every(d => d.nextAttemptAt === at(HOUR + 60_000)));
        assert.deepEqual(await store.claimDeliveries(at(HOUR), 10, [], lease('t6')), []);
      });

      it('settles a row only for the lease that claimed it, and never after it was delivered', async () => {
        const m = message('ada@a.test', ['bob@b.test']);
        await store.putMessage(m, { deliveries: [delivery(m.id, 'b.test')] });
        const [first] = await store.claimDeliveries(at(), 1, [], lease('a', at(10)));
        const [second] = await store.claimDeliveries(at(10), 1, [], lease('b', at(20)));
        assert.equal(await store.settleDelivery({ ...first, status: 'delivered' }, 'a'), false, 'a stale lease');
        const delivered = { ...second, status: 'delivered' as const, server: 'https://b.test', attempts: 1, hints: {} };
        assert.equal(await store.settleDelivery(delivered, 'b'), true);
        assert.equal(await store.settleDelivery({ ...second, reason: 'late' }, 'b'), false, 'delivered stays');
        const [row] = await store.deliveries(m.id);
        assert.deepEqual([row.status, row.server, row.attempts, row.reason], ['delivered', 'https://b.test', 1, null]);
        assert.deepEqual(await store.claimDeliveries(at(HOUR), 1, [], lease('c')), []);
      });

      it('clears the hints of a delivery once it ends, and keeps them while it is pending', async () => {
        const m = message('ada@a.test', ['bob@b.test']);
        const hints = { 'bob@b.test': { invite: 'x' } };
        await store.putMessage(m, { deliveries: [delivery(m.id, 'b.test', { hints })] });
        const [row] = await store.claimDeliveries(at(), 1, [], lease('a'));
        await store.settleDelivery({ ...row, reason: 'temporary', nextAttemptAt: at(1) }, 'a');
        assert.deepEqual((await store.deliveries(m.id))[0].hints, hints);
        const [again] = await store.claimDeliveries(at(1), 1, [], lease('b'));
        await store.settleDelivery({ ...again, status: 'failed', reason: 'expired' }, 'b');
        assert.deepEqual((await store.deliveries(m.id))[0].hints, {});
      });
    });

    describe('published messages, relations and correspondence', () => {
      it('keeps a same-author retraction despite expiry, arrival order and another author', async () => {
        const reply = message('bob@b.test', ['ada@a.test'], {
          inReplyTo: sha('e'),
          headers: { rel: 'reply', listed: 'yes' },
        });
        const retract = {
          ...message('bob@b.test', ['ada@a.test'], { inReplyTo: reply.id, headers: { rel: 'retract' } }),
          expiresAt: at(10),
        };
        await store.putMessage(retract, { arrivals: [arrival(retract.id, 'ada@a.test')] });
        // The original may arrive only after its valid retraction has already expired.
        await store.sweep(at(10), at());
        await store.putMessage(reply, { arrivals: [arrival(reply.id, 'ada@a.test')] });
        assert.equal(await store.listingRetracted('ada@a.test', reply.id, reply.message.from), true);
        assert.equal(await store.listingRetracted('cat@a.test', reply.id, reply.message.from), false);
        assert.equal(await store.listingRetracted('ada@a.test', reply.id, 'eve@e.test'), false);
        const publicReply = message('bob@b.test', [], { headers: { rel: 'reply', listed: 'yes' } });
        const publicRetract = message('bob@b.test', [], { inReplyTo: publicReply.id, headers: { rel: 'retract' } });
        await store.putMessage(publicRetract);
        await store.putMessage(publicReply);
        assert.equal(await store.listingRetracted('ada@a.test', publicReply.id, 'bob@b.test'), true);
        await store.deleteMessage(reply.id);
        assert.equal(
          await store.listingRetracted('ada@a.test', reply.id, 'bob@b.test'),
          true,
          'an accepted early retraction remains durable',
        );
      });

      it('keeps a reaccepted target suppressed after its prior incarnation was deleted', async () => {
        const post = message('ada@a.test', [], { headers: { feed: 'posts' } });
        const reply = message('bob@b.test', ['ada@a.test'], {
          inReplyTo: post.id,
          headers: { rel: 'reply', listed: 'yes' },
        });
        const retract = message('bob@b.test', ['ada@a.test'], { inReplyTo: reply.id, headers: { rel: 'retract' } });
        await store.putMessage(post);
        await store.putMessage(reply);
        await store.addToInbox('ada@a.test', reply.id, at());
        await store.putMessage(retract);
        await store.deleteMessage(reply.id);
        assert.deepEqual((await store.repliesTo('ada@a.test', post.id, null, 10)).records, []);
        await store.putMessage(reply);
        await store.addToInbox('ada@a.test', reply.id, at(1));
        assert.deepEqual(await store.message(reply.id), reply, 'the original target exists again');
        const candidates = (await store.repliesTo('ada@a.test', post.id, null, 10)).records;
        assert.deepEqual(
          candidates.map(r => r.message.id),
          [reply.id],
          'the new target incarnation is a real relation candidate',
        );
        const visible = [];
        for (const r of candidates)
          if (!(await store.listingRetracted('ada@a.test', r.message.id, r.message.message.from)))
            visible.push(r.message.id);
        assert.deepEqual(visible, [], 'the durable same-author suppression still removes the reaccepted target');
      });

      it('reports the first kept retraction after inbox admission, with no repeated arrival work', async () => {
        const m = message('bob@b.test', ['ada@a.test'], { inReplyTo: sha('a'), headers: { rel: 'retract' } });
        await store.putMessage(m, { arrivals: [arrival(m.id, 'ada@a.test')] });
        await store.addToInbox('ada@a.test', m.id, at());
        assert.equal(await store.arrivalDone(m.id, 'ada@a.test', true), 'kept');
        assert.equal(await store.arrivalDone(m.id, 'ada@a.test', true), null);
        assert.equal((await store.arrivals(at(), 10)).length, 0);
        assert.ok(await store.message(m.id));
      });

      it('keeps the claims a carrier signed for a message, beside the ones judged here', async () => {
        const signedClaims = { claims: [{ type: 'acts-for', agent: 'ada@a.test' }], signature: 'AAAA' };
        const m = { ...message('ada@a.test', ['bob@b.test']), signedClaims };
        await store.putMessage(m);
        await store.addToInbox('bob@b.test', m.id, at());
        assert.deepEqual((await store.message(m.id))!.signedClaims, signedClaims);
        assert.deepEqual((await store.sync('bob@b.test', 0, 10, at())).messages[0].signedClaims, signedClaims);
        assert.equal((await store.message(message('ada@a.test', []).id))?.signedClaims ?? null, null);
      });

      it("pages an agent's published messages newest first, by opaque cursor", async () => {
        const posts = [1, 2, 3].map(() => message('ada@a.test', []));
        for (const m of [...posts, message('ada@a.test', ['bob@b.test']), message('cat@a.test', [])]) {
          await store.putMessage(m);
        }
        const first = await store.published('ada@a.test', null, 2);
        assert.deepEqual(
          first.records.map(r => r.message.id),
          [posts[2].id, posts[1].id],
        );
        assert.equal(first.more, true);
        assert.ok(first.records.every(r => /^[\x21-\x7e]{1,128}$/.test(r.cursor)));
        const rest = await store.published('ada@a.test', first.records[1].cursor, 2);
        assert.deepEqual(
          rest.records.map(r => r.message.id),
          [posts[0].id],
        );
        assert.equal(rest.more, false);
        assert.deepEqual((await store.published('eve@a.test', null, 2)).records, []);
      });

      it("pages the messages in an agent's inbox that point at one message, newest first", async () => {
        const post = message('ada@a.test', []);
        const [c1, c2, other] = [post.id, post.id, sha('9')].map(to =>
          message('bob@b.test', ['ada@a.test'], { inReplyTo: to }),
        );
        for (const m of [post, c1, c2, other]) await store.putMessage(m);
        for (const m of [c1, c2, other]) await store.addToInbox('ada@a.test', m.id, at());
        const page = await store.repliesTo('ada@a.test', post.id, null, 1);
        assert.deepEqual(
          page.records.map(r => r.message.id),
          [c2.id],
        );
        assert.equal(page.more, true);
        const next = await store.repliesTo('ada@a.test', post.id, page.records[0].cursor, 5);
        assert.deepEqual(
          next.records.map(r => r.message.id),
          [c1.id],
        );
        assert.deepEqual((await store.repliesTo('cat@a.test', post.id, null, 5)).records, []);
      });

      it('says whether a message is in an inbox, and whether an agent here wrote to an address', async () => {
        const sent = message('ada@a.test', ['bob@b.test', 'cat@c.test']);
        const received = { ...message('bob@b.test', ['ada@a.test']), carrier: 'https://b.test' };
        for (const m of [sent, received]) await store.putMessage(m);
        await store.addToInbox('ada@a.test', received.id, at());
        assert.equal(await store.inInbox('ada@a.test', received.id), true);
        assert.equal(await store.inInbox('ada@a.test', sent.id), false);
        assert.equal(await store.wroteTo('ada@a.test', 'cat@c.test', SELF), true);
        assert.equal(await store.wroteTo('ada@a.test', 'eve@e.test', SELF), false);
        assert.equal(await store.wroteTo('bob@b.test', 'ada@a.test', SELF), false, 'written elsewhere');
      });
    });

    describe('parts', () => {
      it('keeps bytes per source, never shared between sources', async () => {
        await store.putPart(sha('a'), Buffer.from('mine'), { uploader: 'ada@a.test' }, at());
        await store.putPart(sha('a'), Buffer.from('theirs'), { carrier: 'https://e.test' }, at());
        assert.deepEqual(await store.part(sha('a'), { uploader: 'ada@a.test' }), Buffer.from('mine'));
        assert.deepEqual(await store.part(sha('a'), { carrier: 'https://e.test' }), Buffer.from('theirs'));
        assert.equal(await store.part(sha('a'), { uploader: 'cat@a.test' }), null);
        assert.equal(await store.part(sha('a'), { carrier: 'https://f.test' }), null);
      });

      it('says which bytes are held for an agent, and whose messages name a part for a reader', async () => {
        const part = { type: 'application/pdf', sha256: sha('a'), size: 3 };
        for (const a of ['ada@a.test', 'old@a.test', 'cat@a.test']) await store.createAgent(agent(a, `k-${a}`));
        const pub = message('ada@a.test', [], { parts: [part] });
        const retiredPub = message('old@a.test', [], { parts: [part] });
        const priv = message('ada@a.test', ['bob@b.test'], { parts: [part] });
        const received = { ...message('eve@e.test', ['cat@a.test'], { parts: [part] }), carrier: 'https://e.test' };
        const local = message('ada@a.test', ['cat@a.test'], { parts: [part] });
        const forwarded = message('cat@a.test', ['bob@b.test'], { parts: [part] });
        for (const m of [pub, retiredPub, priv, received, local, forwarded]) await store.putMessage(m);
        await store.retireAgent('old@a.test', at());
        await store.addToInbox('cat@a.test', received.id, at());
        await store.addToInbox('cat@a.test', local.id, at());
        const sent = (m: StoredMessage) => [
          delivery(m.id, 'b.test', { status: 'delivered', server: 'https://b.test' }),
        ];
        await store.putMessage(priv, { deliveries: sent(priv) });
        await store.putMessage(forwarded, { deliveries: sent(forwarded) });

        const sorted = <T>(xs: T[]) => xs.sort((x, y) => JSON.stringify(x).localeCompare(JSON.stringify(y)));
        assert.deepEqual(sorted(await store.heldFor(sha('a'), 'cat@a.test', SELF)), [
          { carrier: 'https://e.test', size: 3 },
          { uploader: 'ada@a.test', size: 3 },
        ]);
        assert.deepEqual(await store.heldFor(sha('a'), 'eve@a.test', SELF), []);
        const forward = message('cat@a.test', ['dot@a.test'], { parts: [part] });
        await store.putMessage(forward);
        await store.addToInbox('dot@a.test', forward.id, at());
        assert.deepEqual(
          sorted(await store.heldFor(sha('a'), 'dot@a.test', SELF)),
          [
            { carrier: 'https://e.test', size: 3 },
            { uploader: 'ada@a.test', size: 3 },
            { uploader: 'cat@a.test', size: 3 },
          ],
          'a forward from an agent here: its upload, and what is held for it',
        );
        const again = message('dot@a.test', ['fay@a.test'], { parts: [part] });
        await store.putMessage(again);
        await store.addToInbox('fay@a.test', again.id, at());
        const back = message('fay@a.test', ['cat@a.test'], { parts: [part] });
        await store.putMessage(back);
        await store.addToInbox('cat@a.test', back.id, at());
        assert.deepEqual(
          sorted(await store.heldFor(sha('a'), 'fay@a.test', SELF)),
          [
            { carrier: 'https://e.test', size: 3 },
            { uploader: 'ada@a.test', size: 3 },
            { uploader: 'cat@a.test', size: 3 },
            { uploader: 'dot@a.test', size: 3 },
            { uploader: 'fay@a.test', size: 3 },
          ],
          'forwarded again: what was held for every agent here that passed it on, each once, through a cycle',
        );
        await store.putPart(sha('c'), Buffer.from('abc'), { uploader: 'eve@a.test' }, at());
        assert.deepEqual(await store.heldFor(sha('c'), 'eve@a.test', SELF), [{ uploader: 'eve@a.test', size: 3 }]);

        const authors = (xs: { author: string }[]) => xs.map(x => x.author).sort();
        assert.deepEqual(authors(await store.partNamers(sha('a'), { published: true }, SELF)), ['ada@a.test']);
        const [named] = await store.partNamers(sha('a'), { published: true }, SELF);
        assert.deepEqual(named.message, pub.message);
        assert.deepEqual(authors(await store.partNamers(sha('a'), { server: 'https://b.test' }, SELF)), [
          'ada@a.test',
          'cat@a.test',
        ]);
        assert.deepEqual(await store.partNamers(sha('a'), { server: 'https://e.test' }, SELF), []);
        assert.deepEqual(await store.partNamers(sha('b'), { published: true }, SELF), []);
      });

      it('follows repeated local forwards, terminates cycles and isolates unrelated sources', async () => {
        const part = { type: 'application/octet-stream', sha256: sha('d'), size: 3 };
        await store.putPart(sha('d'), Buffer.from('abc'), { uploader: 'a@a.test' }, at());
        await store.putPart(sha('d'), Buffer.from('abc'), { uploader: 'unrelated@a.test' }, at());
        const unrelated = message('elsewhere@e.test', ['unrelated@a.test'], { parts: [part] });
        await store.putMessage({ ...unrelated, carrier: 'https://unrelated.test' });
        await store.addToInbox('unrelated@a.test', unrelated.id, at());
        for (const [from, to] of [
          ['a@a.test', 'b@a.test'],
          ['b@a.test', 'c@a.test'],
          ['c@a.test', 'd@a.test'],
          ['d@a.test', 'b@a.test'],
        ]) {
          const m = message(from, [to], { parts: [part] });
          await store.putMessage(m);
          await store.addToInbox(to, m.id, at());
        }
        const sources = await store.heldFor(sha('d'), 'd@a.test', SELF);
        assert.deepEqual(sources.map(s => ('uploader' in s ? s.uploader : s.carrier)).sort(), [
          'a@a.test',
          'b@a.test',
          'c@a.test',
          'd@a.test',
        ]);
        assert.ok(sources.every(s => s.size === 3));
        assert.equal(sources.length, 4, 'each source appears once despite the cycle');
        assert.deepEqual(await store.heldFor(sha('d'), 'no-grant@a.test', SELF), []);
        assert.deepEqual(await store.heldFor(sha('e'), 'd@a.test', SELF), []);
      });

      it('queues one fetch per part and carrier, fairly and with token-fenced settlements', async () => {
        const f = await store.queueFetch({
          sha256: sha('a'),
          carrier: 'https://e.test',
          size: 3,
          attempts: 0,
          dueAt: at(10),
        });
        assert.deepEqual(await store.queueFetch(f), f);
        assert.deepEqual(await store.queueFetch({ ...f, dueAt: at(1) }), f);
        for (const [hash, due] of [
          ['b', 5],
          ['c', 6],
          ['d', 7],
        ] as const)
          await store.queueFetch({ ...f, sha256: sha(hash), carrier: 'https://f.test', dueAt: at(due) });
        assert.deepEqual(
          (await store.fetches(at(10), 10)).map(x => x.sha256.slice(0, 1)),
          ['b', 'a', 'c', 'd'],
        );
        assert.equal(await store.claimFetch(f, at(5), lease('early')), false);
        const won = await Promise.all([1, 2, 3].map(i => store.claimFetch(f, at(10), lease(`t${i}`, at(HOUR)))));
        assert.equal(won.filter(Boolean).length, 1);
        const token = `t${won.indexOf(true) + 1}`;
        assert.equal(await store.renewFetch(f.sha256, f.carrier, 'wrong', at(11), at(2 * HOUR)), false);
        assert.equal(await store.renewFetch(f.sha256, f.carrier, token, at(11), at(2 * HOUR)), true);
        assert.equal(await store.fetchRetry(f.sha256, f.carrier, at(20), 'wrong'), false);
        assert.equal(await store.fetchRetry(f.sha256, f.carrier, at(20), token), true);
        const row = (await store.fetches(at(20), 10)).find(r => r.carrier === f.carrier)!;
        assert.equal(row.attempts, 1);
        assert.equal(await store.claimFetch(f, at(20), lease('stale')), false);
        assert.equal(await store.claimFetch(row, at(20), lease('new', at(30))), true);
        assert.equal(await store.fetchDone(f.sha256, f.carrier, token), false);
        assert.equal(await store.fetchGiveUp(f.sha256, f.carrier, token, at(HOUR)), false);
        assert.equal(await store.fetchDefer(f.sha256, f.carrier, at(40), 'new'), true);
        const deferred = (await store.fetches(at(40), 10)).find(r => r.carrier === f.carrier)!;
        assert.equal(deferred.attempts, 1);
        assert.equal(await store.claimFetch(deferred, at(40), lease('last', at(50))), true);
        assert.equal(await store.fetchGiveUp(f.sha256, f.carrier, 'last', at(HOUR)), true);
        assert.equal(await store.fetchExhausted(f.sha256, f.carrier, at(50)), true);
        assert.ok((await store.fetches(at(2 * HOUR), 10)).every(r => r.carrier !== f.carrier));
        assert.equal(await store.fetchExhausted(f.sha256, f.carrier, at(HOUR)), false);
        const next = await store.queueFetch({ ...f, dueAt: at(HOUR) }, at(HOUR));
        assert.equal(next.revision, 0);
        assert.notEqual(next.generation, f.generation);
        assert.equal(next.dueAt, at(HOUR));
      });

      it('rejects a read snapshot after a defer restores the same attempts and due time', async () => {
        const f = { sha256: sha('e'), carrier: 'https://e.test', size: 3, attempts: 0, dueAt: at() };
        const snapshot = await store.queueFetch(f);
        assert.equal(await store.claimFetch(snapshot, at(), lease('a', at(10))), true);
        assert.equal(await store.fetchDefer(f.sha256, f.carrier, at(), 'a'), true);
        assert.equal(await store.claimFetch(snapshot, at(), lease('stale', at(10))), false);
        const [current] = await store.fetches(at(), 1);
        assert.equal(await store.claimFetch(current, at(), lease('new', at(10))), true);
      });

      it('rejects a stale snapshot after its completed row is recreated', async () => {
        const seed = { sha256: sha('f'), carrier: 'https://e.test', size: 3, attempts: 0, dueAt: at() };
        const old = await store.queueFetch(seed);
        assert.equal(await store.claimFetch(old, at(), lease('a', at(10))), true);
        assert.equal(await store.fetchDone(seed.sha256, seed.carrier, 'a'), true);
        const fresh = await store.queueFetch(seed);
        assert.notEqual(fresh.generation, old.generation);
        assert.equal(await store.claimFetch(old, at(), lease('stale', at(10))), false);
        assert.equal(await store.claimFetch(fresh, at(), lease('new', at(10))), true);
      });

      it('fences an expired fetch owner after a new worker claims it, and cannot renew after expiry', async () => {
        const f = await store.queueFetch({
          sha256: sha('b'),
          carrier: 'https://e.test',
          size: 3,
          attempts: 0,
          dueAt: at(),
        });
        assert.equal(await store.claimFetch(f, at(), lease('a', at(10))), true);
        assert.equal(await store.renewFetch(f.sha256, f.carrier, 'a', at(10), at(20)), false);
        const [row] = await store.fetches(at(10), 1);
        assert.equal(await store.claimFetch(row, at(10), lease('b', at(30))), true);
        assert.equal(await store.fetchDone(f.sha256, f.carrier, 'a'), false);
        assert.equal(await store.fetchRetry(f.sha256, f.carrier, at(50), 'a'), false);
        assert.equal(await store.fetchDefer(f.sha256, f.carrier, at(50), 'a'), false);
        assert.equal(await store.fetchGiveUp(f.sha256, f.carrier, 'a', at(HOUR)), false);
        assert.equal(await store.fetchDone(f.sha256, f.carrier, 'b'), true);
        assert.deepEqual(await store.fetches(at(HOUR), 10), []);
      });

      it('queues no more than `max` waiting fetches for a carrier, still answering one already queued', async () => {
        const f = { sha256: sha('a'), carrier: 'https://e.test', size: 3, attempts: 0, dueAt: at() };
        assert.ok(await store.queueFetch(f, at(), 2));
        const second = await store.queueFetch({ ...f, sha256: sha('b') }, at(), 2);
        assert.ok(second);
        assert.equal(await store.queueFetch({ ...f, sha256: sha('c') }, at(), 2), null, 'its carrier has two waiting');
        assert.deepEqual(await store.queueFetch({ ...f, sha256: sha('b') }, at(), 2), second, 'one queued is answered');
        assert.ok(
          await store.queueFetch({ ...f, carrier: 'https://f.test', sha256: sha('c') }, at(), 2),
          'per carrier',
        );
        assert.equal(await store.claimFetch(second!, at(), lease('t', at(10))), true);
        assert.equal(await store.fetchGiveUp(sha('b'), f.carrier, 't', at(HOUR)), true);
        assert.ok(await store.queueFetch({ ...f, sha256: sha('c') }, at(), 2), 'a fetch given up waits no more');
        assert.deepEqual((await store.fetches(at(), 10)).map(r => r.sha256.slice(0, 1)).sort(), ['a', 'c', 'c']);
      });
    });

    describe('marks, counters and values', () => {
      it('lets exactly one of racing callers set a mark, until it expires', async () => {
        const won = await Promise.all([1, 2, 3, 4].map(() => store.mark('nonce', 'x', at(600_000), at())));
        assert.equal(won.filter(Boolean).length, 1);
        assert.equal(await store.marked('nonce', 'x', at(599_999)), true);
        assert.equal(await store.marked('nonce', 'x', at(600_000)), false);
        assert.equal(await store.mark('nonce', 'x', at(1_200_000), at(600_000)), true);
        assert.equal(await store.marked('other', 'x', at()), false);
      });

      it('counts atomically, starting over once the count expires', async () => {
        const counts = await Promise.all([1, 2, 3].map(() => store.count('c', 'x', at(1000), at())));
        assert.deepEqual(counts.sort(), [1, 2, 3]);
        assert.equal(await store.count('c', 'x', at(5000), at(1000)), 1);
        const added = await Promise.all([500, 700].map(by => store.count('b', 'x', at(1000), at(), by)));
        assert.equal(Math.max(...added), 1200, 'by any amount, atomically');
        assert.equal(await store.count('b', 'x', at(1000), at(), -200), 1000, 'taken back by a negative one');
      });

      it('keeps values until they expire, and valueOnce keeps the first', async () => {
        await store.setValue('v', 'x', { a: 1 }, at(1000));
        assert.deepEqual(await store.value('v', 'x', at(999)), { a: 1 });
        assert.equal(await store.value('v', 'x', at(1000)), null);
        assert.equal(await store.valueOnce('v', 'y', 'first', null, at()), 'first');
        assert.equal(await store.valueOnce('v', 'y', 'second', null, at()), 'first');
        assert.equal(await store.releaseValue('v', 'y', 'second'), false, 'released only while it is that value');
        assert.equal(await store.value('v', 'y', at()), 'first');
        assert.equal(await store.releaseValue('v', 'y', 'first'), true);
        assert.equal(await store.valueOnce('v', 'y', 'again', null, at()), 'again', 'and free once released');
        // Renewed only while it is the same value, so a lease another caller took is never extended.
        await store.valueOnce('v', 'z', 'mine', at(1000), at());
        assert.equal(await store.renewValue('v', 'z', 'theirs', at(5000)), false);
        assert.equal(await store.renewValue('v', 'z', 'mine', at(5000)), true);
        assert.equal(await store.value('v', 'z', at(4999)), 'mine', 'kept until the new expiry');
        assert.equal(await store.valueOnce('v', 'z', 'theirs', at(9000), at(2000)), 'mine', 'and not taken meanwhile');
        assert.equal(await store.value('v', 'z', at(5000)), null);
        await store.setValue('v', 'y', 'third', null);
        assert.equal(await store.value('v', 'y', at(10 * HOUR)), 'third');
      });
    });

    describe('sweep', () => {
      it('removes fetches no message from their carrier names any more, waiting or given up', async () => {
        const named = { type: 'a/b', sha256: sha('a'), size: 1 };
        const fromE = { ...message('eve@e.test', ['ada@a.test'], { parts: [named] }), carrier: 'https://e.test' };
        const gone = {
          ...message('eve@e.test', ['ada@a.test'], { parts: [{ ...named, sha256: sha('b') }] }),
          carrier: 'https://e.test',
          expiresAt: at(HOUR),
        };
        await store.putMessage(fromE);
        await store.putMessage(gone);
        const f = { carrier: 'https://e.test', size: 1, attempts: 0, dueAt: at(2 * HOUR) };
        await store.queueFetch({ ...f, sha256: sha('a') });
        await store.queueFetch({ ...f, sha256: sha('b') });
        await store.queueFetch({ ...f, sha256: sha('a'), carrier: 'https://f.test' }, undefined);
        const lost = await store.queueFetch({ ...f, sha256: sha('c'), dueAt: at() });
        assert.equal(await store.claimFetch(lost, at(), lease('t', at(10))), true);
        assert.equal(await store.fetchGiveUp(sha('c'), f.carrier, 't', at(48 * HOUR)), true);
        await store.sweep(at(HOUR), at(HOUR));
        assert.deepEqual(
          (await store.fetches(at(3 * HOUR), 10)).map(r => `${r.sha256.slice(0, 1)} ${r.carrier}`),
          ['a https://e.test'],
          'a message carried by e.test still names a; b went with its message; no message f.test carried names a',
        );
        assert.equal(await store.fetchExhausted(sha('c'), f.carrier, at(2 * HOUR)), false, 'given up, then unnamed');
      });

      it('removes expired messages with their ties, unnamed bytes per source, and expired marks', async () => {
        const named = { type: 'a/b', sha256: sha('a'), size: 1 };
        const old = { ...message('ada@a.test', ['bob@b.test'], { parts: [named] }), expiresAt: at(HOUR) };
        const kept = { ...message('ada@a.test', ['bob@b.test']), expiresAt: at(48 * HOUR) };
        const fromE = { ...message('eve@e.test', ['ada@a.test'], { parts: [named] }), carrier: 'https://e.test' };
        await store.putMessage(old, { deliveries: [delivery(old.id, 'b.test')] });
        await store.putMessage(kept);
        await store.putMessage(fromE);
        await store.addToInbox('bob@b.test', old.id, at());
        await store.putPart(sha('a'), Buffer.from('a'), { uploader: 'ada@a.test' }, at());
        await store.putPart(sha('a'), Buffer.from('a'), { carrier: 'https://e.test' }, at());
        await store.putPart(sha('a'), Buffer.from('a'), { carrier: 'https://f.test' }, at());
        await store.putPart(sha('b'), Buffer.from('b'), { uploader: 'ada@a.test' }, at());
        await store.putPart(sha('c'), Buffer.from('c'), { uploader: 'ada@a.test' }, at(2 * HOUR));
        await store.mark('m', 'x', at(HOUR), at());

        const counts = await store.sweep(at(HOUR), at(HOUR));
        assert.equal(counts.messages, 1);
        assert.equal(await store.message(old.id), null);
        assert.ok(await store.message(kept.id));
        assert.deepEqual((await store.sync('bob@b.test', 0, 10, at())).messages, []);
        assert.deepEqual(ids(await store.sync('ada@a.test', 0, 10, at())), [kept.id]);
        assert.deepEqual(await store.deliveries(old.id), []);
        assert.equal(await store.part(sha('a'), { uploader: 'ada@a.test' }), null, 'no message by ada names it');
        assert.ok(await store.part(sha('a'), { carrier: 'https://e.test' }), 'a message carried by e.test names it');
        assert.equal(await store.part(sha('a'), { carrier: 'https://f.test' }), null, 'fetched bytes go at once');
        assert.equal(
          await store.part(sha('b'), { uploader: 'ada@a.test' }),
          null,
          'an unnamed upload goes after its grace',
        );
        assert.ok(await store.part(sha('c'), { uploader: 'ada@a.test' }), 'an upload within its grace stays');
        assert.equal(await store.marked('m', 'x', at()), false);
      });
    });
  });
}

/** Host admission boundary tests; factories supply the same options to their adapter constructor. */
export function retractionCapacityContract(
  name: string,
  make: (limits: Partial<RetractionCapacity>) => Store | Promise<Store>,
) {
  describe(`Retraction capacity: ${name}`, () => {
    const retract = (from = 'bob@b.test') =>
      message(from, ['ada@a.test'], { inReplyTo: sha('a'), headers: { rel: 'retract' } });
    const capacity = (e: unknown) =>
      !!e &&
      typeof e === 'object' &&
      (e as { code?: string }).code === 'store_capacity' &&
      (e as Error).message === 'The server is temporarily at capacity.';
    it('admits one last-slot writer and rejects before any new state becomes visible', async () => {
      const s = await make({ maxRecords: 1, maxPerAuthor: 1 });
      try {
        const records = [retract(), retract('cat@c.test')];
        const results = await Promise.allSettled(
          records.map(m => s.putMessage(m, { arrivals: [arrival(m.id, 'ada@a.test')] })),
        );
        assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
        const rejected = results.findIndex(r => r.status === 'rejected');
        assert.ok(capacity((results[rejected] as PromiseRejectedResult).reason));
        assert.equal(await s.message(records[rejected].id), null);
        assert.equal(await s.listingRetracted('ada@a.test', sha('a'), records[rejected].message.from), false);
        assert.equal((await s.arrivals(at(), 10)).length, 1);
      } finally {
        await s.close();
      }
    });
    it('bounds each author independently and never recycles an accepted deletion', async () => {
      const s = await make({ maxRecords: 2, maxPerAuthor: 1 });
      try {
        const first = retract(),
          repeat = { ...first, carrier: 'https://changed.test' };
        await s.putMessage(first);
        assert.deepEqual(await s.putMessage(repeat), first);
        await assert.rejects(s.putMessage(retract()), capacity);
        const other = retract('cat@c.test');
        await s.putMessage(other);
        await s.deleteMessage(first.id);
        assert.deepEqual(await s.putMessage(repeat, { arrivals: [arrival(first.id, 'ada@a.test')] }), first);
        assert.equal(await s.message(first.id), null);
        assert.equal(await s.listingRetracted('ada@a.test', sha('a'), 'bob@b.test'), true);
        await assert.rejects(s.putMessage(retract('eve@e.test')), capacity);
        assert.equal((await s.arrivals(at(), 10)).length, 0);
      } finally {
        await s.close();
      }
    });
    it('charges UTF-8 bytes and additional journals before accepting a duplicate', async () => {
      const s = await make({ maxBytes: 8192 });
      try {
        const first = retract();
        await s.putMessage(first);
        const row = arrival(first.id, 'ada@a.test', { hints: { large: 'é'.repeat(5000) } });
        await assert.rejects(s.putMessage(first, { arrivals: [row] }), capacity);
        assert.deepEqual(await s.message(first.id), first);
        assert.equal((await s.arrivals(at(), 10)).length, 0);
        const large = retract('cat@c.test');
        large.claims = [{ large: 'é'.repeat(5000) } as never];
        await assert.rejects(s.putMessage(large), capacity);
        assert.equal(await s.message(large.id), null);
        assert.equal(await s.listingRetracted('ada@a.test', sha('a'), 'cat@c.test'), false);
      } finally {
        await s.close();
      }
    });
  });
}
