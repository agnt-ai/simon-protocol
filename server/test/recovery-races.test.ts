/** Recovery authority races through the real router and Store admission/CAS handoffs. */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  addKeyProofString,
  generateKey,
  keyToken,
  privateKeyFromSeed,
  sign,
  signRecovery,
} from '@agnt-protocol/protocol';
import type { Store } from '../src/store/store.ts';
import { Federation, type Answer } from './harness.ts';

const HOUR = 3_600_000;

/** An explicit one-shot gate, always released by each test's cleanup. */
function gate() {
  let arrive!: () => void, release!: () => void;
  const reached = new Promise<void>(resolve => {
    arrive = resolve;
  });
  const opened = new Promise<void>(resolve => {
    release = resolve;
  });
  return { reached, arrive, opened, release };
}

/** Closing servers wakes long polls before their stores close; gated mutations finish against live stores. */
async function cleanup(fed: Federation, requests: (Promise<Answer> | undefined)[], release = () => {}) {
  release();
  await Promise.all(fed.servers.map(host => host.server.close()));
  await Promise.allSettled(requests.filter((request): request is Promise<Answer> => request !== undefined));
  await fed.close();
}

describe('recovery authority and defense races', () => {
  it(
    'cannot install a successor from an old add-key request paused before Store admission',
    { timeout: 3000 },
    async () => {
      const fed = new Federation(),
        mutation = gate();
      let adding: Promise<Answer> | undefined;
      let armed = false;
      try {
        const host = await fed.server('key-race', {
          wrapStore: store =>
            new Proxy(store, {
              get(target, name) {
                if (name === 'addKey')
                  return async (...args: Parameters<Store['addKey']>) => {
                    if (armed) {
                      armed = false;
                      mutation.arrive();
                      await mutation.opened;
                    }
                    return target.addKey(...args);
                  };
                const value = Reflect.get(target, name, target);
                return typeof value === 'function' ? value.bind(target) : value;
              },
            }),
        });
        const old = host.newAgent(),
          fresh = host.newAgent(),
          successor = generateKey(),
          principal = generateKey();
        const address = 'owner@key-race.test',
          forValue = `simon-key:${principal.key}`;
        const at = fed.clock.now().toISOString(),
          future = new Date(fed.clock.t + 120_000).toISOString();
        // Targeted historical-metadata fixture: the old key is valid for another two minutes. Recovery
        // must end current authority immediately while preserving this historical cryptographic interval.
        assert.equal(
          await host.store.createAgent({
            address,
            kind: 'paired',
            principal: forValue,
            mailbox: false,
            keys: [{ key: old.token, added: at, revoked: future }],
            createdAt: at,
            retiredAt: null,
          }),
          'created',
        );
        old.address = address;
        assert.equal((await old.request('GET', '/simon/account')).status, 200);
        armed = true;
        let finished = false;
        adding = old
          .request('POST', '/simon/keys', {
            body: JSON.stringify({
              key: successor.key,
              proof: sign(successor.privateKey, addKeyProofString(address, successor.key)),
            }),
          })
          .then(answer => {
            finished = true;
            mutation.arrive();
            return answer;
          });
        await mutation.reached;
        assert.equal(finished, false, 'the old request authenticated and reached the actual Store admission boundary');
        assert.equal(
          (await fresh.recover({ address, at, recover: signRecovery(principal.privateKey, address, fresh.token, at) }))
            .status,
          200,
        );
        assert.equal((await host.store.agentByAddress(address))!.keys.find(k => k.key === old.token)!.revoked, future);
        mutation.release();
        const refused = await adding;
        assert.notEqual(refused.status, 200, 'a pre-recovery signer cannot install a post-recovery successor');
        assert.ok(refused.status >= 400 && refused.status < 500, 'the stale mutation is refused rather than crashing');
        const held = (await host.store.agentByAddress(address))!;
        assert.equal(
          held.keys.some(k => k.key === successor.key),
          false,
        );
        assert.deepEqual(held.authorizedKeys, [fresh.token]);
        assert.equal((await old.request('GET', '/simon/account')).status, 401);
        assert.equal((await fresh.request('GET', '/simon/account')).status, 200);
      } finally {
        await cleanup(fed, [adding], mutation.release);
      }
    },
  );

  for (const by of ['mailbox', 'principal'] as const) {
    it(
      `rejects an already waiting old-key sync after ${by} recovery, without rewriting future revocation`,
      { timeout: 3000 },
      async () => {
        const fed = new Federation(),
          waiting = gate();
        let polling: Promise<Answer> | undefined;
        let armed = false;
        try {
          const host = await fed.server(`poll-${by}`, {
            config: { recoveryWaitSeconds: 0 },
            wrapStore: store =>
              new Proxy(store, {
                get(target, name) {
                  if (name === 'sync')
                    return async (...args: Parameters<Store['sync']>) => {
                      const page = await target.sync(...args);
                      if (armed) {
                        armed = false;
                        setImmediate(waiting.arrive);
                      }
                      return page;
                    };
                  const value = Reflect.get(target, name, target);
                  return typeof value === 'function' ? value.bind(target) : value;
                },
              }),
          });
          const domain = `mail-poll-${by}.example`;
          fed.dns.point(domain, host.origin);
          const address = `owner@${domain}`,
            old = host.newAgent(),
            fresh = host.newAgent();
          const principal = generateKey(),
            forValue = `simon-key:${principal.key}`;
          const at = fed.clock.now().toISOString(),
            future = new Date(fed.clock.t + 120_000).toISOString();
          assert.equal(
            await host.store.createAgent({
              address,
              kind: by === 'principal' ? 'paired' : 'solo',
              principal: by === 'principal' ? forValue : null,
              mailbox: true,
              keys: [{ key: old.token, added: at, revoked: future }],
              createdAt: at,
              retiredAt: null,
            }),
            'created',
          );
          old.address = address;
          const before = await old.sync();
          assert.equal(before.status, 200, 'the future-revoked old key still authenticates before recovery');
          armed = true;
          let finished = false;
          polling = old.sync(before.json.token, { wait: 60 }).then(answer => {
            finished = true;
            waiting.arrive();
            return answer;
          });
          await waiting.reached;
          assert.equal(finished, false, 'the old signed request actually reached its empty-page wait');
          // No fake clock advance here: both requests stay within the five-minute signature window.
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
            assert.equal((await fresh.recover({ address })).status, 202);
            await fed.work();
            assert.equal((await fresh.recover({ address, code: host.code(address) })).status, 200);
          }
          const sender = await host.agent('sender');
          const sent = await sender.send(sender.message([address], 'data belongs to the recovered authority'));
          assert.equal(sent.status, 200);
          await fed.work();
          const refused = await polling;
          assert.equal(refused.status, 401);
          assert.equal(refused.headers['www-authenticate'], 'SIMON');
          assert.equal(
            refused.json.messages,
            undefined,
            'a previously authorized wait reveals no new data after recovery',
          );
          const resumed = await fresh.sync(before.json.token);
          assert.equal(resumed.status, 200, 'the same account checkpoint works for its new authorized key');
          assert.ok(resumed.json.messages.some((entry: { id: string }) => entry.id === sent.json.id));
          assert.equal(
            (await host.store.agentByAddress(address))!.keys.find(k => k.key === old.token)!.revoked,
            future,
          );
        } finally {
          await cleanup(fed, [polling], waiting.release);
        }
      },
    );
  }

  it(
    'refuses mailbox recovery when a mismatched postmaster identity silently prevents its notice',
    { timeout: 3000 },
    async () => {
      const fed = new Federation();
      let activationAttempts = 0;
      try {
        const host = await fed.server('silent-notice', {
          wrapStore: store =>
            new Proxy(store, {
              get(target, name) {
                if (name === 'activateRecovery')
                  return async (...args: Parameters<Store['activateRecovery']>) => {
                    activationAttempts++;
                    return target.activateRecovery(...args);
                  };
                const value = Reflect.get(target, name, target);
                return typeof value === 'function' ? value.bind(target) : value;
              },
            }),
        });
        const domain = 'mail.silent-notice.example';
        fed.dns.point(domain, host.origin);
        const address = `owner@${domain}`,
          postmaster = `postmaster@${domain}`;
        const old = host.newAgent(),
          claimant = host.newAgent();
        assert.equal((await old.register({ address })).status, 202);
        await fed.work();
        assert.equal((await old.register({ address, code: host.code(address) })).status, 200);

        // Targeted corruption fixture: the persisted notice seed names one key, while an otherwise
        // usable solo postmaster row holds another. notify returns false rather than throwing.
        const expectedSeed = Buffer.alloc(32, 7),
          otherSeed = Buffer.alloc(32, 8);
        const expected = keyToken(privateKeyFromSeed('ed25519', expectedSeed));
        const other = keyToken(privateKeyFromSeed('ed25519', otherSeed));
        assert.notEqual(expected, other);
        await host.store.setValue('postmaster-key', postmaster, expectedSeed.toString('base64url'), null);
        const at = fed.clock.now().toISOString();
        assert.equal(
          await host.store.createAgent({
            address: postmaster,
            kind: 'solo',
            principal: null,
            keys: [{ key: other, added: at, revoked: null }],
            mailbox: false,
            createdAt: at,
            retiredAt: null,
          }),
          'created',
        );
        assert.equal((await claimant.recover({ address })).status, 202);
        await fed.work();
        const failed = await claimant.recover({ address, code: host.code(address) });
        assert.deepEqual([failed.status, failed.json.code], [503, 'unavailable']);
        assert.equal(activationAttempts, 0, 'a silent failed owner notice never reaches activation');
        assert.equal(
          await host.store.value('recovery', address, fed.clock.now().toISOString()),
          null,
          'the exact unactivated reservation is rolled back',
        );
        assert.equal(
          (await host.store.agentByAddress(address))!.keys.some(k => k.key === claimant.token),
          false,
        );
        assert.equal(await host.store.agentByKey(claimant.token), null);
        assert.deepEqual(
          host.mail.filter(
            note => note.address === address && (note.type === 'recovery' || note.type === 'recoveryPending'),
          ),
          [],
          'no cancellation mail is sent without a confirmed owner notice',
        );
        assert.equal(host.cancelCodes.has(address), false);
        assert.deepEqual(
          await old.received(),
          [],
          'the unavailable notice identity never produced a resident defense message',
        );
        assert.equal((await old.request('GET', '/simon/account')).status, 200, 'the original holder retains authority');
      } finally {
        await cleanup(fed, []);
      }
    },
  );

  it(
    'cannot complete an undefended recovery even when notification and exact rollback both fail',
    { timeout: 5000 },
    async () => {
      const fed = new Federation();
      let notifyFails = false,
        rollbackFails = false,
        notifyAttempts = 0,
        rollbackAttempts = 0;
      let address = '';
      try {
        const host = await fed.server('defense-outage', {
          wrapStore: store =>
            new Proxy(store, {
              get(target, name) {
                if (name === 'putMessage')
                  return async (...args: Parameters<Store['putMessage']>) => {
                    const message = args[0].message;
                    if (notifyFails && message.from.startsWith('postmaster@') && message.to.includes(address)) {
                      notifyAttempts++;
                      throw new Error('defense notification persistence unavailable');
                    }
                    return target.putMessage(...args);
                  };
                if (name === 'cancelRecovery')
                  return async (...args: Parameters<Store['cancelRecovery']>) => {
                    if (rollbackFails && args[0] === address) {
                      rollbackAttempts++;
                      throw new Error('exact recovery rollback unavailable');
                    }
                    return target.cancelRecovery(...args);
                  };
                const value = Reflect.get(target, name, target);
                return typeof value === 'function' ? value.bind(target) : value;
              },
            }),
        });
        fed.dns.point('mail.defense.example', host.origin);
        address = 'owner@mail.defense.example';
        const old = host.newAgent(),
          claimant = host.newAgent();
        assert.equal((await old.register({ address })).status, 202);
        await fed.work();
        assert.equal((await old.register({ address, code: host.code(address) })).status, 200);
        assert.equal((await claimant.recover({ address })).status, 202);
        await fed.work();
        const proof = host.code(address);
        notifyFails = rollbackFails = true;
        const failed = await claimant.recover({ address, code: proof });
        assert.deepEqual(
          [failed.status, failed.json.code],
          [503, 'unavailable'],
          'failure to prepare defenses cannot acknowledge a waiting recovery',
        );
        assert.ok(notifyAttempts > 0, 'the real notification hit the injected persistence failure');
        assert.ok(rollbackAttempts > 0, 'the real failure handler attempted exact pending rollback');
        const stranded = await host.store.value<{ defended?: boolean }>(
          'recovery',
          address,
          fed.clock.now().toISOString(),
        );
        assert.equal(stranded?.defended, false, 'a failed rollback leaves an explicitly non-completable reservation');
        fed.clock.advance(72 * HOUR + 1000);
        const blocked = await claimant.recover({ address, code: proof });
        assert.deepEqual([blocked.status, blocked.json.code], [503, 'unavailable']);
        assert.equal(
          (await old.request('GET', '/simon/account')).status,
          200,
          'the old holder still controls the account',
        );
        assert.equal(
          (await host.store.agentByAddress(address))!.keys.some(k => k.key === claimant.token),
          false,
        );

        notifyFails = rollbackFails = false;
        const cleaned = await claimant.recover({ address, code: proof });
        assert.deepEqual(
          [cleaned.status, cleaned.json.code],
          [503, 'unavailable'],
          'a valid proof cleans the inert reservation but never resumes an undefended takeover',
        );
        assert.equal(await host.store.value('recovery', address, fed.clock.now().toISOString()), null);
        assert.equal((await old.request('GET', '/simon/account')).status, 200);
        const retry = claimant;
        assert.equal((await retry.recover({ address })).status, 202);
        await fed.work();
        const code = host.code(address);
        const prepared = await retry.recover({ address, code });
        assert.deepEqual([prepared.status, prepared.json.status], [202, 'recovery_pending']);
        assert.equal(
          (await host.store.value<{ defended?: boolean }>('recovery', address, fed.clock.now().toISOString()))
            ?.defended,
          true,
          'successful notification/cancel-secret/mail preparation activates exactly that reservation',
        );
        assert.ok(host.cancelCode(address), 'the cancellation secret was sent with the recovery news');
        fed.clock.advance(72 * HOUR + 1000);
        const completed = await retry.recover({ address, code });
        assert.equal(completed.status, 200);
        assert.equal((await retry.sync()).status, 200);
        assert.equal((await old.request('GET', '/simon/account')).status, 401);
        assert.deepEqual((await host.store.agentByAddress(address))!.authorizedKeys, [retry.token]);
      } finally {
        notifyFails = rollbackFails = false;
        await cleanup(fed, []);
      }
    },
  );
});
