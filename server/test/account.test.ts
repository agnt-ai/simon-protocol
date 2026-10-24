/**
 * CLIENT.md "The agent's address and keys", beside register: the account, adding and revoking keys, grants,
 * cancelling a recovery by key and by cancel code, and unpairing, with the reference server's practice.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { addKeyProofString, generateKey, sign, signPairing, signRequest, signUnpairing } from '@agnt-protocol/protocol';
import { Federation, toRequest, type TestAgent } from './harness.ts';

const DAY = 86_400_000;

describe("the agent's address and keys (CLIENT.md)", async () => {
  const fed = new Federation();
  after(() => fed.close());
  const alpha = await fed.server('alpha');
  fed.dns.point('mail.example', alpha.origin);
  const now = () => new Date(fed.clock.t).toISOString();

  const account = (a: TestAgent, key = a.key) => a.request('GET', '/simon/account', { key });
  const post = (a: TestAgent, path: string, body: object, key = a.key) =>
    a.request('POST', path, { body: JSON.stringify(body), key });
  /** Add a fresh key to `a`, with its proof; the new key's pair. */
  async function addKey(a: TestAgent, label?: string, signer = a.key) {
    const next = generateKey();
    const proof = sign(next.privateKey, addKeyProofString(a.address, next.key));
    const res = await post(
      a,
      '/simon/keys',
      { key: next.key, proof, ...(label === undefined ? {} : { label }) },
      signer,
    );
    return { ...next, res };
  }
  const revoke = (a: TestAgent, token: string, key = a.key) => a.request('DELETE', `/simon/keys/${token}`, { key });

  /** An agent at `<local>@mail.example`, bound by the code sent there. */
  async function mailboxAgent(local: string) {
    const a = alpha.newAgent();
    await a.register({ address: `${local}@mail.example` });
    await a.register({ address: `${local}@mail.example`, code: alpha.code(`${local}@mail.example`) });
    return a;
  }
  /** A recovery of `address` started by whoever reads its mail: their key, their code and the cancel code. */
  async function startRecovery(address: string) {
    const thief = alpha.newAgent();
    await thief.recover({ address });
    const code = alpha.code(address);
    assert.equal((await thief.recover({ address, code })).json.status, 'recovery_pending');
    return { thief, code, cancelCode: alpha.cancelCode(address) };
  }
  const cancelByCode = (address: string, cancelCode: string) =>
    post(alpha.newAgent(), '/simon/recovery/cancel', { address, cancelCode });

  describe('the account', () => {
    it("answers the agent's address, keys, grants and pending recovery", async () => {
      const a = await alpha.agent('acct');
      const res = await account(a);
      assert.deepEqual(
        [res.status, res.json],
        [
          200,
          {
            address: 'acct@alpha.test',
            keys: [{ key: a.token, added: now(), revoked: null }],
            grants: [],
            recovery: null,
          },
        ],
      );
    });

    it('is signed by a key the agent holds', async () => {
      const a = await alpha.agent('acct2');
      const res = await account(a, generateKey().privateKey);
      assert.deepEqual([res.status, res.json.code], [401, 'unknown_key']);
    });
  });

  it('denies a retired identity even when a stored revocation is slightly in the future', async () => {
    const isolated = new Federation();
    let retired = false;
    try {
      const host = await isolated.server('retired-skew', {
        wrapStore: store =>
          new Proxy(store, {
            get(target, property) {
              if (property === 'agentByAddress')
                return async (address: string) => {
                  const agent = await target.agentByAddress(address);
                  return agent && retired
                    ? {
                        ...agent,
                        retiredAt: isolated.clock.now().toISOString(),
                        keys: agent.keys.map(k => ({
                          ...k,
                          revoked: new Date(isolated.clock.t + 60_000).toISOString(),
                        })),
                      }
                    : agent;
                };
              const value = Reflect.get(target, property);
              return typeof value === 'function' ? value.bind(target) : value;
            },
          }),
      });
      const agent = await host.agent('skew');
      retired = true;
      for (const [method, path] of [
        ['GET', '/simon/account'],
        ['GET', '/simon/sync'],
        ['POST', '/simon/send'],
      ] as const) {
        const response = await agent.request(method, path);
        assert.deepEqual([response.status, response.json.code], [401, 'unknown_key']);
      }
    } finally {
      await isolated.close();
    }
  });

  for (const denial of ['retired', 'excluded'] as const) {
    it(`keeps a ${denial} expired key rejected if the clock would roll back on another read`, async () => {
      const isolated = new Federation();
      let armed = false;
      let lookedUp = false;
      let verificationReads = 0;
      isolated.clock.now = () => new Date(isolated.clock.t - (lookedUp && verificationReads++ > 0 ? 60_000 : 0));
      try {
        const host = await isolated.server('clock-denial', {
          wrapStore: store =>
            new Proxy(store, {
              get(target, property) {
                if (property === 'agentByAddress')
                  return async (address: string) => {
                    const agent = await target.agentByAddress(address);
                    if (!armed || !agent) return agent;
                    lookedUp = true;
                    return {
                      ...agent,
                      ...(denial === 'retired'
                        ? { retiredAt: new Date(isolated.clock.t).toISOString() }
                        : { authorizedKeys: [] }),
                      keys: agent.keys.map(k => ({ ...k, revoked: new Date(isolated.clock.t - 1_000).toISOString() })),
                    };
                  };
                const value = Reflect.get(target, property);
                return typeof value === 'function' ? value.bind(target) : value;
              },
            }),
        });
        const agent = await host.agent('owner');
        isolated.clock.advance(120_000);
        const url = new URL(`${host.origin}/simon/account`);
        const headers = signRequest(agent.key, {
          method: 'GET',
          url: url.href,
          now: isolated.clock.t,
          agent: agent.address,
        });
        armed = true;
        const req = toRequest('GET', url, headers, Buffer.alloc(0), '192.0.2.50');
        await assert.rejects(host.server.api.authenticate(req), {
          status: 401,
          code: 'key_revoked',
        });
        assert.equal(verificationReads, 1, 'diagnostic selection and protocol validation use the same time');
      } finally {
        await isolated.close();
      }
    });
  }

  describe('adding a key', () => {
    it("adds a device's key with its proof and label, a label the document never shows", async () => {
      const a = await alpha.agent('dev');
      const phone = await addKey(a, "Ada's phone");
      assert.equal(phone.res.status, 200);
      assert.deepEqual(phone.res.json.keys, [
        { key: a.token, added: now(), revoked: null },
        { key: phone.key, added: now(), revoked: null, label: "Ada's phone" },
      ]);
      assert.deepEqual((await account(a, phone.privateKey)).json, phone.res.json, 'the new key acts for the agent');
      const proof = sign(phone.privateKey, addKeyProofString(a.address, phone.key));
      assert.deepEqual((await post(a, '/simon/keys', { key: phone.key, proof })).json, phone.res.json, 'a repeat');
      const doc = await a.request('GET', '/simon/agents/dev@alpha.test', { sign: false });
      assert.equal(JSON.stringify(doc.json).includes('phone'), false);
      assert.equal(doc.json.keys.length, 2);
    });

    it('refuses a missing or failing proof, and a label that is too long or not a string', async () => {
      const a = await alpha.agent('devbad');
      const stranger = generateKey();
      for (const proof of [undefined, sign(stranger.privateKey, 'something else')]) {
        const res = await post(a, '/simon/keys', { key: stranger.key, proof });
        assert.deepEqual([res.status, res.json.code], [401, 'bad_proof']);
      }
      assert.equal((await addKey(a, 'x'.repeat(64))).res.status, 200);
      assert.equal((await addKey(a, 'é'.repeat(64))).res.status, 200, 'characters, not bytes');
      assert.deepEqual((await addKey(a, 'x'.repeat(65))).res.json.details, { field: 'label' });
      const proof = sign(stranger.privateKey, addKeyProofString(a.address, stranger.key));
      assert.deepEqual((await post(a, '/simon/keys', { key: stranger.key, proof, label: 7 })).json.details, {
        field: 'label',
      });
    });

    it('refuses a full agent, a key another agent holds, and a key this agent held before', async () => {
      const a = await alpha.agent('full');
      for (let i = 1; i < 8; i++) assert.equal((await addKey(a)).res.status, 200);
      assert.deepEqual([(await addKey(a)).res.status, (await addKey(a)).res.json.code], [400, 'too_many_keys']);

      const other = await alpha.agent('other');
      const taken = await post(other, '/simon/keys', {
        key: a.token,
        proof: sign(a.key, addKeyProofString(other.address, a.token)),
      });
      assert.deepEqual([taken.status, taken.json.code], [409, 'key_in_use'], 'a key serves one address here');

      const b = await alpha.agent('again');
      const old = await addKey(b);
      await revoke(b, old.key);
      const back = await post(b, '/simon/keys', {
        key: old.key,
        proof: sign(old.privateKey, addKeyProofString(b.address, old.key)),
      });
      assert.deepEqual([back.status, back.json.code], [409, 'key_in_use'], 'a revoked key never returns');
    });
  });

  describe('revoking a key', () => {
    it('revokes a key at the time of the call: itself, or one added after the key that signs', async () => {
      const a = await alpha.agent('rev');
      const laptop = await addKey(a);
      fed.clock.advance(1000);
      const phone = await addKey(a);
      fed.clock.advance(1000);
      const res = await revoke(a, phone.key);
      assert.equal(res.status, 200);
      assert.deepEqual(
        res.json.keys.map((k: { key: string; revoked: string | null }) => [k.key, k.revoked]),
        [
          [a.token, null],
          [laptop.key, null],
          [phone.key, now()],
        ],
      );
      const self = await revoke(a, laptop.key, laptop.privateKey);
      assert.equal(self.json.keys[1].revoked, now(), 'a key may revoke itself');
      assert.equal((await account(a, laptop.privateKey)).json.code, 'key_revoked');
    });

    it('never lets a key revoke one added before it, nor the last active key', async () => {
      const a = await alpha.agent('senior');
      const phone = await addKey(a);
      const res = await revoke(a, a.token, phone.privateKey);
      assert.deepEqual([res.status, res.json.code], [409, 'key_senior']);
      await revoke(a, phone.key);
      const last = await revoke(a, a.token);
      assert.deepEqual([last.status, last.json.code], [409, 'last_key']);
    });

    it('is not_found for a key the agent does not hold, or no longer does', async () => {
      const a = await alpha.agent('revgone');
      const phone = await addKey(a);
      await revoke(a, phone.key);
      assert.equal((await revoke(a, phone.key)).status, 404, 'a repeat');
      assert.equal((await revoke(a, generateKey().key)).status, 404);
      const other = await alpha.agent('revother');
      assert.equal((await revoke(a, other.token)).status, 404);
    });
  });

  describe('grants', () => {
    it('are none on this server, so ending one is not_found', async () => {
      const a = await alpha.agent('grants');
      const res = await a.request('DELETE', '/simon/grants/g1');
      assert.deepEqual([res.status, res.json.code], [404, 'not_found']);
      const stranger = await a.request('DELETE', '/simon/grants/g1', { key: generateKey().privateKey });
      assert.deepEqual([stranger.status, stranger.json.code], [401, 'unknown_key']);
    });
  });

  describe('cancelling a recovery', () => {
    it('lets a key the agent held when it started cancel it, and tells the address', async () => {
      const old = await mailboxAgent('keep');
      const { thief, code } = await startRecovery('keep@mail.example');
      const res = await post(old, '/simon/recovery/cancel', {});
      assert.deepEqual([res.status, res.json], [200, { status: 'cancelled', address: 'keep@mail.example' }]);
      assert.deepEqual(alpha.mail.at(-1), { address: 'keep@mail.example', type: 'recoveryCancelled' });
      assert.equal((await account(old)).json.recovery, null);
      fed.clock.advance(73 * 3600_000);
      assert.equal((await thief.recover({ address: 'keep@mail.example', code })).json.code, 'code_expired');
      assert.equal((await post(old, '/simon/recovery/cancel', {})).status, 404, 'nothing pending');
    });

    it('never lets a key added while it is pending cancel it', async () => {
      const old = await mailboxAgent('late');
      await startRecovery('late@mail.example');
      fed.clock.advance(1000);
      const mallory = await addKey(old);
      assert.deepEqual((await account(old, mallory.privateKey)).json.recovery.cancellable, false);
      const res = await post(old, '/simon/recovery/cancel', {}, mallory.privateKey);
      assert.deepEqual([res.status, res.json.code], [409, 'recovery_not_cancellable']);
      assert.equal((await account(old)).json.recovery.cancellable, true);
    });

    it('lets a key cancel once in 30 days; the cancel code still stops the next recovery', async () => {
      // Mallory holds a stolen key and Ada's mailbox is back with Ada: a key cancels Ada's recovery once,
      // and Ada's next recovery is cancellable only by the code sent to Ada.
      const ada = await mailboxAgent('ada');
      const first = await startRecovery('ada@mail.example');
      assert.equal((await post(ada, '/simon/recovery/cancel', {})).status, 200);

      fed.clock.advance(10 * DAY);
      const second = await startRecovery('ada@mail.example');
      assert.equal((await account(ada)).json.recovery.cancellable, false);
      const notice = (await ada.received()).at(-1);
      assert.match(notice.message.parts[0].data, /no key can/);
      const byKey = await post(ada, '/simon/recovery/cancel', {});
      assert.deepEqual([byKey.status, byKey.json.code], [409, 'recovery_not_cancellable']);
      assert.equal((await cancelByCode('ada@mail.example', first.cancelCode)).status, 422, 'a spent cancel code');
      const byCode = await cancelByCode('ada@mail.example', second.cancelCode);
      assert.deepEqual([byCode.status, byCode.json], [200, { status: 'cancelled', address: 'ada@mail.example' }]);

      fed.clock.advance(20 * DAY);
      await startRecovery('ada@mail.example');
      assert.equal((await account(ada)).json.recovery.cancellable, true, 'thirty days on, a key may again');
    });

    it('takes a cancel code signed by any key, never locks it, and refuses everything else alike', async () => {
      await mailboxAgent('coded');
      const { cancelCode } = await startRecovery('coded@mail.example');
      await mailboxAgent('quiet');
      const refusals = [];
      for (let i = 0; i < 10; i++) refusals.push(await cancelByCode('coded@mail.example', `${i}`.repeat(22)));
      refusals.push(await cancelByCode('quiet@mail.example', cancelCode)); // nothing pending there
      refusals.push(await cancelByCode('nobody@mail.example', cancelCode)); // no agent there
      assert.equal((await cancelByCode('coded@mail.example', cancelCode)).status, 200, 'never locked');
      refusals.push(await cancelByCode('coded@mail.example', cancelCode)); // a recovery that ended
      for (const res of refusals) assert.deepEqual([res.status, res.json.code], [422, 'wrong_code']);
      assert.equal(new Set(refusals.map(res => res.bytes.toString())).size, 1, 'the same bytes');
    });

    it('checks the signature of a cancel by code, and the address it names', async () => {
      const { cancelCode } = await startRecovery((await mailboxAgent('sig')).address);
      const a = alpha.newAgent();
      const body = JSON.stringify({ address: 'sig@mail.example', cancelCode });
      const forged = await a.request('POST', '/simon/recovery/cancel', {
        body,
        headers: { 'simon-key': generateKey().key },
      });
      assert.deepEqual([forged.status, forged.json.code], [401, 'bad_signature']);
      const elsewhere = await a.request('POST', '/simon/recovery/cancel', { body, agent: 'other@mail.example' });
      assert.deepEqual([elsewhere.status, elsewhere.json.code], [401, 'signature_required']);
      assert.equal(
        (await a.request('POST', '/simon/recovery/cancel', { body, agent: 'sig@mail.example' })).status,
        200,
      );
    });

    it('needs a key the agent holds to cancel by key', async () => {
      const old = await mailboxAgent('nokey');
      await startRecovery('nokey@mail.example');
      const res = await post(old, '/simon/recovery/cancel', {}, generateKey().privateKey);
      assert.deepEqual([res.status, res.json.code], [401, 'unknown_key']);
    });
  });

  describe('unpairing', () => {
    const principal = generateKey();
    const forValue = `simon-key:${principal.key}`;
    async function paired(local: string) {
      const a = alpha.newAgent();
      const address = `${local}@alpha.test`;
      await a.register({ address, for: forValue, pairing: signPairing(principal.privateKey, address, forValue) });
      return a;
    }

    it("retires the address at once by the principal's unpairing, signed by any key", async () => {
      const a = await paired('up');
      const unpairing = signUnpairing(principal.privateKey, a.address, forValue);
      const res = await post(alpha.newAgent(), '/simon/unpair', { address: a.address, unpairing });
      assert.deepEqual([res.status, res.json], [200, { status: 'retired', address: 'up@alpha.test' }]);
      const doc = await a.request('GET', '/simon/agents/up@alpha.test', { sign: false });
      if (doc.status === 404) assert.equal(doc.json.code, 'not_found');
      else {
        assert.equal(doc.status, 200);
        assert.equal(doc.json.unpairing, unpairing);
        assert.ok(Number.isFinite(Date.parse(doc.json.retired)));
        assert.ok(
          doc.json.keys.every(
            (k: { revoked: string | null }) =>
              k.revoked !== null && Date.parse(k.revoked) <= Date.parse(doc.json.retired),
          ),
        );
      }
      assert.equal((await account(a)).json.code, 'key_revoked');
      const again = await post(alpha.newAgent(), '/simon/unpair', { address: a.address, unpairing });
      assert.deepEqual([again.status, again.json], [200, res.json], 'a repeat');
    });

    it('refuses an unpairing that does not verify, or names no paired agent, with one answer', async () => {
      const a = await paired('upbad');
      const solo = await alpha.agent('upsolo');
      const answers = [
        await post(alpha.newAgent(), '/simon/unpair', {
          address: a.address,
          unpairing: signUnpairing(generateKey().privateKey, a.address, forValue),
        }),
        await post(alpha.newAgent(), '/simon/unpair', {
          address: solo.address,
          unpairing: signUnpairing(principal.privateKey, solo.address, forValue),
        }),
        await post(alpha.newAgent(), '/simon/unpair', { address: 'nobody@alpha.test', unpairing: 'AAAA' }),
      ];
      for (const res of answers) assert.deepEqual([res.status, res.json.code], [401, 'bad_proof']);
      assert.equal(new Set(answers.map(res => res.json.detail)).size, 1);
      assert.equal((await account(a)).status, 200);
      assert.equal((await post(a, '/simon/unpair', { address: 7 })).json.details.field, 'address');
    });
  });
});
