/**
 * CLIENT.md `register`: leasing, hosted names, the code exchange, recovery by the mailbox and by a key
 * principal, pairing with a key principal, and the limits on codes.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import {
  addKeyProofString,
  generateKey,
  pairingBytes,
  readAgentDocument,
  readServerDocument,
  sign,
  signPairing,
  signRecovery,
  signRequest,
  signUnpairing,
  verifyUnpairing,
} from '@agnt-sdk/simon-protocol';
import { replyBody } from '../src/testing.ts';
import { Federation, toRequest, type TestAgent } from './harness.ts';

describe('register (CLIENT.md)', async () => {
  const fed = new Federation();
  after(() => fed.close());
  const alpha = await fed.server('alpha');
  const beta = await fed.server('beta');
  // mail.example names alpha, so alpha binds its addresses by a code sent there.
  fed.dns.point('mail.example', alpha.origin);

  describe('with a key alone', () => {
    it('leases an address on the lease domain, the same one on every repeat', async () => {
      const a = alpha.newAgent();
      const first = await a.register();
      assert.equal(first.status, 200);
      assert.match(first.json.address, /^[a-z2-7]{16}@lease\.alpha\.test$/);
      assert.deepEqual(first.json, {
        address: first.json.address,
        keys: [{ key: a.token, added: new Date(fed.clock.t).toISOString(), revoked: null }],
        grants: [],
        recovery: null,
      });
      assert.deepEqual((await a.register()).json, first.json);
      const unnamed = alpha.newAgent();
      const repeat = await unnamed.request('POST', '/simon/register', {
        key: a.key,
        body: JSON.stringify({ key: a.token }),
      });
      assert.deepEqual([repeat.status, repeat.json], [200, first.json], 'the same proof may omit simon-agent');
    });

    it('is address_required on a server that leases none', async () => {
      const gamma = await fed.server('gamma', { config: { leaseDomain: null } });
      const res = await gamma.newAgent().register();
      assert.equal(res.status, 400);
      assert.equal(res.json.code, 'address_required');
    });

    it('keeps names on the lease domain for their keys', async () => {
      const res = await alpha.newAgent().register({ address: 'chosen@lease.alpha.test' });
      assert.equal(res.json.code, 'address_taken');
    });
  });

  describe('with an address on a hosted domain', () => {
    it('gives the name at once, and refuses it to anyone else', async () => {
      const a = alpha.newAgent();
      assert.equal((await a.register({ address: 'Ada@Alpha.test' })).json.address, 'ada@alpha.test');
      const taken = await alpha.newAgent().register({ address: 'ada@alpha.test' });
      assert.equal(taken.status, 409);
      assert.equal(taken.json.code, 'address_taken');
    });

    it("keeps RFC 2142's role names for the server", async () => {
      assert.equal((await alpha.newAgent().register({ address: 'postmaster@alpha.test' })).json.code, 'address_taken');
    });

    it('answers a repeat with the same agent, and a key already registered elsewhere with key_in_use', async () => {
      const a = await alpha.agent('rep');
      assert.equal((await a.register({ address: 'rep@alpha.test' })).status, 200);
      assert.equal((await a.register({ address: 'other@alpha.test' })).json.code, 'key_in_use');
    });
  });

  describe('with an address whose domain resolves here: the code exchange', () => {
    it('sends a code, and binds the key when the code comes back', async () => {
      const a = alpha.newAgent();
      const sent = await a.register({ address: 'ann@mail.example' });
      assert.equal(sent.status, 202);
      assert.deepEqual(sent.json, { status: 'code_sent', address: 'ann@mail.example' });
      const wrong = await a.register({ address: 'ann@mail.example', code: 'not-the-code' });
      assert.equal(wrong.status, 422);
      assert.equal(wrong.json.code, 'wrong_code');
      const bound = await a.register({ address: 'ann@mail.example', code: alpha.code('ann@mail.example') });
      assert.equal(bound.status, 200);
      assert.equal(bound.json.address, 'ann@mail.example');
      assert.equal((await a.register({ address: 'ann@mail.example' })).status, 200, 'a repeat');
    });

    it('answers a code request before the code is sent, so its timing tells nothing', async () => {
      let sent!: () => void;
      const delta = await fed.server('delta', { sendDelay: new Promise<void>(r => (sent = r)) });
      fed.dns.point('slowmail.example', delta.origin);
      const res = await delta.newAgent().register({ address: 'ann@slowmail.example' });
      assert.deepEqual([res.status, res.json.status], [202, 'code_sent'], 'answered while the mail is underway');
      assert.equal(delta.codes.get('ann@slowmail.example'), undefined);
      sent();
      await delta.server.work();
      assert.ok(delta.codes.get('ann@slowmail.example'), 'sent after the answer');
    });

    it('locks a code after five wrong tries, and lets it expire', async () => {
      const a = alpha.newAgent();
      await a.register({ address: 'lock@mail.example' });
      for (let i = 0; i < 5; i++) await a.register({ address: 'lock@mail.example', code: 'nope' });
      const locked = await a.register({ address: 'lock@mail.example', code: alpha.code('lock@mail.example') });
      assert.equal(locked.status, 410);
      assert.equal(locked.json.code, 'code_locked');

      const b = alpha.newAgent();
      await b.register({ address: 'late@mail.example' });
      fed.clock.advance(16 * 60_000);
      const expired = await b.register({ address: 'late@mail.example', code: alpha.code('late@mail.example') });
      assert.equal(expired.json.code, 'code_expired');
    });

    it('counts simultaneous wrong guesses atomically and refuses a correct code after the fifth', async () => {
      const a = alpha.newAgent();
      const address = 'concurrent-code@mail.example';
      assert.equal((await a.register({ address })).status, 202);
      const guesses = await Promise.all(Array.from({ length: 8 }, () => a.register({ address, code: 'nope' })));
      assert.equal(guesses.filter(r => r.status === 422 && r.json.code === 'wrong_code').length, 5);
      assert.equal(guesses.filter(r => r.status === 410 && r.json.code === 'code_locked').length, 3);
      const correct = await a.register({ address, code: alpha.code(address) });
      assert.deepEqual([correct.status, correct.json.code], [410, 'code_locked']);
    });

    it('recovers an address after a wait the agent is told of: the new key then replaces every old one', async () => {
      const old = alpha.newAgent();
      await old.register({ address: 'rec@mail.example' });
      await old.register({ address: 'rec@mail.example', code: alpha.code('rec@mail.example') });
      const fresh = alpha.newAgent();
      assert.equal((await fresh.recover({ address: 'rec@mail.example' })).json.status, 'code_sent');
      const code = alpha.code('rec@mail.example');
      const pending = await fresh.recover({ address: 'rec@mail.example', code });
      const completesAt = new Date(fed.clock.t + 72 * 3600_000).toISOString();
      assert.deepEqual(
        [pending.status, pending.json],
        [202, { status: 'recovery_pending', address: 'rec@mail.example', completesAt }],
      );

      const [notice] = await old.received();
      assert.equal(notice.message.from, 'postmaster@mail.example', 'told by the server itself');
      assert.equal(notice.carrier, alpha.origin);
      assert.match(notice.message.parts[0].data, /POST \/simon\/recovery\/cancel/);
      const news = alpha.mail.at(-1)!;
      assert.deepEqual(
        { ...news, cancelCode: null },
        { address: 'rec@mail.example', type: 'recovery', key: fresh.token, completesAt, cancelCode: null },
        'the address is told too, with a code that cancels it',
      );
      assert.match(alpha.cancelCode('rec@mail.example'), /^[A-Za-z0-9_-]{22}$/, '128 random bits');
      const account = await old.request('GET', '/simon/account');
      assert.deepEqual(account.json.recovery, { completesAt, cancellable: true });
      assert.equal((await fresh.recover({ address: 'rec@mail.example', code: '00000000' })).json.code, 'wrong_code');

      fed.clock.advance(71 * 3600_000);
      assert.equal((await fresh.recover({ address: 'rec@mail.example', code })).json.status, 'recovery_pending');
      fed.clock.advance(3600_000);
      const done = await fresh.recover({ address: 'rec@mail.example', code });
      assert.equal(done.status, 200);
      assert.deepEqual(
        done.json.keys.map((k: { key: string; revoked: string | null }) => [k.key, k.revoked !== null]),
        [
          [old.token, true],
          [fresh.token, false],
        ],
      );
      assert.equal((await old.sync()).json.code, 'key_revoked');
      assert.equal(done.json.recovery, null);
    });

    it('holds one recovery of an address at a time, and answers a code asked for meanwhile as any other', async () => {
      const address = 'one@mail.example';
      const old = alpha.newAgent();
      await old.register({ address });
      await old.register({ address, code: alpha.code(address) });
      const early = alpha.newAgent();
      await early.recover({ address });
      const earlyCode = alpha.code(address);
      const first = alpha.newAgent();
      await first.recover({ address });
      const code = alpha.code(address);
      const { completesAt } = (await first.recover({ address, code })).json;

      const sent = alpha.mail.length;
      const again = await alpha.newAgent().recover({ address });
      assert.deepEqual([again.status, again.json], [202, { status: 'code_sent', address }]);
      const originalCancelCode = alpha.cancelCode(address);
      assert.equal(alpha.mail.length, sent, 'a pending recovery sends neither another code nor a reminder');
      assert.equal(typeof completesAt, 'string');
      const repeat = await first.recover({ address });
      assert.deepEqual([repeat.status, repeat.json.status], [202, 'code_sent'], 'its own key too');
      assert.equal(alpha.mail.length, sent, 'a repeat from the waiting key sends nothing too');
      assert.equal(alpha.cancelCode(address), originalCancelCode, 'the original cancellation secret remains valid');
      const stacked = await early.recover({ address, code: earlyCode });
      assert.deepEqual([stacked.status, stacked.json.code], [422, 'wrong_code'], 'a code sent before it binds no key');
      assert.equal((await first.recover({ address, code })).json.status, 'recovery_pending');

      const cancelCode = originalCancelCode;
      const cancel = await alpha.newAgent().request('POST', '/simon/recovery/cancel', {
        body: JSON.stringify({ address, cancelCode }),
        agent: address,
      });
      assert.deepEqual([cancel.status, cancel.json.status], [200, 'cancelled'], 'that code cancels the recovery');
      const stale = await early.recover({ address, code: earlyCode });
      assert.deepEqual([stale.status, stale.json.code], [422, 'wrong_code'], 'cancellation cannot revive an old code');
      assert.equal(await alpha.store.value('recovery', address, new Date(fed.clock.t).toISOString()), null);
    });

    it('keeps an earlier code invalid after completion within its original TTL and clock rollback', async () => {
      const world = new Federation();
      try {
        const home = await world.server('quick', { config: { recoveryWaitSeconds: 1 } });
        world.dns.point('quick-mail.example', home.origin);
        const address = 'owner@quick-mail.example';
        const old = home.newAgent();
        await old.register({ address });
        assert.equal((await old.register({ address, code: home.code(address) })).status, 200);
        const early = home.newAgent();
        await early.recover({ address });
        const earlyCode = home.code(address);
        const first = home.newAgent();
        await first.recover({ address });
        const code = home.code(address);
        assert.equal((await first.recover({ address, code })).json.status, 'recovery_pending');
        world.clock.advance(1000);
        assert.equal((await first.recover({ address, code })).status, 200);
        const after = await early.recover({ address, code: earlyCode });
        assert.deepEqual([after.status, after.json.code], [422, 'wrong_code']);
        world.clock.advance(-1000);
        const rolledBack = await early.recover({ address, code: earlyCode });
        assert.deepEqual([rolledBack.status, rolledBack.json.code], [422, 'wrong_code']);
        assert.equal(await home.store.value('recovery', address, new Date(world.clock.t).toISOString()), null);
        assert.equal((await home.store.agentByAddress(address))!.keys.at(-1)!.key, first.token);
      } finally {
        await world.close();
      }
    });

    for (const boundary of ['issue', 'submit'] as const)
      it(`rejects a challenge across an account authority change at ${boundary}`, async () => {
        const world = new Federation();
        try {
          const home = await world.server('authority');
          world.dns.point('authority-mail.example', home.origin);
          const address = 'owner@authority-mail.example';
          const old = home.newAgent();
          await old.register({ address });
          await old.register({ address, code: home.code(address) });
          const fresh = home.newAgent();
          if (boundary === 'submit') await fresh.recover({ address });
          const lookup = home.store.agentByAddress.bind(home.store);
          let changed = false;
          home.store.agentByAddress = async asked => {
            const snapshot = await lookup(asked);
            if (asked === address && !changed) {
              changed = true;
              await home.store.keepOnlyKey(address, old.token, new Date(world.clock.t).toISOString());
            }
            return snapshot;
          };
          if (boundary === 'issue') await fresh.recover({ address });
          const answer = await fresh.recover({ address, code: home.code(address) });
          assert.equal(changed, true);
          assert.deepEqual([answer.status, answer.json.code], [422, 'wrong_code']);
          assert.equal(await home.store.value('recovery', address, new Date(world.clock.t).toISOString()), null);
          assert.equal((await lookup(address))!.keys.at(-1)!.key, old.token);
        } finally {
          await world.close();
        }
      });

    it('refuses missing, null and malformed challenge authority for an existing account', async () => {
      for (const binding of [undefined, null, '0', -1, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
        const world = new Federation();
        try {
          const home = await world.server('binding');
          world.dns.point('binding-mail.example', home.origin);
          const address = 'owner@binding-mail.example';
          const old = home.newAgent();
          await old.register({ address });
          await old.register({ address, code: home.code(address) });
          const fresh = home.newAgent();
          await fresh.recover({ address });
          const id = ['recovery', address, fresh.token].join('\n');
          const pending = await home.store.value<Record<string, unknown>>(
            'code',
            id,
            new Date(world.clock.t).toISOString(),
          );
          assert.ok(pending);
          await home.store.setValue('code', id, { ...pending, recoveryEpoch: binding }, null);
          const answer = await fresh.recover({ address, code: home.code(address) });
          assert.deepEqual([answer.status, answer.json.code], [422, 'wrong_code']);
          assert.equal(await home.store.value('recovery', address, new Date(world.clock.t).toISOString()), null);
        } finally {
          await world.close();
        }
      }
    });

    it('keeps a code good while a key holder adds and revokes keys meanwhile', async () => {
      const address = 'churn@mail.example';
      const old = alpha.newAgent();
      await old.register({ address });
      await old.register({ address, code: alpha.code(address) });
      const owner = alpha.newAgent();
      await owner.recover({ address });
      const code = alpha.code(address);
      // A thief holding the old key churns throwaway keys while the owner reads the email.
      for (let i = 0; i < 3; i++) {
        const spare = generateKey();
        const proof = sign(spare.privateKey, addKeyProofString(address, spare.key));
        const added = await old.request('POST', '/simon/keys', { body: JSON.stringify({ key: spare.key, proof }) });
        assert.equal(added.status, 200);
        assert.equal((await old.request('DELETE', `/simon/keys/${spare.key}`)).status, 200);
      }
      const answer = await owner.recover({ address, code });
      assert.deepEqual([answer.status, answer.json.status], [202, 'recovery_pending']);
    });

    for (const path of ['register', 'recovery'] as const)
      it(`counts concurrent guesses before comparing, so the right code is locked out too (${path})`, async () => {
        const address = `flood-${path}@mail.example`;
        const guesser = alpha.newAgent();
        if (path === 'recovery') {
          const old = alpha.newAgent();
          await old.register({ address });
          await old.register({ address, code: alpha.code(address) });
        }
        const call = (body: { address: string; code?: string }) =>
          path === 'register' ? guesser.register(body) : guesser.recover(body);
        await call({ address });
        const code = alpha.code(address);
        const wrong = code === '00000000' ? '00000001' : '00000000';
        const answers = await Promise.all([
          ...Array.from({ length: 64 }, () => call({ address, code: wrong })),
          call({ address, code }),
        ]);
        const right = answers.at(-1)!;
        assert.deepEqual([right.status, right.json.code], [410, 'code_locked']);
        assert.equal(answers.filter(a => a.json?.code === 'wrong_code').length, 5);
        assert.equal(await alpha.store.value('recovery', address, new Date(fed.clock.t).toISOString()), null);
        if (path === 'register') assert.equal(await alpha.store.agentByAddress(address), null);
      });

    it('answers a code handed back during a recovery as it would any other', async () => {
      const address = 'same@mail.example';
      const old = alpha.newAgent();
      await old.register({ address });
      await old.register({ address, code: alpha.code(address) });
      const thief = alpha.newAgent();
      await thief.recover({ address });
      await thief.recover({ address, code: alpha.code(address) });
      const stranger = alpha.newAgent();
      const none = await stranger.recover({ address, code: '12345678' });
      assert.deepEqual([none.status, none.json.code], [410, 'code_expired'], 'no code asked for');
      await stranger.recover({ address });
      const tries = [];
      for (let i = 0; i < 6; i++) tries.push((await stranger.recover({ address, code: '12345678' })).json.code);
      assert.deepEqual(tries, ['wrong_code', 'wrong_code', 'wrong_code', 'wrong_code', 'wrong_code', 'code_locked']);
    });

    /** An agent bound at `address` by code, and a second key whose recovery of it now waits. */
    async function waiting(address: string) {
      const old = alpha.newAgent();
      await old.register({ address });
      await old.register({ address, code: alpha.codes.get(address)! });
      const thief = alpha.newAgent();
      await thief.recover({ address });
      const code = alpha.codes.get(address)!;
      const pending = await thief.recover({ address, code });
      assert.equal(pending.json.status, 'recovery_pending');
      return { old, thief, code, completesAt: pending.json.completesAt as string };
    }
    const status = (a: TestAgent) => a.request('GET', '/simon/recovery');
    const cancel = (a: TestAgent) => a.request('POST', '/simon/recovery/cancel', { body: '{}' });

    it('lets a key held before a recovery cancel it once in 30 days, and reads its state', async () => {
      const address = 'keep@mail.example';
      const { old, thief, code, completesAt } = await waiting(address);
      assert.ok(alpha.cancelCodes.get(address), 'a cancel code went to the address with the news');
      assert.deepEqual((await status(old)).json.recovery, { completesAt, cancellable: true });
      // A key added while the recovery waits may not cancel it.
      fed.clock.advance(1000);
      const added = generateKey();
      await old.request('POST', '/simon/keys', {
        body: JSON.stringify({ key: added.key, proof: sign(added.privateKey, addKeyProofString(address, added.key)) }),
      });
      const late = (cancel: boolean) =>
        old.request(cancel ? 'POST' : 'GET', cancel ? '/simon/recovery/cancel' : '/simon/recovery', {
          ...(cancel ? { body: '{}' } : {}),
          key: added.privateKey,
        });
      assert.deepEqual((await late(false)).json.recovery, { completesAt, cancellable: false });
      const notYours = await late(true);
      assert.deepEqual([notYours.status, notYours.json.code], [409, 'recovery_not_cancellable']);

      const cancelled = await cancel(old);
      assert.deepEqual([cancelled.status, cancelled.json], [200, { status: 'cancelled', address }]);
      const again = await cancel(old);
      assert.deepEqual([again.status, again.json.code], [404, 'not_found'], 'a repeat finds none waiting');
      assert.equal((await status(old)).json.recovery, null);
      fed.clock.advance(73 * 3600_000);
      assert.equal((await thief.recover({ address, code })).json.code, 'code_expired');
      assert.equal((await old.sync()).status, 200, 'the old key still holds the agent');
      const stranger = alpha.newAgent();
      assert.equal((await cancel(stranger)).json.code, 'signature_required', 'membership calls require an actor');
      assert.equal((await status(stranger)).json.code, 'signature_required');
      const refused = await stranger.request('POST', '/simon/recovery/cancel', { body: '{}', agent: address });
      assert.deepEqual([refused.status, refused.json.code], [401, 'unknown_key']);
      assert.equal(refused.headers['www-authenticate'], 'SIMON');
      assert.equal((await stranger.request('GET', '/simon/recovery', { agent: address })).json.code, 'unknown_key');

      // Within 30 days of that cancel, a key cannot cancel again; the cancel code sent with the news can.
      const second = alpha.newAgent();
      await second.recover({ address });
      assert.equal(
        (await second.recover({ address, code: alpha.codes.get(address)! })).json.status,
        'recovery_pending',
      );
      assert.deepEqual((await status(old)).json.recovery.cancellable, false);
      assert.equal((await cancel(old)).json.code, 'recovery_not_cancellable');
      const wrong = await alpha.newAgent().cancelRecovery({ address, cancelCode: 'x'.repeat(22) });
      assert.deepEqual([wrong.status, wrong.json.code], [422, 'wrong_code']);
      const cancelCode = alpha.cancelCodes.get(address)!;
      assert.match(cancelCode, /^[A-Za-z0-9_-]{22}$/, '128 bits');
      const byCode = await alpha.newAgent().cancelRecovery({ address, cancelCode });
      assert.deepEqual([byCode.status, byCode.json], [200, { status: 'cancelled', address }]);
      const spent = await alpha.newAgent().cancelRecovery({ address, cancelCode });
      assert.deepEqual(spent.json, wrong.json, 'a code for a recovery that ended answers as a wrong one');
      const none = await alpha.newAgent().cancelRecovery({ address: 'nobody@mail.example', cancelCode });
      assert.deepEqual(none.json, wrong.json, 'and so does an address with none waiting');

      // Thirty days on, a key may cancel again.
      fed.clock.advance(31 * 86_400_000);
      const third = alpha.newAgent();
      await third.recover({ address });
      await third.recover({ address, code: alpha.codes.get(address)! });
      assert.equal((await cancel(old)).json.status, 'cancelled');
    });

    it('keeps one recovery waiting when two keys hand back their codes at once', async () => {
      const address = 'race@mail.example';
      const old = alpha.newAgent();
      await old.register({ address });
      await old.register({ address, code: alpha.codes.get(address)! });
      const thieves = [alpha.newAgent(), alpha.newAgent()];
      const codes: string[] = [];
      for (const t of thieves) {
        await t.recover({ address });
        codes.push(alpha.codes.get(address)!);
      }
      const answers = await Promise.all(thieves.map((t, i) => t.recover({ address, code: codes[i] })));
      assert.deepEqual(answers.map(r => r.status).sort(), [202, 422]);
      assert.equal(
        answers.find(r => r.status === 422)?.json.code,
        'wrong_code',
        'the superseded key learns no recovery state',
      );
      assert.equal(alpha.cancelsSent.filter(a => a === address).length, 1, 'one cancel code, for that one');
    });

    it('completes a waiting recovery once while settled repeats return the same account', async () => {
      const events: string[] = [];
      const server = await fed.server('completion', {
        extensions: [{ name: 'completion-events', on: { recovered: event => void events.push(event.address) } }],
      });
      fed.dns.point('mail.completion.example', server.origin);
      const address = 'once@mail.completion.example';
      const old = server.newAgent();
      await old.register({ address });
      await old.register({ address, code: server.code(address) });
      const thief = server.newAgent();
      await thief.recover({ address });
      const code = server.code(address);
      assert.equal((await thief.recover({ address, code })).json.status, 'recovery_pending');
      fed.clock.advance(72 * 3600_000 + 1000);
      const answers = await Promise.all([1, 2, 3].map(() => thief.recover({ address, code })));
      assert.ok(
        answers.some(r => r.status === 200),
        'one caller completes the waiting recovery',
      );
      assert.ok(
        answers.every(r => r.status === 200 || (r.status === 422 && r.json.code === 'wrong_code')),
        'successful repeats return the account; an already-read superseded snapshot reveals no recovery state',
      );
      const active = (await server.store.agentByAddress(address))!.keys.filter(k => k.revoked === null);
      assert.deepEqual(
        active.map(k => k.key),
        [thief.token],
        'the new key is installed once',
      );
      assert.equal((await thief.recover({ address, code })).status, 200, 'a settled repeat returns the same account');
      assert.deepEqual(events, [address], 'a single completed transition emits one recovery event');
    });

    it('completes a legacy recovery without restarting its wait or granting cancellation authority', async () => {
      const address = 'legacy@mail.example';
      const { old, thief, code } = await waiting(address);
      const r = (await alpha.store.value<Record<string, unknown>>(
        'recovery',
        address,
        new Date(fed.clock.t).toISOString(),
      ))!;
      const legacy = { key: r.key, hash: r.hash, completesAt: r.completesAt };
      assert.equal(await alpha.store.cancelRecovery(address, r, new Date(fed.clock.t).toISOString()), true);
      await alpha.store.beginRecovery(address, legacy, '2099-01-01T00:00:00.000Z', new Date(fed.clock.t).toISOString());
      const byCode = await alpha.newAgent().cancelRecovery({ address, cancelCode: alpha.cancelCodes.get(address)! });
      assert.deepEqual([byCode.status, byCode.json.code], [422, 'wrong_code']);
      assert.equal((await status(old)).json.recovery.cancellable, false, 'missing start time grants no key authority');
      assert.equal((await cancel(old)).json.code, 'recovery_not_cancellable');
      fed.clock.advance(72 * 3600_000 + 1000);
      const done = await thief.recover({ address, code });
      assert.equal(done.status, 200, 'the original code completes the original wait');
      assert.equal(done.json.recovery, null);
      assert.equal((await old.sync()).json.code, 'key_revoked');
    });

    it('drops a recovery whose cancel code could not be sent, after telling the agent', async () => {
      const delta = await fed.server('delta', { cancelFails: true });
      fed.dns.point('nomail.example', delta.origin);
      const address = 'x@nomail.example';
      const old = delta.newAgent();
      await old.register({ address });
      await old.register({ address, code: delta.codes.get(address)! });
      const thief = delta.newAgent();
      await thief.recover({ address });
      const res = await thief.recover({ address, code: delta.codes.get(address)! });
      assert.deepEqual([res.status, res.json.code], [503, 'unavailable']);
      assert.equal(await delta.store.value('recovery', address, new Date(fed.clock.t).toISOString()), null);
      const told = (await old.received()).map(
        (m: { message: { parts: { data: string }[] } }) => m.message.parts[0].data,
      );
      assert.equal(told.length, 2, 'the agent was told of the recovery, then that it was dropped');
      assert.match(told[1], /was dropped: the cancel code could not be sent/);
      fed.clock.advance(73 * 3600_000);
      assert.notEqual((await thief.recover({ address, code: delta.codes.get(address)! })).status, 200);
    });

    it("judges the 30 days at the recovery's start: one started on day 29 stays uncancellable by key", async () => {
      const address = 'thirty@mail.example';
      const { old } = await waiting(address);
      assert.equal((await cancel(old)).json.status, 'cancelled', 'day 0');
      fed.clock.advance(29 * 86_400_000);
      const second = alpha.newAgent();
      await second.recover({ address });
      assert.equal(
        (await second.recover({ address, code: alpha.codes.get(address)! })).json.status,
        'recovery_pending',
      );
      fed.clock.advance(1.5 * 86_400_000);
      assert.equal((await status(old)).json.recovery.cancellable, false);
      const res = await cancel(old);
      assert.deepEqual([res.status, res.json.code], [409, 'recovery_not_cancellable'], 'day 30.5');
    });

    it('keeps pending proof and cooldown atomic when key cancellation fails admission', async () => {
      const address = 'crash@mail.example';
      const { old } = await waiting(address);
      const now = new Date(fed.clock.t).toISOString();
      const pending = await alpha.store.value('recovery', address, now);
      const cancelRecovery = alpha.store.cancelRecovery.bind(alpha.store);
      alpha.store.cancelRecovery = async (address, expected, now, _admit, keyCancelledAt) =>
        cancelRecovery(
          address,
          expected,
          now,
          () => {
            throw new Error('crash at atomic admission');
          },
          keyCancelledAt,
        );
      try {
        assert.equal((await cancel(old)).status, 500);
      } finally {
        alpha.store.cancelRecovery = cancelRecovery;
      }
      assert.deepEqual(await alpha.store.value('recovery', address, now), pending);
      assert.equal((await alpha.store.agentByAddress(address))?.recoveryKeyCancelledAt, undefined);
      assert.equal((await cancel(old)).status, 200);
      assert.equal(await alpha.store.value('recovery', address, now), null);
      assert.equal((await alpha.store.agentByAddress(address))?.recoveryKeyCancelledAt, now);
    });

    it("honours the mark an earlier version left on a key's cancel, for recoveries started under it", async () => {
      const address = 'oldmark@mail.example';
      const old = alpha.newAgent();
      await old.register({ address });
      await old.register({ address, code: alpha.codes.get(address)! });
      const at = (ms: number) => new Date(fed.clock.t + ms).toISOString();
      assert.ok(await alpha.store.mark('recovery-key-cancelled', address, at(30 * 86_400_000), at(0)), 'day 0');
      fed.clock.advance(29 * 86_400_000);
      const thief = alpha.newAgent();
      await thief.recover({ address });
      await thief.recover({ address, code: alpha.codes.get(address)! });
      assert.equal((await status(old)).json.recovery.cancellable, false, 'day 29');
      fed.clock.advance(1.5 * 86_400_000);
      assert.equal((await status(old)).json.recovery.cancellable, false, 'day 30.5');
      const res = await cancel(old);
      assert.deepEqual([res.status, res.json.code], [409, 'recovery_not_cancellable']);

      // A recovery the earlier version itself started under its mark: no key cancels it while the mark lasts.
      const legacyAddress = 'oldmark2@mail.example';
      const { old: holder } = await waiting(legacyAddress);
      const r = (await alpha.store.value<Record<string, unknown>>('recovery', legacyAddress, at(0)))!;
      const legacy = { key: r.key, hash: r.hash, completesAt: r.completesAt };
      assert.equal(await alpha.store.cancelRecovery(legacyAddress, r, at(0)), true);
      await alpha.store.beginRecovery(legacyAddress, legacy, '2099-01-01T00:00:00.000Z', at(0));
      assert.ok(await alpha.store.mark('recovery-key-cancelled', legacyAddress, at(86_400_000), at(0)));
      assert.equal((await cancel(holder)).json.code, 'recovery_not_cancellable');
    });

    it('never locks a cancel code: a hundred wrong tries leave the right one working', async () => {
      const address = 'tries@mail.example';
      const { old } = await waiting(address);
      for (let i = 0; i < 100; i++) {
        assert.equal((await alpha.newAgent().cancelRecovery({ address, cancelCode: `wrong-${i}` })).status, 422);
      }
      const byCode = await alpha.newAgent().cancelRecovery({ address, cancelCode: alpha.cancelCodes.get(address)! });
      assert.equal(byCode.json.status, 'cancelled');
      assert.equal((await old.sync()).status, 200);
    });

    it('answers a code asked for while a recovery waits as when none waits, without sending another code', async () => {
      const address = 'hush@mail.example';
      const { code } = await waiting(address);
      const quiet = 'quiet@mail.example';
      const holder = alpha.newAgent();
      await holder.register({ address: quiet });
      await holder.register({ address: quiet, code: alpha.codes.get(quiet)! });
      const answers = async (at: string) => {
        const stranger = alpha.newAgent();
        const out = [await stranger.recover({ address: at })];
        for (let i = 0; i < 6; i++) out.push(await stranger.recover({ address: at, code: '00000000' }));
        return out.map(r => [r.status, { ...r.json, address: undefined }]);
      };
      const whileWaiting = await answers(address);
      assert.equal(alpha.codes.get(address), code, 'no code was sent while the recovery waits');
      assert.deepEqual(whileWaiting, await answers(quiet), 'every answer is the one given when nothing waits');
      assert.deepEqual(
        whileWaiting.map(([status]) => status),
        [202, 422, 422, 422, 422, 422, 410],
      );
      // And the stored code expires as a sent one does.
      const later = alpha.newAgent();
      await later.recover({ address });
      fed.clock.advance(16 * 60_000);
      assert.equal((await later.recover({ address, code: '12345678' })).json.code, 'code_expired');
    });

    it('keeps the postmaster name it writes notices as, on every domain it serves', async () => {
      const res = await alpha.newAgent().register({ address: 'postmaster@mail.example' });
      assert.deepEqual([res.status, res.json.code], [409, 'address_taken']);
    });

    it('cannot recover a name that has no mailbox behind it', async () => {
      await alpha.agent('nomail');
      fed.dns.point('alpha.test', alpha.origin);
      const res = await alpha.newAgent().register({ address: 'nomail@alpha.test' });
      assert.equal(res.json.code, 'address_taken');
    });

    it('is address_homed_elsewhere for a domain naming another server, or none', async () => {
      const elsewhere = await alpha.newAgent().register({ address: 'bob@beta.test' });
      assert.equal(elsewhere.status, 409);
      assert.deepEqual(
        [elsewhere.json.code, elsewhere.json.details],
        ['address_homed_elsewhere', { server: beta.origin }],
      );
      const none = await alpha.newAgent().register({ address: 'x@nowhere.example' });
      assert.deepEqual([none.json.code, none.json.details], ['address_homed_elsewhere', { server: null }]);
    });

    it('is unavailable when no code sender is configured', async () => {
      const delta = await fed.server('delta', { codes: false });
      fed.dns.point('d.example', delta.origin);
      const res = await delta.newAgent().register({ address: 'x@d.example' });
      assert.equal(res.status, 400);
      assert.equal(res.json.details.field, 'address');
    });
  });

  describe('limits on codes (CLIENT.md, "Recommended host practice")', () => {
    it('counts the codes asked for per address and per client network, never a call that answers one', async () => {
      const rates = {
        code: { limit: 2, seconds: 3600 },
        codeClient: { limit: 3, seconds: 3600 },
        // Four new calls from the one network fill it, and the call answering a code is not one.
        register: { limit: 4, seconds: 3600 },
      };
      const eps = await fed.server('epsilon', { config: { rates } });
      fed.dns.point('mail.eps.test', eps.origin);
      const asker = (ip: string) => async (address: string) => {
        const a = eps.newAgent();
        const res = await a.request('POST', '/simon/register', {
          body: JSON.stringify({ key: a.token, address }),
          ip,
          agent: address,
        });
        return { a, status: res.status };
      };
      const [x1, x2, y] = [asker('2001:db8:1:2::5'), asker('2001:db8:1:2::6'), asker('198.51.100.7')];
      const ada = await x1('ada@mail.eps.test');
      assert.equal(ada.status, 202);
      const code = eps.code('ada@mail.eps.test');
      assert.equal((await x2('ada@mail.eps.test')).status, 202, 'one /64 is one client network');
      assert.equal((await y('ada@mail.eps.test')).status, 429, 'the address has had its two');
      assert.equal((await x1('bob@mail.eps.test')).status, 202);
      assert.equal((await x2('cy@mail.eps.test')).status, 429, 'the network has had its three');
      assert.equal((await y('cy@mail.eps.test')).status, 202);
      assert.equal((await y('cy@mail.eps.test')).status, 202, "the refused network spent none of cy's");

      const answer = await ada.a.request('POST', '/simon/register', {
        body: JSON.stringify({ key: ada.a.token, address: 'ada@mail.eps.test', code }),
        ip: '2001:db8:1:2::5',
        agent: 'ada@mail.eps.test',
      });
      assert.equal(answer.status, 200, 'a call carrying a code is answered past both limits');
      ada.a.address = 'ada@mail.eps.test';
      const held = await ada.a.request('POST', '/simon/register', {
        body: JSON.stringify({ key: ada.a.token, address: 'ada@mail.eps.test' }),
        ip: '2001:db8:1:2::5',
      });
      assert.equal(held.status, 200, 'and so is one signed by a key the agent holds');
    });
  });

  describe('recovery by a key principal', () => {
    const principal = generateKey();
    const forValue = `simon-key:${principal.key}`;
    const now = () => new Date(fed.clock.t).toISOString();
    const recover = (agent: ReturnType<typeof alpha.newAgent>, address: string, at = now(), by = principal) =>
      agent.recover({ address, at, recover: signRecovery(by.privateKey, address, agent.token, at) });

    it('gives the address a new key at once, ending every old key, whatever they say', async () => {
      const old = alpha.newAgent();
      const pairing = signPairing(principal.privateKey, 'kp@alpha.test', forValue);
      await old.register({ address: 'kp@alpha.test', for: forValue, pairing });
      const fresh = alpha.newAgent();
      const res = await recover(fresh, 'kp@alpha.test');
      assert.equal(res.status, 200);
      assert.deepEqual(res.json, {
        address: 'kp@alpha.test',
        keys: [
          { key: old.token, added: res.json.keys[0].added, revoked: now() },
          { key: fresh.token, added: now(), revoked: null },
        ],
        grants: [],
        recovery: null,
      });
      assert.deepEqual((await recover(fresh, 'kp@alpha.test')).json, res.json, 'a repeat');
      assert.equal((await old.request('GET', '/simon/account')).json.code, 'key_revoked');
    });

    it('ends a pending recovery by the mailbox, which no key could cancel', async () => {
      const old = alpha.newAgent();
      await old.register({ address: 'kpm@mail.example' });
      const pairing = signPairing(principal.privateKey, 'kpm@mail.example', forValue);
      await old.register({ address: 'kpm@mail.example', code: alpha.code('kpm@mail.example'), for: forValue, pairing });
      const thief = alpha.newAgent();
      await thief.recover({ address: 'kpm@mail.example' });
      const code = alpha.code('kpm@mail.example');
      assert.equal((await thief.recover({ address: 'kpm@mail.example', code })).json.status, 'recovery_pending');

      const fresh = alpha.newAgent();
      assert.equal((await recover(fresh, 'kpm@mail.example')).json.recovery, null);
      fed.clock.advance(73 * 3600_000);
      assert.equal((await thief.recover({ address: 'kpm@mail.example', code })).json.code, 'code_expired');
      assert.equal((await fresh.request('GET', '/simon/account')).status, 200);
    });

    it('takes a signature at most 24 hours old and 5 minutes ahead', async () => {
      const old = alpha.newAgent();
      const pairing = signPairing(principal.privateKey, 'kpt@alpha.test', forValue);
      await old.register({ address: 'kpt@alpha.test', for: forValue, pairing });
      const at = (ms: number) => new Date(fed.clock.t + ms).toISOString();
      for (const when of [at(-24 * 3600_000 - 1000), at(5 * 60_000 + 1000), 'yesterday']) {
        const res = await recover(alpha.newAgent(), 'kpt@alpha.test', when);
        assert.deepEqual([res.status, res.json.details.field], [400, 'at'], when);
      }
      assert.equal((await recover(alpha.newAgent(), 'kpt@alpha.test', at(-24 * 3600_000))).status, 200);
    });

    it('refuses every recovery the principal did not sign with one answer', async () => {
      const old = alpha.newAgent();
      const pairing = signPairing(principal.privateKey, 'kpb@alpha.test', forValue);
      await old.register({ address: 'kpb@alpha.test', for: forValue, pairing });
      const solo = await alpha.agent('kps');
      const retired = alpha.newAgent();
      const retiredPairing = signPairing(principal.privateKey, 'kpr@alpha.test', forValue);
      await retired.register({ address: 'kpr@alpha.test', for: forValue, pairing: retiredPairing });
      await alpha.server.api.retire(retired.address);
      const answers = [
        await recover(alpha.newAgent(), 'kpb@alpha.test', now(), generateKey()),
        await recover(alpha.newAgent(), solo.address),
        await recover(alpha.newAgent(), 'nobody@alpha.test'),
        await recover(alpha.newAgent(), retired.address),
        await alpha.newAgent().recover({ address: 'kpb@alpha.test', at: now(), recover: 'AAAA' }),
      ];
      for (const res of answers) assert.deepEqual([res.status, res.json.code], [401, 'bad_proof']);
      assert.equal(new Set(answers.map(res => res.json.detail)).size, 1);
      assert.equal((await old.request('GET', '/simon/account')).status, 200);
    });
  });

  describe('pairing with a key principal (spec section 2.2)', () => {
    it('pairs a named address with the principal that signed the pairing', async () => {
      const principal = generateKey();
      const forValue = `simon-key:${principal.key}`;
      const a = alpha.newAgent();
      const res = await a.register({
        address: 'paired@alpha.test',
        for: forValue,
        pairing: signPairing(principal.privateKey, 'paired@alpha.test', forValue),
      });
      assert.equal(res.status, 200);
      const doc = await a.request('GET', '/simon/agents/paired@alpha.test', { sign: false });
      assert.equal(doc.json.kind, 'paired');
      assert.equal(JSON.stringify(doc.json).includes(principal.key), false, 'the document never names the principal');
    });

    it('tells a leasing agent its address first, then pairs on the call that signs it', async () => {
      const principal = generateKey();
      const forValue = `simon-key:${principal.key}`;
      const a = alpha.newAgent();
      const first = await a.register({ for: forValue });
      assert.equal(first.status, 202);
      assert.equal(first.json.status, 'pairing_required');
      const pairing = sign(principal.privateKey, pairingBytes(first.json.address, forValue));
      const done = await a.register({ for: forValue, pairing });
      assert.equal(done.status, 200);
      assert.equal(done.json.address, first.json.address);
    });

    it('refuses a held or retired address before asking for a pairing', async () => {
      const forValue = `simon-key:${generateKey().key}`;
      await alpha.agent('held');
      const held = await alpha.newAgent().register({ address: 'held@alpha.test', for: forValue });
      assert.deepEqual([held.status, held.json.code], [409, 'address_taken']);
      const gone = await alpha.agent('gone');
      await alpha.server.api.retire(gone.address);
      const retired = await alpha.newAgent().register({ address: 'gone@alpha.test', for: forValue });
      assert.deepEqual([retired.status, retired.json.code], [409, 'address_taken']);
    });

    it('retires the address on its unpairing and validates a retired document if the host serves one', async () => {
      const principal = generateKey();
      const forValue = `simon-key:${principal.key}`;
      const a = alpha.newAgent();
      const address = 'unpaired@alpha.test';
      const paired = await a.register({
        address,
        for: forValue,
        pairing: signPairing(principal.privateKey, address, forValue),
      });
      assert.equal(paired.status, 200);
      const before = await a.request('GET', `/simon/agents/${address}`, { sign: false });
      const unpair = signUnpairing(principal.privateKey, address, forValue);
      const res = await alpha
        .newAgent()
        .request('POST', '/simon/unpair', { body: JSON.stringify({ address, unpairing: unpair }), agent: address });
      assert.deepEqual([res.status, res.json.status], [200, 'retired']);
      const doc = await a.request('GET', `/simon/agents/${address}`, { sign: false });
      if (doc.status === 404) {
        assert.equal(doc.json.code, 'not_found');
        assert.equal((await a.sync()).json.code, 'key_revoked');
        const repeat = await alpha
          .newAgent()
          .request('POST', '/simon/unpair', { body: JSON.stringify({ address, unpairing: unpair }), agent: address });
        assert.equal(repeat.json.status, 'retired');
        return;
      }
      assert.equal(doc.status, 200);
      const server = readServerDocument(
        (await a.request('GET', '/simon/server', { sign: false })).bytes,
        alpha.origin,
        fed.clock.now(),
      )!;
      const read = readAgentDocument(doc.bytes, address, server.keys, fed.clock.now());
      assert.ok(read?.retired, 'a readable retired document');
      assert.equal(read.unpairing, unpair);
      assert.ok(verifyUnpairing(address, forValue, read.unpairing!));
      assert.deepEqual(
        read.keys.map(k => [k.key, k.revoked]),
        before.json.keys.map((k: { key: string }) => [k.key, read.retired]),
        'every key revoked when it retired',
      );
      // A repeat, and a later retirement, change nothing.
      await alpha
        .newAgent()
        .request('POST', '/simon/unpair', { body: JSON.stringify({ address, unpairing: unpair }), agent: address });
      fed.clock.advance(1000);
      await alpha.server.api.retire(address);
      const again = await a.request('GET', `/simon/agents/${address}`, { sign: false });
      assert.deepEqual([again.json.retired, again.json.unpairing], [read.retired, unpair]);
    });

    it('lets a key principal recover its agent at once, ending a waiting recovery (CLIENT.md)', async () => {
      const principal = generateKey();
      const forValue = `simon-key:${principal.key}`;
      const address = 'rescued@mail.example';
      const old = alpha.newAgent();
      const pairing = signPairing(principal.privateKey, address, forValue);
      await old.register({ address, for: forValue, pairing });
      assert.equal(
        (await old.register({ address, code: alpha.codes.get(address)!, for: forValue, pairing })).status,
        200,
      );
      const thief = alpha.newAgent();
      await thief.recover({ address });
      const thiefCode = alpha.codes.get(address)!;
      assert.equal((await thief.recover({ address, code: thiefCode })).json.status, 'recovery_pending');

      const fresh = alpha.newAgent();
      const at = new Date(fed.clock.t).toISOString();
      const recover = signRecovery(principal.privateKey, address, fresh.token, at);
      const done = await fresh.recover({ address, at, recover });
      assert.equal(done.status, 200);
      assert.deepEqual(
        done.json.keys.map((k: { key: string; revoked: string | null }) => [k.key, k.revoked !== null]),
        [
          [old.token, true],
          [fresh.token, false],
        ],
      );
      assert.deepEqual((await fresh.recover({ address, at, recover })).json, done.json, 'a repeat answers alike');
      fed.clock.advance(73 * 3600_000);
      assert.equal((await thief.recover({ address, code: thiefCode })).json.code, 'code_expired', 'the wait ended');

      const now = () => new Date(fed.clock.t);
      const signedAt = (k: string, t: Date) => signRecovery(principal.privateKey, address, k, t.toISOString());
      const next = alpha.newAgent();
      for (const t of [new Date(now().getTime() - 24 * 3600_000 - 1000), new Date(now().getTime() + 6 * 60_000)]) {
        const res = await next.recover({ address, at: t.toISOString(), recover: signedAt(next.token, t) });
        assert.deepEqual([res.status, res.json.details?.field], [400, 'at'], t.toISOString());
      }
      const forged = await next.recover({
        address,
        at: now().toISOString(),
        recover: signRecovery(generateKey().privateKey, address, next.token, now().toISOString()),
      });
      assert.deepEqual([forged.status, forged.json.code], [401, 'bad_proof']);
      const nobody = await next.recover({
        address: 'nobody@mail.example',
        at: now().toISOString(),
        recover: signedAt(next.token, now()),
      });
      assert.deepEqual(nobody.json, forged.json, 'one answer whatever the refusal');
      const back = await old.recover({ address, at: now().toISOString(), recover: signedAt(old.token, now()) });
      assert.deepEqual([back.status, back.json.code], [409, 'key_in_use'], 'a revoked key never returns');
      const notSigner = await old.request('POST', '/simon/recovery', {
        body: JSON.stringify({
          address,
          key: next.token,
          at: now().toISOString(),
          recover: signedAt(next.token, now()),
        }),
        agent: address,
      });
      assert.deepEqual([notSigner.status, notSigner.json.details?.field], [400, 'key']);
    });

    it('tells extensions how an agent was recovered: by code, or by its principal', async () => {
      const seen: string[] = [];
      const gamma = await fed.server('gamma', {
        config: { recoveryWaitSeconds: 0 },
        extensions: [{ name: 'watch', on: { recovered: e => void seen.push(e.by) } }],
      });
      fed.dns.point('gmail.example', gamma.origin);
      const principal = generateKey();
      const forValue = `simon-key:${principal.key}`;
      const address = 'pat@gmail.example';
      const pairing = signPairing(principal.privateKey, address, forValue);
      const old = gamma.newAgent();
      await old.register({ address, for: forValue, pairing });
      await old.register({ address, code: gamma.codes.get(address)!, for: forValue, pairing });
      const byCode = gamma.newAgent();
      await byCode.recover({ address });
      assert.equal((await byCode.recover({ address, code: gamma.codes.get(address)! })).status, 200);
      const at = new Date(fed.clock.t).toISOString();
      const fresh = gamma.newAgent();
      const res = await fresh.recover({
        address,
        at,
        recover: signRecovery(principal.privateKey, address, fresh.token, at),
      });
      assert.equal(res.status, 200);
      assert.deepEqual(seen, ['mailbox', 'principal']);
    });

    it('recovers to a key the agent already holds: every other key revoked, a waiting recovery ended', async () => {
      const principal = generateKey();
      const forValue = `simon-key:${principal.key}`;
      const address = 'kept@mail.example';
      const old = alpha.newAgent();
      const pairing = signPairing(principal.privateKey, address, forValue);
      await old.register({ address, for: forValue, pairing });
      await old.register({ address, code: alpha.codes.get(address)!, for: forValue, pairing });
      const second = generateKey();
      await old.request('POST', '/simon/keys', {
        body: JSON.stringify({
          key: second.key,
          proof: sign(second.privateKey, addKeyProofString(address, second.key)),
        }),
      });
      const thief = alpha.newAgent();
      await thief.recover({ address });
      const thiefCode = alpha.codes.get(address)!;
      assert.equal((await thief.recover({ address, code: thiefCode })).json.status, 'recovery_pending');
      const at = new Date(fed.clock.t).toISOString();
      const body = JSON.stringify({
        address,
        key: second.key,
        at,
        recover: signRecovery(principal.privateKey, address, second.key, at),
      });
      const res = await old.request('POST', '/simon/recovery', { body, key: second.privateKey });
      assert.equal(res.status, 200, JSON.stringify(res.json));
      assert.deepEqual(
        res.json.keys.map((k: { key: string; revoked: string | null }) => [k.key, k.revoked !== null]),
        [
          [old.token, true],
          [second.key, false],
        ],
      );
      fed.clock.advance(73 * 3600_000);
      assert.equal((await thief.recover({ address, code: thiefCode })).json.code, 'code_expired', 'the wait ended');
    });

    it('refuses a pairing that does not verify, and a principal kind no extension verifies', async () => {
      const principal = generateKey();
      const forValue = `simon-key:${principal.key}`;
      const bad = await alpha
        .newAgent()
        .register({ address: 'bp@alpha.test', for: forValue, pairing: sign(principal.privateKey, 'x') });
      assert.deepEqual([bad.status, bad.json.code], [401, 'bad_proof']);
      const mail = await alpha.newAgent().register({ address: 'm@alpha.test', for: 'mailto:ann@example.org' });
      assert.deepEqual([mail.status, mail.json.details.field], [400, 'for']);
    });
  });

  describe('the request', () => {
    it('refuses members that are not strings, and a key other than the one that signs', async () => {
      const a = alpha.newAgent();
      assert.equal((await a.register({ address: 7 })).json.details.field, 'address');
      assert.equal((await a.recover({ address: 'nobody@alpha.test', recover: true })).json.details.field, 'recover');
      const res = await a.request('POST', '/simon/register', { body: JSON.stringify({ key: generateKey().key }) });
      assert.deepEqual([res.status, res.json.details.field], [400, 'key']);
    });

    it('ignores members it does not define, and the forms it no longer takes', async () => {
      const a = await alpha.agent('ignores');
      const res = await a.register({ note: 7, cancelRecovery: true, unpair: 'x' });
      assert.deepEqual([res.status, res.json.address], [200, 'ignores@alpha.test']);
    });

    it('takes a lease signed by a key this server does not know, and still checks the signature', async () => {
      const a = alpha.newAgent();
      const forged = await a.request('POST', '/simon/register', {
        body: JSON.stringify({ key: a.token }),
        headers: { 'simon-key': generateKey().key },
      });
      assert.deepEqual([forged.status, forged.json.code], [400, 'invalid'], 'key is not the signing key');
      const other = generateKey();
      const bad = await a.request('POST', '/simon/register', {
        body: JSON.stringify({ key: other.key }),
        headers: { 'simon-key': other.key },
      });
      assert.deepEqual([bad.status, bad.json.code], [401, 'bad_signature']);
    });

    it('tells no one whose a key is: a mismatched simon-agent is refused alike, and only once signed', async () => {
      const ada = await alpha.agent('keyholder');
      const stranger = generateKey().privateKey;
      const url = new URL(`${alpha.origin}/simon/register`);
      const body = Buffer.from(JSON.stringify({ key: ada.token }));
      const signed = signRequest(stranger, {
        method: 'POST',
        url: url.href,
        body,
        now: fed.clock.t,
        agent: 'x@alpha.test',
      });
      // ada's key token over a stranger's signature, naming an address that is not ada's.
      const forged = { ...signed, 'simon-key': ada.token };
      const res = await alpha.server.handle(toRequest('POST', url, forged, body, '192.0.2.9'));
      const text = replyBody(res).toString();
      assert.equal(res.status, 401);
      assert.ok(!text.includes(ada.address), `the refusal names no address: ${text}`);
      assert.equal(JSON.parse(text).code, 'bad_signature');
      // An unknown key in the same call is refused with the same status, before simon-agent is read.
      const unknownKey = alpha.newAgent().token;
      const unknown = { ...signed, 'simon-key': unknownKey };
      const unknownBody = Buffer.from(JSON.stringify({ key: unknownKey }));
      const other = await alpha.server.handle(toRequest('POST', url, unknown, unknownBody, '192.0.2.9'));
      assert.equal(other.status, res.status, "a key that is no one's is refused with the same status");
      assert.notEqual(JSON.parse(replyBody(other).toString()).code, 'signature_required', 'and the signature first');

      const own = await ada.request('POST', '/simon/register', { body, agent: 'x@alpha.test' });
      assert.deepEqual([own.status, own.json.code], [401, 'signature_required']);
      const leasing = alpha.newAgent();
      const named = await leasing.request('POST', '/simon/register', {
        body: JSON.stringify({ key: leasing.token }),
        agent: 'x@alpha.test',
      });
      assert.deepEqual([named.status, named.json.code], [401, 'signature_required']);
      assert.equal(own.json.detail, named.json.detail, 'one refusal, whatever the address');
      assert.ok(!own.json.detail.includes(ada.address));
    });

    it('registers and sends with an ML-DSA-65 key', async () => {
      const a = alpha.newAgent('ml-dsa-65');
      assert.equal((await a.register({ address: 'pq@alpha.test' })).status, 200);
      assert.equal((await a.send(a.message(['ada@alpha.test'], 'post-quantum'))).status, 200);
    });
  });
});
