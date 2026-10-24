/** Waiting for the next message: each shown once, oldest first, remembered on disk, a correspondent at a time. */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateKey } from '@agnt-sdk/simon-protocol';
import { Agent, SimonError, type Fetch } from '../src/index.ts';
import { readWaitState, saveWaitState, waitFile, waitForMessage } from '../src/wait.ts';
import { fakeServer } from './fake-server.ts';

async function world() {
  const fake = fakeServer();
  const keys = new Map<Agent, string>();
  const make = async () => {
    const key = generateKey().privateKeyPem;
    const a = new Agent({ server: fake.origin, key, fetch: fake.fetch });
    await a.register();
    keys.set(a, key);
    return a;
  };
  /** The same agent, reaching its server through another fetch. */
  const through = (a: Agent, fetch: Fetch) =>
    new Agent({ server: fake.origin, key: keys.get(a)!, address: a.address, fetch });
  const [ada, bob, carol] = [await make(), await make(), await make()];
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'simon-wait-'));
  // A clock that moves only when the wait sleeps, so timeouts take no time.
  let t = 0;
  const clock = { now: () => t, sleep: async (ms: number) => void (t += ms) };
  const wait = (opts: { from?: string; timeoutMs?: number } = {}, agent = bob) =>
    waitForMessage(agent, home, { timeoutMs: 10_000, intervalMs: 3000, ...clock, ...opts });
  return { fake, ada, bob, carol, home, wait, clock, through };
}

describe('waitForMessage', () => {
  it('shows each message once, oldest first, and times out with null when nothing is new', async () => {
    const { ada, bob, home, wait } = await world();
    assert.equal(await wait({ timeoutMs: 9000 }), null);
    const first = await ada.send({ to: [bob.address!], text: 'one' });
    const second = await ada.send({ to: [bob.address!], text: 'two' });
    const a = await wait();
    assert.deepEqual([a?.entry.id, a?.more], [first.id, true]);
    const b = await wait();
    assert.deepEqual([b?.entry.id, b?.more], [second.id, false]);
    assert.equal(await wait(), null);
    assert.equal(typeof readWaitState(home).token, 'string');
    assert.deepEqual(readWaitState(home).pending, []);
    assert.equal(fs.statSync(waitFile(home)).mode & 0o777, 0o600);
  });

  it('polls until a message arrives within the timeout', async () => {
    const { ada, bob, fake, home, clock, through } = await world();
    let polls = 0;
    const later: Fetch = async (url, init) => {
      if (url.includes('/simon/sync') && ++polls === 3) await ada.send({ to: [bob.address!], text: 'at last' });
      return fake.fetch(url, init);
    };
    const got = await waitForMessage(through(bob, later), home, { timeoutMs: 60_000, intervalMs: 3000, ...clock });
    assert.deepEqual(got?.entry.message.parts, [{ type: 'text/plain', data: 'at last' }]);
    assert.equal(polls, 3);
    assert.equal(clock.now(), 6000);
  });

  it('waits for one correspondent, and leaves the others for a later wait, still once each', async () => {
    const { ada, bob, carol, home, wait } = await world();
    const fromCarol = await carol.send({ to: [bob.address!], text: 'carol 1' });
    const fromAda = await ada.send({ to: [bob.address!], text: 'ada 1' });
    const carol2 = await carol.send({ to: [bob.address!], text: 'carol 2' });
    assert.equal((await wait({ from: ada.address!.toUpperCase() }))?.entry.id, fromAda.id);
    assert.equal(
      readWaitState(home).pending.length,
      2,
      'unmatched entries remain queued while the opaque token advances',
    );
    assert.equal(await wait({ from: ada.address! }), null);
    assert.equal((await wait())?.entry.id, fromCarol.id);
    assert.equal((await wait())?.entry.id, carol2.id, "ada's message is not shown again");
    assert.equal(await wait(), null);
    assert.deepEqual(readWaitState(home).pending, []);
  });

  it('shows buffered messages without network access and excludes overlapping waits', async () => {
    const { ada, bob, home, through, wait } = await world();
    const sent = await ada.send({ to: [bob.address!], text: 'buffered' });
    const page = await bob.sync();
    saveWaitState(home, { token: page.token, pending: page.messages, seen: [] });
    const offline = through(bob, async () => {
      throw new Error('network must not be used');
    });
    assert.equal((await wait({ timeoutMs: 0 }, offline))?.entry.id, sent.id);
    fs.mkdirSync(path.join(home, 'wait.lock'));
    fs.writeFileSync(path.join(home, 'wait.lock', 'owner.json'), JSON.stringify({ pid: process.pid }));
    await assert.rejects(wait({ timeoutMs: 0 }), { code: 'concurrent_wait' });
    assert.ok(fs.existsSync(path.join(home, 'wait.lock')), 'another owner lock was not removed');
    fs.rmSync(path.join(home, 'wait.lock'), { recursive: true });
    assert.equal(await wait({ timeoutMs: 0 }), null);
    assert.equal(fs.existsSync(path.join(home, 'wait.lock')), false, 'own lock released');
  });

  it('zero timeout reads at most one page even when unmatched backlog has more', async () => {
    const { bob, ada, home } = await world();
    let calls = 0;
    const scanning = {
      address: bob.address,
      sync: async () => {
        calls++;
        return { messages: [], signals: [], marks: [], removed: [], token: `opaque-${calls}`, more: true };
      },
    } as unknown as Agent;
    assert.equal(await waitForMessage(scanning, home, { from: ada.address!, timeoutMs: 0, intervalMs: 1 }), null);
    assert.equal(calls, 1);
  });

  it('bounds positive pagination by the remaining budget and checkpoints each completed page', async () => {
    const { bob, ada, home } = await world();
    let now = 0;
    const budgets: number[] = [];
    const scanning = {
      address: bob.address,
      sync: async (opts: { timeoutMs: number }) => {
        budgets.push(opts.timeoutMs);
        now += 6;
        return { messages: [], signals: [], marks: [], removed: [], token: `opaque-${budgets.length}`, more: true };
      },
    } as unknown as Agent;
    assert.equal(
      await waitForMessage(scanning, home, { from: ada.address!, timeoutMs: 10, intervalMs: 1, now: () => now }),
      null,
    );
    assert.deepEqual(budgets, [10, 4]);
    assert.equal(readWaitState(home).token, 'opaque-2');
  });

  it('shows a message delivered twice once', async () => {
    const { ada, bob, fake, wait } = await world();
    const sent = await ada.send({ to: [bob.address!], text: 'once' });
    assert.equal((await wait())?.entry.id, sent.id);
    fake.redeliver(sent.id);
    assert.equal(await wait(), null);
  });

  it('waits out failures that may pass, and throws the rest', async () => {
    const { ada, bob, fake, home, clock, through } = await world();
    let calls = 0;
    const flaky: Fetch = async (url, init) =>
      ++calls < 3 ? new Response('busy', { status: 503 }) : fake.fetch(url, init);
    await ada.send({ to: [bob.address!], text: 'through' });
    assert.ok(await waitForMessage(through(bob, flaky), home, { timeoutMs: 60_000, intervalMs: 1000, ...clock }));
    saveWaitState(home, { token: null, pending: [], seen: [] });
    const stranger = new Agent({
      server: fake.origin,
      key: generateKey().privateKeyPem,
      address: 'x@agents.test',
      fetch: fake.fetch,
    });
    await assert.rejects(
      waitForMessage(stranger, home, { timeoutMs: 60_000, intervalMs: 1000, ...clock }),
      (e: SimonError) => e.code === 'unknown_key',
    );
    fs.writeFileSync(waitFile(home), '{"cursor":-1}');
    await assert.rejects(
      waitForMessage(bob, home, { timeoutMs: 1000, intervalMs: 1000, ...clock }),
      (e: SimonError) => e.code === 'invalid',
    );
  });
});
