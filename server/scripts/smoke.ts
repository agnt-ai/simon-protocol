/**
 * Smoke test of the real thing: two `node server/src/main.ts` processes on localhost, two agents
 * registered with nothing but @agnt-sdk/simon-protocol, a message each way, then both stopped.
 *
 *   node server/scripts/smoke.ts
 */
import { spawn, type ChildProcess } from 'node:child_process';
import path from 'node:path';
import {
  canonicalBytes,
  generateKey,
  keyToken,
  signMessage,
  signRequest,
  timestamp,
  type Message,
  VERSION,
} from '@agnt-sdk/simon-protocol';

const main = path.resolve(import.meta.dirname, '../src/main.ts');
const servers = { 'a.test': 'http://127.0.0.1:8701', 'b.test': 'http://127.0.0.1:8702' };
const resolve = Object.entries(servers)
  .map(([d, o]) => `${d}=${o}`)
  .join(',');

const children: ChildProcess[] = [];

async function start(domain: string, origin: string): Promise<ChildProcess> {
  const child = spawn(process.execPath, [main], {
    env: {
      ...process.env,
      SIMON_DEV: '1',
      SIMON_ORIGIN: origin,
      SIMON_PORT: new URL(origin).port,
      SIMON_HOSTED_DOMAINS: domain,
      SIMON_DB: ':memory:',
      SIMON_DEV_RESOLVE: resolve,
    },
    stdio: ['ignore', 'inherit', 'pipe'],
  });
  children.push(child);
  return new Promise((ok, fail) => {
    const timeout = setTimeout(() => fail(new Error(`${origin} did not start within 10 seconds`)), 10_000);
    const reject = (error: Error) => {
      clearTimeout(timeout);
      fail(error);
    };
    let startupLog = '';
    child.stderr!.on('data', (chunk: Buffer) => {
      process.stderr.write(chunk);
      startupLog = (startupLog + chunk.toString()).slice(-4096);
      if (startupLog.includes('"listening"')) {
        clearTimeout(timeout);
        ok(child);
      }
    });
    child.once('error', reject);
    child.once('exit', code => reject(new Error(`${origin} exited with ${code}`)));
  });
}

/** Stop only children this script spawned; wait for exit and escalate within a fixed cleanup budget. */
async function stop(child: ChildProcess): Promise<void> {
  if (child.pid === undefined || child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    let killTimer: ReturnType<typeof setTimeout> | undefined;
    let exitTimer: ReturnType<typeof setTimeout> | undefined;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(killTimer);
      clearTimeout(exitTimer);
      child.off('exit', onExit);
      if (error) reject(error);
      else resolve();
    };
    const onExit = () => finish();
    child.once('exit', onExit);
    killTimer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch (error) {
        finish(error as Error);
      }
    }, 2000);
    exitTimer = setTimeout(() => finish(new Error(`Could not reap owned child ${child.pid}`)), 4000);
    try {
      child.kill('SIGTERM');
    } catch (error) {
      finish(error as Error);
    }
  });
}

async function call(
  origin: string,
  key: ReturnType<typeof generateKey>,
  method: string,
  target: string,
  body?: Uint8Array,
  agent?: string,
  timeoutMs = 5000,
) {
  const headers = signRequest(key.privateKey, { method, url: origin + target, body: body ?? '', agent });
  const res = await fetch(origin + target, {
    method,
    signal: AbortSignal.timeout(timeoutMs),
    headers: headers as Record<string, string>,
    body: body && new Uint8Array(body),
  });
  return { status: res.status, json: await res.json() };
}

async function agent(domain: keyof typeof servers, name: string) {
  const key = generateKey();
  const origin = servers[domain];
  const res = await call(
    origin,
    key,
    'POST',
    '/simon/register',
    Buffer.from(JSON.stringify({ key: keyToken(key.privateKey), address: `${name}@${domain}` })),
  );
  if (res.status !== 200) throw new Error(`register: ${JSON.stringify(res.json)}`);
  return {
    address: res.json.address as string,
    send: async (to: string, text: string) => {
      const m = signMessage<Message>(
        {
          v: VERSION,
          from: res.json.address,
          to: [to],
          inReplyTo: null,
          parts: [{ type: 'text/plain', data: text }],
          headers: {},
          sentAt: timestamp(Date.now()),
        },
        key.privateKey,
      );
      const sent = await call(origin, key, 'POST', '/simon/send', canonicalBytes(m), res.json.address);
      if (sent.status !== 200) throw new Error(`send: ${JSON.stringify(sent.json)}`);
      return sent;
    },
    async waitFor(text: string) {
      const deadline = Date.now() + 5000;
      while (Date.now() < deadline) {
        const response = await call(
          origin,
          key,
          'GET',
          '/simon/sync',
          undefined,
          res.json.address,
          Math.max(1, deadline - Date.now()),
        );
        if (response.status !== 200 || !Array.isArray(response.json.messages))
          throw new Error(`sync: ${response.status} ${JSON.stringify(response.json)}`);
        const { json } = response;
        if (json.messages.some((e: { message: Message }) => e.message.parts.some(p => 'data' in p && p.data === text)))
          return;
        await new Promise(r => setTimeout(r, 50));
      }
      throw new Error(`${res.json.address} never received: ${text}`);
    },
  };
}

try {
  await Promise.all(Object.entries(servers).map(([d, o]) => start(d, o)));
  const ada = await agent('a.test', 'ada');
  const bob = await agent('b.test', 'bob');
  console.log(`registered ${ada.address} and ${bob.address}`);
  console.log('ada -> bob', (await ada.send(bob.address, 'Hello, Bob.')).status);
  await bob.waitFor('Hello, Bob.');
  console.log('bob <- ada: received');
  console.log('bob -> ada', (await bob.send(ada.address, 'Hello, Ada.')).status);
  await ada.waitFor('Hello, Ada.');
  console.log('ada <- bob: received');
} finally {
  const stopped = await Promise.allSettled(children.map(stop));
  const failures = stopped.filter((r): r is PromiseRejectedResult => r.status === 'rejected');
  if (failures.length)
    throw new AggregateError(
      failures.map(r => r.reason),
      'Owned smoke child cleanup failed',
    );
}
console.log('smoke test passed');
