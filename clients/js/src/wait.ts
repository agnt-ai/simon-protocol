/** Persistent waits share opaque tokens, queued messages and deduplication across CLI and MCP. */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { Agent, Delivered } from './agent.ts';
import { AgntError, addressArg } from './errors.ts';

export interface WaitState {
  token: string | null;
  pending: Delivered[];
  seen: string[];
}
export interface WaitOptions {
  from?: string;
  timeoutMs: number;
  intervalMs: number;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}
export interface Waited {
  entry: Delivered;
  more: boolean;
}
const SEEN_KEPT = 1000;
const HEX64 = /^[0-9a-f]{64}$/;
export const waitFile = (home: string) => path.join(home, 'wait.json');

/** JS and Python hold the same directory lock for the whole read/modify/write wait operation. */
async function locked<T>(home: string, run: () => Promise<T>): Promise<T> {
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  const lock = path.join(home, 'wait.lock');
  try {
    fs.mkdirSync(lock, { mode: 0o700 });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
    let ownerPid: number | undefined;
    try {
      const owner = JSON.parse(fs.readFileSync(path.join(lock, 'owner.json'), 'utf8'));
      if (Number.isSafeInteger(owner.pid) && owner.pid > 0) ownerPid = owner.pid;
    } catch {
      /* Unknown owners are never stolen. */
    }
    throw new AgntError(
      'concurrent_wait',
      `Another wait owns AGNT_HOME/wait.lock${ownerPid ? ` (PID ${ownerPid})` : ''}. Stop it first. After confirming its owner is no longer running, remove only the stale wait.lock directory; keep wait.json.`,
      { details: { field: 'wait.lock', ...(ownerPid ? { ownerPid } : {}) } },
    );
  }
  try {
    fs.writeFileSync(
      path.join(lock, 'owner.json'),
      JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() }),
      { flag: 'wx', mode: 0o600 },
    );
    return await run();
  } finally {
    fs.rmSync(lock, { recursive: true, force: true });
  }
}

/** A damaged or legacy file is explicit: never silently skip or replay messages. */
export function readWaitState(home: string): WaitState {
  let text: string;
  try {
    text = fs.readFileSync(waitFile(home), 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return { token: null, pending: [], seen: [] };
    throw e;
  }
  let s: Partial<WaitState> | null = null;
  try {
    s = JSON.parse(text);
  } catch {
    /* Diagnosed below. */
  }
  if (
    !s ||
    !(s.token === null || (typeof s.token === 'string' && s.token.length > 0)) ||
    !Array.isArray(s.pending) ||
    !s.pending.every(
      e =>
        e &&
        typeof e.id === 'string' &&
        HEX64.test(e.id) &&
        e.message &&
        typeof e.message.from === 'string' &&
        Array.isArray(e.message.to) &&
        typeof e.carrier === 'string' &&
        typeof e.receivedAt === 'string' &&
        Array.isArray(e.claims),
    ) ||
    !Array.isArray(s.seen) ||
    !s.seen.every(id => typeof id === 'string' && HEX64.test(id))
  ) {
    throw new AgntError(
      'invalid',
      'The wait state is damaged or uses the old numeric cursor format; delete wait.json to start again from retained messages.',
      { details: { field: 'wait.json' } },
    );
  }
  return s as WaitState;
}
export function saveWaitState(home: string, state: WaitState) {
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  const fresh = `${waitFile(home)}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(fresh, `${JSON.stringify(state)}\n`, { flag: 'wx', mode: 0o600 });
  fs.renameSync(fresh, waitFile(home));
}

/** Show one new received message, retaining skipped correspondents and ignoring our own sent entries. */
export async function waitForMessage(agent: Agent, home: string, opts: WaitOptions): Promise<Waited | null> {
  if (
    !Number.isFinite(opts.timeoutMs) ||
    opts.timeoutMs < 0 ||
    !Number.isFinite(opts.intervalMs) ||
    opts.intervalMs <= 0
  )
    throw new AgntError('invalid', 'Wait timeout is nonnegative and its interval is positive.');
  const from = opts.from === undefined ? undefined : addressArg('from', opts.from);
  const now = opts.now ?? Date.now;
  const sleep = opts.sleep ?? (ms => new Promise<void>(resolve => setTimeout(resolve, ms)));
  const deadline = now() + opts.timeoutMs;
  return locked(home, async () => {
    for (;;) {
      let pause = opts.intervalMs;
      try {
        const found = await scan(agent, home, from, () => deadline - now(), opts.timeoutMs === 0);
        if (found) return found;
      } catch (e) {
        if (!(e instanceof AgntError && e.retryable)) throw e;
        if (e.retryAfter !== undefined) pause = Math.max(pause, e.retryAfter * 1000);
      }
      const left = deadline - now();
      if (left <= 0) return null;
      await sleep(Math.min(pause, left));
    }
  });
}

async function scan(
  agent: Agent,
  home: string,
  from: string | undefined,
  remaining: () => number,
  once: boolean,
): Promise<Waited | null> {
  const state = readWaitState(home);
  const seen = new Set(state.seen);
  const wanted = (e: Delivered) => from === undefined || e.message.from === from;
  const take = (more: boolean): Waited | null => {
    const i = state.pending.findIndex(wanted);
    if (i < 0) return null;
    const [entry] = state.pending.splice(i, 1);
    seen.add(entry.id);
    state.seen = [...seen].slice(-SEEN_KEPT);
    saveWaitState(home, state);
    return { entry, more: more || state.pending.some(wanted) };
  };
  // Pending entries are already private local data: show them before making another network request.
  const buffered = take(false);
  if (buffered) return buffered;
  let more: boolean;
  do {
    const left = remaining();
    if (!once && left <= 0) return null;
    const page = await agent.sync({
      since: state.token ?? undefined,
      limit: 200,
      ...(once ? {} : { timeoutMs: Math.max(1, left) }),
    });
    if (
      !page ||
      typeof page.token !== 'string' ||
      !page.token ||
      typeof page.more !== 'boolean' ||
      !Array.isArray(page.messages) ||
      !page.messages.every(
        e =>
          e &&
          typeof e.id === 'string' &&
          HEX64.test(e.id) &&
          e.message &&
          typeof e.message.from === 'string' &&
          Array.isArray(e.message.to) &&
          typeof e.carrier === 'string' &&
          typeof e.receivedAt === 'string' &&
          Array.isArray(e.claims),
      )
    ) {
      throw new AgntError('bad_response', 'Sync did not return a valid opaque token and message page.');
    }
    const pendingIds = new Set(state.pending.map(e => e.id));
    for (const e of page.messages) {
      if (!seen.has(e.id) && !pendingIds.has(e.id)) {
        if (e.message.to.includes(agent.address!)) {
          state.pending.push(e);
          pendingIds.add(e.id);
        } else seen.add(e.id);
      }
    }
    if (page.more && page.token === state.token)
      throw new AgntError('bad_response', 'Sync pagination did not advance its token.');
    state.token = page.token;
    more = page.more;
    // Checkpoint each page so retrying a later page cannot lose messages just queued.
    state.seen = [...seen].slice(-SEEN_KEPT);
    saveWaitState(home, state);
    if (!once && remaining() <= 0) return null;
  } while (!once && more && !state.pending.some(wanted));
  return take(more);
}
