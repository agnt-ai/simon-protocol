/**
 * What an agent reads about its own messages (client.md):
 *
 *   GET /simon/sync?since=<token>&limit=<n>&wait=<seconds>   what entered the agent's stream since the token:
 *                                     the messages it received and those it wrote here, from any of its
 *                                     clients, in the order this server took them, each with its carrier and
 *                                     its claims (the authoritative ones always, the others only from a
 *                                     carrier this server trusts, and the carrier's claims as it signed
 *                                     them, so any client checks them); and the signals it was told of
 *   GET /simon/sent/<id>               delivery of one of its messages, per recipient server
 *
 * Sync shows what entered the stream within the last `syncDays` (published in the server document). A
 * token is the position it reaches and when it was given, so one older than that, which may reach back
 * past what sync no longer shows, is `410 token_expired`, as is one this server never gave: a gap is said,
 * never hidden. This server keeps no history, so `marks` and `removed` are always empty.
 *
 * With nothing new, a sync waits up to `wait` seconds for something to enter the stream: told at once
 * within this process, and looked for again every few seconds, for what another process wrote.
 */
import crypto from 'node:crypto';
import { invalid, unauthorized, WireError } from '@agnt-sdk/simon-protocol';
import { authenticateAgent, authenticateAgentKey } from './auth.ts';
import { iso, type Context } from './context.ts';
import { notFound } from './errors.ts';
import { shownClaims } from './fanout.ts';
import { json, type Reply, type Request } from './http.ts';
import type { Delivery, SyncEntry, SyncPage } from './store/store.ts';

const DAY_MS = 86_400_000;
const MAX_WAIT_S = 60;
/** How often a waiting sync looks again, for what other processes wrote. */
const RECHECK_MS = 5_000;
// A persisted per-origin secret keeps checkpoints valid across workers and restarts, without a
// database row for every poll. Authenticated encryption binds both position and account to this host.
async function checkpointKey(ctx: Context): Promise<Buffer> {
  const value = await ctx.store.valueOnce(
    'sync-secret',
    ctx.config.origin,
    crypto.randomBytes(32).toString('base64url'),
    null,
    iso(ctx.now()),
  );
  const key = Buffer.from(value, 'base64url');
  if (key.length !== 32) throw new Error('Invalid persisted sync secret');
  return key;
}
function checkpoint(key: Buffer, origin: string, address: string, cursor: number, at: number): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(origin));
  const data = Buffer.concat([cipher.update(JSON.stringify({ v: 1, address, cursor, at })), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64url');
}
function position(key: Buffer, origin: string, address: string, token: string, oldest: number, now: number): number {
  try {
    if (token.length > 2048 || !/^[A-Za-z0-9_-]+$/.test(token)) throw tokenExpired();
    const data = Buffer.from(token, 'base64url');
    if (data.length < 29 || data.toString('base64url') !== token) throw tokenExpired();
    const cipher = crypto.createDecipheriv('aes-256-gcm', key, data.subarray(0, 12));
    cipher.setAAD(Buffer.from(origin));
    cipher.setAuthTag(data.subarray(12, 28));
    const value = JSON.parse(Buffer.concat([cipher.update(data.subarray(28)), cipher.final()]).toString('utf8'));
    if (
      value.v !== 1 ||
      value.address !== address ||
      !Number.isSafeInteger(value.cursor) ||
      value.cursor < 0 ||
      !Number.isSafeInteger(value.at) ||
      value.at < oldest ||
      value.at > now
    )
      throw tokenExpired();
    return value.cursor;
  } catch {
    throw tokenExpired();
  }
}

/** Who waits for news of which agent in this process: each `sync` held open. */
export class Changes {
  readonly #waiting = new Map<string, Set<() => void>>();
  #closed = false;

  /** Answer everyone waiting for news of `address`. */
  tell(address: string): void {
    for (const done of this.#waiting.get(address) ?? []) done();
  }

  /** Wait until `address` is told of, or `ms` pass; false once closed, when no one waits any more. */
  async wait(address: string, ms: number): Promise<boolean> {
    if (this.#closed) return false;
    const waiting = this.#waiting.get(address) ?? new Set();
    this.#waiting.set(address, waiting);
    let done!: () => void;
    const told = new Promise<void>(resolve => (done = resolve));
    const timer = setTimeout(done, ms);
    waiting.add(done);
    await told;
    clearTimeout(timer);
    waiting.delete(done);
    if (!waiting.size) this.#waiting.delete(address);
    return !this.#closed;
  }

  close(): void {
    this.#closed = true;
    for (const address of this.#waiting.keys()) this.tell(address);
  }
}

/** Something entered an agent's stream: its waiting syncs answer, and its webhooks fall due. */
export async function changed(ctx: Context, address: string): Promise<void> {
  ctx.changes.tell(address);
  await ctx.store.wakeWebhooks(address, iso(ctx.now()));
  ctx.wake();
}

function whole(value: string | null, fallback: number, min: number, max: number, name: string): number {
  if (value === null) return fallback;
  const n = /^[0-9]{1,3}$/.test(value) ? Number(value) : NaN;
  if (!(n >= min && n <= max)) throw invalid(`${name} is a whole number from ${min} to ${max}.`, { field: name });
  return n;
}

const tokenExpired = () =>
  new WireError(410, 'token_expired', 'This token reaches back past what sync still shows, or is unknown; sync anew.');

export async function sync(ctx: Context, req: Request): Promise<Reply> {
  const { agent, key: signer } = await authenticateAgentKey(ctx, req);
  const limit = whole(req.query.get('limit'), 50, 1, 200, 'limit');
  const wait = whole(req.query.get('wait'), 0, 0, MAX_WAIT_S, 'wait');
  const now = ctx.now();
  const oldest = now.getTime() - ctx.config.syncDays * DAY_MS;
  const key = await checkpointKey(ctx);
  const since = req.query.get('since');
  if (since === null && (await ctx.store.value<boolean>('sync-history-gap', agent.address, iso(now)))) {
    // Every device must learn of the upgrade gap. This does not clear account state or silently replay.
    throw new WireError(
      410,
      'token_expired',
      'This account predates sent-message tracking; retained sent history may be incomplete. Explicitly resume with the supplied token.',
      { reason: 'history_migration', resumeToken: checkpoint(key, ctx.config.origin, agent.address, 0, now.getTime()) },
    );
  }
  const after = since === null ? 0 : position(key, ctx.config.origin, agent.address, since, oldest, now.getTime());
  const read = () =>
    ctx.store.sync(
      agent.address,
      after,
      limit,
      iso(ctx.now()),
      iso(new Date(ctx.now().getTime() - ctx.config.syncDays * DAY_MS)),
    );
  let page = await read();
  if (page.cursor < after) throw tokenExpired();
  const deadline = Date.now() + wait * 1000;
  while (isEmpty(page) && Date.now() < deadline) {
    if (!(await ctx.changes.wait(agent.address, Math.min(deadline - Date.now(), RECHECK_MS)))) break;
    page = await read();
    if (page.cursor < after) throw tokenExpired();
  }
  // Authentication consumed the nonce once. Recheck its authority after waiting without replaying it.
  const current = await ctx.store.agentByAddress(agent.address);
  const active = current?.keys.find(k => k.key === signer.key);
  if (
    !current ||
    current.retiredAt ||
    !active ||
    (current.authorizedKeys && !current.authorizedKeys.includes(signer.key)) ||
    (active.revoked !== null && active.revoked <= iso(ctx.now()))
  ) {
    throw unauthorized('bad_signature', 'This signing key is no longer active.', ctx.now());
  }
  const at = page.more
    ? Math.min(
        ctx.now().getTime(),
        ...page.messages.map(e => Date.parse(e.receivedAt)),
        ...page.signals.map(e => Date.parse(e.at)),
      )
    : ctx.now().getTime();
  return json({
    messages: page.messages.map(e => entry(ctx, e)),
    marks: [],
    removed: [],
    signals: page.signals.map(({ type, from, about, at }) => ({ type, from, about, at })),
    token: checkpoint(key, ctx.config.origin, agent.address, page.cursor, at),
    more: page.more,
  });
}

const isEmpty = (page: SyncPage) => !page.messages.length && !page.signals.length;

const entry = (ctx: Context, e: SyncEntry) => ({
  id: e.id,
  message: e.message,
  carrier: e.carrier,
  claims: shownClaims(ctx, e.carrier, e.claims),
  ...(e.signedClaims && { signedClaims: e.signedClaims }),
  receivedAt: e.receivedAt,
});

/**
 * One entry per recipient server. Domains not yet resolved, or that resolved to no server, have `server`
 * null; domains that resolved to the same server share its entry.
 */
export async function sent(ctx: Context, req: Request): Promise<Reply> {
  const agent = await authenticateAgent(ctx, req);
  const record = await ctx.store.message(req.params.id);
  if (!record || record.message.from !== agent.address || record.carrier !== ctx.config.origin) {
    throw notFound('This agent sent no message with this id here.');
  }
  const servers = new Map<
    string,
    { server: string | null; recipients: string[]; status: Delivery['status']; reason?: string }
  >();
  for (const d of await ctx.store.deliveries(record.id)) {
    const reason = d.status === 'failed' ? (d.reason ?? 'failed') : undefined;
    const key = d.server === null ? `domain ${d.domain}` : `${d.server} ${d.status} ${reason ?? ''}`;
    const entry = servers.get(key) ?? {
      server: d.server,
      recipients: [],
      status: d.status,
      ...(reason ? { reason } : {}),
    };
    entry.recipients.push(...d.recipients);
    servers.set(key, entry);
  }
  return json({ id: record.id, servers: [...servers.values()] });
}
