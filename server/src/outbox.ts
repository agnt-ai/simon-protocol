/**
 * The outbox: delivering stored messages to recipient servers (spec section 6), modelled on Postfix's
 * queue manager.
 *
 *   - **Claims.** Due rows are claimed from the store atomically, each leased to this attempt's token, so
 *     two workers never take the same row, and every outcome is written only under that lease: an attempt
 *     that outlived its lease writes nothing, and a delivered row is never written again.
 *   - **Bounded concurrency:** at most CONCURRENCY rows in flight, so at most that many POSTs, and at most
 *     PER_DESTINATION POSTs to one server at once. Rows for a busy server wait a moment without spending
 *     an attempt.
 *   - **Dead and throttled destinations.** A server that refuses connections, cannot be connected to, or
 *     holds one past the deadline (a tarpit) is skipped for DEAD_MS, and so is its address, so a thousand
 *     names for one tarpit cost one timeout. A `429` throttles its server until its Retry-After.
 *   - **Timing.** No attempt before `sentAt`, none at or after the deadline (the earlier of five days after
 *     acceptance and 143 hours after `sentAt`), when the recipients fail as `expired`. Retries back off
 *     exponentially from a minute to four hours, honour Retry-After up to an hour, and are capped to fall
 *     before the deadline. `429` and `5xx` answers, and failures that may pass, are retried; other answers
 *     are final (spec section 6.3), except two a domain's move can cause while caches still name the old
 *     server: a `400 invalid` on `recipients` is retried for an hour from the first such answer, the
 *     recipients' domain resolved again without the cache before each attempt; a `403 bad_signature` is
 *     retried while this server began serving the author's domain less than an hour ago ("serving since",
 *     kept in the store by `send`).
 *   - **One envelope per server,** naming that server and the recipients it serves, with only their hints:
 *     a message's recipient domains are resolved together, and those naming the same server share one. A
 *     server document must be readable before anything is posted.
 *   - Recipients on a domain naming this server become arrivals here, offered through the admit chain.
 *
 * Caps, dead and throttled destinations are this process's; several workers on one store each keep their own.
 */
import crypto from 'node:crypto';
import { canonicalBytes, domainOf, envelopeFor, parseProblem, signEnvelope, type Hints } from '@agnt-protocol/protocol';
import { iso, later, type Context } from './context.ts';
import { arrivalsFor } from './fanout.ts';
import { Unreachable } from './net/fetch.ts';
import type { Delivery, StoredMessage } from './store/store.ts';

export const PER_DESTINATION = 4;
export const CONCURRENCY = 32;
const LEASE_MS = 2 * 60_000;
const MIN_BACKOFF_MS = 60_000;
const MAX_BACKOFF_MS = 4 * 3600_000;
const MAX_RETRY_AFTER_S = 3600;
const DEAD_MS = 5 * 60_000;
const CAPACITY_WAIT_MS = 5_000;
const POST_TIMEOUT_MS = 30_000;
const ANSWER_BYTES = 65_536;
/** The last retry is scheduled this long before the deadline, at the latest. */
const LAST_CHANCE_MS = 1_000;

/** Outcomes of resolution that mean a domain has no server to deliver to. */
const NO_SERVER = ['invalid_domain', 'invalid_record', 'conflict', 'not_found'];
/** How long the answers a domain's move can cause are retried: the longest a resolver caches (spec section 3). */
export const MOVE_WINDOW_MS = 3600_000;
/** Store scopes: when a row was first answered 400 on its recipients; when this server began serving a domain. */
const RECIPIENTS_REFUSED = 'recipients-refused';
/** Per-row absolute migration cutoffs, retained through the normal delivery deadline. */
const MOVE_CUTOFF = 'delivery-move-cutoff';
type MoveCutoff = { until: string; reason: string; fresh: boolean };
export const SERVING_SINCE = 'serving-since';

type Outcome =
  | { delivered: true }
  | { fail: string; field?: unknown; status: number }
  | { retry: string; afterS?: number };

export class Outbox {
  readonly #ctx: Context;
  readonly #running = new Set<Promise<void>>();
  /** POSTs in flight, per server. */
  readonly #posting = new Map<string, number>();
  /** Servers skipped until a time: dead, or throttled by a 429. */
  readonly #blocked = new Map<string, number>();
  /** Addresses that refused or held a connection, skipped until a time. */
  readonly #deadAddresses = new Map<string, number>();
  /** Rows claimed and not yet settled. */
  #active = 0;

  constructor(ctx: Context) {
    this.#ctx = ctx;
  }

  /** Claim due rows as far as capacity allows, and start attempting them. Returns how many messages it started. */
  async tick(): Promise<number> {
    const room = CONCURRENCY - this.#active;
    if (room <= 0) return 0;
    const now = this.#ctx.now();
    const busy = [...new Set([...this.#posting.keys(), ...this.#blocked.keys()])].filter(s => !this.#open(s, now));
    const token = crypto.randomUUID();
    const rows = await this.#ctx.store.claimDeliveries(iso(now), room, busy, { token, until: later(now, LEASE_MS) });
    this.#active += rows.length;
    const byMessage = Map.groupBy(rows, r => r.id);
    for (const [id, group] of byMessage) {
      const attempt: Promise<void> = this.#attempt(id, group, token)
        .catch(e => this.#ctx.log('error', 'delivery attempt failed', { id, error: String(e) }))
        .finally(() => {
          this.#active -= group.length;
          this.#running.delete(attempt);
        });
      this.#running.add(attempt);
    }
    return byMessage.size;
  }

  /** Wait until every attempt underway has ended. */
  async idle(): Promise<void> {
    while (this.#running.size) await Promise.all(this.#running);
  }

  /** Whether a server may take another POST now: not blocked, and under its cap. */
  #open(server: string, now: Date): boolean {
    return !blockedUntil(this.#blocked, server, now) && (this.#posting.get(server) ?? 0) < PER_DESTINATION;
  }

  async #attempt(id: string, claimed: Delivery[], token: string): Promise<void> {
    const ctx = this.#ctx;
    const now = ctx.now();
    const record = await ctx.store.message(id);
    const rows = record ? claimed.filter(r => now < new Date(r.deadline)) : [];
    const expired = claimed.filter(r => !rows.includes(r));
    if (expired.length) await this.#fail(expired, 'expired', token);
    if (!record) return;

    const byServer = new Map<string, Delivery[]>();
    for (const row of rows) {
      const route = await this.#route(row, record.message.from);
      const r = { ...row, server: 'server' in route ? route.server : row.server };
      if ('retry' in route) await this.#retry([r], route.retry, token);
      else if ('fail' in route) await this.#fail([r], route.fail, token);
      else byServer.set(route.server, [...(byServer.get(route.server) ?? []), r]);
    }
    await Promise.all([...byServer].map(([server, group]) => this.#deliverTo(server, record, group, token)));
  }

  /**
   * Where a row's domain delivers to now, or why not; resolved afresh while its recipients were refused. The
   * lookups are its author's, in the author's share of the server's own pool, so no agent's slow recipient
   * domains hold up another's.
   */
  async #route(row: Delivery, author: string): Promise<{ server: string } | { retry: string } | { fail: string }> {
    try {
      const { store, now } = this.#ctx;
      const at = now();
      const move = await store.value<MoveCutoff>(MOVE_CUTOFF, rowKey(row), iso(at));
      if (move && at.getTime() >= Date.parse(move.until)) return { fail: move.reason };
      const first = await store.value<string>(RECIPIENTS_REFUSED, rowKey(row), iso(at));
      if (first && at.getTime() >= Date.parse(first) + MOVE_WINDOW_MS) return { fail: 'invalid' };
      const fresh = move?.fresh || first !== null;
      const peer = await this.#ctx.resolver.peer(row.domain, { agent: author }, { fresh });
      if (peer.outcome !== 'server') {
        return NO_SERVER.includes(peer.outcome) ? { fail: peer.outcome } : { retry: peer.outcome };
      }
      if (!peer.document) return { retry: 'no_server_document' };
      return { server: peer.server };
    } catch {
      return { retry: 'temporary' };
    }
  }

  async #deliverTo(server: string, record: StoredMessage, rows: Delivery[], token: string): Promise<void> {
    const ctx = this.#ctx;
    const now = ctx.now();
    const recipients = rows.flatMap(r => r.recipients);
    const hints: Hints = Object.assign({}, ...rows.map(r => r.hints));
    if (server === ctx.config.origin) {
      await ctx.store.putMessage(record, { arrivals: arrivalsFor(record.id, recipients, hints, now) });
      ctx.wake();
      return this.#delivered(rows, server, token);
    }
    if (!this.#open(server, now)) {
      const until = Math.max(blockedUntil(this.#blocked, server, now), now.getTime() + CAPACITY_WAIT_MS);
      for (const r of rows) await ctx.store.settleDelivery({ ...r, nextAttemptAt: iso(new Date(until)) }, token);
      return;
    }
    this.#posting.set(server, (this.#posting.get(server) ?? 0) + 1);
    try {
      const outcome = await this.#post(server, record, recipients, hints);
      if ('delivered' in outcome) await this.#delivered(rows, server, token);
      else if ('fail' in outcome) {
        // Rows sharing one destination can have different migration histories.
        for (const row of rows) {
          if (await this.#moved(record, row, outcome)) await this.#retry([row], outcome.fail, token);
          else await this.#fail([row], outcome.fail, token);
        }
      } else await this.#retry(rows, outcome.retry, token, outcome.afterS);
    } finally {
      const n = this.#posting.get(server)! - 1;
      if (n) this.#posting.set(server, n);
      else this.#posting.delete(server);
    }
  }

  async #post(server: string, record: StoredMessage, recipients: string[], hints: Hints): Promise<Outcome> {
    const ctx = this.#ctx;
    // The claims as they were signed for the message at send, without this server's judgement of them.
    const claims = record.signedClaims?.claims;
    const envelope = signEnvelope(
      envelopeFor(record.message, { server, recipients }, { ...(claims ? { claims } : {}), hints }),
      ctx.config.serverKey,
    );
    try {
      const res = await ctx.http.request({
        method: 'POST',
        url: `${server}/agnt/deliver`,
        headers: { 'content-type': 'application/json' },
        body: canonicalBytes(envelope),
        maxBytes: ANSWER_BYTES,
        timeoutMs: POST_TIMEOUT_MS,
        avoid: address => blockedUntil(this.#deadAddresses, address, ctx.now()) > 0,
      });
      if (res.status >= 200 && res.status < 300) return { delivered: true };
      const problem = parseProblem(res.status, res.body);
      const code = problem?.code ?? `http_${res.status}`;
      if (res.status !== 429 && res.status < 500)
        return { fail: code, field: problem?.details?.field, status: res.status };
      const afterS = retryAfter(res.headers['retry-after'], ctx.now());
      if (res.status === 429) this.#blocked.set(server, ctx.now().getTime() + (afterS ?? 60) * 1000);
      return { retry: code, afterS };
    } catch (e) {
      const kind = e instanceof Unreachable ? e.kind : 'failed';
      if (kind === 'refused' || kind === 'connect' || kind === 'timeout') {
        const until = ctx.now().getTime() + DEAD_MS;
        this.#blocked.set(server, until);
        if (e instanceof Unreachable && e.address) this.#deadAddresses.set(e.address, until);
      }
      return { retry: kind };
    }
  }

  /**
   * Whether a refusal is one a domain's move can cause, still within its hour (spec section 6.3): a `400
   * invalid` on `recipients`, an hour from the first such answer for the row, which is then resolved afresh
   * before each attempt; a `403 bad_signature` while this server began serving the author's domain less than
   * an hour ago.
   */
  async #moved(record: StoredMessage, row: Delivery, outcome: { fail: string; field?: unknown; status: number }) {
    const { store, now } = this.#ctx;
    const at = now();
    if (
      !(
        (outcome.status === 403 && outcome.fail === 'bad_signature') ||
        (outcome.status === 400 && outcome.fail === 'invalid' && outcome.field === 'recipients')
      )
    )
      return false;
    const existing = await store.value<MoveCutoff>(MOVE_CUTOFF, rowKey(row), iso(at));
    if (existing) {
      if (outcome.status === 400 && outcome.field === 'recipients') {
        // A later routing mismatch requires fresh resolution without extending the existing cutoff.
        await store.valueOnce(RECIPIENTS_REFUSED, rowKey(row), iso(at), row.deadline, iso(at));
      }
      return at.getTime() < Date.parse(existing.until);
    }
    let cutoff: MoveCutoff | null = null;
    if (outcome.fail === 'invalid' && outcome.field === 'recipients') {
      const first = await store.valueOnce(RECIPIENTS_REFUSED, rowKey(row), iso(at), row.deadline, iso(at));
      cutoff = { until: later(new Date(first), MOVE_WINDOW_MS), reason: 'invalid', fresh: true };
    } else if (outcome.fail === 'bad_signature') {
      const noted = await store.value<{ since: string } | string>(
        SERVING_SINCE,
        domainOf(record.message.from),
        iso(at),
      );
      if (typeof noted === 'object' && noted !== null) {
        const since = Date.parse(noted.since);
        if (since <= at.getTime() && at.getTime() < since + MOVE_WINDOW_MS) {
          cutoff = { until: later(new Date(since), MOVE_WINDOW_MS), reason: 'bad_signature', fresh: false };
        }
      }
    }
    if (!cutoff) return false;
    cutoff.until = iso(new Date(Math.min(Date.parse(cutoff.until), Date.parse(row.deadline))));
    const fixed = await store.valueOnce(MOVE_CUTOFF, rowKey(row), cutoff, row.deadline, iso(at));
    return at.getTime() < Date.parse(fixed.until);
  }

  async #delivered(rows: Delivery[], server: string, token: string) {
    const settled: Delivery[] = [];
    for (const r of rows) {
      const row = { ...r, server, status: 'delivered' as const, reason: null, attempts: r.attempts + 1 };
      if (await this.#ctx.store.settleDelivery(row, token)) settled.push(r);
    }
    if (settled.length) {
      await this.#ctx.hooks.emit('delivered', {
        id: rows[0].id,
        server,
        recipients: settled.flatMap(r => r.recipients),
      });
    }
  }

  async #fail(rows: Delivery[], reason: string, token: string) {
    const { store, hooks } = this.#ctx;
    const failed: Delivery[] = [];
    for (const r of rows) {
      const attempts = r.attempts + 1;
      if (reason === 'not_found' && (await this.#bridged(r))) {
        await store.settleDelivery({ ...r, status: 'delivered', reason: null, attempts }, token);
      } else if (await store.settleDelivery({ ...r, status: 'failed', reason, attempts }, token)) {
        failed.push(r);
      }
    }
    if (!failed.length) return;
    await hooks.emit('deliveryFailed', {
      id: failed[0].id,
      server: failed[0].server,
      recipients: failed.flatMap(r => r.recipients),
      reason,
    });
  }

  /** Whether an extension took recipients whose domain names no AGNT server (a bridge to email, say). */
  async #bridged(row: Delivery): Promise<boolean> {
    const record = await this.#ctx.store.message(row.id);
    return (
      !!record &&
      this.#ctx.hooks.emit('unroutable', {
        id: row.id,
        domain: row.domain,
        recipients: row.recipients,
        message: record.message,
      })
    );
  }

  /** Try again after backoff or Retry-After, before the deadline; past the last chance, the rows expire. */
  async #retry(rows: Delivery[], reason: string, token: string, afterS?: number) {
    const now = this.#ctx.now().getTime();
    const expired: Delivery[] = [];
    for (const r of rows) {
      const backoff = Math.min(MIN_BACKOFF_MS * 2 ** r.attempts, MAX_BACKOFF_MS);
      const delay = afterS === undefined ? backoff : Math.max(afterS * 1000, MIN_BACKOFF_MS);
      const move = await this.#ctx.store.value<MoveCutoff>(MOVE_CUTOFF, rowKey(r), iso(new Date(now)));
      const deadline = Math.min(Date.parse(r.deadline), move ? Date.parse(move.until) : Infinity);
      const next = Math.min(now + delay, deadline - LAST_CHANCE_MS);
      if (next <= now && move && Date.parse(move.until) <= Date.parse(r.deadline))
        await this.#fail([r], move.reason, token);
      else if (next <= now) expired.push(r);
      else {
        const row = { ...r, reason, attempts: r.attempts + 1, nextAttemptAt: iso(new Date(next)) };
        await this.#ctx.store.settleDelivery(row, token);
      }
    }
    if (expired.length) await this.#fail(expired, 'expired', token);
  }
}

/** A delivery row's key in the store: its message and recipient domain. */
const rowKey = (row: Pick<Delivery, 'id' | 'domain'>) => `${row.id} ${row.domain}`;

/** When a key stops being blocked, or 0 when it is not (an entry past its time is forgotten). */
function blockedUntil(map: Map<string, number>, key: string, now: Date): number {
  const until = map.get(key) ?? 0;
  if (until > now.getTime()) return until;
  map.delete(key);
  return 0;
}

/** Retry-After in seconds, from seconds or an HTTP date, at most an hour; undefined when absent or unreadable. */
function retryAfter(value: string | undefined, now: Date): number | undefined {
  if (!value) return undefined;
  const s = /^\d+$/.test(value) ? Number(value) : (Date.parse(value) - now.getTime()) / 1000;
  return Number.isFinite(s) ? Math.min(MAX_RETRY_AFTER_S, Math.max(0, Math.ceil(s))) : undefined;
}
