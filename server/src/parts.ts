/**
 * Content-addressed parts (spec section 7.2, CLIENT.md parts). Bytes are kept per source: the agent here
 * that uploaded them, or the carrier they were fetched from. Bytes **held for an agent** are its uploads
 * and the bytes fetched for messages in its inbox, so it can forward a part it received. Nothing is ever
 * served because a message merely names a hash.
 *
 *   PUT /simon/parts/<sha256>   an agent uploads bytes before sending the message that names them; the
 *                              extensions' `upload` checks may refuse them
 *   GET /simon/parts/<sha256>   to readers of a published message: bytes held for its author, when its
 *                              audience admits them; to a server that signs the request: bytes held for an
 *                              agent here whose message, delivered to that server, names them; to an agent
 *                              here: bytes held for it (`503` while they are being fetched), and what it
 *                              may read as a reader of published messages
 *
 * The route is dispatched by who signs (spec section 7.2): an agent hosted here gets the client API's answers,
 * its `401` for a signature that fails and `503` while a fetch is underway included; a server, by
 * `simon-server`, the files of messages delivered to it; anyone else, a request unsigned or whose signature
 * fails among them, the files of published messages it may read. Every refusal outside the first kind is
 * the same `404 not_found`.
 *
 * **Fetching tells a carrier nothing.** The parts of every message accepted at deliver are queued at once,
 * whoever its recipients are and whatever policy will decide, each after a random delay of up to
 * PREFETCH_JITTER_MS; bytes of a message nobody here took are checked, then swept with it. A read never
 * queues a fetch, and a fetch given up is final: the agent is answered `404`, never a fetch the carrier
 * could time. Fetches run at most MAX_FETCHES at once and MAX_FETCHES_PER_CARRIER for one carrier, are
 * taken in turn across carriers, keep MAX_FETCH_BYTES of declared size in flight, and are checked against
 * the hash and size. Every attempt charges its declared size to its carrier's hourly budget
 * (`fetchBytesPerHour`), whether it succeeds or not, so the budget never depends on admission; a fetch past
 * the budget waits for the next hour without spending an attempt. The budget and the per-carrier cap are kept
 * in the store, shared by every process on it.
 */
import crypto from 'node:crypto';
import { domainOf, invalid, isAddress, sha256Hex, signRequest, unauthorized, WireError } from '@agnt-protocol/protocol';
import { authenticateAgent, authenticateServer, isAgentSigned, isServerSigned } from './auth.ts';
import { iso, later, type Context } from './context.ts';
import { notFound, unavailable } from './errors.ts';
import { clientKey } from './net/ip.ts';
import type { Reply, Request, Route } from './http.ts';
import { askerOf, asReader, audienceOf, mayRead, type Asker } from './readers.ts';
import { contentParts } from './send.ts';
import type { PartFetch, PartSource, StoredMessage } from './store/store.ts';

const SHA256 = /^[0-9a-f]{64}$/;
export const PREFETCH_JITTER_MS = 3 * 60_000;
export const MAX_FETCHES = 4;
export const MAX_FETCHES_PER_CARRIER = 2;
export const MAX_FETCH_BYTES = 64 * 1024 * 1024;
const MAX_FETCH_ATTEMPTS = 6;
const FETCH_BACKOFF_MS = 60_000;
const FETCH_TIMEOUT_MS = 60_000;
const HOUR_MS = 3600_000;
/** Due fetches read per tick, enough to reach a turn of every carrier with one waiting. */
const FETCH_WINDOW = 64;
/**
 * Fetches waiting for one carrier, at most. A part past it is given up at once, as a fetch that failed is,
 * so no carrier's messages grow the queue without bound; its rows go with the messages that name them.
 */
export const MAX_PENDING_FETCHES_PER_CARRIER = 4096;
/** Carriers whose last fetch start this process remembers, to take carriers in turn; the oldest are forgotten first. */
const MAX_REMEMBERED_CARRIERS = 10_000;
/** A fetch given up is remembered as long as a message naming it can be kept. */
const givenUp = (sha256: string, carrier: string) => `${sha256} ${carrier}`;
const GIVEN_UP = 'part-given-up';

/** A fetch of `size` bytes from `carrier`, due after a random delay of up to PREFETCH_JITTER_MS. */
const jittered = (ctx: Context, sha256: string, carrier: string, size: number): PartFetch => ({
  sha256,
  carrier,
  size,
  attempts: 0,
  dueAt: later(ctx.now(), crypto.randomInt(PREFETCH_JITTER_MS + 1)),
});

/** Queue the fetch of an accepted message's content-addressed parts from its carrier. */
export async function queuePrefetch(ctx: Context, record: StoredMessage): Promise<void> {
  if (record.carrier === ctx.config.origin) return;
  const now = iso(ctx.now());
  for (const p of contentParts(record.message)) {
    const f = jittered(ctx, p.sha256, record.carrier, p.size);
    if (await ctx.store.queueFetch(f, now, MAX_PENDING_FETCHES_PER_CARRIER)) continue;
    // The carrier has its whole share waiting: this part is given up, final as any fetch given up is.
    const keep = later(ctx.now(), ctx.config.retentionDays * 86_400_000);
    await ctx.store.mark(GIVEN_UP, givenUp(p.sha256, record.carrier), keep, now);
  }
  ctx.wake();
}

/** Scopes of the store state every process running fetches on one store shares. */
const SPENT = 'part-fetch-bytes';
const SLOT = 'part-fetch-slot';
/**
 * A claimed fetch, and a carrier's slot, are held this long, so a process that died frees them; a fetch still
 * running renews both before half of it is left, so no other process runs it while it lasts.
 */
const LEASE_MS = 2 * FETCH_TIMEOUT_MS;
/** How often, in real time, a running fetch looks whether its claim is due for renewal by the server's clock. */
const RENEW_CHECK_MS = 250;

type Lease = { scope: string; id: string; token: string };

/**
 * Runs due part fetches within the caps, in turn across carriers. A carrier's hourly budget and its share of
 * the fetches underway are kept in the store, so every process running fetches on it shares them, and a
 * restart starts over on neither; a fetch is claimed in the store before it runs, so no two processes run it.
 * MAX_FETCHES and MAX_FETCH_BYTES bound each process's own work.
 */
export class Fetcher {
  readonly #ctx: Context;
  readonly #running = new Set<Promise<void>>();
  /** How many fetches each carrier has underway in this process. */
  readonly #underway = new Map<string, number>();
  /** When each carrier's last fetch started here, as a count of starts, most recent last. */
  readonly #lastStart = new Map<string, number>();
  #starts = 0;
  #bytes = 0;

  constructor(ctx: Context) {
    this.#ctx = ctx;
  }

  /** Start due fetches, as far as the caps allow. Returns how many it started. */
  async tick(): Promise<number> {
    const { store } = this.#ctx;
    if (this.#running.size >= MAX_FETCHES) return 0;
    let started = 0;
    /** Carriers found holding every slot this tick. */
    const full = new Set<string>();
    // A slot that frees goes first to the carrier with the fewest fetches underway here; among those, to the
    // one whose last fetch here started longest ago (one never started first), then in the store's turn. So
    // among the carriers read, neither older backlogs nor carriers that just finished keep another waiting.
    const due = await store.fetches(iso(this.#ctx.now()), FETCH_WINDOW);
    const underway = (carrier: string) => this.#underway.get(carrier) ?? 0;
    const last = (carrier: string) => this.#lastStart.get(carrier) ?? -1;
    for (const f of due.sort(
      (a, b) => underway(a.carrier) - underway(b.carrier) || last(a.carrier) - last(b.carrier),
    )) {
      if (full.has(f.carrier)) continue;
      if (this.#running.size >= MAX_FETCHES) break;
      // Claimed in the store, so no other process runs it, and a row read before another settled it is skipped.
      const claimEnds = later(this.#ctx.now(), LEASE_MS);
      const token = crypto.randomUUID();
      if (!(await store.claimFetch(f, iso(this.#ctx.now()), { token, until: claimEnds }))) continue;
      const slot = await this.#slot(f.carrier);
      if (!slot) {
        full.add(f.carrier);
        await store.fetchDefer(f.sha256, f.carrier, f.dueAt, token);
        continue;
      }
      // Past the bytes in flight, nothing more starts until they drain, so a large part is not passed over for
      // ever; one larger than the whole budget still runs, alone. Judged once a slot is held, so a carrier
      // whose slots are all held elsewhere holds up nothing.
      if (this.#bytes + f.size > MAX_FETCH_BYTES && this.#running.size) {
        await this.#release(slot);
        await store.fetchDefer(f.sha256, f.carrier, f.dueAt, token);
        break;
      }
      if (!(await this.#charge(f, token))) {
        await this.#release(slot);
        continue;
      }
      this.#bytes += f.size;
      this.#underway.set(f.carrier, underway(f.carrier) + 1);
      this.#started(f.carrier);
      const stopRenewing = this.#keepClaimed(f, token, claimEnds, slot);
      const run: Promise<void> = this.#fetch(f)
        .then(async () => {
          if (await stopRenewing()) await store.fetchDone(f.sha256, f.carrier, token);
        })
        .catch(async e => {
          if (await stopRenewing()) await this.#retry(f, e, token);
        })
        .catch(e => this.#ctx.log('error', 'part fetch could not be settled', { error: String(e) }))
        .finally(async () => {
          await stopRenewing();
          this.#bytes -= f.size;
          if (underway(f.carrier) > 1) this.#underway.set(f.carrier, underway(f.carrier) - 1);
          else this.#underway.delete(f.carrier);
          await this.#release(slot).catch(() => {});
          this.#running.delete(run);
        });
      this.#running.add(run);
      started++;
    }
    return started;
  }

  /** Note a carrier's fetch started now, forgetting the carriers that started longest ago past the bound. */
  #started(carrier: string) {
    this.#lastStart.delete(carrier);
    this.#lastStart.set(carrier, this.#starts++);
    if (this.#lastStart.size > MAX_REMEMBERED_CARRIERS) this.#lastStart.delete(this.#lastStart.keys().next().value!);
  }

  /** Wait until every fetch underway has ended. */
  async idle(): Promise<void> {
    while (this.#running.size) await Promise.all(this.#running);
  }

  /**
   * Keep a running fetch's claim, and its carrier's slot, while it runs: before half the lease is left, by
   * the server's clock, both move LEASE_MS on, the claim by claiming the row again as of its claim's end
   * (which only the claim that holds it can), the slot only while it is still this fetch's. A fetch that
   * outlasts its first lease (a store slow to take the bytes, say) is then never taken up by another process.
   * Returns what stops it.
   */
  #keepClaimed(f: PartFetch, token: string, claimEnds: string, slot: Lease): () => Promise<boolean> {
    const { store } = this.#ctx;
    let ends = claimEnds;
    let lost = false;
    let renewal: Promise<void> | null = null;
    const timer = setInterval(() => {
      const now = this.#ctx.now();
      if (lost || renewal || now.getTime() < Date.parse(ends) - LEASE_MS / 2) return;
      const next = later(now, LEASE_MS);
      renewal = (async () => {
        const held = await store.renewFetch(f.sha256, f.carrier, token, iso(now), next);
        const slotHeld = held && (await store.renewValue(slot.scope, slot.id, slot.token, next));
        if (!held || !slotHeld) {
          lost = true;
          this.#ctx.log('warn', 'part fetch ownership lost', { sha256: f.sha256, carrier: f.carrier });
        } else ends = next;
      })()
        .catch(error => {
          lost = true;
          this.#ctx.log('warn', 'part fetch renewal failed', { sha256: f.sha256, error: String(error) });
        })
        .finally(() => {
          renewal = null;
        });
    }, RENEW_CHECK_MS);
    timer.unref();
    return async () => {
      clearInterval(timer);
      await renewal;
      return !lost;
    };
  }

  /** One of the carrier's MAX_FETCHES_PER_CARRIER slots, held in the store until released: null when all are held. */
  async #slot(carrier: string): Promise<Lease | null> {
    for (let i = 0; i < MAX_FETCHES_PER_CARRIER; i++) {
      const slot = await this.#lease(SLOT, `${carrier} ${i}`);
      if (slot) return slot;
    }
    return null;
  }

  /** A store value only this caller holds until it releases it or LEASE_MS pass, or null when another holds it. */
  async #lease(scope: string, id: string): Promise<Lease | null> {
    const { store, now } = this.#ctx;
    const token = crypto.randomUUID();
    const held = await store.valueOnce(scope, id, token, later(now(), LEASE_MS), iso(now()));
    return held === token ? { scope, id, token } : null;
  }

  async #release({ scope, id, token }: Lease) {
    await this.#ctx.store.releaseValue(scope, id, token);
  }

  /**
   * Charge an attempt's declared size to its carrier's hour, unless that would pass the budget. A fetch past
   * it moves to the next hour without spending an attempt, so it never holds a place among the due fetches
   * read each tick that a carrier within its budget could have.
   */
  async #charge(f: PartFetch, token: string): Promise<boolean> {
    const { store, now, config } = this.#ctx;
    const hour = Math.floor(now().getTime() / HOUR_MS);
    const next = new Date((hour + 1) * HOUR_MS).toISOString();
    const counter = `${f.carrier} ${hour}`;
    const spent = await store.count(SPENT, counter, next, iso(now()), f.size);
    // A part larger than the whole budget is fetched alone, at the start of an hour.
    if (spent - f.size === 0 || spent <= config.fetchBytesPerHour) return true;
    await store.count(SPENT, counter, next, iso(now()), -f.size);
    await store.fetchDefer(f.sha256, f.carrier, next, token);
    return false;
  }

  async #fetch(f: PartFetch): Promise<void> {
    const ctx = this.#ctx;
    const url = `${f.carrier}/simon/parts/${f.sha256}`;
    const headers = signRequest(ctx.config.serverKey, {
      method: 'GET',
      url,
      now: ctx.now().getTime(),
      server: ctx.config.origin,
    });
    const res = await ctx.http.request({ method: 'GET', url, headers, maxBytes: f.size, timeoutMs: FETCH_TIMEOUT_MS });
    if (res.status !== 200 || res.body.length !== f.size || sha256Hex(res.body) !== f.sha256) {
      throw new Error(`${url} answered ${res.status} with ${res.body.length} bytes that do not match`);
    }
    await ctx.store.putPart(f.sha256, res.body, { carrier: f.carrier }, iso(ctx.now()));
  }

  async #retry(f: PartFetch, error: unknown, token: string) {
    const { store, log, now, config } = this.#ctx;
    log('info', 'part fetch failed', { sha256: f.sha256, carrier: f.carrier, error: String(error) });
    if (f.attempts + 1 < MAX_FETCH_ATTEMPTS) {
      await store.fetchRetry(f.sha256, f.carrier, later(now(), FETCH_BACKOFF_MS * 2 ** f.attempts), token);
      return;
    }
    const keep = later(now(), config.retentionDays * 86_400_000);
    await store.fetchGiveUp(f.sha256, f.carrier, token, keep);
  }
}

export function partRoutes(ctx: Context): Route[] {
  /** The bytes of the first source that holds them; for an agent, `503` while they are being fetched. */
  async function read(
    sources: (PartSource & { size: number })[],
    sha256: string,
    agent: boolean,
    additional?: () => AsyncIterable<PartSource & { size: number }>,
  ): Promise<Reply> {
    const grants = [...sources];
    for (const source of sources) {
      const bytes = await ctx.store.part(sha256, source);
      if (bytes) return { status: 200, bytes };
    }
    // An already-held grant needs no publication lookup or audience hook. Only try additional grants
    // after these bytes are unavailable; pending private fetches can still fall back to a publication.
    if (additional) {
      for await (const source of additional()) {
        grants.push(source);
        const bytes = await ctx.store.part(sha256, source);
        if (bytes) return { status: 200, bytes };
      }
    }
    const now = iso(ctx.now());
    for (const s of grants) {
      if (
        agent &&
        'carrier' in s &&
        !(await ctx.store.fetchExhausted(sha256, s.carrier, now)) &&
        !(await ctx.store.marked(GIVEN_UP, givenUp(sha256, s.carrier), now))
      ) {
        throw unavailable("Fetching this part from its carrier's server.", Math.ceil(PREFETCH_JITTER_MS / 1000));
      }
    }
    throw notFound();
  }

  /** Bytes held for each agent here whose message, as this viewer may see it, names the part. */
  async function* namedFor(
    sha256: string,
    viewer: { published: Asker } | { server: string },
  ): AsyncGenerator<PartSource & { size: number }> {
    const self = ctx.config.origin;
    const namers = await ctx.store.partNamers(sha256, 'published' in viewer ? { published: true } : viewer, self);
    if (!('published' in viewer)) {
      for (const { author } of namers) {
        for (const source of await ctx.store.heldFor(sha256, author, self)) yield source;
      }
      return;
    }
    const reader = await viewer.published.reader();
    // Try every unconditional grant before invoking an unrelated asynchronous audience policy.
    // Yield lazily: read() can return held bytes without starting or retaining that policy work.
    const unconditional = ({ message }: (typeof namers)[number]) =>
      audienceOf(message) === null || reader === message.from;
    for (const { author } of namers.filter(unconditional)) {
      for (const source of await ctx.store.heldFor(sha256, author, self)) yield source;
    }
    for (const { author, message } of namers.filter(namer => !unconditional(namer))) {
      let admitted: boolean;
      try {
        admitted = await mayRead(ctx, message, viewer.published);
      } catch (error) {
        // Only a failed audience decision grants nothing. Store and byte-read errors still propagate.
        ctx.log('warn', 'part audience policy failed', { error: String(error) });
        continue;
      }
      if (admitted) {
        for (const source of await ctx.store.heldFor(sha256, author, self)) yield source;
      }
    }
  }

  return [
    {
      method: 'PUT',
      path: '/simon/parts/:sha256',
      maxBody: ctx.config.limits.partBytes,
      async handle(req): Promise<Reply> {
        const agent = await authenticateAgent(ctx, req);
        const sha256 = req.params.sha256;
        if (!SHA256.test(sha256) || sha256Hex(req.body) !== sha256) {
          throw invalid('The path is the lower-case hex SHA-256 of the body.', { field: 'sha256' });
        }
        ctx.rate.hit('upload', agent.address);
        await ctx.hooks.upload({ address: agent.address, sha256, bytes: req.body });
        await ctx.store.putPart(sha256, req.body, { uploader: agent.address }, iso(ctx.now()));
        return { status: 200, json: { sha256, size: req.body.length } };
      },
    },
    {
      method: 'GET',
      path: '/simon/parts/:sha256',
      async handle(req: Request): Promise<Reply> {
        const sha256 = req.params.sha256;
        if (!SHA256.test(sha256)) throw notFound();
        // Hosted dispatch is based on public service routing, never a hidden account/key record.
        const address = req.headers['simon-agent'];
        let hosted = false;
        /** Why whether the signer's domain names this server could not be known just now. */
        let outage: WireError | null = null;
        if (isAgentSigned(req) && isAddress(address)) {
          const domain = domainOf(address);
          hosted = ctx.config.hostedDomains.includes(domain) || ctx.config.leaseDomain === domain;
          if (!hosted) {
            hosted = await ctx.resolver
              .servesHere(domain, () => ctx.rate.hit('lookup', clientKey(req.ip)))
              .catch(error => {
                asNobody(error);
                if (error instanceof WireError && error.status === 503) outage = error;
                return false;
              });
          }
        }
        if (hosted) {
          const agent = await authenticateAgent(ctx, req).catch(error => {
            if (error instanceof WireError && error.status === 401) {
              throw unauthorized('bad_signature', 'This request is not authorized.', ctx.now());
            }
            throw error;
          });
          return read(await ctx.store.heldFor(sha256, agent.address, ctx.config.origin), sha256, true, () =>
            namedFor(sha256, { published: asReader(agent.address) }),
          );
        }
        // A failed foreign signature grants no private access; independent public grants still count.
        const server = isServerSigned(req) ? await authenticateServer(ctx, req).catch(asNobody) : null;
        const asker = await askerOf(ctx, req);
        try {
          return await read([], sha256, false, async function* () {
            if (server) yield* namedFor(sha256, { server });
            yield* namedFor(sha256, { published: asker });
          });
        } catch (error) {
          // A signer that may be an agent here, whose own files may be among them, is not told a final 404
          // while its domain cannot be resolved: it is answered as the lookup was, 503, whatever is asked.
          if (outage && error instanceof WireError && error.status === 404) throw outage;
          throw error;
        }
      },
    },
  ];
}

/** A server whose signature fails, or whose document cannot be read for now, is nobody in particular. */
function asNobody(e: unknown): null {
  if (e instanceof WireError && [401, 429, 503].includes(e.status)) return null;
  throw e;
}
