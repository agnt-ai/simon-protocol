/**
 * Finding other servers and their keys: resolution (spec section 3), server and agent documents (section 4),
 * and key continuity (section 11.1, continuity.ts).
 *
 *   - **Caching.** Within the spec's bounds (`resolutionCacheMs`): a `server` answer for ten minutes, the
 *     TTL assumed since c-ares does not report one; `not_found` for ten minutes; `temporary` for a minute,
 *     so a failing domain costs one lookup a minute, however often it is asked for. Documents are cached
 *     ten minutes, and a server document that failed for now one minute.
 *   - **Refetching.** A signature that fails against a cached document is checked again against a fresh
 *     one, though a server document is fetched at most once a minute (anyone can name any server).
 *   - **Bounded outbound work.** Concurrent asks for the same answer share one lookup, and every lookup is
 *     paid for by whoever caused it (`Payer`): an unauthenticated client, counted before each lookup; a
 *     carrier whose signature verified, for the work its delivery asks (its recipients' domains, its
 *     claims, its author's document); or this server itself, for an agent's send and its outbox. Each runs
 *     in its own bounded pool, and a carrier has at most MAX_LOOKUPS_PER_CARRIER of its pool (more are
 *     refused for now, 503), so nothing another server or an unauthenticated client asks for can starve
 *     the server's own sending (spec section 11.2). The server's own work for an agent here, its send's and
 *     its messages' deliveries, has at most MAX_LOOKUPS_PER_AGENT of the own pool (more are refused for now,
 *     and a delivery retried), so no agent's recipients, slow as they may be, hold up another's.
 *   - **The bound before a signature verifies** (spec section 11.2). Every lookup an unauthenticated caller
 *     causes counts against its client network (`lookup`, in this process) and against the registrable
 *     domain of the name looked up (`lookupDomain`, by the Public Suffix List's ICANN section, in the store,
 *     so it holds for every process sharing it). Only lookups made count: a cache hit, or a lookup another
 *     ask already has underway, costs nothing. Past either bound the lookup is `429`, and it is not counted.
 */
import {
  addressSegment,
  DOCUMENT_CACHE_MS,
  MAX_DOCUMENT_BYTES,
  readAgentDocument,
  readServerDocument,
  resolutionCacheMs,
  resolveDomain,
  SERVER_DOCUMENT_REFETCH_MS,
  TEMPORARY_CACHE_MS,
  type AgentKind,
  type KeyEntry,
  type Resolution,
  type ServerDocument,
} from '@agnt-protocol/protocol';
import { AsyncLocalStorage } from 'node:async_hooks';
import type { Config } from './config.ts';
import { Continuity } from './continuity.ts';
import { rateLimited, unavailable } from './errors.ts';
import type { Log } from './extensions.ts';
import type { Dns } from './net/dns.ts';
import { registrableDomain, shippedPublicSuffixes, type PublicSuffixes } from './net/psl.ts';
import { Unreachable, type Http, type HttpResponse } from './net/fetch.ts';
import type { Store } from './store/store.ts';

/** The TTL taken for a `server` answer, whose DNS TTL or HTTP freshness this resolver does not read. */
const SERVER_TTL_MS = 10 * 60_000;
/** Lookups at once: for unauthenticated callers, for carriers whose signature verified, and for this server's own work. */
const MAX_LOOKUPS = { charged: 24, carrier: 32, own: 16 };
/** A carrier's lookups at once, of the carrier pool. */
export const MAX_LOOKUPS_PER_CARRIER = 8;
/**
 * The lookups at once of every carrier whose deliveries come from one network (`networkKey`): carriers cost
 * nothing to make up, networks do. Twice a carrier's share, so carriers behind one egress network, the
 * tenants of a host behind one NAT for instance, do not share one carrier's share, while no one network
 * holds more than half the carrier pool.
 */
export const MAX_LOOKUPS_PER_NETWORK = 2 * MAX_LOOKUPS_PER_CARRIER;
/**
 * An agent here's lookups at once, of the own pool: its send's and its messages' deliveries'. Not shared by
 * the agents of a domain, as every agent of a hosted domain is on it.
 */
export const MAX_LOOKUPS_PER_AGENT = 4;
const MAX_CACHED = 10_000;
const FETCH_TIMEOUT_MS = 10_000;

/** A small TTL cache that forgets its oldest entries first. */
class Cache<T> {
  readonly #entries = new Map<string, { value: T; until: number; at: number }>();

  get(key: string, now: number): { value: T; at: number } | null {
    const hit = this.#entries.get(key);
    if (!hit || hit.until <= now) return null;
    return hit;
  }

  set(key: string, value: T, now: number, ttl: number) {
    this.#entries.delete(key);
    if (ttl <= 0) return;
    this.#entries.set(key, { value, until: now + ttl, at: now });
    if (this.#entries.size > MAX_CACHED) this.#entries.delete(this.#entries.keys().next().value!);
  }
}

export type Peer =
  | { outcome: 'server'; server: string; document: ServerDocument | null }
  | { outcome: Exclude<Resolution['outcome'], 'server'> };

export interface AgentKeys {
  kind: AgentKind | 'unknown';
  keys: KeyEntry[];
}

/** Counts one lookup against whoever caused it, before it is made; throws 429 when they have none left. */
export type Charge = () => void;

/**
 * Who a lookup is for: an unauthenticated client (its `Charge`), the carrier of a delivery whose signature
 * verified (its origin, the network its delivery came from, and a `Charge` when its lookups are counted),
 * this server's own work for an agent here (its address), or, when absent, this server's own other work.
 */
export type Payer = Charge | { carrier: string; network?: string; charge?: Charge } | { agent: string };

/** The pool a payer's lookups run in. */
const poolOf = (payer: Payer | undefined): keyof typeof MAX_LOOKUPS =>
  payer === undefined || (typeof payer === 'object' && 'agent' in payer)
    ? 'own'
    : typeof payer === 'function'
      ? 'charged'
      : 'carrier';

export interface ResolverDeps {
  config: Config;
  store: Store;
  http: Http;
  dns: Dns;
  now: () => Date;
  log: Log;
  /** This server's own document, which is never fetched. */
  ownDocument: () => Promise<ServerDocument>;
  /** An agent here's keys and kind, or null. */
  localAgent: (address: string) => Promise<AgentKeys | null>;
  /** The public suffixes registrable domains are judged by; the shipped snapshot by default. */
  publicSuffixes?: PublicSuffixes;
  /** Counts a lookup a carrier's verified delivery asks for against its rate: a held key change's confirmation. */
  chargeCarrier?: (carrier: string) => void;
}

const REFUSED = Symbol('refused');

/** Mark an error as a lookup refused before it was made: for room, or by its payer's rate or domain bound. */
function refused<E>(e: E): E {
  if (typeof e === 'object' && e !== null) Object.defineProperty(e, REFUSED, { value: true });
  return e;
}

/** Whether an error is a lookup refused before it was made, so nothing was looked up. */
export const isRefusal = (e: unknown) => typeof e === 'object' && e !== null && REFUSED in e;

/** Store scope of the per-registrable-domain counts of lookups made before a signature verifies. */
const DOMAIN_LOOKUPS = 'lookup-domain';

/** A failure that may pass, as a cached document lookup remembers it. */
const TEMPORARY = 'temporary';

export class Resolver {
  readonly #d: ResolverDeps;
  readonly #domains = new Cache<Resolution>();
  readonly #servers = new Cache<ServerDocument | null | typeof TEMPORARY>();
  readonly #agents = new Cache<AgentKeys | null>();
  readonly #pending = new Map<string, Promise<unknown>>();
  readonly #continuity: Continuity;
  readonly #lookups = { charged: 0, carrier: 0, own: 0 };
  /** The carrier pool's lookups underway, per carrier and per network. */
  readonly #shares = new Map<string, number>();
  /** The tally of the `tallied` call underway, which lookups made (or joined) within it mark. */
  readonly #tally = new AsyncLocalStorage<{ made: boolean }>();

  constructor(deps: ResolverDeps) {
    this.#d = deps;
    this.#continuity = new Continuity({
      store: deps.store,
      now: deps.now,
      log: deps.log,
      holdSeconds: deps.config.keyChangeHoldSeconds,
      // Confirming a held change is work for the server that changed, in its own share of the carrier pool,
      // counted against its carrierLookup rate as its other lookups are.
      confirm: async (domain, server, keys) => {
        const payer = { carrier: server, charge: () => deps.chargeCarrier?.(server) };
        const again = await this.resolve(domain, { fresh: true, charge: payer });
        if (again.outcome !== 'server' || again.server !== server) return false;
        const doc = await this.serverDocument(server, { force: true, charge: payer });
        return (
          !!doc &&
          doc.keys
            .map(k => k.key)
            .sort()
            .join() === [...keys].sort().join()
        );
      },
    });
  }

  get #self() {
    return this.#d.config.origin;
  }

  /** Resolution of a domain, from the cache unless `fresh`. */
  async resolve(domain: string, opts: { fresh?: boolean; charge?: Payer } = {}): Promise<Resolution> {
    const now = this.#d.now().getTime();
    const hit = opts.fresh ? null : this.#domains.get(domain, now);
    if (hit) return hit.value;
    const override = this.#d.config.devResolve[domain];
    if (override) return { outcome: 'server', server: override.replace(/\/$/, ''), via: 'dns' };
    return this.#once(`resolve ${domain}`, opts.charge, domain, async () => {
      const r = await resolveDomain(
        domain,
        { txt: name => this.#d.dns.txt(name), get: url => this.#wellKnown(url) },
        { allowHttp: this.#d.config.dev },
      );
      this.#domains.set(domain, r, this.#d.now().getTime(), resolutionCacheMs(r, SERVER_TTL_MS));
      return r;
    });
  }

  /** Whether a resolution of `domain` is cached now, so a fresh one might answer otherwise. */
  isCached(domain: string): boolean {
    return this.#domains.get(domain, this.#d.now().getTime()) !== null;
  }

  /** Whether a domain names this server now. Throws 503 when that cannot be known. */
  async servesHere(domain: string, charge?: Payer, fresh = false): Promise<boolean> {
    const r = await this.resolve(domain, { charge, fresh });
    if (r.outcome === 'temporary') throw unavailable(`Could not resolve ${domain} just now.`);
    return r.outcome === 'server' && r.server === this.#self;
  }

  /**
   * The server a domain names and its document, trusted under key continuity's listing check. `document`
   * is null when the server serves no readable one. Throws 503 when resolution or the document failed for
   * now, or while a key change is held.
   */
  async peer(domain: string, charge?: Payer, opts: { fresh?: boolean } = {}): Promise<Peer> {
    const r = await this.resolve(domain, { charge, fresh: opts.fresh });
    if (r.outcome === 'temporary') throw unavailable(`Could not resolve ${domain} just now.`);
    if (r.outcome !== 'server') return r;
    const document = await this.serverDocument(r.server, { charge, refresh: opts.fresh });
    if (document && r.server !== this.#self) await this.#continuity.listed(domain, r.server, keysOf(document));
    return { outcome: 'server', server: r.server, document };
  }

  /** A signature by `key` from a domain's server, under `document`: held unless `key` is trusted to sign. */
  trustSigner(domain: string, server: string, key: string, document: ServerDocument): Promise<void> {
    return this.#continuity.signed(domain, server, key, keysOf(document));
  }

  /** A trusted signer signed afresh under `document`, vouching for each key it lists. */
  vouch(domain: string, document: ServerDocument): Promise<void> {
    return this.#continuity.vouch(domain, keysOf(document));
  }

  /**
   * A server's document, or null when it serves none that is readable. `refresh` fetches again when the
   * cached one is a minute old or more; `force` always does. Throws 503 on a failure that may pass.
   */
  async serverDocument(
    origin: string,
    opts: { refresh?: boolean; force?: boolean; charge?: Payer } = {},
  ): Promise<ServerDocument | null> {
    if (origin === this.#self) return this.#d.ownDocument();
    const now = this.#d.now().getTime();
    const hit = this.#servers.get(origin, now);
    const stale = hit && (opts.force || (opts.refresh && now - hit.at >= SERVER_DOCUMENT_REFETCH_MS));
    const doc =
      hit && !stale
        ? hit.value
        : await this.#once(`server ${origin}`, opts.charge, new URL(origin).hostname, async () => {
            let fetched: ServerDocument | null | typeof TEMPORARY;
            try {
              const res = await this.#getDocument(`${origin}/simon/server`);
              fetched = res && readServerDocument(res.body, origin, this.#d.now());
            } catch {
              fetched = TEMPORARY;
            }
            // A failure for now does not hide a document already known, but is remembered for a minute.
            const ttl = fetched === TEMPORARY ? TEMPORARY_CACHE_MS : DOCUMENT_CACHE_MS;
            if (fetched !== TEMPORARY || !hit) this.#servers.set(origin, fetched, this.#d.now().getTime(), ttl);
            return fetched;
          });
    if (doc === TEMPORARY) throw unavailable(`Could not fetch the server document of ${origin} just now.`);
    return doc;
  }

  /**
   * An agent's kind and keys: from the store for an agent here, otherwise from its signed agent document
   * on `server`. Null when there is no readable document. `refresh` skips the cache (a signature failed).
   * `charge` names who pays for the fetch, as `resolve`'s does.
   */
  async agentKeys(address: string, server: string, refresh = false, charge?: Payer): Promise<AgentKeys | null> {
    if (server === this.#self) return this.#d.localAgent(address);
    const now = this.#d.now();
    const key = `${server} ${address}`;
    // A cached answer that there is no document is kept against an unauthenticated caller's refetch too, as
    // section 4 allows, so naming an agent that does not exist costs one lookup in ten minutes, not one each.
    const hit = this.#agents.get(key, now.getTime());
    if (hit && (!refresh || (hit.value === null && typeof charge === 'function'))) return hit.value;
    const res = await this.#once(`agent ${key}`, charge, new URL(server).hostname, () =>
      this.#getDocument(`${server}/simon/agents/${addressSegment(address)}`),
    );
    let agent: AgentKeys | null = null;
    if (res) {
      const read = async (opts = {}) => {
        // The server document is fetched for whoever pays for the agent's, never on this server's own account.
        const doc = await this.serverDocument(server, { ...opts, charge });
        return doc && readAgentDocument(res.body, address, doc.keys, now);
      };
      // A document signed by a key the cached server document lacks: that document may be stale.
      agent = (await read()) ?? (await read({ refresh: true }));
    }
    this.#agents.set(key, agent, now.getTime(), DOCUMENT_CACHE_MS);
    return agent;
  }

  /** How many more lookups a payer may start now: its pool's room, and for a carrier, its shares'. */
  room(payer: Payer | undefined): number {
    const pool = poolOf(payer);
    const shares = this.#sharesOf(payer).map(([k, max]) => max - (this.#shares.get(k) ?? 0));
    return Math.max(0, Math.min(MAX_LOOKUPS[pool] - this.#lookups[pool], ...shares));
  }

  /**
   * The shares of its pool a payer's lookups count against, with their caps: a carrier's and its network's, or
   * an agent's.
   */
  #sharesOf(payer: Payer | undefined): [string, number][] {
    if (typeof payer !== 'object') return [];
    if ('agent' in payer) return [[`agent ${payer.agent}`, MAX_LOOKUPS_PER_AGENT]];
    const network: [string, number][] = payer.network ? [[`network ${payer.network}`, MAX_LOOKUPS_PER_NETWORK]] : [];
    return [[`carrier ${payer.carrier}`, MAX_LOOKUPS_PER_CARRIER], ...network];
  }

  /**
   * Run `fn`, setting `tally.made` when a lookup is made within it (one it starts, or one underway that it
   * joins). A lookup refused before it was made, or answered from the cache, sets nothing.
   */
  tallied<T>(tally: { made: boolean }, fn: () => Promise<T>): Promise<T> {
    return this.#tally.run(tally, fn);
  }

  /**
   * Network work, bounded: one lookup per key at a time (concurrent asks share it), charged to whoever pays
   * before it starts (and only when there is room for it), and at most MAX_LOOKUPS of its pool at once,
   * MAX_LOOKUPS_PER_CARRIER for one carrier and MAX_LOOKUPS_PER_NETWORK for one network. A lookup for an unauthenticated caller also
   * counts against the registrable domain of `name`, the name looked up (`#chargeDomain`).
   */
  #once<T>(key: string, payer: Payer | undefined, name: string, work: () => Promise<T>): Promise<T> {
    const pending = this.#pending.get(key);
    if (pending) {
      const tally = this.#tally.getStore();
      return (pending as Promise<T>).then(
        value => {
          if (tally) tally.made = true;
          return value;
        },
        error => {
          if (tally && !isRefusal(error)) tally.made = true;
          throw error;
        },
      );
    }
    const pool = poolOf(payer);
    const shares = this.#sharesOf(payer);
    const full = shares.some(([k, max]) => (this.#shares.get(k) ?? 0) >= max);
    if (this.#lookups[pool] >= MAX_LOOKUPS[pool] || full) {
      throw refused(unavailable('This server is busy with lookups; try again shortly.', 5));
    }
    this.#lookups[pool]++;
    for (const [k] of shares) this.#shares.set(k, (this.#shares.get(k) ?? 0) + 1);
    const charged = pool === 'charged' ? this.#chargeDomain(name) : Promise.resolve(undefined);
    const tally = this.#tally.getStore();
    const p = charged
      .then(async releaseDomain => {
        try {
          // Both admissions must succeed before either account pays for outbound work.
          (typeof payer === 'function' ? payer : payer && 'charge' in payer ? payer.charge : undefined)?.();
        } catch (error) {
          await releaseDomain?.();
          throw refused(error);
        }
        if (tally) tally.made = true;
        return work();
      })
      .finally(() => {
        this.#lookups[pool]--;
        for (const [k] of shares) {
          const n = this.#shares.get(k)! - 1;
          if (n) this.#shares.set(k, n);
          else this.#shares.delete(k);
        }
        this.#pending.delete(key);
      });
    this.#pending.set(key, p);
    return p;
  }

  /**
   * Count one lookup made before a signature verifies against the registrable domain of `name`, in a store
   * counter per window, so every process on the store shares the bound; `429` past it, and the lookup is not
   * made. A reservation refused here or by the caller's quota is returned without consuming a lookup.
   */
  async #chargeDomain(name: string): Promise<() => Promise<void>> {
    const { store, config } = this.#d;
    const rate = config.rates.lookupDomain;
    const now = this.#d.now().getTime();
    const window = Math.floor(now / (rate.seconds * 1000));
    const ends = (window + 1) * rate.seconds * 1000;
    const id = `${registrableDomain(name, this.#d.publicSuffixes ?? shippedPublicSuffixes())} ${window}`;
    const at = new Date(now).toISOString();
    const count = await store.count(DOMAIN_LOOKUPS, id, new Date(ends).toISOString(), at);
    const release = async () => {
      await store.count(DOMAIN_LOOKUPS, id, new Date(ends).toISOString(), at, -1);
    };
    if (count <= rate.limit) return release;
    await release();
    throw refused(rateLimited(Math.max(1, Math.ceil((ends - now) / 1000))));
  }

  /** GET a document: the answer when 200, null when there is none, 503 on a failure that may pass. */
  async #getDocument(url: string): Promise<HttpResponse | null> {
    let res: HttpResponse;
    try {
      res = await this.#d.http.request({
        method: 'GET',
        url,
        maxBytes: MAX_DOCUMENT_BYTES,
        timeoutMs: FETCH_TIMEOUT_MS,
      });
    } catch (e) {
      const kind = e instanceof Unreachable ? e.kind : 'failed';
      if (kind === 'absent' || kind === 'forbidden' || kind === 'too_large') return null;
      throw unavailable(`Could not fetch ${url} just now.`);
    }
    if (res.status === 429 || res.status >= 500) throw unavailable(`${url} answered ${res.status}.`);
    return res.status === 200 ? res : null;
  }

  /**
   * The well-known fetch as resolution needs it: null when there is no answer to be had (no such host, a
   * refused connection, a certificate not valid for the host, an address this server may not call, or an
   * answer too large to be one); a throw for a failure that may pass.
   */
  async #wellKnown(url: string): Promise<{ status: number; body: Uint8Array } | null> {
    try {
      return await this.#d.http.request({
        method: 'GET',
        url,
        maxBytes: MAX_DOCUMENT_BYTES,
        timeoutMs: FETCH_TIMEOUT_MS,
      });
    } catch (e) {
      const kind = e instanceof Unreachable ? e.kind : 'failed';
      if (['absent', 'forbidden', 'refused', 'certificate', 'too_large'].includes(kind)) return null;
      throw e;
    }
  }
}

const keysOf = (doc: ServerDocument) => doc.keys.map(k => k.key);
