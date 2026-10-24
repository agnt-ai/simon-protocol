/**
 * Rate limits: fixed windows, in this process's memory. Each limit is a count per window per key; a client
 * IP is keyed by `clientKey` (IPv6 by /64). Memory is bounded: past `maxKeys`, expired windows go first,
 * then the oldest. A server run as several processes divides each limit by their number, or keeps these
 * counts in a shared store.
 */
import type { Rate, RateName } from './config.ts';
import { rateLimited } from './errors.ts';
import { clientKey, inNetworks, type Network } from './net/ip.ts';

/**
 * The rates counted per client that a client's network may be exempt from. `lookup` and `badSignature`
 * are never exempt: they bound the work deliveries from other servers make, which no exempt client needs.
 */
export type ClientRateName = 'request' | 'register' | 'codeClient' | 'agentMiss';

interface Window {
  resetAt: number;
  count: number;
  values?: Set<string>;
}

export class RateLimiter {
  readonly #windows = new Map<string, Window>();
  readonly #rates: Record<RateName, Rate>;
  readonly #now: () => Date;
  readonly #maxKeys: number;
  readonly #exempt: readonly Network[];

  /** `exempt`: networks whose clients the client rates do not count, such as a hosting service's own. */
  constructor(rates: Record<RateName, Rate>, now: () => Date, exempt: readonly Network[] = [], maxKeys = 100_000) {
    this.#rates = rates;
    this.#now = now;
    this.#exempt = exempt;
    this.#maxKeys = maxKeys;
  }

  #window(name: RateName, key: string): Window {
    const id = `${name}\n${key}`;
    const now = this.#now().getTime();
    let w = this.#windows.get(id);
    if (!w || w.resetAt <= now) {
      this.#windows.delete(id);
      if (this.#windows.size >= this.#maxKeys) this.#evict(now);
      w = { resetAt: now + this.#rates[name].seconds * 1000, count: 0 };
      this.#windows.set(id, w);
    }
    return w;
  }

  #evict(now: number) {
    for (const [id, w] of this.#windows) if (w.resetAt <= now) this.#windows.delete(id);
    for (const id of this.#windows.keys()) {
      if (this.#windows.size < this.#maxKeys) break;
      this.#windows.delete(id);
    }
  }

  #refuse(w: Window): never {
    throw rateLimited(Math.max(1, Math.ceil((w.resetAt - this.#now().getTime()) / 1000)));
  }

  /** Count one event, or refuse with 429 when the window is full. */
  hit(name: RateName, key: string): void {
    const w = this.#window(name, key);
    if (w.count >= this.#rates[name].limit) this.#refuse(w);
    w.count++;
  }

  /** Count one event for the client at `ip`, unless its network is exempt. */
  hitClient(name: ClientRateName, ip: string): void {
    if (!inNetworks(ip, this.#exempt)) this.hit(name, clientKey(ip));
  }

  /** Take back an event `hitClient` counted that turned out not to be one of what the rate counts. */
  refundClient(name: ClientRateName, ip: string): void {
    if (inNetworks(ip, this.#exempt)) return;
    const w = this.#window(name, clientKey(ip));
    w.count = Math.max(0, w.count - 1);
  }

  /** Refuse with 429 when the window is full, without counting. */
  check(name: RateName, key: string): void {
    const w = this.#window(name, key);
    if (w.count >= this.#rates[name].limit) this.#refuse(w);
  }

  /** Count only values not seen in this window (destinations, say), all or none. */
  distinct(name: RateName, key: string, values: string[]): void {
    const w = this.#window(name, key);
    w.values ??= new Set();
    const fresh = [...new Set(values)].filter(v => !w.values!.has(v));
    if (w.values.size + fresh.length > this.#rates[name].limit) this.#refuse(w);
    for (const v of fresh) w.values.add(v);
  }
}
