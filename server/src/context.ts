/**
 * What every part of the core shares: built once by `createServer`, passed to each module.
 */
import type { Config } from './config.ts';
import type { Hooks, Log } from './extensions.ts';
import type { Http } from './net/fetch.ts';
import type { RateLimiter } from './rate.ts';
import type { Resolver } from './resolver.ts';
import type { Store } from './store/store.ts';
import type { Changes } from './sync.ts';

/**
 * What this server sends an address's mailbox (CLIENT.md register and "Recommended host practice"): the
 * code that binds the address to a key; the news of a recovery waiting until `completesAt`, with the code
 * that cancels it; in place of a code asked for while one waits, the news that it is pending, with another
 * code that cancels it; and the news that a key of the agent cancelled one.
 */
export type MailboxNote =
  | { type: 'code'; code: string }
  | { type: 'recovery'; key: string; completesAt: string; cancelCode: string }
  | { type: 'recoveryPending'; key: string; completesAt: string; cancelCode: string }
  | { type: 'recoveryCancelled' };

/** Sends a note to an address, by whatever channel reaches its mailbox. */
export type MailboxSender = (address: string, note: MailboxNote) => Promise<void>;

export interface Context {
  config: Config;
  store: Store;
  now: () => Date;
  log: Log;
  http: Http;
  resolver: Resolver;
  rate: RateLimiter;
  hooks: Hooks;
  /** Null when no sender is configured: the code flow is then unavailable. */
  mailbox: MailboxSender | null;
  /** Syncs held open, waiting for news of their agents. */
  changes: Changes;
  /** Ask the worker to run soon: work is waiting. */
  wake(): void;
  /**
   * Start work the answer does not wait for: it begins at once and runs on beside the answer, tracked so the
   * server can wait for it on close.
   */
  defer(task: () => Promise<unknown>): void;
}

export const iso = (d: Date) => d.toISOString();
export const later = (now: Date, ms: number) => new Date(now.getTime() + ms).toISOString();
