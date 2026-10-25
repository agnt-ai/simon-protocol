/**
 * This application's rate limits: fixed windows counted in the store, so a limit holds across processes.
 * Each counts calls, per the key its caller gives. Overrides: `SIMON_APP_RATES=name=count/seconds,...`.
 */
import type { ServerApi } from '@agnt-sdk/simon-server';
import { fail, list, type Env } from './env.ts';
import { rateLimited } from './errors.ts';

export interface Rate {
  limit: number;
  seconds: number;
}

export const DEFAULT_RATES = {
  /** Directory reads (resolve, search, reach, graph), per agent. */
  discovery: { limit: 300, seconds: 3600 },
  /** Writes of edges or attestations, per agent. */
  directoryWrites: { limit: 200, seconds: 3600 },
  /** Principal-reserved calls held for an agent's person, per agent. */
  requests: { limit: 100, seconds: 86_400 },
  /** Introduction requests, per agent. */
  intros: { limit: 20, seconds: 86_400 },
  /** Codes sent to one email address or phone number, by everyone together. */
  codes: { limit: 5, seconds: 3600 },
  /** Codes one asker sends, to anyone: an owner session, a person, an agent registering. */
  codesByAsker: { limit: 10, seconds: 86_400 },
  /** Text-message codes this server sends in all; past it, none until the day turns, and the log says so. */
  smsCodes: { limit: 1000, seconds: 86_400 },
  /** Email codes this server sends in all. */
  emailCodes: { limit: 10_000, seconds: 86_400 },
  /** Emails the bridge sends for one agent, and for one person across their agents. */
  bridgeEmails: { limit: 100, seconds: 86_400 },
  /** Emailed replies taken for one bridged message. */
  bridgeReplies: { limit: 20, seconds: 86_400 },
  /** Owner window calls, per person. */
  owner: { limit: 3000, seconds: 3600 },
  /** Sign-in pages, client registrations and recovery links, per client IP. */
  pages: { limit: 60, seconds: 3600 },
  /** Anonymous profile reads, per client IP. */
  publicReads: { limit: 600, seconds: 3600 },
} satisfies Record<string, Rate>;

export type RateName = keyof typeof DEFAULT_RATES;
export type Rates = Record<RateName, Rate>;

export function readRates(env: Env): Rates {
  const rates: Rates = { ...DEFAULT_RATES };
  for (const entry of list(env, 'SIMON_APP_RATES')) {
    const m = /^([a-zA-Z]+)=(\d+)\/(\d+)$/.exec(entry);
    if (!m || !(m[1] in DEFAULT_RATES) || Number(m[2]) < 1 || Number(m[3]) < 1) {
      fail(
        `SIMON_APP_RATES: ${entry} is not name=count/seconds with a name of ${Object.keys(DEFAULT_RATES).join(', ')}.`,
      );
    }
    rates[m[1] as RateName] = { limit: Number(m[2]), seconds: Number(m[3]) };
  }
  return rates;
}

/** Count one call against `rate` for `key`; past the limit, `429 rate_limited` with when to retry. */
export async function spend(api: ServerApi, name: RateName, rate: Rate, key: string): Promise<void> {
  const now = api.now().getTime();
  const windowMs = rate.seconds * 1000;
  const start = now - (now % windowMs);
  const end = new Date(start + windowMs);
  const count = await api.store.count(
    `rate:${name}`,
    `${key}\n${start}`,
    end.toISOString(),
    new Date(now).toISOString(),
  );
  if (count > rate.limit) throw rateLimited(Math.max(1, Math.ceil((end.getTime() - now) / 1000)));
}

/** A client's network for per-IP limits: IPv6 by /64, as the server counts it. */
export { clientKey } from '@agnt-sdk/simon-server';
