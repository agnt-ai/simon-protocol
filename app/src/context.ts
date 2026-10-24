/**
 * What every module shares, built once by `createApp`: the configuration, the database, the outside world
 * (mail, text messages, DNS, outbound HTTP), the server's api once the server exists, and this
 * application's own agents. Nothing is a module-level singleton, so several applications run in one
 * process, as the tests do.
 */
import type { Dns, Extension, Http, Log, ServerApi } from 'simon-server';
import type { Db } from 'mongodb';
import type { z } from 'zod';
import type { Mailer } from './adapters/mail.ts';
import type { Sms } from './adapters/sms.ts';
import type { AppConfig, ModuleName } from './config.ts';
import type { ApiRoute } from './http/route.ts';
import type { SystemAgents } from './system.ts';

export interface Ctx {
  config: AppConfig;
  db: Db;
  mail: Mailer | null;
  sms: Sms | null;
  dns: Dns;
  http: Http;
  log: Log;
  /** The server's api. Read only once the server exists: in hooks, routes and background work. */
  readonly api: ServerApi;
  system: SystemAgents;
  now(): Date;
  /** Run work after the answer, tracked so the application can wait for it (tests, shutdown). */
  defer(task: () => Promise<unknown>): void;
  /** Retire an agent here (spec section 2.2), and have every module forget what it kept about it. */
  retire(address: string): Promise<void>;
  /** Have every module forget a person: the owner window's erasure, once their agents are retired. */
  erase(person: string): Promise<void>;
}

/**
 * One module of the application: its routes, its hooks into the server, its background work, and what it
 * adds to an agent's check-in. Everything it adds to the server goes through the extension API.
 */
export interface Module {
  name: ModuleName | 'agents';
  routes?: ApiRoute[];
  hooks?: Omit<Extension, 'name' | 'routes'>;
  /** Create collections' indexes. Run once at startup. */
  init?(): Promise<void>;
  /** Background work, run by the application's worker; answers how much it did, so it runs again soon. */
  work?(): Promise<number>;
  home?: HomeSection;
  /** What the module forgets when an agent retires, and when a person is erased. */
  forget?: Forget;
}

export interface Forget {
  agent?(address: string): Promise<void>;
  person?(id: string): Promise<void>;
}

/** What a module adds to `GET /api/agents/me/home`: fields of its own, and things needing attention. */
export interface HomeSection {
  fields: Record<string, z.ZodType>;
  build(address: string): Promise<{ fields: Record<string, unknown>; attention: Attention[] }>;
}

export interface Attention {
  kind: string;
  message: string;
}

/**
 * The owner window's activity log: what any agent did as a person. Modules record into it; with the
 * owner module off, nothing is kept.
 */
export interface Activity {
  record(person: string, kind: string, fields?: ActivityFields): Promise<void>;
}

export interface ActivityFields {
  /** The agent that acted, by address. */
  agent?: string;
  /**
   * The identifier the entry concerns, so only owner sessions that proved it see it: by default the acting
   * agent's principal. Without either, it concerns the whole person.
   */
  identifier?: string;
  message?: string;
  intro?: string;
  [field: string]: unknown;
}

export const noActivity: Activity = { record: async () => {} };
