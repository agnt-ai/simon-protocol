/**
 * Webhooks: a wake-up call, never the source of truth. An agent's endpoint hears `inbox.changed` and then
 * reads its inbox; a person's endpoint hears the part of their activity log the session that made it
 * may see. Each POST is signed `simon-webhook-signature: v1=<hex HMAC-SHA256(secret, timestamp + "." +
 * body)>`, retried with backoff, and an endpoint that keeps failing is switched off (the inbox still has
 * everything). Where an agent is woken is its principal's to decide: its key alone only lists them.
 *
 * Hooks: on.inbox.
 */
import type { Agent } from '@agnt-protocol/server';
import { z } from 'zod';
import type { Ctx, Module } from '../../context.ts';
import { conflict, invalid, notFound } from '../../lib/errors.ts';
import { newId } from '../../lib/ids.ts';
import { randomToken, seal, unseal, webhookSignature } from '../../lib/secrets.ts';
import { pageOf } from '../../store/db.ts';
import { Queue } from '../../store/queue.ts';
import { agent, defineRoute, Paged, PageQuery, type ApiRoute, type Caller } from '../../http/route.ts';

const MAX_ACTIVE = 5;
const SWITCH_OFF_AFTER = 50;
/** A webhook answers quickly or not at all; a slow one holds up only its own posts. */
const TIMEOUT_MS = 5_000;
/** Posts in flight at once, at most one per webhook. */
const CONCURRENCY = 16;
/** How long a delivery is kept once it went, or gave up. */
const KEEP_MS = 7 * 86_400_000;
/** Eight tries over about ten hours. */
const RETRY_SECONDS = [10, 60, 300, 1800, 3600, 3 * 3600, 6 * 3600];

interface Hook {
  _id: string;
  /** An agent's address, or a person's id. */
  owner: string;
  /** A person's endpoint hears only activity about these identifiers, the session's that made it; null hears all. */
  scope: string[] | null;
  url: string;
  secretSealed: string;
  active: boolean;
  failures: number;
  lastSuccessAt: Date | null;
  createdAt: Date;
}

export const Webhook = z
  .object({
    id: z.string(),
    url: z.string(),
    active: z.boolean(),
    failures: z.number().int(),
    lastSuccessAt: z.string().nullable(),
    createdAt: z.string(),
  })
  .meta({ id: 'Webhook' });

const view = (h: Hook) => ({
  id: h._id,
  url: h.url,
  active: h.active,
  failures: h.failures,
  lastSuccessAt: h.lastSuccessAt?.toISOString() ?? null,
  createdAt: h.createdAt.toISOString(),
});

export class Webhooks {
  readonly #ctx: Ctx;
  readonly #hooks;
  readonly queue: Queue<{ hook: string; body: string }>;

  constructor(ctx: Ctx) {
    this.#ctx = ctx;
    this.#hooks = ctx.db.collection<Hook>('webhooks.hooks');
    this.queue = new Queue(ctx.db, 'webhooks.deliveries', RETRY_SECONDS);
  }

  async create(owner: string, url: string, scope: string[] | null = null) {
    if (!validUrl(url, this.#ctx.config.server.dev))
      throw invalid('url is an https URL with no credentials.', { field: 'url' });
    if ((await this.#hooks.countDocuments({ owner, active: true })) >= MAX_ACTIVE) {
      throw conflict('too_many_webhooks', `At most ${MAX_ACTIVE} active webhooks.`);
    }
    const secret = `whsec_${randomToken(24)}`;
    const hook: Hook = {
      _id: newId('webhook'),
      owner,
      scope,
      url,
      secretSealed: seal(this.#ctx.config.dataKey, secret),
      active: true,
      failures: 0,
      lastSuccessAt: null,
      createdAt: this.#ctx.now(),
    };
    await this.#hooks.insertOne(hook);
    return { ...view(hook), secret };
  }

  async list(owner: string, page: { after?: string; limit: number }, within?: string[]) {
    const hooks = await this.#hooks
      .find({ ...this.#mine(owner, within), ...(page.after ? { _id: { $gt: page.after } } : {}) })
      .sort({ _id: 1 })
      .limit(page.limit + 1)
      .toArray();
    return pageOf(hooks, page, view);
  }

  async remove(owner: string, id: string, within?: string[]) {
    if (!(await this.#hooks.deleteOne({ _id: id, ...this.#mine(owner, within) })).deletedCount)
      throw notFound('webhook');
  }

  /** Switch a failing endpoint back on. */
  async reactivate(owner: string, id: string, within?: string[]) {
    const hook = await this.#hooks.findOneAndUpdate(
      { _id: id, ...this.#mine(owner, within) },
      { $set: { active: true, failures: 0 } },
      { returnDocument: 'after' },
    );
    if (!hook) throw notFound('webhook');
    return view(hook);
  }

  /** An owner's endpoints, those whose scope lies within some identifiers when given. */
  #mine(owner: string, within?: string[]) {
    return { owner, ...(within ? { scope: { $not: { $elemMatch: { $nin: within } } } } : {}) };
  }

  /** A person's endpoints become another's when the two merge. */
  async reassign(from: string, to: string) {
    await this.#hooks.updateMany({ owner: from }, { $set: { owner: to } });
  }

  /** An owner's endpoints, and what waits to be posted to them, are gone. */
  async forget(owner: string) {
    const ids = (await this.#hooks.find({ owner }, { projection: { _id: 1 } }).toArray()).map(h => h._id);
    await this.#hooks.deleteMany({ owner });
    await this.queue.drop('hook', ids);
  }

  /** Whether any of an owner's endpoints was switched off, for its check-in. */
  async switchedOff(owner: string): Promise<number> {
    return this.#hooks.countDocuments({ owner, active: false });
  }

  /** Queue a payload for every active endpoint of an owner whose scope covers the identifier it concerns. */
  async announce(owner: string, payload: Record<string, unknown>, identifier: string | null = null) {
    const now = this.#ctx.now();
    const covers = identifier ? { $or: [{ scope: null }, { scope: identifier }] } : {};
    for (const hook of await this.#hooks.find({ owner, active: true, ...covers }).toArray()) {
      const id = newId('delivery');
      await this.queue.push(
        id,
        { hook: hook._id, body: JSON.stringify({ id, ...payload, sentAt: now.toISOString() }) },
        now,
      );
    }
  }

  /** Background work: post due deliveries, and drop old ones. */
  async work(): Promise<number> {
    const pruned = await this.queue.prune(new Date(this.#ctx.now().getTime() - KEEP_MS));
    return pruned + (await this.#drain());
  }

  #drain(): Promise<number> {
    return this.queue.drain(
      () => this.#ctx.now(),
      100,
      async ({ hook: id, body }) => {
        const hook = await this.#hooks.findOne({ _id: id });
        if (!hook?.active) return { fail: 'webhook removed or switched off' };
        const timestamp = String(Math.floor(this.#ctx.now().getTime() / 1000));
        const signature = webhookSignature(unseal(this.#ctx.config.dataKey, hook.secretSealed), timestamp, body);
        let error: string;
        try {
          const res = await this.#ctx.http.request({
            method: 'POST',
            url: hook.url,
            headers: {
              'content-type': 'application/json',
              'simon-webhook-timestamp': timestamp,
              'simon-webhook-signature': `v1=${signature}`,
            },
            body: Buffer.from(body),
            maxBytes: 65_536,
            timeoutMs: TIMEOUT_MS,
          });
          if (res.status >= 200 && res.status < 300) {
            await this.#hooks.updateOne({ _id: id }, { $set: { failures: 0, lastSuccessAt: this.#ctx.now() } });
            return 'done';
          }
          error = `HTTP ${res.status}`;
        } catch (e) {
          error = e instanceof Error ? e.message : String(e);
        }
        const failed = await this.#hooks.findOneAndUpdate(
          { _id: id },
          { $inc: { failures: 1 } },
          { returnDocument: 'after' },
        );
        if (failed && failed.failures >= SWITCH_OFF_AFTER)
          await this.#hooks.updateOne({ _id: id }, { $set: { active: false } });
        return { retry: error };
      },
      { concurrency: CONCURRENCY, apart: 'hook' },
    );
  }
}

function validUrl(raw: string, dev: boolean): boolean {
  try {
    const u = new URL(raw);
    return !u.username && !u.password && (u.protocol === 'https:' || (dev && u.protocol === 'http:'));
  } catch {
    return false;
  }
}

/**
 * Routes for an owner's endpoints, under `prefix`: an agent's (`/api/agents/me`) or a person's (`/api/me`).
 * `caller` reads them and `writer` changes them; `scope` gives the identifiers a person's session proved.
 */
export function webhookRoutes<C>(
  webhooks: Webhooks,
  o: {
    prefix: string;
    tag: string;
    caller: Caller<C>;
    writer: Caller<C>;
    owner: (caller: C) => string;
    scope?: (caller: C) => string[];
    ids: string;
  },
): ApiRoute[] {
  const reserved = o.writer !== o.caller ? 'Principal-reserved.' : undefined;
  const Id = z.object({ webhookId: z.string().max(40) });
  return [
    defineRoute({
      method: 'GET',
      path: `${o.prefix}/webhooks`,
      operationId: `list${o.ids}Webhooks`,
      tag: o.tag,
      summary: 'Webhooks',
      caller: o.caller,
      query: PageQuery,
      response: Paged(Webhook),
      handle: async ({ caller, query }) => webhooks.list(o.owner(caller), query, o.scope?.(caller)),
    }),
    defineRoute({
      method: 'POST',
      path: `${o.prefix}/webhooks`,
      operationId: `create${o.ids}Webhook`,
      tag: o.tag,
      summary: 'Be woken at a URL; the secret is shown once',
      description: reserved,
      caller: o.writer,
      body: z.strictObject({ url: z.string().max(2000) }),
      status: 201,
      response: Webhook.extend({ secret: z.string() }),
      handle: async ({ caller, body }) => webhooks.create(o.owner(caller), body.url, o.scope?.(caller) ?? null),
    }),
    defineRoute({
      method: 'DELETE',
      path: `${o.prefix}/webhooks/:webhookId`,
      operationId: `delete${o.ids}Webhook`,
      tag: o.tag,
      summary: 'Remove a webhook',
      description: reserved,
      caller: o.writer,
      params: Id,
      status: 204,
      handle: async ({ caller, params }) => webhooks.remove(o.owner(caller), params.webhookId, o.scope?.(caller)),
    }),
    defineRoute({
      method: 'POST',
      path: `${o.prefix}/webhooks/:webhookId/reactivate`,
      operationId: `reactivate${o.ids}Webhook`,
      tag: o.tag,
      summary: 'Switch a webhook that kept failing back on',
      description: reserved,
      caller: o.writer,
      params: Id,
      response: Webhook,
      handle: async ({ caller, params }) => webhooks.reactivate(o.owner(caller), params.webhookId, o.scope?.(caller)),
    }),
  ];
}

export function webhooksModule(ctx: Ctx, deps: { reserved: Caller<Agent> }) {
  const webhooks = new Webhooks(ctx);
  const module: Module = {
    name: 'webhooks',
    routes: webhookRoutes(webhooks, {
      prefix: '/api/agents/me',
      tag: 'Webhooks',
      caller: agent,
      writer: deps.reserved,
      owner: a => a.address,
      ids: '',
    }),
    hooks: {
      on: {
        inbox: ({ address, message }) => webhooks.announce(address, { type: 'inbox.changed', message: message.id }),
      },
    },
    init: () => webhooks.queue.init(),
    work: () => webhooks.work(),
    forget: { agent: address => webhooks.forget(address), person: id => webhooks.forget(id) },
    home: {
      fields: {},
      async build(address) {
        const off = await webhooks.switchedOff(address);
        return {
          fields: {},
          attention: off
            ? [{ kind: 'webhook_off', message: `${off} webhook(s) were switched off after failing; reactivate them.` }]
            : [],
        };
      },
    },
  };
  return { module, webhooks };
}
