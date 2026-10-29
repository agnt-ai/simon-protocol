/** Verified, signed wakeups for clients that do not hold a sync connection open. */
import crypto from 'node:crypto';
import { canonicalBytes, invalid, signRequest } from '@agnt-sdk/simon-protocol';
import { readBody } from './account.ts';
import { authenticateAgent } from './auth.ts';
import { iso, later, type Context } from './context.ts';
import { conflict, notFound } from './errors.ts';
import { json, type Route } from './http.ts';
import type { Webhook } from './store/store.ts';

const hash = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
const matches = (code: string, expected: string) => {
  const actual = Buffer.from(hash(code), 'hex'),
    wanted = Buffer.from(expected, 'hex');
  return actual.length === wanted.length && crypto.timingSafeEqual(actual, wanted);
};
const LIMIT = 5,
  CONCURRENCY = 4,
  TIMEOUT_MS = 10_000,
  LEASE_MS = 30_000;
const FAILURE_MS = 3 * 86_400_000;

async function post(ctx: Context, url: string, payload: object): Promise<boolean> {
  const body = canonicalBytes(payload);
  const headers = signRequest(ctx.config.serverKey, {
    method: 'POST',
    url,
    body,
    now: ctx.now().getTime(),
    server: ctx.config.origin,
  });
  const res = await ctx.http.request({
    method: 'POST',
    url,
    body,
    headers: { ...headers, 'content-type': 'application/json' },
    maxBytes: 16_384,
    timeoutMs: TIMEOUT_MS,
  });
  return res.status >= 200 && res.status < 300;
}

export function webhookRoutes(ctx: Context): Route[] {
  const owned = async (id: string, address: string) => {
    const row = await ctx.store.webhook(id);
    if (!row || row.address !== address) throw notFound();
    return row;
  };
  return [
    {
      method: 'POST',
      path: '/simon/webhooks',
      async handle(req) {
        const agent = await authenticateAgent(ctx, req);
        ctx.rate.hit('send', agent.address);
        const body = readBody(req.body, ['url']);
        let url: URL;
        try {
          url = new URL(body.url ?? '');
        } catch {
          throw invalid('url must be an HTTPS URL.', { field: 'url' });
        }
        // Development accepts http: here as it does for origins (protocol.md section 3), so the conformance
        // suite's simulator, which listens on a local port, can receive wakeups.
        const scheme = url.protocol === 'https:' || (ctx.config.dev && url.protocol === 'http:');
        if (!scheme || url.username || url.password || url.hash || url.href.length > 2000) {
          throw invalid('url must be an HTTPS URL without credentials or a fragment, at most 2000 characters.', {
            field: 'url',
          });
        }
        const code = crypto.randomBytes(32).toString('base64url');
        const row: Webhook = {
          id: crypto.randomUUID(),
          address: agent.address,
          url: url.href,
          codeHash: hash(code),
          verified: false,
          createdAt: iso(ctx.now()),
          failingSince: null,
        };
        if (!(await ctx.store.addWebhook(row, LIMIT)))
          throw conflict('too_many_webhooks', `An agent holds at most ${LIMIT} webhooks.`);
        // A failed verification post leaves an unverified row the owner may delete and recreate. It sends
        // no wakeups, and never deletes a row that the receiver verified while the HTTP answer was delayed.
        ctx.defer(async () => {
          await post(ctx, row.url, { type: 'verify', code });
        });
        return json({ id: row.id }, 201);
      },
    },
    {
      method: 'POST',
      path: '/simon/webhooks/:id/verify',
      async handle(req) {
        const agent = await authenticateAgent(ctx, req);
        const row = await owned(req.params.id, agent.address);
        const { code } = readBody(req.body, ['code']);
        if (typeof code !== 'string' || !matches(code, row.codeHash))
          throw invalid('The verification code does not match.', { field: 'code' });
        await ctx.store.verifyWebhook(row.id);
        await ctx.store.wakeWebhooks(agent.address, iso(ctx.now()));
        ctx.wake();
        return json({ id: row.id, verified: true });
      },
    },
    {
      method: 'DELETE',
      path: '/simon/webhooks/:id',
      async handle(req) {
        const agent = await authenticateAgent(ctx, req);
        const row = await owned(req.params.id, agent.address);
        await ctx.store.deleteWebhook(row.id);
        return json({ deleted: true });
      },
    },
  ];
}

/** Each delivery is leased, so a late attempt cannot settle or disable a successor's webhook. */
export class WebhookPoster {
  readonly #ctx: Context;
  readonly #running = new Set<Promise<void>>();
  #active = 0;
  constructor(ctx: Context) {
    this.#ctx = ctx;
  }
  async tick(): Promise<number> {
    const room = CONCURRENCY - this.#active;
    if (room <= 0) return 0;
    const ctx = this.#ctx,
      now = ctx.now(),
      token = crypto.randomUUID();
    const rows = await ctx.store.claimWebhooks(iso(now), room, later(now, 1000), {
      token,
      until: later(now, LEASE_MS),
    });
    this.#active += rows.length;
    for (const row of rows) {
      const task = this.#deliver(row, token)
        .catch(error => ctx.log('error', 'webhook attempt failed', { id: row.id, error: String(error) }))
        .finally(() => {
          this.#active--;
          this.#running.delete(task);
        });
      this.#running.add(task);
    }
    return rows.length;
  }
  async #deliver(row: Webhook, token: string): Promise<void> {
    const ctx = this.#ctx;
    const current = await ctx.store.webhook(row.id);
    const agent = await ctx.store.agentByAddress(row.address);
    if (!current || !current.verified || current.url !== row.url || !agent || agent.retiredAt) {
      await ctx.store.settleWebhook(row.id, row.failingSince, null, token, true);
      return;
    }
    let success = false;
    try {
      success = await post(ctx, row.url, { type: 'changed', agent: row.address });
    } catch {
      /* Retry below. */
    }
    const now = ctx.now();
    const failingSince = success ? null : (row.failingSince ?? iso(now));
    const disable = failingSince !== null && now.getTime() - Date.parse(failingSince) >= FAILURE_MS;
    await ctx.store.settleWebhook(row.id, failingSince, success || disable ? null : later(now, 60_000), token, disable);
  }
  async idle(): Promise<void> {
    while (this.#running.size) await Promise.all(this.#running);
  }
}
