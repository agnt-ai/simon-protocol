/**
 * `createServer`: the core assembled from its configuration, its store, the outside world (DNS, HTTP, a
 * clock, a code sender) and any extensions. Everything outside is injectable, so tests run whole
 * federations in one process on a fake network and a movable clock.
 */
import http from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { bodyTooLarge, WireError } from '@agnt-sdk/simon-protocol';
import { addKey, cancelRecovery, endGrant, getAccount, getRecovery, revokeKey, unpair } from './account.ts';
import { authenticateAgent } from './auth.ts';
import type { Config } from './config.ts';
import { iso, type Context, type MailboxSender } from './context.ts';
import { deliver } from './deliver.ts';
import { notFound, unavailable } from './errors.ts';
import { Hooks, type Extension, type Log, type ServerApi } from './extensions.ts';
import { fanOut, processArrivals, takeIntoInbox, tellInboxEvents } from './fanout.ts';
import { errorReply, nodeListener, Router, type Reply, type Request } from './http.ts';
import { systemDns, type Dns } from './net/dns.ts';
import { guardedHttp, type Http } from './net/fetch.ts';
import { loadPublicSuffixes } from './net/psl.ts';
import { Outbox } from './outbox.ts';
import { Fetcher, partRoutes } from './parts.ts';
import { ownDocument, publicRoutes } from './public.ts';
import { publishedRoutes } from './published.ts';
import { RateLimiter } from './rate.ts';
import { recover, register } from './register.ts';
import { Resolver } from './resolver.ts';
import { send, sendAs } from './send.ts';
import { sendSignal, signal } from './signal.ts';
import { Changes, sent, sync } from './sync.ts';
import { StoreCapacityError, type Store, type SweepCounts } from './store/store.ts';
import { WebhookPoster, webhookRoutes } from './webhooks.ts';
import { startWorker, type Worker } from './worker.ts';

/** Uploads no message names are kept this long, so an agent can send the message after uploading. */
const UPLOAD_GRACE_MS = 48 * 3600_000;
/**
 * Connections: headers within 10 s and a whole request within two minutes (a part of 25 MiB at 200 KiB/s),
 * idle keep-alive connections closed after `config.keepAliveSeconds`, and at most `config.maxConnections`
 * at once, so a client holding connections open (slowloris) cannot exhaust the server.
 */
const HTTP_OPTIONS = { headersTimeout: 10_000, requestTimeout: 120_000 };
/** Passes `work()` runs at most to let one burst of work settle. */
const SETTLE_PASSES = 10;

export interface ServerOptions {
  config: Config;
  store: Store;
  extensions?: Extension[];
  /** DNS through c-ares (and DNS-over-HTTPS confirmation when configured) by default. */
  dns?: Dns;
  /** Outbound HTTP through the SSRF guard by default. */
  http?: Http;
  now?: () => Date;
  log?: Log;
  /** How codes, and the news of a recovery, reach an address. Default: logged in development, none in production. */
  mailbox?: MailboxSender | null;
  /** Run the worker loop in this process (default true). Tests turn it off and call `work()`. */
  worker?: boolean;
  /**
   * Public retirement evidence is host policy. Default: `config.retiredAgentDocuments`, which is `private`
   * unless chosen otherwise; `public` serves signed retired documents and is an explicit opt-in.
   */
  retiredAgentDocuments?: 'public' | 'private';
}

export interface SimonServer {
  /** What extensions see. */
  api: ServerApi;
  /** Answer one request, in-process. */
  handle(req: Request): Promise<Reply>;
  /** The node:http listener, for a server of your own. */
  listener: http.RequestListener;
  /** Listen on a port (the configured one by default; 0 for any), over https when `config.tls` is set; resolves to the port. */
  listen(port?: number, host?: string): Promise<number>;
  /**
   * Background work until it settles, waited for: arrivals offered, inbox events told, part fetches and
   * deliveries attempted, as far as they are due now.
   */
  work(): Promise<void>;
  /** Remove what retention says has expired. */
  sweep(): Promise<SweepCounts>;
  close(): Promise<void>;
}

const defaultLog: Log = (level, message, fields) => {
  if (level !== 'debug') console.error(JSON.stringify({ time: new Date().toISOString(), level, message, ...fields }));
};

export function createServer(opts: ServerOptions): SimonServer {
  const retiredAgentDocuments =
    opts.retiredAgentDocuments === undefined
      ? (opts.config.retiredAgentDocuments ?? 'private')
      : opts.retiredAgentDocuments;
  if (retiredAgentDocuments !== 'public' && retiredAgentDocuments !== 'private')
    throw new TypeError('retiredAgentDocuments is public or private.');
  const { config, store } = opts;
  const now = opts.now ?? (() => new Date());
  const log = opts.log ?? defaultLog;
  const dns = opts.dns ?? systemDns({ doh: config.dohResolvers, servers: config.dnsServers });
  const outbound = opts.http ?? guardedHttp({ dns, dev: config.dev, trustedNetworks: config.trustedNetworks });
  const deferred = new Set<Promise<unknown>>();
  let worker: Worker | null = null;
  let docCache: ReturnType<typeof ownDocument> | null = null;

  const ctx: Context = {
    config,
    store,
    now,
    log,
    http: outbound,
    resolver: new Resolver({
      config,
      store,
      http: outbound,
      dns,
      now,
      log,
      ownDocument: () => (docCache ??= ownDocument(ctx)),
      localAgent: async address => {
        const agent = await store.agentByAddress(address);
        return agent && !agent.retiredAt ? { keys: agent.keys } : null;
      },
      publicSuffixes: config.publicSuffixFile ? loadPublicSuffixes(config.publicSuffixFile) : undefined,
      chargeCarrier: carrier => ctx.rate.hit('carrierLookup', carrier),
    }),
    rate: new RateLimiter(config.rates, now, config.rateExemptNetworks),
    hooks: new Hooks(opts.extensions ?? [], () => api),
    mailbox:
      opts.mailbox !== undefined
        ? opts.mailbox
        : config.dev
          ? async (address, { type, ...note }) =>
              // Logged, never sent: a conformance run reads the codes from the `register code` lines.
              log('info', `${type === 'code' ? 'register code' : type} (development: not sent)`, { address, ...note })
          : null,
    changes: new Changes(),
    wake: () => worker?.wake(),
    defer(task) {
      const p: Promise<unknown> = task()
        .catch(e => log('error', 'deferred work failed', { error: String(e) }))
        .finally(() => deferred.delete(p));
      deferred.add(p);
    },
  };

  const api: ServerApi = {
    config,
    store,
    now,
    log,
    authenticate: req => authenticateAgent(ctx, req),
    async admit(address, id) {
      const record = await store.message(id);
      return !!record && takeIntoInbox(ctx, address, record);
    },
    async offer(address, id) {
      const record = await store.message(id);
      return !!record && fanOut(ctx, record, [address], {});
    },
    send: (message, hints) => sendAs(ctx, message, hints),
    retire: address => store.retireAgent(address, iso(now())),
  };

  const router = new Router<ServerApi>();
  const core = (
    method: 'GET' | 'POST' | 'DELETE',
    path: string,
    handle: (ctx: Context, req: Request) => Promise<Reply>,
  ) => router.add({ method, path, handle: req => handle(ctx, req) });
  core('POST', '/simon/register', register);
  core('GET', '/simon/account', getAccount);
  core('POST', '/simon/recovery', recover);
  core('GET', '/simon/recovery', getRecovery);
  core('POST', '/simon/keys', addKey);
  core('DELETE', '/simon/keys/:key', revokeKey);
  core('DELETE', '/simon/grants/:id', endGrant);
  core('POST', '/simon/recovery/cancel', cancelRecovery);
  core('POST', '/simon/unpair', unpair);
  core('POST', '/simon/send', send);
  core('GET', '/simon/sync', sync);
  core('GET', '/simon/sent/:id', sent);
  core('POST', '/simon/deliver', deliver);
  core('POST', '/simon/signal', signal);
  core('POST', '/simon/send-signal', sendSignal);
  for (const route of [
    ...publicRoutes(ctx, retiredAgentDocuments),
    ...publishedRoutes(ctx),
    ...partRoutes(ctx),
    ...webhookRoutes(ctx),
    ...ctx.hooks.routes,
  ]) {
    router.add(route);
  }

  const bodyLimit = (method: string, path: string) =>
    router.match(method, path)?.route.maxBody ?? config.limits.requestBodyBytes;

  async function handle(req: Request): Promise<Reply> {
    try {
      ctx.rate.hitClient('request', req.ip);
      const match = router.match(req.method, req.path);
      if (!match) throw notFound();
      const limit = match.route.maxBody ?? config.limits.requestBodyBytes;
      if (req.body.length > limit) throw bodyTooLarge(limit);
      return await match.route.handle({ ...req, params: match.params }, api);
    } catch (e) {
      if (e instanceof StoreCapacityError) return errorReply(unavailable('The server is temporarily at capacity.', 60));
      if (e instanceof WireError) return errorReply(e);
      log('error', 'request failed', { method: req.method, path: req.path, error: String((e as Error)?.stack ?? e) });
      return errorReply(new WireError(500, 'internal', 'This server failed; try again later.'));
    }
  }

  const outbox = new Outbox(ctx);
  const fetcher = new Fetcher(ctx);
  const webhooks = new WebhookPoster(ctx);
  const settle = async () => {
    while (deferred.size) await Promise.all(deferred);
  };
  const drain = async (step: (ctx: Context) => Promise<number>) => {
    let total = 0;
    for (let n; (n = await step(ctx)) > 0; ) total += n;
    return total;
  };
  /** Every stage of background work, each on its own: one that fails stops no other. Returns the work begun. */
  const pass = async () => {
    let begun = 0;
    const stages = [
      () => drain(processArrivals),
      () => drain(tellInboxEvents),
      () => fetcher.tick(),
      () => outbox.tick(),
      () => webhooks.tick(),
    ];
    for (const stage of stages) {
      begun += await stage().catch(e => (log('error', 'worker stage failed', { error: String(e) }), 0));
    }
    return begun;
  };
  const sweep = () => store.sweep(iso(now()), iso(new Date(now().getTime() - UPLOAD_GRACE_MS)));
  if (opts.worker ?? true) {
    worker = startWorker(
      async () => void (await pass()),
      async () => void (await sweep()),
      e => log('error', 'worker pass failed', { error: String(e) }),
    );
  }

  const listener = nodeListener({ bodyLimit, handle }, config);
  let httpServer: http.Server | https.Server | null = null;

  return {
    api,
    handle,
    listener,
    listen(port = config.port, host = config.listenHost ?? undefined) {
      const options = { ...HTTP_OPTIONS, keepAliveTimeout: config.keepAliveSeconds * 1000 };
      httpServer = config.tls
        ? https.createServer({ ...options, cert: config.tls.cert, key: config.tls.key }, listener)
        : http.createServer(options, listener);
      httpServer.maxConnections = config.maxConnections;
      return new Promise((resolve, reject) => {
        httpServer!.once('error', reject);
        httpServer!.listen(port, host, () => resolve((httpServer!.address() as AddressInfo).port));
      });
    },
    async work() {
      for (let i = 0; i < SETTLE_PASSES; i++) {
        const begun = await pass();
        await Promise.all([outbox.idle(), fetcher.idle(), webhooks.idle(), settle()]);
        if (!begun) return;
      }
    },
    sweep,
    async close() {
      ctx.changes.close();
      await worker?.stop();
      await new Promise<void>(resolve => {
        if (!httpServer) return resolve();
        httpServer.close(() => resolve());
        httpServer.closeAllConnections();
      });
      await Promise.all([outbox.idle(), fetcher.idle(), webhooks.idle(), settle()]);
    },
  };
}
