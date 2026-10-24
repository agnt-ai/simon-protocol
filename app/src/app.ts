/**
 * `createApp`: the basic server with this application's modules installed through its extension API.
 * Each module is built from the context and the modules before it, and becomes one extension: its routes,
 * its hooks, its background work. Nothing here edits the core.
 *
 *   const app = createApp({ config, db });
 *   await app.start();          // indexes, this application's own agents
 *   await app.server.listen();
 */
import {
  createServer,
  guardedHttp,
  systemDns,
  type AgntServer,
  type Dns,
  type Extension,
  type Http,
  type Log,
  type MailboxNote,
  type ServerApi,
  type Store,
} from '@agnt-protocol/server';
import type { Db } from 'mongodb';
import { mailerFor, type Mailer } from './adapters/mail.ts';
import type { Scanner } from './adapters/scanner.ts';
import { smsFor, type Sms } from './adapters/sms.ts';
import type { AppConfig } from './config.ts';
import { noActivity, type Ctx, type Module } from './context.ts';
import { openApiDocument, openApiRoute } from './http/openapi.ts';
import type { ApiRoute } from './http/route.ts';
import { Codes } from './lib/codes.ts';
import { mongoCards } from './modules/agents/cards.ts';
import { agentsModule } from './modules/agents/index.ts';
import { bridgeModule } from './modules/bridge/index.ts';
import { directoryModule } from './modules/directory/index.ts';
import { introsModule } from './modules/intros/index.ts';
import { nudgeModule } from './modules/nudge/index.ts';
import { ActivityLog } from './modules/owner/activity.ts';
import { ownerModule } from './modules/owner/index.ts';
import { Requests } from './modules/owner/requests.ts';
import { policyModule } from './modules/policy/index.ts';
import { uploadsModule } from './modules/uploads/index.ts';
import { webhooksModule } from './modules/webhooks/index.ts';
import { MongoStore } from './store/mongo-store.ts';
import { SystemAgents } from './system.ts';

export interface AppOptions {
  config: AppConfig;
  db: Db;
  /** The server's Store: MongoDB in the same database unless given. */
  store?: Store;
  /** The outside world; by default what the configuration names. Tests pass fakes. */
  mail?: Mailer | null;
  sms?: Sms | null;
  dns?: Dns;
  http?: Http;
  scanner?: Scanner | null;
  now?: () => Date;
  log?: Log;
  /** Run the server's and this application's background loops in this process (default true). */
  worker?: boolean;
}

export interface App {
  server: AgntServer;
  api: ServerApi;
  /** Every route this application adds, for its API document. */
  routes: ApiRoute[];
  /** Create indexes and this application's own agents. Run once, before serving. */
  start(): Promise<void>;
  /** All background work, the server's and every module's, until nothing is left. */
  work(): Promise<void>;
  close(): Promise<void>;
}

const WORK_MS = 1000;

/** The email the server's note to an address's mailbox becomes. */
function mailboxEmail(address: string, note: MailboxNote): { subject: string; text: string } {
  switch (note.type) {
    case 'code':
      return {
        subject: `Your AGNT code: ${note.code}`,
        text: `Your code to bind ${address} to an agent is ${note.code}. If you did not ask, ignore this message.`,
      };
    case 'recovery':
      return {
        subject: `A recovery of ${address}`,
        text:
          `A code sent to ${address} was used to replace its agent's keys with ${note.key}. That happens at ` +
          `${note.completesAt}. If you did not ask, cancel it with POST /agnt/recovery/cancel and ` +
          `{"address":"${address}","cancelCode":"${note.cancelCode}"}.`,
      };
    case 'recoveryPending':
      return {
        subject: `A recovery of ${address} is pending`,
        text:
          `A code was asked for ${address}, and none was sent: a recovery replacing its agent's keys with ` +
          `${note.key} is pending until ${note.completesAt}. If you did not ask for it, cancel it with POST ` +
          `/agnt/recovery/cancel and {"address":"${address}","cancelCode":"${note.cancelCode}"}.`,
      };
    case 'recoveryCancelled':
      return {
        subject: `The recovery of ${address} was cancelled`,
        text:
          `A key of the agent at ${address} cancelled the recovery of the address that was waiting. If that was ` +
          'not you, someone else holds a key of the agent: recover the address again. For 30 days no key can ' +
          'cancel a recovery of it.',
      };
  }
}

export function createApp(opts: AppOptions): App {
  const { config } = opts;
  const dns = opts.dns ?? systemDns({ doh: config.server.dohResolvers });
  const deferred = new Set<Promise<unknown>>();
  let api: ServerApi | null = null;
  let modules: Module[] = [];
  const log: Log =
    opts.log ??
    ((level, message, fields) => level !== 'debug' && console.error(JSON.stringify({ level, message, ...fields })));
  const ctx: Ctx = {
    config,
    db: opts.db,
    mail: opts.mail !== undefined ? opts.mail : config.mail && mailerFor(config.mail),
    sms: opts.sms !== undefined ? opts.sms : config.sms && smsFor(config.sms),
    dns,
    http: opts.http ?? guardedHttp({ dns, dev: config.server.dev, trustedNetworks: config.server.trustedNetworks }),
    log,
    get api() {
      if (!api) throw new Error('The server does not exist yet.');
      return api;
    },
    system: new SystemAgents(config.server.serverKey, config.systemDomain, () => ctx.api),
    now: () => ctx.api.now(),
    defer(task) {
      const p: Promise<unknown> = task()
        .catch(e => log('error', 'deferred work failed', { error: String(e) }))
        .finally(() => deferred.delete(p));
      deferred.add(p);
    },
    async retire(address) {
      await ctx.api.retire(address);
      for (const m of modules) await m.forget?.agent?.(address);
    },
    async erase(person) {
      for (const m of modules) await m.forget?.person?.(person);
    },
  };

  const requests = new Requests(ctx, config.modules.includes('owner'));
  modules = assemble(ctx, requests, opts.scanner);
  const extensions: Extension[] = modules.map(m => ({
    name: m.name,
    ...m.hooks,
    routes: (m.routes ?? []).map(r => r.route),
  }));
  const routes = modules.flatMap(m => m.routes ?? []);
  requests.adopt(routes);
  extensions.push({ name: 'openapi', routes: [openApiRoute(openApiDocument(routes, config.server.origin)).route] });

  const store = opts.store ?? new MongoStore(opts.db);
  const server = createServer({
    config: config.server,
    store,
    extensions,
    dns,
    http: ctx.http,
    now: opts.now,
    log,
    // What binds an address, and the news of its recovery, go to that address, by mail.
    mailbox: ctx.mail ? (address, note) => ctx.mail!.send({ to: address, ...mailboxEmail(address, note) }) : null,
    worker: opts.worker,
    // Private unless AGNT_RETIRED_AGENT_DOCUMENTS=public chooses otherwise.
    retiredAgentDocuments: config.server.retiredAgentDocuments,
  });
  api = server.api;

  // Each module's work runs beside the others', so a slow one (webhooks to a tarpit) holds up only itself.
  const workOnce = async () => {
    const done = await Promise.all(
      modules.map(async m => {
        try {
          return (await m.work?.()) ?? 0;
        } catch (e) {
          log('error', `${m.name}: background work failed`, { error: String(e) });
          return 0;
        }
      }),
    );
    return done.reduce((a, b) => a + b, 0);
  };
  const settle = async () => {
    while (deferred.size) await Promise.all(deferred);
  };
  let loop: NodeJS.Timeout | null = null;
  let running = false;

  return {
    server,
    api: server.api,
    routes,
    async start() {
      if (store instanceof MongoStore) await store.init();
      for (const m of modules) await m.init?.();
      await ctx.system.start();
      if (opts.worker ?? true) {
        loop = setInterval(() => {
          if (running) return;
          running = true;
          void workOnce().finally(() => (running = false));
        }, WORK_MS);
        loop.unref();
      }
    },
    async work() {
      for (let round = 0; round < 10; round++) {
        await server.work();
        await settle();
        if (!(await workOnce())) break;
      }
      await server.work();
      await settle();
    },
    async close() {
      if (loop) clearInterval(loop);
      await server.close();
      await settle();
    },
  };
}

/**
 * The modules the configuration runs, each built on the ones before it. Principal-reserved routes take
 * `requests.caller`, so a paired agent's call to one waits for its person (owner/requests.ts).
 */
function assemble(ctx: Ctx, requests: Requests, scanner: Scanner | null | undefined): Module[] {
  const on = (name: AppConfig['modules'][number]) => ctx.config.modules.includes(name);
  const reserved = requests.caller;
  const cards = mongoCards(ctx.db);
  const codes = new Codes(ctx);
  const webhooks = on('webhooks') ? webhooksModule(ctx, { reserved }) : null;
  const activity = on('owner') ? new ActivityLog(ctx, webhooks?.webhooks ?? null) : null;
  const directory = on('directory')
    ? directoryModule(ctx, { cards, activity: activity ?? noActivity, codes, reserved })
    : null;
  const policy = on('policy') ? policyModule(ctx, { directory: directory?.directory ?? null, reserved }) : null;
  const uploads = on('uploads') ? uploadsModule(ctx, scanner) : null;
  const nudge = on('nudge') ? nudgeModule(ctx) : null;
  const intros = on('intros')
    ? introsModule(ctx, {
        directory: directory!.directory,
        policy: policy!.policy,
        activity: activity ?? noActivity,
        reserved,
      })
    : null;
  const owner = on('owner')
    ? ownerModule(ctx, {
        directory: directory!.directory,
        activity: activity!,
        codes,
        cards,
        requests,
        policy: policy?.policy ?? null,
        intros: intros?.intros ?? null,
        webhooks: webhooks?.webhooks ?? null,
      })
    : null;
  const bridge = on('bridge') ? bridgeModule(ctx, { directory: directory!.directory, cards }) : null;
  // Policy first: its admit hook is the chain's first link.
  const built = [policy, directory, webhooks, uploads, nudge, intros, owner, bridge].flatMap(m =>
    m ? [m.module] : [],
  );
  const sections = built.flatMap(m => (m.home ? [m.home] : []));
  return [...built, agentsModule(ctx, { cards, directory: directory?.directory ?? null, sections, reserved })];
}
