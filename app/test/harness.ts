/**
 * Whole federations in one process: application servers (the basic server with every module) and plain
 * basic servers, on the server's fake network and DNS, with one movable clock, MongoDB in memory, and mail
 * and text messages kept for the test to read. Agents and people use the real clients.
 *
 *   const world = new World();
 *   const alpha = await world.app('alpha');            // https://agnt.alpha.test, hosting alpha.test
 *   const ada = await alpha.paired('ada@mail.test');   // an agent paired with mailto:ada@mail.test by a code
 *   await ada.agent.send({ to: ['bob@beta.test'], text: 'hi' });
 *   await ada.approved.updateListing({ listed: true }); // a principal-reserved call, which ada's person approves
 *   await world.work();                                // every server's background work, settled
 */
import type { KeyObject } from 'node:crypto';
import { generateKey, keyToken, sign, signPairing } from '@agnt-protocol/protocol';
import { Agent, type Delivered, AgntError, type Fetch } from '@agnt-protocol/client';
import { createServer, defineConfig, SqliteStore, type AgntServer, type ConfigInput } from '@agnt-protocol/server';
import { Clock, FakeDns, FakeNet, replyBody, toRequest } from '@agnt-protocol/server/testing';
import type { Db } from 'mongodb';
import type { Email, Mailer } from '../src/adapters/mail.ts';
import type { Scanner } from '../src/adapters/scanner.ts';
import type { Sms } from '../src/adapters/sms.ts';
import { createApp, type App } from '../src/app.ts';
import { AppAgent, AppOwner, isAwaiting, pair, type Awaiting } from '../src/client.ts';
import { loadAppConfig } from '../src/config.ts';
import { pkceS256, randomToken } from '../src/lib/secrets.ts';
import { freshDb, stopMongo } from './mongo.ts';

/** Mail and text messages, kept; a text message is kept as mail with no subject. */
export class Outbox implements Mailer, Sms {
  readonly sent: Email[] = [];
  async send(m: Email | { to: string; text: string }) {
    this.sent.push({ subject: '', ...m });
  }
  last(to: string) {
    return this.sent.findLast(m => m.to === to);
  }
  /**
   * The code last sent to an address or number: eight digits, from this application or the core. A recovery's
   * cancel code, sent with its news, is not one of these.
   */
  code(to: string): string {
    const last = this.sent.findLast(m => m.to === to && !m.subject.startsWith('A recovery of'));
    const code = /\b(\d{8})\b/.exec(last?.text ?? '')?.[1];
    if (!code) throw new Error(`No code was sent to ${to}.`);
    return code;
  }
}

/** Flags the EICAR test string and passes everything else. */
export const testScanner: Scanner = {
  scan: async data => (data.includes('EICAR-STANDARD-ANTIVIRUS-TEST-FILE') ? 'infected' : 'clean'),
};

const loose = { limit: 1_000_000, seconds: 3600 };

export class World {
  readonly clock = new Clock();
  readonly dns = new FakeDns();
  readonly net = new FakeNet();
  readonly outbox = new Outbox();
  readonly apps: TestApp[] = [];
  readonly basics: { name: string; server: AgntServer; store: SqliteStore }[] = [];

  /** fetch, answered by the servers on the fake network. */
  readonly fetch: Fetch = async (url, init = {}) => {
    const u = new URL(url);
    const host = this.net.hosts.get(u.origin);
    if (!host || host === 'down') throw new TypeError(`fetch failed: ${u.host}`);
    const headers = Object.fromEntries(new Headers(init.headers).entries());
    const body =
      init.body === undefined || init.body === null ? Buffer.alloc(0) : Buffer.from(init.body as string | Uint8Array);
    const reply = await host(toRequest(init.method ?? 'GET', u, headers, body, '192.0.2.50'));
    return new Response(reply.status === 204 || reply.status === 302 ? null : new Uint8Array(replyBody(reply)), {
      status: reply.status,
      headers: { 'content-type': reply.bytes ? 'application/octet-stream' : 'application/json', ...reply.headers },
    });
  };

  /** An application server at https://agnt.<name>.test, hosting <name>.test. */
  async app(
    name: string,
    opts: { env?: Record<string, string>; config?: Partial<ConfigInput>; scanner?: Scanner | null } = {},
  ): Promise<TestApp> {
    const origin = `https://agnt.${name}.test`;
    const server = defineConfig({
      origin,
      dev: true,
      hostedDomains: [`${name}.test`],
      leaseDomain: `lease.${name}.test`,
      serverKey: generateKey().privateKey,
      rates: {
        request: loose,
        register: loose,
        send: loose,
        destinations: loose,
        upload: loose,
        deliver: loose,
        code: loose,
      },
      ...opts.config,
    });
    const rates =
      'discovery=1000000/3600,directoryWrites=1000000/3600,requests=1000000/3600,intros=1000000/3600,codes=1000000/3600,bridgeEmails=1000000/3600,owner=1000000/3600,pages=1000000/3600';
    const config = loadAppConfig(
      { AGNT_APP_RATES: rates, AGNT_BRIDGE_INBOUND_SECRET: 'bridge-secret', ...opts.env },
      server,
    );
    const db = await freshDb();
    const app = createApp({
      config,
      db,
      mail: this.outbox,
      sms: this.outbox,
      dns: this.dns,
      http: this.net,
      now: this.clock.now,
      log: process.env.AGNT_TEST_LOG ? (l, m, f) => console.error(l, m, f ?? '') : () => {},
      scanner: opts.scanner === undefined ? testScanner : opts.scanner,
      worker: false,
    });
    await app.start();
    this.net.hosts.set(origin, req => app.server.handle(req));
    for (const d of [`${name}.test`, `lease.${name}.test`]) this.dns.point(d, origin);
    const t = new TestApp(this, name, origin, app, db);
    this.apps.push(t);
    return t;
  }

  /** A plain basic server at https://agnt.<name>.test, hosting <name>.test: no application on it. */
  async basic(name: string, config: Partial<ConfigInput> = {}) {
    const origin = `https://agnt.${name}.test`;
    const store = new SqliteStore(':memory:');
    const server = createServer({
      config: defineConfig({ origin, hostedDomains: [`${name}.test`], serverKey: generateKey().privateKey, ...config }),
      store,
      dns: this.dns,
      http: this.net,
      now: this.clock.now,
      log: () => {},
      worker: false,
    });
    this.net.hosts.set(origin, req => server.handle(req));
    this.dns.point(`${name}.test`, origin);
    this.basics.push({ name, server, store });
    return { origin, server, agent: (local: string) => this.agent(origin, `${local}@${name}.test`) };
  }

  /** A solo agent registered at `address` on the server at `origin`. */
  async agent(origin: string, address: string) {
    const key = generateKey().privateKey;
    const agent = new Agent({ server: origin, key, fetch: this.fetch, now: this.clock.now });
    await agent.register({ address });
    return agent;
  }

  /** Every server's background work, until nothing is left. */
  async work() {
    for (let round = 0; round < 3; round++) {
      for (const a of this.apps) await a.app.work();
      for (const b of this.basics) await b.server.work();
    }
  }

  async close() {
    for (const a of this.apps) await a.app.close();
    for (const b of this.basics) {
      await b.server.close();
      await b.store.close();
    }
    await stopMongo();
  }
}

/** The application's client with every principal-reserved call approved by the agent's person. */
export type Approved = {
  [K in keyof AppAgent]: AppAgent[K] extends (...args: infer A) => Promise<infer R>
    ? (...args: A) => Promise<Exclude<R, Awaiting>>
    : AppAgent[K];
};

/** An agent on an application server: the protocol client, and the application's client. */
export interface Member {
  agent: Agent;
  api: AppAgent;
  /** The same calls, each reserved one approved in the owner window of the agent's principal. */
  approved: Approved;
  key: KeyObject;
}

/** An edge at strength 4, by email. */
export const strong = (email: string) => ({ identifier: `mailto:${email}`, strength: 4 });

/** An owner session is good for an hour: one signed in 50 minutes ago is signed in again. */
const SESSION_MS = 50 * 60_000;

export class TestApp {
  readonly world: World;
  readonly name: string;
  readonly origin: string;
  readonly domain: string;
  readonly app: App;
  /** The application's database, for a test to see what it keeps. */
  readonly db: Db;
  #n = 0;
  readonly #owners = new Map<string, { owner: AppOwner; at: number }>();
  /** Key principals' private keys, by identifier, to sign in with. */
  readonly #keys = new Map<string, KeyObject>();

  constructor(world: World, name: string, origin: string, app: App, db: Db) {
    this.world = world;
    this.name = name;
    this.origin = origin;
    this.domain = `${name}.test`;
    this.app = app;
    this.db = db;
  }

  #member(agent: Agent, key: KeyObject, principal: string | null = null): Member {
    const api = new AppAgent(agent);
    const approved = new Proxy(api, {
      get: (target, name: keyof AppAgent) => {
        const call = target[name];
        if (typeof call !== 'function') return call;
        return async (...args: unknown[]) => {
          const answer = await (call as (...a: unknown[]) => Promise<unknown>)(...args);
          if (!isAwaiting(answer)) return answer;
          const decided = await (await this.ownerOf(principal!)).decide(answer.request.id, 'approve');
          if (decided.error) throw new AgntError(decided.error.code, decided.error.detail);
          return decided.answer;
        };
      },
    }) as unknown as Approved;
    return { agent, api, approved, key };
  }

  /** The owner window of a principal, signed in once and kept while its session is good. */
  async ownerOf(principal: string): Promise<AppOwner> {
    const held = this.#owners.get(principal);
    const now = this.world.clock.now().getTime();
    if (held && now - held.at < SESSION_MS) return held.owner;
    const owner = await this.owner(principal);
    this.#owners.set(principal, { owner, at: now });
    return owner;
  }

  /** A solo agent at `<local>@<name>.test`. */
  async solo(local = `solo${++this.#n}`): Promise<Member> {
    const key = generateKey().privateKey;
    const agent = new Agent({ server: this.origin, key, fetch: this.world.fetch, now: this.world.clock.now });
    await agent.register({ address: `${local}@${this.domain}` });
    return this.#member(agent, key);
  }

  /** An agent paired with `mailto:<email>` (or a `tel:` principal) by the code sent there. */
  async paired(identifier: string, opts: { local?: string; scope?: string[] } = {}): Promise<Member> {
    const principal = identifier.includes(':') ? identifier : `mailto:${identifier}`;
    const key = generateKey().privateKey;
    const blank = new Agent({ server: this.origin, key, fetch: this.world.fetch, now: this.world.clock.now });
    const address = `${opts.local ?? `agent${++this.#n}`}@${this.domain}`;
    await pair(blank, { for: principal, address, scope: opts.scope });
    const code = this.world.outbox.code(principal.slice(principal.indexOf(':') + 1));
    const done = await pair(blank, { for: principal, address, pairingCode: code });
    if (!('keys' in done)) throw new Error(`pairing failed: ${JSON.stringify(done)}`);
    const agent = new Agent({
      server: this.origin,
      key,
      address,
      for: principal,
      fetch: this.world.fetch,
      now: this.world.clock.now,
    });
    return this.#member(agent, key, principal);
  }

  /** An agent paired with a key principal by the principal's signature, which can sign in to the owner window. */
  async keyed(local = `keyed${++this.#n}`): Promise<Member & { principal: string; principalKey: KeyObject }> {
    const principalKey = generateKey().privateKey;
    const principal = `agnt-key:${keyToken(principalKey)}`;
    this.#keys.set(principal, principalKey);
    const key = generateKey().privateKey;
    const address = `${local}@${this.domain}`;
    const pairing = signPairing(principalKey, address, principal);
    const blank = new Agent({ server: this.origin, key, fetch: this.world.fetch, now: this.world.clock.now });
    await blank.register({ address, for: principal, pairing });
    const agent = new Agent({
      server: this.origin,
      key,
      address,
      for: principal,
      pairing,
      fetch: this.world.fetch,
      now: this.world.clock.now,
    });
    const member = this.#member(agent, key, principal);
    await member.api.home(); // Its first check-in records its pair: the core verified it, with no code.
    return { ...member, principal, principalKey };
  }

  /** An agent paired with `email`, whose person listed themselves (unless `list` is false), and that person's id. */
  async joined(email: string, opts: { list?: boolean } = {}): Promise<Member & { person: string }> {
    const m = await this.paired(email);
    if (opts.list ?? true) await (await this.ownerOf(`mailto:${email}`)).updateListing({ listed: true });
    return { ...m, person: (await m.api.home()).pair!.person };
  }

  /** The owner window, signed in by an identifier (an email address alone is read as `mailto:`). */
  async owner(identifier: string): Promise<AppOwner> {
    const { access_token } = await this.signIn(identifier);
    return new AppOwner({ server: this.origin, token: access_token, fetch: this.world.fetch });
  }

  /**
   * Sign in by an identifier, through OAuth with PKCE: by the code sent to an email address or phone
   * number, or by a key principal's signature. The token answer, and the client's id.
   */
  async signIn(identifier: string): Promise<{ access_token: string; refresh_token: string; client_id: string }> {
    const principal = identifier.includes(':') ? identifier : `mailto:${identifier}`;
    const typed = principal.startsWith('agnt-key:') ? principal : principal.slice(principal.indexOf(':') + 1);
    const { fetch } = this.world;
    const post = (path: string, body: Record<string, string>, type = 'application/x-www-form-urlencoded') =>
      fetch(`${this.origin}${path}`, {
        method: 'POST',
        headers: { 'content-type': type },
        body: type.includes('json') ? JSON.stringify(body) : new URLSearchParams(body).toString(),
      });
    const redirect = 'https://portal.example.com/callback';
    const client = await (
      await post(
        '/api/oauth/register',
        { client_name: 'Portal', redirect_uris: [redirect] } as never,
        'application/json',
      )
    ).json();
    const verifier = randomToken();
    const authorize = new URLSearchParams({
      response_type: 'code',
      client_id: client.client_id,
      redirect_uri: redirect,
      code_challenge: pkceS256(verifier),
      code_challenge_method: 'S256',
      state: 'xyz',
    });
    const login = (await fetch(`${this.origin}/api/oauth/authorize?${authorize}`)).headers.get('location')!;
    const page = await (await post(`${login}/identifier`, { identifier: typed })).text();
    const key = this.#keys.get(principal);
    const proof = key
      ? post(`${login}/signature`, { signature: sign(key, challengeOf(page)) })
      : post(`${login}/code`, { code: this.world.outbox.code(typed) });
    const back = (await proof).headers.get('location')!;
    const code = new URL(back).searchParams.get('code')!;
    const tokens = await (
      await post('/api/oauth/token', {
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        client_id: client.client_id,
        redirect_uri: redirect,
      })
    ).json();
    return { ...tokens, client_id: client.client_id };
  }
}

/** The bytes a sign-in page asks a key principal to sign. */
export function challengeOf(page: string): string {
  const pre = /<pre>([^<]*)<\/pre>/.exec(page)?.[1];
  if (!pre) throw new Error('The page asks for no signature.');
  return pre.replace(
    /&(amp|lt|gt|quot|#39);/g,
    (_, e) => ({ amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'" })[e as 'amp'],
  );
}

/** Received messages only, read through the opaque sync-token API. */
export async function received(agent: Agent) {
  const messages: Delivered[] = [];
  const seen = new Set<string>();
  let since: string | undefined;
  for (let page = 0; page < 20; page++) {
    const result = await agent.sync({ since, limit: 200 });
    for (const entry of result.messages) {
      if ((entry.message.from !== agent.address || entry.message.to.includes(agent.address!)) && !seen.has(entry.id)) {
        seen.add(entry.id);
        messages.push(entry);
      }
    }
    if (!result.more) return { messages };
    if (result.token === since) throw new Error('Sync reported more without advancing its token.');
    since = result.token;
  }
  throw new Error('Received helper exceeded 4000 sync entries.');
}

/** The texts in an agent's inbox, oldest first, without this application's notices. */
export async function texts(agent: Agent, opts: { notices?: boolean } = {}): Promise<string[]> {
  const { messages } = await received(agent);
  return messages
    .filter(m => opts.notices || !m.message.headers?.notice)
    .map(m => m.message.parts.flatMap(p => ('data' in p && p.type === 'text/plain' ? [p.data] : [])).join(''));
}

/** This application's notices of one kind in an agent's inbox, with their details. */
export async function notices(agent: Agent, kind: string): Promise<{ text: string; data: Record<string, any> }[]> {
  const { messages } = await received(agent);
  return messages
    .filter(m => m.message.headers?.notice === kind)
    .map(m => {
      const part = (type: string) =>
        m.message.parts.find(p => p.type === type && 'data' in p) as { data: string } | undefined;
      return {
        text: part('text/plain')?.data ?? '',
        data: JSON.parse(Buffer.from(part('application/json')?.data ?? '', 'base64').toString() || '{}'),
      };
    });
}
