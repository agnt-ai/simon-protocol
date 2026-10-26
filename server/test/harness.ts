/**
 * Whole federations in one process: servers on a fake network with a fake DNS and one movable clock,
 * and agents that speak the client API with nothing but @agnt-sdk/simon-protocol.
 *
 *   const fed = new Federation();
 *   const alpha = await fed.server('alpha');            // https://simon.alpha.test, hosting alpha.test
 *   const ada = await alpha.agent('ada');               // ada@alpha.test, registered
 *   await ada.send(ada.message(['bob@beta.test'], 'hi'));
 *   await fed.work();                                   // every server's background work, settled
 */
import type { KeyObject } from 'node:crypto';
import {
  canonicalBytes,
  domainOf,
  generateKey,
  keyToken,
  messageId,
  serverDocument,
  sha256Hex,
  signAgentDocument,
  signEnvelope,
  signMessage,
  signRequest,
  isAddress,
  timestamp,
  type AnyMessage,
  type UnsignedEnvelope,
  type Json,
  type Message,
  type Part,
  type Unsigned,
  VERSION,
} from '@agnt-sdk/simon-protocol';
import { defineConfig, type ConfigInput } from '../src/config.ts';
import type { Extension } from '../src/extensions.ts';
import type { MailboxNote } from '../src/context.ts';
import type { Reply, Request } from '../src/http.ts';
import { createServer, type SimonServer } from '../src/server.ts';
import { SqliteStore } from '../src/store/sqlite.ts';
import type { Store } from '../src/store/store.ts';
import { Clock, FakeDns, FakeNet, replyBody, toRequest } from '../src/testing.ts';

export { CLOCK_PAIRING_UNTIL, Clock, FakeDns, FakeNet, TARPIT_MS, toRequest } from '../src/testing.ts';

export interface Answer {
  status: number;
  json: any;
  bytes: Buffer;
  headers: Record<string, string>;
}

export interface ServerOpts {
  config?: Partial<ConfigInput>;
  extensions?: Extension[];
  /** false: no code sender, so the code flow is unavailable. */
  codes?: boolean;
  /** Waited on before each code is recorded as sent: a mail server that takes its time. */
  sendDelay?: Promise<void>;
  /** A mail server that refuses every recovery's cancel code. */
  cancelFails?: boolean;
  /** Where the server's log goes, beside SIMON_TEST_LOG. */
  log?: (level: string, message: string, fields?: object) => void;
  /** Wrap the store the server uses, to watch it. */
  wrapStore?: (store: Store) => Store;
  /**
   * The server's origin is its hosted domain (https://<name>.test), with no TXT record: the domain resolves
   * by the well-known answer the server serves itself, as on a laptop's Tailscale name.
   */
  wellKnown?: boolean;
}

export class Federation {
  readonly clock = new Clock();
  readonly dns = new FakeDns();
  readonly net = new FakeNet();
  readonly servers: TestServer[] = [];

  /** The origin a domain resolves to here: a test server's own domain, or its TXT record. */
  originOf(domain: string): string | undefined {
    const record = this.dns.records.get(`_simon.${domain}`)?.[0]?.join('');
    return this.servers.find(s => s.domain === domain)?.origin ?? /server=(\S+)/.exec(record ?? '')?.[1];
  }

  async server(name: string, opts: ServerOpts = {}) {
    const s = new TestServer(this, name, opts);
    this.servers.push(s);
    return s;
  }

  /** Run every server's background work until nothing is left. */
  async work(rounds = 3) {
    for (let i = 0; i < rounds; i++) for (const s of this.servers) await s.server.work();
  }

  async close() {
    for (const s of this.servers) {
      await s.server.close();
      await s.store.close();
    }
  }
}

export class TestServer {
  readonly fed: Federation;
  readonly origin: string;
  /** The domain whose names agents take at once. */
  readonly domain: string;
  readonly leaseDomain: string;
  readonly store = new SqliteStore(':memory:');
  readonly server: SimonServer;
  /** What this server sent addresses' mailboxes, oldest first. */
  readonly mail: ({ address: string } & MailboxNote)[] = [];
  readonly codes = new Map<string, string>();
  readonly cancelCodes = new Map<string, string>();
  readonly cancelsSent: string[] = [];

  constructor(fed: Federation, name: string, opts: ServerOpts) {
    this.fed = fed;
    this.origin = opts.wellKnown ? `https://${name}.test` : `https://simon.${name}.test`;
    this.domain = `${name}.test`;
    this.leaseDomain = `lease.${name}.test`;
    // Rate limits get their own tests; elsewhere they stay out of the way.
    const loose = { limit: 1_000_000, seconds: 3600 };
    const config = defineConfig({
      origin: this.origin,
      hostedDomains: [this.domain],
      leaseDomain: this.leaseDomain,
      serverKey: generateKey().privateKey,
      rates: {
        request: loose,
        register: loose,
        send: loose,
        destinations: loose,
        upload: loose,
        deliver: loose,
        lookup: loose,
        lookupDomain: loose,
        carrierLookup: loose,
        code: loose,
        codeClient: loose,
      },
      ...opts.config,
    });
    this.server = createServer({
      config,
      store: opts.wrapStore ? opts.wrapStore(this.store) : this.store,
      extensions: opts.extensions,
      dns: fed.dns,
      http: fed.net,
      now: fed.clock.now,
      log: (l, m, f) => {
        opts.log?.(l, m, f);
        if (process.env.SIMON_TEST_LOG) console.error(l, m, f ?? '');
      },
      mailbox:
        opts.codes === false
          ? null
          : async (address, note) => {
              await opts.sendDelay;
              if ((note.type === 'recovery' || note.type === 'recoveryPending') && opts.cancelFails)
                throw new Error('mail refused');
              this.mail.push({ address, ...note });
              if (note.type === 'code') this.codes.set(address, note.code);
              if (note.type === 'recovery' || note.type === 'recoveryPending') {
                this.cancelCodes.set(address, note.cancelCode);
                this.cancelsSent.push(address);
              }
            },
      worker: false,
    });
    fed.net.hosts.set(this.origin, req => this.server.handle(req));
    if (!opts.wellKnown) fed.dns.point(this.domain, this.origin);
    fed.dns.point(this.leaseDomain, this.origin);
  }

  /** The last code sent to an address. */
  code(address: string): string {
    const note = this.mail.findLast(m => m.address === address && m.type === 'code');
    if (note?.type !== 'code') throw new Error(`No code was sent to ${address}.`);
    return note.code;
  }

  /** The cancel code sent to an address with the news of its last recovery. */
  cancelCode(address: string): string {
    const note = this.mail.findLast(m => m.address === address && m.type === 'recovery');
    if (note?.type !== 'recovery') throw new Error(`No recovery of ${address} was announced.`);
    return note.cancelCode;
  }

  /** An agent with a fresh key, not yet registered. */
  newAgent(alg: 'ed25519' | 'ml-dsa-65' = 'ed25519') {
    return new TestAgent(this, generateKey(alg).privateKey);
  }

  /** A solo agent registered at `<name>@<domain>`. */
  async agent(name: string): Promise<TestAgent> {
    const a = this.newAgent();
    const res = await a.register({ address: `${name}@${this.domain}` });
    if (res.status !== 200) throw new Error(`register failed: ${JSON.stringify(res.json)}`);
    return a;
  }
}

export class TestAgent {
  readonly home: TestServer;
  readonly key: KeyObject;
  readonly token: string;
  address = '';

  constructor(home: TestServer, key: KeyObject) {
    this.home = home;
    this.key = key;
    this.token = keyToken(key);
  }

  get fed() {
    return this.home.fed;
  }

  /** A request to this agent's server, signed unless `sign` is false. */
  async request(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    target: string,
    opts: {
      body?: Uint8Array | string;
      headers?: Record<string, string>;
      sign?: boolean;
      key?: KeyObject;
      ip?: string;
      /** Act as this address (`simon-agent`); by default the agent's own, once it has one. */
      agent?: string;
    } = {},
  ): Promise<Answer> {
    const url = new URL(this.home.origin + target);
    const body = Buffer.from(opts.body ?? '');
    const agent = opts.agent ?? (this.address || undefined);
    const signed =
      opts.sign === false
        ? {}
        : signRequest(opts.key ?? this.key, { method, url: url.href, body, now: this.fed.clock.t, agent });
    const reply = await this.home.server.handle(
      toRequest(method, url, { ...signed, ...opts.headers }, body, opts.ip ?? '192.0.2.50'),
    );
    const bytes = replyBody(reply);
    const json = reply.json === undefined ? undefined : JSON.parse(bytes.toString('utf8'));
    return { status: reply.status, json, bytes, headers: reply.headers ?? {} };
  }

  async register(body: Record<string, Json> = {}) {
    // An explicit requested address is the actor; a no-address repeat may name its current holder.
    const asked = isAddress(body.address) ? body.address : undefined;
    const res = await this.request('POST', '/simon/register', {
      body: JSON.stringify({ key: this.token, ...body }),
      agent: asked ?? (this.address || undefined),
    });
    if (res.status === 200) this.address = res.json.address;
    return res;
  }

  /** Recover an existing address with mailbox or principal proof, signed as that address. */
  async recover(body: Record<string, Json>) {
    const res = await this.request('POST', '/simon/recovery', {
      body: JSON.stringify({ key: this.token, ...body }),
      agent: isAddress(body.address) ? body.address : undefined,
    });
    if (res.status === 200) this.address = res.json.address;
    return res;
  }

  /** Cancel by mailbox secret, independent of the request signer's membership. */
  cancelRecovery(body: Record<string, Json>) {
    return this.request('POST', '/simon/recovery/cancel', {
      body: JSON.stringify(body),
      agent: isAddress(body.address) ? body.address : undefined,
    });
  }

  /** A signed version 1 message from this agent. */
  message(to: string[], text: string, extra: Partial<Unsigned<Message>> & { parts?: Part[] } = {}): Message {
    return signMessage<Message>(
      {
        v: VERSION,
        from: this.address,
        to,
        inReplyTo: null,
        parts: [{ type: 'text/plain', data: text }],
        sentAt: timestamp(this.fed.clock.t),
        ...extra,
        // A message to no one is published, and says who may read it: public unless the test says otherwise.
        headers: { ...(to.length === 0 ? { audience: 'public' } : {}), ...extra.headers },
      },
      this.key,
    );
  }

  send(m: object, hints?: object) {
    return this.request('POST', '/simon/send', {
      body: canonicalBytes(m),
      headers: hints ? { 'simon-hints': JSON.stringify(hints) } : {},
    });
  }

  sync(since?: string, query: { limit?: number; wait?: number } = {}) {
    const q = new URLSearchParams({
      ...(since === undefined ? {} : { since }),
      ...Object.fromEntries(Object.entries(query).map(([k, v]) => [k, String(v)])),
    });
    return this.request('GET', `/simon/sync${q.size ? `?${q}` : ''}`);
  }

  /** The entries of messages this agent received, as sync shows them, oldest first, each once. */
  async received(): Promise<any[]> {
    const messages: any[] = [];
    const seen = new Set<string>();
    let since: string | undefined;
    for (let page = 0; page < 20; page++) {
      const res = await this.sync(since, { limit: 200 });
      if (res.status !== 200) throw new Error(`sync failed: ${JSON.stringify(res.json)}`);
      for (const entry of res.json.messages as { id: string; message: Message }[]) {
        const outgoingOnly = entry.message.from === this.address && !entry.message.to.includes(this.address);
        if (!outgoingOnly && !seen.has(entry.id)) {
          seen.add(entry.id);
          messages.push(entry);
        }
      }
      if (!res.json.more) return messages;
      if (res.json.token === since) throw new Error('Sync reported more without advancing its token.');
      since = res.json.token;
    }
    throw new Error('Received helper exceeded 4000 sync entries.');
  }

  /** The texts of the messages this agent received, oldest first. */
  async texts(): Promise<string[]> {
    return (await this.received()).map((e: { message: Message }) =>
      e.message.parts.map(p => ('data' in p ? p.data : '')).join(''),
    );
  }

  sent(id: string) {
    return this.request('GET', `/simon/sent/${id}`);
  }

  upload(bytes: Buffer) {
    return this.request('PUT', `/simon/parts/${sha256Hex(bytes)}`, { body: bytes });
  }

  part(sha256: string) {
    return this.request('GET', `/simon/parts/${sha256}`);
  }
}

/**
 * A server played by the test itself, for what a well-behaved server never sends: it serves the documents
 * the test gives it and posts any envelope, signed or not.
 */
export class Peer {
  readonly fed: Federation;
  readonly origin: string;
  readonly domain: string;
  key = generateKey().privateKey;
  /** Keys listed beside `key`, for a rotation that overlaps. */
  extraKeys: KeyObject[] = [];
  /** Hold every delivery forever: a tarpit. */
  hang = false;
  readonly agents = new Map<string, KeyObject>();
  readonly kinds = new Map<string, 'solo' | 'paired'>();
  /** Replaces the server document's bytes, or its status, when set. */
  serverDocument: Buffer | number | null = null;
  agentStatus: number | null = null;
  /** Envelopes posted to this peer. */
  delivered = 0;
  /** The answer to every delivery, in place of 202, when set: a refusal, for one. */
  refuse: { status: number; json: object } | null = null;

  constructor(fed: Federation, name: string) {
    this.fed = fed;
    this.origin = `https://simon.${name}.test`;
    this.domain = `${name}.test`;
    fed.dns.point(this.domain, this.origin);
    fed.net.hosts.set(this.origin, async req => this.#answer(req));
  }

  async #answer(req: Request): Promise<Reply> {
    if (req.path === '/simon/server') {
      if (typeof this.serverDocument === 'number') return { status: this.serverDocument, json: {} };
      if (this.serverDocument) return { status: 200, bytes: this.serverDocument };
      const keys = [this.key, ...this.extraKeys].map(k => ({
        key: keyToken(k),
        added: '2026-01-01T00:00:00Z',
        revoked: null,
      }));
      return { status: 200, json: serverDocument(this.origin, keys) };
    }
    if (req.path === '/simon/deliver') {
      this.delivered++;
      if (this.hang) await new Promise(() => {});
      return this.refuse ?? { status: 202, json: { accepted: true } };
    }
    const address = decodeURIComponent(req.path.slice('/simon/agents/'.length));
    const key = this.agents.get(address);
    if (this.agentStatus) return { status: this.agentStatus, json: {} };
    if (!key) return { status: 404, json: {} };
    const doc = signAgentDocument(
      {
        address,
        kind: this.kinds.get(address) ?? 'solo',
        keys: [{ key: keyToken(key), added: '2026-01-01T00:00:00Z', revoked: null }],
      },
      this.key,
    );
    return { status: 200, json: doc };
  }

  /** An agent here, solo unless it names a principal: its address. */
  agent(local: string, kind: 'solo' | 'paired' = 'solo'): string {
    const address = `${local}@${this.domain}`;
    this.agents.set(address, generateKey().privateKey);
    this.kinds.set(address, kind);
    return address;
  }

  message(from: string, to: string[], text: string, extra: Record<string, unknown> = {}): Message {
    return signMessage<Message>(
      {
        v: VERSION,
        from,
        to,
        inReplyTo: null,
        parts: [{ type: 'text/plain', data: text }],
        headers: {},
        sentAt: timestamp(this.fed.clock.t),
        ...extra,
      } as Unsigned<Message>,
      this.agents.get(from)!,
    );
  }

  /**
   * An envelope for the server of the message's first recipient, naming every recipient there; `extra`
   * overrides any member.
   */
  envelope(message: AnyMessage, extra: Record<string, unknown> = {}) {
    const server = this.fed.originOf(domainOf(message.to[0]));
    const recipients = message.to.filter(r => this.fed.originOf(domainOf(r)) === server);
    return signEnvelope({ message, server, recipients, ...extra } as UnsignedEnvelope, this.key);
  }

  /** POST a body to a server's /simon/deliver, as this peer. */
  async post(to: TestServer, body: object | Buffer): Promise<Answer> {
    const res = await this.fed.net.request({
      method: 'POST',
      url: `${to.origin}/simon/deliver`,
      body: Buffer.isBuffer(body) ? body : canonicalBytes(body),
      maxBytes: 1 << 20,
    });
    return {
      status: res.status,
      json: JSON.parse(res.body.toString() || 'null'),
      bytes: res.body,
      headers: res.headers,
    };
  }
}

export { messageId };
