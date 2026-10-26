/**
 * What the checks share: the options, the server under test and its document, the clock the suite reads
 * it by, the simulated peers, and the agents the suite registers there. Everything is set up lazily, the
 * first time a check needs it; a setup that fails makes the checks that need it skip, saying why.
 */
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import net from 'node:net';
import {
  canonicalize,
  domainOf,
  generateKey,
  isJsonObject,
  MINIMUM_LIMITS,
  PAIRING_DEFAULT_MS,
  parseStrict,
  readKeys,
  serverOrigin,
  timestamp,
  type Json,
  type Envelope,
  type Limits,
  type ServerDocument,
} from '@agnt-sdk/simon-protocol';
import { buildMessage, TargetAgent, type MessageFields } from './agent.ts';
import { CheckSkip, problem, T, type Exchange, type Res } from './harness.ts';
import { Peer, type PeerAgent } from './peer.ts';

export interface Options {
  /** The server under test: its base URL, `https://host[:port]`. */
  server: string;
  /** The domain the server under test resolves to the simulator. */
  peerDomain: string;
  peerHost: string;
  peerPort: number;
  /**
   * Where the server under test reaches the simulator, when not at `peerHost` and `peerPort`: a tunnel's
   * `https://<name>` in front of them, for a server elsewhere. With `peerDomain` set to that name, the
   * simulator answers its well-known resolution.
   */
  peerOrigin?: string;
  /** A domain whose names agents take at once on the server, when it has one. */
  hostedDomain?: string;
  /** A domain that names no SIMON server at all. */
  unresolvableDomain: string;
  /** A shell command that prints the code the server sent to an address (given as $1 and SIMON_ADDRESS). */
  codeCommand?: string;
  /** An address on a domain that resolves to the server, for the code flow. */
  codeAddress?: string;
  /** A shell command that prints the cancel code sent to an address with the news of a recovery. */
  cancelCodeCommand?: string;
  /** A shell command that retires the agent at an address (given as $1 and SIMON_ADDRESS). */
  retireCommand?: string;
  /**
   * A second domain the server resolves to a second simulator, on `secondPeerPort`: for the checks that a
   * message to two servers goes as one envelope to each.
   */
  secondPeerDomain?: string;
  secondPeerPort: number;
  /** Where the server under test reaches the second simulator, as `peerOrigin` is for the first. */
  secondPeerOrigin?: string;
  /** How long to wait for the server to deliver a message to the simulator. */
  deliveryWaitMs: number;
  /** How long to wait for the server to retry a delivery the simulator answered with 503. */
  retryWaitMs: number;
  /** How long to wait for the server to fetch a received message's parts (it may delay by a few minutes). */
  prefetchWaitMs: number;
  /** The longest a waiting recovery may take to complete for the suite to wait for it. */
  recoveryWaitMs: number;
  /** How far the suite's idea of the server's clock may be off, at boundaries. */
  clockMarginSeconds: number;
  /** The longest Retry-After the suite waits out. */
  rateLimitWaitMs: number;
  /** Check ids, or prefixes ending in `.`, to run; all when empty. */
  only: string[];
}

export const DEFAULTS: Omit<Options, 'server'> = {
  peerDomain: 'peer.test',
  peerHost: '127.0.0.1',
  peerPort: 47100,
  unresolvableDomain: 'example.invalid',
  secondPeerPort: 47101,
  deliveryWaitMs: 30_000,
  retryWaitMs: 180_000,
  prefetchWaitMs: 240_000,
  recoveryWaitMs: 30_000,
  clockMarginSeconds: 5,
  rateLimitWaitMs: 15_000,
  only: [],
};

export class Prerequisite extends CheckSkip {}

export class Ctx {
  readonly origin: string;
  readonly runId = `c${crypto.randomBytes(4).toString('hex')}`;
  readonly peer: Peer;
  /** The second simulator, when `secondPeerDomain` is given. */
  readonly secondPeer: Peer | null = null;
  readonly notes: string[] = [];
  readonly setupExchanges: Exchange[] = [];
  /** Every exchange with the server under test, for the error checks at the end. */
  readonly allExchanges: Exchange[] = [];
  /** Milliseconds the server's clock is ahead of the suite's, as its 401s report it. */
  clockOffsetMs = 0;
  readonly #once = new Map<string, Promise<unknown>>();
  readonly #cleanup: (() => Promise<unknown>)[] = [];
  readonly #setup: T;

  readonly opts: Options;

  constructor(opts: Options) {
    this.opts = opts;
    this.origin = new URL(opts.server).origin;
    this.peer = new Peer(opts.peerDomain, opts.peerHost, opts.peerPort, this.runId, opts.peerOrigin);
    this.peer.target.origin = this.origin;
    for (const d of [opts.hostedDomain, opts.codeAddress && domainOf(opts.codeAddress)])
      if (d) this.servedDomains.add(d);
    if (opts.secondPeerDomain) {
      this.secondPeer = new Peer(
        opts.secondPeerDomain,
        opts.peerHost,
        opts.secondPeerPort,
        this.runId,
        opts.secondPeerOrigin,
      );
      this.secondPeer.target = this.peer.target;
    }
    this.#setup = new T(
      { id: 'setup', section: '', level: 'must', title: 'setup', expected: '' },
      e => {
        this.setupExchanges.push(e);
        if (e.direction === 'to-target') this.allExchanges.push(e);
      },
      opts.rateLimitWaitMs,
    );
  }

  /** The server's clock, as far as the suite can tell, in milliseconds. */
  now = () => Date.now() + this.clockOffsetMs;

  /** A pairing's until `ms` from the server's clock, a year by default, so it counts at the server's time. */
  until = (ms = PAIRING_DEFAULT_MS) => timestamp(this.now() + ms);

  get server() {
    return { origin: this.origin, now: this.now };
  }

  /** Run `fn` once; every later call gets the same result, or the same refusal. */
  once<X>(name: string, fn: (t: T) => Promise<X>): Promise<X> {
    if (!this.#once.has(name)) {
      this.#once.set(
        name,
        fn(this.#setup).catch(e => {
          throw e instanceof CheckSkip ? e : new Prerequisite(`${name}: ${(e as Error).message}`);
        }),
      );
    }
    return this.#once.get(name) as Promise<X>;
  }

  /** Read the server's clock from a 401's details.serverTime, so time boundaries are the server's. */
  async calibrate() {
    await this.once('clock', async t => {
      const sent = Date.now();
      const res = await t.http(
        { method: 'GET', origin: this.origin, target: '/simon/sync' },
        { label: 'read the server clock' },
      );
      const serverTime = problem(res)?.details?.serverTime;
      if (Number.isInteger(serverTime)) {
        const offset = serverTime * 1000 + 500 - (sent + Date.now()) / 2;
        // Whole seconds only tell the clock to within a second; anything under that is noise.
        this.clockOffsetMs = Math.abs(offset) > 1500 ? Math.round(offset) : 0;
        this.notes.push(
          `The server's clock is ${(this.clockOffsetMs / 1000).toFixed(1)} s from the suite's; time boundaries use the server's.`,
        );
      } else {
        this.notes.push("No details.serverTime on an unsigned request; time boundaries use the suite's clock.");
      }
    });
  }

  /**
   * The server document as fetched: its keys read under section 4's rules, and its limits as published
   * where they are safe integers (the minimums otherwise; documents.server.limits judges them).
   */
  serverDoc(): Promise<{ res: Res; doc: ServerDocument }> {
    return this.once('server document', async t => {
      const res = await t.http(
        { method: 'GET', origin: this.origin, target: '/simon/server' },
        { label: 'server document' },
      );
      let value: Json = null;
      try {
        value = parseStrict(res.bytes);
      } catch {
        // Not a document.
      }
      const keys =
        isJsonObject(value) && serverOrigin(value.server, true) === this.origin
          ? readKeys(value.keys, new Date(this.now()))
          : null;
      const algorithms =
        isJsonObject(value) && Array.isArray(value.algorithms)
          ? value.algorithms.filter((a): a is string => typeof a === 'string')
          : [];
      if (res.status !== 200 || !isJsonObject(value) || !keys) {
        throw new Prerequisite(
          `GET /simon/server did not give a server document naming ${this.origin} with readable keys (${res.status})`,
        );
      }
      const published = isJsonObject(value.limits) ? value.limits : {};
      const limits = { ...MINIMUM_LIMITS };
      for (const name of Object.keys(limits) as (keyof Limits)[]) {
        const n = published[name];
        if (Number.isSafeInteger(n) && (n as number) > 0) limits[name] = n as number;
      }
      return { res, doc: { server: this.origin, keys, algorithms, limits } };
    });
  }

  async limits(): Promise<Limits> {
    return (await this.serverDoc()).doc.limits;
  }

  /**
   * An agent on the server, registered once per name: by leasing (a key alone), or else on the hosted
   * domain. `alg` picks its key's algorithm.
   */
  agent(name: string, alg: 'ed25519' | 'ml-dsa-65' = 'ed25519'): Promise<TargetAgent> {
    return this.once(`agent ${name}`, async t => {
      const a = new TargetAgent(this.server, generateKey(alg).privateKey);
      const leased = await a.register(t, {}, {}, `register ${name} by leasing`);
      if (leased.status === 200 && typeof leased.json?.address === 'string') {
        a.address = leased.json.address;
        this.servedDomains.add(domainOf(a.address));
        return a;
      }
      if (this.opts.hostedDomain) {
        const address = `${this.runId}-${name}@${this.opts.hostedDomain}`;
        const hosted = await a.register(t, { address }, {}, `register ${name} on the hosted domain`);
        if (hosted.status === 200 && hosted.json?.address === address) {
          a.address = address;
          this.servedDomains.add(domainOf(a.address));
          return a;
        }
        throw new Prerequisite(
          `could not register an agent: leasing answered ${leased.status}, the hosted domain ${hosted.status}`,
        );
      }
      throw new Prerequisite(
        `could not register an agent: leasing answered ${leased.status} ${problem(leased)?.code ?? ''}; pass --hosted-domain for a server that leases no addresses`,
      );
    });
  }

  /** The domains the server serves, as far as the suite knows them: where its agents live, and the options. */
  get servedDomains() {
    return this.peer.target.domains;
  }

  /** The domain the suite's agents live on at the server. */
  async domain() {
    return domainOf((await this.agent('a')).address);
  }

  /** POST an envelope (or raw text) to the server's /simon/deliver. */
  deliver(t: T, envelope: Envelope | Record<string, unknown> | string | Buffer, label?: string) {
    const body = typeof envelope === 'string' || Buffer.isBuffer(envelope) ? envelope : canonicalize(envelope);
    return t.http({ method: 'POST', origin: this.origin, target: '/simon/deliver', body }, { label });
  }

  /**
   * Make sure deliveries from the simulator get past resolution and the envelope: a server that refetches
   * a document at most once a minute may still answer 503 for a while after the server-document check.
   */
  peerReady(): Promise<void> {
    return this.once('the simulator is reachable', async t => {
      const a = await this.agent('a');
      const p = this.peer.agent('warmup');
      const end = Date.now() + 75_000;
      for (;;) {
        const m = buildFrom(p, [a.address], this.now());
        const res = await this.deliver(t, this.peer.envelope(m), 'a delivery from the simulator');
        if (res.status === 202) return;
        if (res.status !== 503 || Date.now() > end) {
          throw new Prerequisite(
            `a valid delivery from the simulator was answered ${res.status} ${problem(res)?.code ?? ''}. ` +
              `Is the server configured to resolve ${this.opts.peerDomain} to ${this.peer.origin}?`,
          );
        }
        await new Promise(r => setTimeout(r, 5000));
      }
    });
  }

  /** A second simulated server, on a free port, that the server under test never delivered to. */
  strangerPeer(): Promise<Peer> {
    return this.once('a stranger server', async () => {
      if (this.opts.peerOrigin) {
        this.notes.push(
          'The stranger simulator has no tunnel, so a server elsewhere cannot check its signature: in ' +
            'parts.refusals-identical it is one more unverifiable request.',
        );
      }
      const port = await freePort(this.opts.peerHost);
      const p = new Peer('stranger.test', this.opts.peerHost, port, this.runId);
      p.target = this.peer.target;
      await p.start();
      this.#cleanup.push(() => p.stop());
      return p;
    });
  }

  /** Stop what setup started. */
  async close() {
    for (const f of this.#cleanup.splice(0)) await f().catch(() => undefined);
  }

  /** Run the operator's code command for an address, and return the code it prints. */
  async code(address: string): Promise<string> {
    const cmd = this.opts.codeCommand;
    if (!cmd) throw new Prerequisite('no --code-command was given');
    const code = (await operator(cmd, 'code', address)).trim().split('\n').at(-1)?.trim() ?? '';
    if (!code) throw new Prerequisite('--code-command printed nothing');
    return code;
  }

  /** Run the operator's cancel code command for an address, and return the cancel code it prints. */
  async cancelCode(address: string): Promise<string> {
    const cmd = this.opts.cancelCodeCommand;
    if (!cmd) throw new Prerequisite('no --cancel-code-command was given');
    const code = (await operator(cmd, 'cancel code', address)).trim().split('\n').at(-1)?.trim() ?? '';
    if (!code) throw new Prerequisite('--cancel-code-command printed nothing');
    return code;
  }

  /** Run the operator's retire command for an address. */
  async retire(address: string): Promise<void> {
    const cmd = this.opts.retireCommand;
    if (!cmd) throw new Prerequisite('no --retire-command was given');
    await operator(cmd, 'retire', address);
  }

  /** A setup T, for checks that call helpers which record as setup. */
  get setup() {
    return this.#setup;
  }
}

/** Run an operator hook with the address as $1 and SIMON_ADDRESS; its stdout. */
function operator(cmd: string, name: string, address: string): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      '/bin/sh',
      ['-c', cmd, `simon-${name}`, address],
      { env: { ...process.env, SIMON_ADDRESS: address }, timeout: 60_000 },
      (err, stdout) => (err ? reject(new Prerequisite(`--${name}-command failed: ${err.message}`)) : resolve(stdout)),
    );
  });
}

/** A version 1 message from a simulated agent. */
export function buildFrom(p: PeerAgent, to: string[], now: number, f: MessageFields = {}) {
  return buildMessage({ ...f, from: p.address, to }, f.signWith ?? p.key, now);
}

/** A port nothing listens on just now. */
export function freePort(host: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, host, () => {
      const port = (s.address() as net.AddressInfo).port;
      s.close(() => resolve(port));
    });
  });
}
