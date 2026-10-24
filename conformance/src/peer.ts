/**
 * The peer simulator: an AGNT server the suite runs on localhost, so it can deliver to the server under
 * test as another server would, and receive that server's deliveries and check them.
 *
 *   GET  /agnt/server              its server document (or a 503, on demand)
 *   GET  /agnt/agents/<address>    documents for the agents it controls, each with its own faults
 *   POST /agnt/deliver             records every envelope; answers 202, or 503 or 400 for chosen recipients
 *   GET  /agnt/parts/<sha256>      part bytes, only to a server request signed by a server it delivered to
 *
 * Its server keys come from fixed seeds, so a server under test that cached its document from an earlier
 * run still verifies it. Its agents get new addresses every run, so no agent document is ever stale.
 */
import http from 'node:http';
import crypto, { type KeyObject } from 'node:crypto';
import {
  canonicalize,
  checkSignedRequest,
  domainOf,
  isJsonObject,
  keyToken,
  MINIMUM_LIMITS,
  NonceCache,
  parseStrict,
  privateKeyFromSeed,
  readKeys,
  readSignedHeaders,
  requestSigningString,
  actorOf,
  serverOrigin,
  sha256Hex,
  sign,
  signAgentDocument,
  signEnvelope,
  V1_ALGORITHMS,
  WireError,
  type Claim,
  type Envelope,
  type Hints,
  type Json,
  type KeyEntry,
  type AnyMessage,
} from '@agnt-protocol/protocol';
import { newNonce } from './agent.ts';
import { transport } from './harness.ts';

/** How a peer agent's document is served. */
export type DocMode =
  | 'ok'
  | '404'
  | '403'
  | '429'
  | '500'
  | '503'
  | 'wrong-address'
  | 'bad-signature'
  | 'malformed-key'
  | 'unknown-algorithm'
  | 'too-many-keys'
  | 'too-large'
  | 'extra-members';

export interface PeerAgent {
  name: string;
  address: string;
  key: KeyObject;
  token: string;
  kind: string;
  /** The entries the document lists; by default the key, added long ago. */
  keys: KeyEntry[];
  doc: DocMode;
}

/** One envelope the server under test posted here. */
export interface Received {
  at: Date;
  headers: Record<string, string>;
  raw: Buffer;
  /** The parsed envelope, or null when it did not parse. */
  envelope: (Envelope & Record<string, unknown>) | null;
  messageText: string | null;
  /** The envelope's recipients when it lists them as an array, else its message's `to`. */
  recipients: string[];
  answer: number;
}

/** What `envelope` may change from a valid envelope: its members, and its signer. */
export interface EnvelopeOptions {
  claims?: Claim[];
  hints?: Hints;
  /** The receiving origin; the server under test's by default. */
  server?: string;
  /** By default, the addresses in `to` on domains the server under test serves (all of `to`, when none is). */
  recipients?: string[];
  /** Members set last, overriding any above (any value, for malformed envelopes). */
  members?: Record<string, unknown>;
  /** Members left out. */
  omit?: string[];
  signer?: KeyObject;
}

export interface PartFetch {
  at: Date;
  sha256: string;
  headers: Record<string, string>;
  target: string;
  /** null when the signed server request verified; otherwise why not. */
  refusal: string | null;
  server: string | null;
  answer: number;
}

const json = (res: http.ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
};
const wireError = (res: http.ServerResponse, e: WireError, headers: Record<string, string> = {}) =>
  json(res, e.status, e.toJSON(), { ...e.headers, ...headers });

const seeded = (label: string) => privateKeyFromSeed('ed25519', crypto.createHash('sha256').update(label).digest());

export const LONG_AGO = '2026-01-01T00:00:00Z';

export class Peer {
  readonly origin: string;
  /** The key it signs with; listed, valid now. */
  readonly serverKey: KeyObject;
  /** Listed, revoked before any test runs. */
  readonly revokedKey: KeyObject;
  /** Listed, added far in the future. */
  readonly futureKey: KeyObject;
  serverDocStatus = 200;
  readonly agents = new Map<string, PeerAgent>();
  readonly received: Received[] = [];
  readonly requests: { at: Date; method: string; target: string }[] = [];
  readonly partFetches: PartFetch[] = [];
  /** Part bytes it serves: to the servers named in `servers`, or wrong bytes when `wrong` is set. */
  readonly parts = new Map<string, { bytes: Buffer; servers: Set<string>; wrong?: Buffer }>();
  /** Fetches a server document, for checking signed server requests. */
  keysOf: (origin: string) => Promise<KeyEntry[] | null> = fetchServerKeys;
  /** The server under test: its origin, and the domains it serves as far as the suite knows (shared by every simulator). */
  target = { origin: '', domains: new Set<string>() };
  readonly #attempts = new Map<string, number>();
  readonly #nonces = new NonceCache();
  #server: http.Server | null = null;

  readonly domain: string;
  readonly host: string;
  readonly port: number;
  readonly runId: string;

  /**
   * A simulator for `domain`, listening on `host` and `port`. `origin` is where the server under test
   * reaches it, when that is not where it listens: a tunnel's `https://<name>`, for a server elsewhere.
   */
  constructor(domain: string, host: string, port: number, runId: string, origin?: string) {
    this.domain = domain;
    this.host = host;
    this.port = port;
    this.runId = runId;
    const announced = origin === undefined ? `http://${host.includes(':') ? `[${host}]` : host}:${port}` : origin;
    this.origin = serverOrigin(announced, true) ?? fail(`The simulator's origin ${announced} is not an origin.`);
    const seed = `agnt-conformance-peer ${domain} ${this.origin}`;
    this.serverKey = seeded(`${seed} active`);
    this.revokedKey = seeded(`${seed} revoked`);
    this.futureKey = seeded(`${seed} future`);
  }

  serverDocument() {
    return {
      server: this.origin,
      keys: [
        { key: keyToken(this.serverKey), added: LONG_AGO, revoked: null },
        { key: keyToken(this.revokedKey), added: '2025-01-01T00:00:00Z', revoked: '2025-06-01T00:00:00Z' },
        { key: keyToken(this.futureKey), added: '9999-01-01T00:00:00Z', revoked: null },
      ],
      algorithms: [...V1_ALGORITHMS],
      limits: { ...MINIMUM_LIMITS, 'x-later-limit': 7 },
      // Readers ignore members they do not know (section 10); this one is always here to prove it.
      'x-conformance': { note: 'a member no reader knows' },
    };
  }

  /** A new agent here, `<run>-<name>@<domain>`. */
  agent(name: string, o: Partial<Omit<PeerAgent, 'name' | 'address'>> & { alg?: 'ed25519' | 'ml-dsa-65' } = {}) {
    const key =
      o.key ??
      (o.alg === 'ml-dsa-65' ? crypto.generateKeyPairSync('ml-dsa-65') : crypto.generateKeyPairSync('ed25519'))
        .privateKey;
    const token = keyToken(key);
    const a: PeerAgent = {
      name,
      address: `${this.runId}-${name}@${this.domain}`,
      key,
      token,
      kind: o.kind ?? 'solo',
      keys: o.keys ?? [{ key: token, added: LONG_AGO, revoked: null }],
      doc: o.doc ?? 'ok',
    };
    this.agents.set(a.address, a);
    return a;
  }

  /** An address here that the simulator answers for by its local part: `x503-` and `x400-` misbehave. */
  address(local: string) {
    return `${this.runId}-${local}@${this.domain}`;
  }

  agentDocument(a: PeerAgent): { status: number; body: string } {
    const status = Number(a.doc);
    if (status) {
      const err = new WireError(
        status,
        status === 429 ? 'rate_limited' : status >= 500 ? 'unavailable' : 'not_found',
        'Not now.',
        status === 429 || status >= 500,
      );
      return { status, body: JSON.stringify(err.toJSON()) };
    }
    let keys: unknown[] = a.keys;
    const extra: Record<string, unknown> = {};
    if (a.doc === 'malformed-key')
      keys = [...keys, { key: `ed25519:${Buffer.alloc(31, 7).toString('base64url')}`, added: LONG_AGO, revoked: null }];
    if (a.doc === 'unknown-algorithm') keys = [{ key: 'x-future-alg:AAAA', added: LONG_AGO, revoked: null }, ...keys];
    if (a.doc === 'too-many-keys') {
      keys = [
        ...keys,
        ...Array.from({ length: 32 }, () => ({
          key: keyToken(crypto.generateKeyPairSync('ed25519').privateKey),
          added: LONG_AGO,
          revoked: null,
        })),
      ];
    }
    if (a.doc === 'too-large') extra.padding = 'x'.repeat(131_072);
    if (a.doc === 'extra-members')
      Object.assign(extra, { encryptionKeys: [{ key: 'x-kem:AAAA' }], 'x-conformance': { any: ['thing', 1] } });
    const doc = {
      address: a.doc === 'wrong-address' ? `someone-else-${a.address}` : a.address,
      kind: a.kind,
      keys: keys as KeyEntry[],
      ...extra,
    };
    const signer = a.doc === 'bad-signature' ? crypto.generateKeyPairSync('ed25519').privateKey : this.serverKey;
    return { status: 200, body: canonicalize(signAgentDocument(doc as never, signer)) };
  }

  /**
   * An envelope carrying `message`, for the server under test and the recipients it serves, signed by this
   * server (or by `signer`).
   */
  envelope(message: AnyMessage | Record<string, unknown>, o: EnvelopeOptions = {}): Envelope {
    const e: Record<string, unknown> = {
      message,
      server: o.server ?? this.target.origin,
      recipients: o.recipients ?? this.recipientsOf(message),
    };
    if (o.claims !== undefined) e.claims = o.claims;
    if (o.hints !== undefined) e.hints = o.hints;
    Object.assign(e, o.members);
    for (const k of o.omit ?? []) delete e[k];
    return signEnvelope(e as never, o.signer ?? this.serverKey);
  }

  /** The addresses in a message's `to` that the server under test serves; all of `to` when none is known to. */
  recipientsOf(message: AnyMessage | Record<string, unknown>): string[] {
    const to = (message as { to?: unknown }).to;
    if (!Array.isArray(to)) return [];
    const all = [...new Set(to.filter((a): a is string => typeof a === 'string'))];
    const served = all.filter(a => this.target.domains.has(domainOf(a)));
    return served.length ? served : all;
  }

  /** Signature headers for a server request this simulator makes to `origin`. */
  serverRequestHeaders(method: string, origin: string, target: string, o: { key?: KeyObject; server?: string } = {}) {
    const key = o.key ?? this.serverKey;
    const ts = String(Math.floor(Date.now() / 1000));
    const nonce = newNonce();
    const actor = o.server ?? this.origin;
    const signing = requestSigningString({ method, origin, actor, target, timestamp: ts, nonce, body: '' });
    return {
      'agnt-key': keyToken(key),
      'agnt-timestamp': ts,
      'agnt-nonce': nonce,
      'agnt-signature': sign(key, signing),
      'agnt-server': actor,
    };
  }

  /** Serve `bytes` as a part, to the servers named. */
  offerPart(bytes: Buffer, servers: string[], wrong?: Buffer) {
    const sha = sha256Hex(bytes);
    this.parts.set(sha, { bytes, servers: new Set(servers), wrong });
    return { sha256: sha, size: bytes.length };
  }

  /** Envelopes received whose message satisfies `pred`. */
  deliveriesOf(pred: (m: Record<string, any>) => boolean) {
    return this.received.filter(r => r.envelope && pred(r.envelope.message as Record<string, any>));
  }

  async start() {
    this.#server = http.createServer((req, res) => {
      this.handle(req, res).catch(e => {
        if (!res.headersSent) json(res, 500, { error: { code: 'internal', message: String(e), retryable: true } });
      });
    });
    await new Promise<void>((resolve, reject) => {
      this.#server!.once('error', reject);
      this.#server!.listen(this.port, this.host, () => resolve());
    });
  }

  async stop() {
    const s = this.#server;
    if (!s) return;
    s.closeAllConnections();
    await new Promise(resolve => s.close(resolve));
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse) {
    const target = req.url ?? '/';
    const at = new Date();
    this.requests.push({ at, method: req.method ?? '', target });
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const c of req) {
      size += c.length;
      if (size <= 4 * 1024 * 1024) chunks.push(c);
    }
    const body = Buffer.concat(chunks);
    const path = target.split('?')[0];
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers[k] = v;

    // A domain that is the origin's own host, as a tunnel's name is, resolves by the well-known answer.
    if (req.method === 'GET' && path === '/.well-known/agnt' && new URL(this.origin).hostname === this.domain) {
      return json(res, 200, { server: this.origin });
    }
    if (req.method === 'GET' && path === '/agnt/server') {
      if (this.serverDocStatus !== 200) {
        return wireError(res, new WireError(this.serverDocStatus, 'unavailable', 'Try later.', true), {
          'retry-after': '1',
        });
      }
      return json(res, 200, this.serverDocument());
    }
    if (req.method === 'GET' && path.startsWith('/agnt/agents/')) {
      const address = decodeURIComponent(path.slice('/agnt/agents/'.length));
      const a = this.agents.get(address);
      if (!a) return wireError(res, new WireError(404, 'not_found', 'No such agent.'));
      const d = this.agentDocument(a);
      return json(res, d.status, d.body, d.status === 503 || d.status === 429 ? { 'retry-after': '1' } : {});
    }
    if (req.method === 'POST' && path === '/agnt/deliver') return this.deliver(at, headers, body, res);
    if (req.method === 'GET' && path.startsWith('/agnt/parts/')) return this.part(at, headers, target, path, res);
    return wireError(res, new WireError(404, 'not_found', 'Nothing here.'));
  }

  private deliver(at: Date, headers: Record<string, string>, raw: Buffer, res: http.ServerResponse) {
    let envelope: Received['envelope'] = null;
    let messageText: string | null = null;
    let recipients: string[] = [];
    try {
      const v = parseStrict(raw) as Record<string, any>;
      if (v && typeof v === 'object' && !Array.isArray(v) && v.message && typeof v.message === 'object') {
        envelope = v as Received['envelope'];
        messageText = canonicalize(v.message);
        const listed = Array.isArray(v.recipients) ? v.recipients : v.message.to;
        if (Array.isArray(listed)) recipients = listed.filter((a: unknown): a is string => typeof a === 'string');
      }
    } catch {
      // Recorded as unparsed; the checks say what was wrong with it.
    }
    const mine = recipients.filter(a => a.endsWith(`@${this.domain}`));
    const id = messageText ? sha256Hex(messageText) : '';
    const attempt = (this.#attempts.get(id) ?? 0) + 1;
    this.#attempts.set(id, attempt);
    let answer = 202;
    if (!envelope) answer = 400;
    else if (mine.some(a => a.startsWith(`${this.runId}-x400-`))) answer = 400;
    else if (mine.some(a => a.startsWith(`${this.runId}-x503-`)) && attempt === 1) answer = 503;
    this.received.push({ at, headers, raw, envelope, messageText, recipients, answer });
    if (answer === 202) return json(res, 202, { accepted: true });
    if (answer === 503)
      return wireError(res, new WireError(503, 'unavailable', 'Try again shortly.', true), { 'retry-after': '1' });
    return wireError(
      res,
      new WireError(400, 'invalid', 'This simulator refuses this recipient.', false, { field: 'message' }),
    );
  }

  private async part(
    at: Date,
    headers: Record<string, string>,
    target: string,
    path: string,
    res: http.ServerResponse,
  ) {
    const sha256 = path.slice('/agnt/parts/'.length);
    const f: PartFetch = {
      at,
      sha256,
      headers,
      target,
      refusal: null,
      server: headers['agnt-server'] ?? null,
      answer: 404,
    };
    this.partFetches.push(f);
    try {
      // A local run has the simulator and the server under test on http origins.
      const h = readSignedHeaders(headers, at, { server: true, allowHttp: true });
      const server = h['agnt-server']!;
      const keys = await this.keysOf(server);
      const entry = keys?.find(k => k.key === h['agnt-key']) ?? null;
      await checkSignedRequest({ method: 'GET', origin: this.origin, actor: actorOf(headers), target, body: '' }, h, {
        now: at,
        entry,
        nonceSeen: (k, n) => this.#nonces.seen(k, n, at),
      });
      this.#nonces.record(h['agnt-key'], h['agnt-nonce'], h['agnt-timestamp'], at);
      f.server = h['agnt-server']!;
    } catch (e) {
      f.refusal = e instanceof WireError ? `${e.status} ${e.code}: ${e.message}` : String(e);
      return wireError(res, new WireError(404, 'not_found', 'No such part.'));
    }
    const p = this.parts.get(sha256);
    if (!p || !p.servers.has(f.server!)) return wireError(res, new WireError(404, 'not_found', 'No such part.'));
    f.answer = 200;
    res.writeHead(200, { 'content-type': 'application/octet-stream' });
    res.end(p.wrong ?? p.bytes);
  }
}

/**
 * The keys of the server document at `origin`, read under section 4's key rules, or null. Only the keys: a
 * document wrong in another way is judged by the documents checks, not by every check that signs with it.
 */
export async function fetchServerKeys(origin: string): Promise<KeyEntry[] | null> {
  try {
    const res = await transport({ method: 'GET', origin, target: '/agnt/server' }, 10_000);
    if (res.status !== 200) return null;
    const doc: Json = parseStrict(res.bytes);
    return isJsonObject(doc) && serverOrigin(doc.server, true) === origin ? readKeys(doc.keys, new Date()) : null;
  } catch {
    return null;
  }
}

function fail(message: string): never {
  throw new Error(message);
}
