/** Signed agent calls to its own server, as specified in spec/CLIENT.md. */
import type { KeyObject } from 'node:crypto';
import {
  VERSION,
  addKeyProofString,
  canonicalBytes,
  keyToken,
  isPrincipal,
  normalizeAddress,
  privateKeyObject,
  sha256Hex,
  sign,
  signMessage,
  signRequest,
  timestamp,
  readSuccession,
  verifyPairing,
  verifyRecovery,
  type Claim,
  type Hints,
  type KeyEntry,
  type Message,
  type Part,
  type SignedClaims,
  isHeaderName,
  isJsonType,
  jsonDataProblem,
  isListableIdentifier,
  isJsonObject,
  parseStrict,
  readDirectoryRecord,
  serverOrigin,
  MAX_DOCUMENT_BYTES,
  type DirectoryRecord,
} from '@agnt-sdk/simon-protocol';
import { SimonError, addressArg, invalid, originArg } from './errors.ts';
import { DEFAULT_TIMEOUT_MS, exchange, failure, readJson, type Answer, type Transport } from './http.ts';
import { fetchServerDocument, identifierAuthority, type ReadOptions } from './read.ts';

export interface AgentOptions extends Transport {
  /** The agent's own server, as an origin: `https://simon.example.com`. `http:` is for local development. */
  server: string;
  /** The private key: PKCS #8 PEM, or a KeyObject. */
  key: string | KeyObject;
  /** The agent's address, once registered. */
  address?: string | null;
  /** A paired agent's principal (spec section 2.2), written into every message as the `for` header. */
  for?: string;
  /** With a key principal: the principal's pairing signature, written into every message as `pairing`. */
  pairing?: string;
  /** With a key principal that moved to a new key: its signed succession, written into every message. */
  succession?: string;
}

/** The assistant an identifier's holder chose, by whose record (discovery profile). */
export interface FoundAssistant {
  address: string;
  record: DirectoryRecord;
  /** Whether the identifier's own domain issued the record, rather than a directory this agent trusts. */
  authoritative: boolean;
}

/** Account state, answered by register on success and by account/key operations. */
export interface Account {
  /** Success has no status member. */
  status?: never;
  address: string;
  keys: (KeyEntry & { label?: string })[];
  grants: { id: string; client: string; scopes: string[]; createdAt: string; lastUsedAt: string }[];
  recovery: { completesAt: string; cancellable: boolean } | null;
}

/** A successful registration is an account; pending responses explain the next step. */
export type Registration =
  | Account
  | { status: 'code_sent'; address: string }
  | { status: 'pairing_required'; address: string };

export interface RegisterOptions {
  address?: string;
  code?: string;
  for?: string;
  pairing?: string;
  /** Host-specific creation proofs must use namespaced members. */
  [extension: `${string}:${string}`]: string | undefined;
}

export interface RecoverOptions {
  address: string;
  code?: string;
  at?: string;
  recover?: string;
  /** Local pairing state: checked and retained, never added to the recovery request body. */
  for?: string;
  pairing?: string;
}
export type Recovery =
  | Account
  | { status: 'code_sent'; address: string }
  | { status: 'recovery_pending'; address: string; completesAt: string };

/**
 * What to send. `text`, when given, becomes the first part (`text/plain`), ahead of `parts`. A message may
 * carry any parts, or none (spec section 5.3). The agent adds `for` and `pairing` itself, so `headers` must
 * not hold them.
 */
export interface Draft {
  to: string[];
  text?: string;
  parts?: Part[];
  inReplyTo?: string | null;
  headers?: Record<string, string>;
}

/** One sync entry; its contents may be of an unsupported message version. */
export interface Delivered {
  id: string;
  message: Message;
  carrier: string;
  claims: Claim[];
  signedClaims?: SignedClaims;
  receivedAt: string;
  conversation?: string;
  marks?: string[];
}

export interface Signal {
  type: string;
  from: string;
  about: string;
  at: string;
}

export interface Sync {
  messages: Delivered[];
  signals: Signal[];
  marks: { id: string; marks: string[] }[];
  removed: string[];
  /** Opaque: store unchanged and pass as `since`, never interpret it. */
  token: string;
  more: boolean;
}

export interface SyncOptions {
  since?: string;
  limit?: number;
  wait?: number;
  /** Local request deadline, not a query member. */ timeoutMs?: number;
}

/**
 * How delivery of a sent message is going, one entry per recipient server. A failure's `reason` is the
 * resolution outcome, the code the receiving server answered, or `expired` when the delivery deadline
 * passed.
 */
export interface Delivery {
  id: string;
  servers: {
    server: string | null;
    recipients: string[];
    status: 'pending' | 'delivered' | 'failed';
    reason?: string;
  }[];
}

/** A content-addressed part: what `uploadPart` returns, ready for a draft's `parts`. */
export type HashPart = Extract<Part, { sha256: string }>;

const HEX64 = /^[0-9a-f]{64}$/;
const JSON_TYPE = { 'content-type': 'application/json' };
const BYTES_TYPE = { 'content-type': 'application/octet-stream' };

export class Agent {
  /** The server's origin. */
  readonly server: string;
  /** This agent's key token. */
  readonly key: string;
  readonly #privateKey: KeyObject;
  readonly #transport: Required<Transport>;
  #address: string | null;
  #for: string | undefined;
  #pairing: string | undefined;
  #succession: string | undefined;

  constructor(opts: AgentOptions) {
    this.server = originArg('server', opts.server);
    this.#privateKey = privateKeyObject(opts.key);
    this.key = keyToken(this.#privateKey);
    this.#transport = {
      fetch: opts.fetch ?? ((url, init) => fetch(url, init)),
      timeoutMs: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      now: opts.now ?? (() => new Date()),
    };
    this.#address = opts.address == null ? null : addressArg('address', opts.address);
    this.#for = opts.for;
    this.#pairing = opts.pairing;
    this.#succession = opts.succession;
  }

  /** The agent's address, or null until a registration is active. */
  get address(): string | null {
    return this.#address;
  }

  /** The principal this agent is paired with, or undefined for a solo agent. */
  get for(): string | undefined {
    return this.#for;
  }

  /** The pairing every message carries, `<until> <signature>`; `parsePairing` reads when it lapses. */
  get pairing(): string | undefined {
    return this.#pairing;
  }

  /** The succession every message carries, from the principal's earlier keys on to its `for`. */
  get succession(): string | undefined {
    return this.#succession;
  }

  /**
   * Move to the principal's new key (spec section 2.2): `for` its new identifier, a `pairing` that key signed,
   * and the `succession`, steps both keys signed, leading from the principal this agent has to it. The steps
   * from this agent's principal on are added to the chain it already carries, so moving twice before sending
   * keeps the whole way. Checked here; the server moves its record on the next message, so this needs no call.
   */
  succeed(opts: { for: string; pairing: string; succession: string }): void {
    const address = this.#requireAddress();
    const steps = readSuccession(opts.succession, opts.for);
    const from = steps?.findIndex(s => s.from === this.#for) ?? -1;
    if (from < 0)
      throw invalid('succession', "A succession must verify and lead from this agent's principal to the new one.");
    const added = opts.succession.split(',').slice(from).join(',');
    const succession = this.#succession === undefined ? opts.succession : `${this.#succession},${added}`;
    if (readSuccession(succession, opts.for) === null)
      throw invalid('succession', 'The chain this agent carries and the new steps do not make one succession.');
    if (!verifyPairing(address, opts.for, opts.pairing, this.#transport.now()))
      throw invalid('pairing', "The new key's pairing must be for this address, and count now.");
    [this.#for, this.#pairing, this.#succession] = [opts.for, opts.pairing, succession];
  }

  /**
   * Carry a renewed pairing from now on: the principal's signature over a later `until` (spec section 2.2).
   * The server holds no pairing, so renewing needs no call to it; this checks the pairing counts now.
   */
  renewPairing(pairing: string): void {
    const address = this.#requireAddress();
    if (this.#for === undefined || !verifyPairing(address, this.#for, pairing, this.#transport.now()))
      throw invalid('pairing', "A renewed pairing must be the principal's, for this address, and count now.");
    this.#pairing = pairing;
  }

  /** Create or pair an address. Use recover for an existing address. An account answer binds this agent. */
  async register(opts: RegisterOptions = {}): Promise<Registration> {
    const address = opts.address === undefined ? undefined : addressArg('address', opts.address);
    for (const name of Object.keys(opts)) {
      if (!['address', 'code', 'for', 'pairing'].includes(name) && !/^[a-z0-9][a-z0-9.-]*:[a-zA-Z0-9._-]+$/.test(name))
        throw invalid(name, 'Creation extensions must be namespaced; recovery uses recover().');
    }
    const body = withoutUndefined({ ...opts, key: this.key, address });
    // A lease has an empty identity line, even on an object with a saved address.
    const r = await readJson<Registration>(
      await this.#request('POST', '/simon/register', Buffer.from(JSON.stringify(body)), JSON_TYPE, address ?? null),
      this.#transport.now(),
    );
    if ('keys' in r) {
      this.#address = r.address;
      if ('for' in opts && opts.for !== undefined)
        [this.#for, this.#pairing, this.#succession] = [opts.for, opts.pairing, undefined];
    }
    return r;
  }

  /** Recover an existing address; successful recovery binds this new key. */
  async recover(opts: RecoverOptions): Promise<Recovery> {
    const address = addressArg('address', opts.address);
    if (opts.for === undefined && this.#for !== undefined && this.#address !== address)
      throw invalid('for', 'Recovery of a different address requires an explicit local principal choice.');
    const principal = opts.for ?? this.#for;
    const pairing = opts.for === undefined ? (opts.pairing ?? this.#pairing) : opts.pairing;
    if (pairing !== undefined && principal === undefined) throw invalid('for', 'Pairing needs its principal.');
    if (
      principal !== undefined &&
      (!isPrincipal(principal) ||
        (principal.startsWith('simon-key:') && !verifyPairing(address, principal, pairing, this.#transport.now())))
    )
      throw invalid(
        'pairing',
        'Effective recovery principal must be valid; its key pairing must verify for the target address.',
      );
    if (
      opts.recover !== undefined &&
      (principal === undefined ||
        !principal.startsWith('simon-key:') ||
        typeof opts.at !== 'string' ||
        !verifyRecovery(address, principal, this.key, opts.at, opts.recover))
    )
      throw invalid(
        'recover',
        'Recovery proof must verify for this same principal, target address, new key and timestamp.',
      );
    const body = withoutUndefined({ address, key: this.key, code: opts.code, at: opts.at, recover: opts.recover });
    const result = await readJson<Recovery>(
      await this.#request('POST', '/simon/recovery', Buffer.from(JSON.stringify(body)), JSON_TYPE, address),
      this.#transport.now(),
    );
    if ('keys' in result) {
      this.#address = result.address;
      if (principal !== this.#for) this.#succession = undefined;
      [this.#for, this.#pairing] = [principal, pairing];
    }
    return result;
  }

  /** Read recovery state only as the registered agent, never as an unauthenticated requester. */
  async recoveryStatus(): Promise<{ recovery: Account['recovery'] }> {
    this.#requireAddress();
    return this.#json('GET', '/simon/recovery');
  }

  async account(): Promise<Account> {
    return this.#json('GET', '/simon/account');
  }

  /** Add a device key, proving possession with that new private key. */
  async addKey(key: string | KeyObject, label?: string): Promise<Account> {
    const added = privateKeyObject(key);
    const token = keyToken(added);
    if (label !== undefined && (typeof label !== 'string' || [...label].length > 64))
      throw invalid('label', 'label is at most 64 characters.');
    return this.call('POST', '/simon/keys', {
      key: token,
      proof: sign(added, addKeyProofString(this.#requireAddress(), token)),
      ...(label === undefined ? {} : { label }),
    });
  }

  async revokeKey(key: string): Promise<Account> {
    return this.call('DELETE', `/simon/keys/${encodeURIComponent(key)}`);
  }

  async endGrant(id: string): Promise<Account | { status: 'ended' }> {
    return this.call('DELETE', `/simon/grants/${encodeURIComponent(id)}`);
  }

  /** Cancel by a known agent key, or by the cancel code from the address's mailbox. */
  async cancelRecovery(opts?: {
    address: string;
    cancelCode: string;
  }): Promise<{ status: 'cancelled'; address: string }> {
    if (!opts) this.#requireAddress();
    const address = opts ? addressArg('address', opts.address) : this.#address!;
    const body = opts ? { address, cancelCode: opts.cancelCode } : {};
    return readJson(
      await this.#request('POST', '/simon/recovery/cancel', Buffer.from(JSON.stringify(body)), JSON_TYPE, address),
      this.#transport.now(),
    );
  }

  /**
   * Retire a paired address by its principal's unpairing. An unpairing signed by a key the principal moved on
   * from also counts, given `succession`, the chain from that key to the principal the server holds.
   */
  async unpair(
    address: string,
    unpairing: string,
    succession?: string,
  ): Promise<{ status: 'retired'; address: string }> {
    address = addressArg('address', address);
    return readJson(
      await this.#request(
        'POST',
        '/simon/unpair',
        Buffer.from(JSON.stringify({ address, unpairing, ...(succession !== undefined && { succession }) })),
        JSON_TYPE,
        address,
      ),
      this.#transport.now(),
    );
  }

  /** A signed version 1 message from a draft, written now. Send it with `send`; sending it again is safe. */
  compose(draft: Draft): Message {
    const from = this.#requireAddress();
    for (const name of ['for', 'pairing', 'succession']) {
      if (draft.headers && Object.hasOwn(draft.headers, name)) {
        throw invalid('headers', `The agent writes the ${name} header from its pairing; leave it out of the draft.`);
      }
    }
    const paired = withoutUndefined({ for: this.#for, pairing: this.#pairing, succession: this.#succession });
    const to = draft.to.map((a, i) => addressArg(`to[${i}]`, a));
    const parts = [
      ...(draft.text === undefined ? [] : [{ type: 'text/plain', data: draft.text }]),
      ...(draft.parts ?? []),
    ];
    // A JSON block's value is signed as canonical JSON: say how to write one that is not, before signing.
    for (const p of parts) {
      if (typeof p?.type !== 'string' || !isJsonType(p.type) || !('data' in p)) continue;
      const problem = jsonDataProblem(p.data);
      if (problem !== null) throw invalid('parts', problem);
    }
    return signMessage<Message>(
      {
        v: VERSION,
        from,
        to,
        inReplyTo: draft.inReplyTo ?? null,
        parts,
        headers: { ...draft.headers, ...paired },
        sentAt: timestamp(this.#transport.now()),
      },
      this.#privateKey,
    );
  }

  /**
   * Send a draft, or a message `compose` signed. `hints` go to each recipient's server, keyed by an address
   * in `to`: `{ "bob@example.net": { "invite": "7KQ2-..." } }`.
   */
  async send(message: Draft | Message, opts: { hints?: Hints } = {}): Promise<{ id: string; receivedAt: string }> {
    const m = 'signature' in message ? message : this.compose(message);
    const headers: Record<string, string> = { ...JSON_TYPE };
    if (opts.hints) headers['simon-hints'] = asciiJson(hintsFor(m.to, opts.hints));
    return this.#json('POST', '/simon/send', canonicalBytes(m), headers);
  }

  /** Read messages, signals and history changes since an opaque token. */
  async sync(opts: SyncOptions = {}): Promise<Sync> {
    const { since, limit, wait, timeoutMs } = opts;
    if (timeoutMs !== undefined && (!Number.isFinite(timeoutMs) || timeoutMs <= 0))
      throw invalid('timeoutMs', 'timeoutMs is positive.');
    if (since !== undefined && (typeof since !== 'string' || !since.length))
      throw invalid('since', 'since is a nonempty opaque token.');
    if (limit !== undefined && !(Number.isInteger(limit) && limit >= 1 && limit <= 200))
      throw invalid('limit', 'limit is a whole number from 1 to 200.');
    if (wait !== undefined && !(Number.isInteger(wait) && wait >= 0 && wait <= 60))
      throw invalid('wait', 'wait is a whole number from 0 to 60 seconds.');
    const query = new URLSearchParams();
    if (since !== undefined) query.set('since', since);
    if (limit !== undefined) query.set('limit', String(limit));
    if (wait !== undefined) query.set('wait', String(wait));
    const path = `/simon/sync${query.size ? `?${query}` : ''}`;
    // Leave time for the server's requested long poll as well as transport overhead.
    return readJson(
      await this.#request(
        'GET',
        path,
        undefined,
        {},
        this.#address ?? undefined,
        timeoutMs ?? Math.max(this.#transport.timeoutMs, (wait ?? 0) * 1000 + 5000),
      ),
      this.#transport.now(),
    );
  }

  async sendSignal(type: Signal['type'], about: string, to: string[]): Promise<{ accepted: true }> {
    if (!isHeaderName(type))
      throw invalid('type', 'A signal type is a name: a registry name, or a private reverse-domain one.');
    if (!HEX64.test(about)) throw invalid('about', 'A message id is 64 lower-case hex digits.');
    return this.call('POST', '/simon/send-signal', { type, about, to: to.map((a, i) => addressArg(`to[${i}]`, a)) });
  }

  async createWebhook(url: string): Promise<{ id: string }> {
    return this.call('POST', '/simon/webhooks', { url });
  }

  async verifyWebhook(id: string, code: string): Promise<{ id: string; verified: boolean }> {
    return this.call('POST', `/simon/webhooks/${encodeURIComponent(id)}/verify`, { code });
  }

  async deleteWebhook(id: string): Promise<{ deleted: boolean }> {
    return this.call('DELETE', `/simon/webhooks/${encodeURIComponent(id)}`);
  }

  /** How delivery of this agent's own message is going. */
  async sent(id: string): Promise<Delivery> {
    if (!HEX64.test(id)) throw invalid('id', 'A message id is 64 lower-case hex digits.');
    return this.#json('GET', `/simon/sent/${id}`);
  }

  /**
   * Upload a part's bytes before sending a message that names them. Returns the part to put in `parts`,
   * with `name`, the file name suggested to its readers, when given.
   */
  async uploadPart(bytes: Uint8Array, type: string, name?: string): Promise<HashPart> {
    const sha256 = sha256Hex(bytes);
    await this.#json('PUT', `/simon/parts/${sha256}`, bytes, BYTES_TYPE);
    return { type, sha256, size: bytes.length, ...(name === undefined ? {} : { name }) };
  }

  /**
   * The bytes of a content-addressed part, checked against its hash, and its size when given. A `503
   * unavailable` (retryable, with `retryAfter`) means the server is still fetching them from the author's.
   */
  async fetchPart(part: { sha256: string; size?: number }): Promise<Uint8Array> {
    if (!HEX64.test(part.sha256)) throw invalid('sha256', 'A part hash is 64 lower-case hex digits.');
    const a = await this.#request(
      'GET',
      `/simon/parts/${part.sha256}`,
      undefined,
      {},
      undefined,
      this.#transport.timeoutMs,
      part.size,
    );
    if (a.status !== 200) throw failure(a, this.#transport.now());
    const hash = sha256Hex(a.body);
    if (hash !== part.sha256 || (part.size !== undefined && a.body.length !== part.size)) {
      throw new SimonError('hash_mismatch', `${a.url} sent ${a.body.length} bytes hashing to ${hash}.`, {
        details: { url: a.url, sha256: hash, size: a.body.length },
      });
    }
    return a.body;
  }

  /**
   * Any signed request to this agent's server, for calls a server adds. `path` is the path and query. A
   * Uint8Array body is sent as bytes, anything else as JSON. Answers the response's JSON, or null for none.
   */
  async call<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
    opts: { headers?: Record<string, string> } = {},
  ): Promise<T> {
    const raw = body instanceof Uint8Array;
    const bytes = body === undefined ? undefined : raw ? body : Buffer.from(JSON.stringify(body));
    const type = bytes === undefined ? {} : raw ? BYTES_TYPE : JSON_TYPE;
    return this.#json<T>(method.toUpperCase(), path, bytes, { ...type, ...opts.headers });
  }

  /**
   * The assistant the holder of `identifier`, an email address or a phone number, chose (discovery profile):
   * asked of the identifier's own authority when its domain's TXT record names a server that answers lookups
   * (its server document says `discovery`), whose answer is final, and otherwise of `directories`, the
   * directory servers this agent trusts, in order, https origins only (`allowHttp` admits http for local
   * development). Each record is checked with its issuer's server document. Null only when every server asked
   * answered that it holds no record. A domain whose `_simon` records are malformed or conflict is `no_server`,
   * no directory asked; a directory that answers something other than a record or `404`, a record that fails
   * its checks included, is passed over, and when no other holds a record its failure is thrown, retryable
   * when it may pass: never "nobody".
   */
  async findAssistant(
    identifier: string,
    opts: ReadOptions & { directories?: readonly string[] } = {},
  ): Promise<FoundAssistant | null> {
    if (!isListableIdentifier(identifier)) throw invalid('identifier', 'An identifier is mailto: or tel:.');
    const transport = { ...this.#transport, ...opts };
    const directories = (opts.directories ?? []).map(d => {
      const origin = serverOrigin(d, !!opts.allowHttp);
      if (!origin)
        throw invalid('directories', `A directory is an https origin such as https://simon.example.com, not ${d}.`);
      return origin;
    });
    let authority = await identifierAuthority(identifier, transport);
    // A server that does not implement the profile does not end the search: its domain has not spoken.
    if (authority && !(await fetchServerDocument(authority, transport)).discovery) authority = null;
    const servers = authority ? [authority] : directories;
    let failed: SimonError | null = null;
    for (const server of servers) {
      const target = `${server}/simon/lookup?identifier=${encodeURIComponent(identifier)}`;
      try {
        const a = await this.#signed('GET', target, undefined, MAX_DOCUMENT_BYTES);
        if (a.status === 404) continue;
        const found = await this.#readLookup(a, server, identifier, transport);
        return { address: found.address, record: found, authoritative: !!authority };
      } catch (e) {
        if (!(e instanceof SimonError)) throw e;
        // The authority's failure is final; a directory that misbehaves is passed over, its failure remembered,
        // one that may pass before one that will not.
        if (authority) throw e;
        if (!failed || (e.retryable && !failed.retryable)) failed = e;
      }
    }
    if (failed) throw failed;
    return null;
  }

  /** The record a lookup answered, read as strictly as any signed object, from `server` alone; else `bad_response`. */
  async #readLookup(a: Answer, server: string, identifier: string, opts: ReadOptions): Promise<DirectoryRecord> {
    if (a.status < 200 || a.status > 299) throw failure(a, this.#transport.now());
    const bad = (why: string) =>
      new SimonError('bad_response', `${a.url} answered ${a.status} with ${why}.`, {
        status: a.status,
        details: { url: a.url },
      });
    if (a.body.length > MAX_DOCUMENT_BYTES) throw bad('more than a lookup answer may hold');
    let answer: unknown;
    try {
      answer = parseStrict(a.body);
    } catch {
      throw bad('a body that is not JSON under the canonical rules');
    }
    const value = isJsonObject(answer) ? answer.record : undefined;
    const keys = (await fetchServerDocument(server, opts)).keys;
    const read = readDirectoryRecord(value, identifier, keys, this.#transport.now(), opts.allowHttp);
    // A record counts only from the server asked: no server answers in another's name.
    if (!read || read.issuer !== server) throw bad(`no record of ${identifier} that ${server} signed`);
    return read;
  }

  /**
   * Ask `directory` to list this agent as the assistant of `identifier` (discovery profile, section 4): without
   * a code, it sends one to the identifier; with the code its holder read, it lists this agent and answers
   * the record.
   */
  async listIn(
    directory: string,
    identifier: string,
    code?: string,
  ): Promise<{ status: 'code_sent' } | { record: DirectoryRecord }> {
    this.#requireAddress();
    const body = Buffer.from(JSON.stringify(withoutUndefined({ identifier, code })));
    const target = `${originArg('directory', directory)}/simon/directory`;
    return readJson(await this.#signed('POST', target, body), this.#transport.now());
  }

  /** Unlist this agent as the assistant of `identifier` in `directory`; the answer is the same either way. */
  async unlistFrom(directory: string, identifier: string): Promise<{ status: 'unlisted' }> {
    this.#requireAddress();
    const body = Buffer.from(JSON.stringify({ identifier }));
    const target = `${originArg('directory', directory)}/simon/directory`;
    return readJson(await this.#signed('DELETE', target, body), this.#transport.now());
  }

  /** A request to another server, signed as this agent: a reader or a directory's client (spec section 8). */
  #signed(method: string, url: string, body?: Uint8Array, maxBytes?: number): Promise<Answer> {
    const signed = signRequest(this.#privateKey, {
      method,
      url,
      body,
      now: this.#transport.now().getTime(),
      agent: this.#requireAddress(),
    });
    const headers = body ? { ...JSON_TYPE, ...signed } : signed;
    return exchange(
      this.#transport,
      url,
      { method, headers, body: body as Uint8Array<ArrayBuffer> | undefined },
      maxBytes,
    );
  }

  async #json<T>(method: string, path: string, body?: Uint8Array, headers?: Record<string, string>): Promise<T> {
    return readJson<T>(await this.#request(method, path, body, headers), this.#transport.now());
  }

  /** A request signed as `agent`, by default this agent's address (spec section 8). */
  #request(
    method: string,
    path: string,
    body?: Uint8Array,
    headers: Record<string, string> = {},
    agent: string | null | undefined = this.#address ?? undefined,
    timeoutMs = this.#transport.timeoutMs,
    maxBytes?: number,
  ): Promise<Answer> {
    if (!path.startsWith('/') || path.startsWith('//')) throw invalid('path', `A path starts with a single /: ${path}`);
    const url = new URL(path, this.server).href;
    const now = this.#transport.now().getTime();
    const signed = signRequest(this.#privateKey, { method, url, body, now, agent: agent ?? undefined });
    // fetch's types refuse a Uint8Array that may sit on a SharedArrayBuffer; these never do.
    const init = { method, headers: { ...headers, ...signed }, body: body as Uint8Array<ArrayBuffer> | undefined };
    return exchange({ ...this.#transport, timeoutMs }, url, init, maxBytes);
  }

  #requireAddress(): string {
    if (this.#address === null) {
      throw new SimonError('not_registered', 'This agent has no address yet: register first.');
    }
    return this.#address;
  }
}

/** Hints keyed by recipient addresses in their wire form, each one in `to`. */
function hintsFor(to: string[], hints: Hints): Hints {
  const out: Hints = {};
  for (const [key, value] of Object.entries(hints)) {
    const address = normalizeAddress(key);
    if (!address || !to.includes(address)) throw invalid('hints', `Hints are keyed by an address in to, not ${key}.`);
    out[address] = value;
  }
  return out;
}

/** JSON in ASCII, as an HTTP header carries it: every other character escaped as `\uXXXX`, by UTF-16 code unit. */
const asciiJson = (value: unknown) =>
  JSON.stringify(value).replace(/[^\x20-\x7e]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);

function withoutUndefined<T extends Record<string, string | undefined>>(o: T): Record<string, string> {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as Record<string, string>;
}
