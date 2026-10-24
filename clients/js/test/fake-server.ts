/**
 * An in-process server for tests: the six calls of spec/CLIENT.md and the two documents, with every
 * request's signature checked by @agnt-protocol/protocol. It holds one hosted domain, and treats every other domain
 * as resolving to it with the code 123456. It speaks the current wire: errors are RFC 9457
 * problem details, the server document lists `algorithms`, `send` refuses versions it does not implement,
 * a recovery of an agent that still holds a valid key waits 72 hours (`recovery_pending`, cancelled by
 * `cancelRecovery`), and inbox claims carry `authoritative` beside the claims as the carrier signed them
 * (`signedClaims`). `fetch` serves it without a network; `listen`
 * serves it over HTTP on localhost, for the CLI and the MCP server.
 */
import http from 'node:http';
import {
  actorOf,
  NonceCache,
  SEND_WINDOW_MS,
  WireError,
  checkSupportedVersion,
  addKeyProofString,
  canonicalBytes,
  checkPrincipal,
  claimsBytes,
  checkSignedRequest,
  domainOf,
  generateKey,
  isFresh,
  messageId,
  parseJson,
  parseMessage,
  readSignedHeaders,
  serverDocument,
  sha256Hex,
  sign,
  signAgentDocument,
  splitUrl,
  timestamp,
  verify,
  verifyPairing,
  verifyRecovery,
  type Claim,
  type AnyMessage,
  type KeyEntry,
  type Message,
  type SignedClaims,
} from '@agnt-protocol/protocol';

/** How long a recovery waits while the agent still holds a valid key, as the reference server waits. */
export const RECOVERY_WAIT_MS = 72 * 3600_000;

export const CODE = '123456';
/** The cancel code this fake sends with the news of every recovery. */
export const CANCEL_CODE = 'cancel-0123456789abcdef';

interface Held {
  address: string;
  for?: string;
  keys: (KeyEntry & { label?: string })[];
  retired?: string;
  unpairing?: string;
}

interface Entry {
  to: string;
  cursor: number;
  id: string;
  message: Message;
  carrier: string;
  claims: Claim[];
  signedClaims?: SignedClaims;
  receivedAt: string;
}

const refuse = (status: number, code: string, message: string, details?: Record<string, unknown>) =>
  new WireError(status, code, message, false, details);

export interface FakeOptions {
  origin?: string;
  domain?: string;
  now?: () => Date;
  /** The claims this server keeps with a message it delivers, as a receiving server judged them. */
  claims?: (m: Message) => Claim[];
}

export function fakeServer(opts: FakeOptions = {}) {
  const origin = opts.origin ?? 'https://simon.test';
  const domain = opts.domain ?? 'agents.test';
  const now = opts.now ?? (() => new Date());
  const serverKey = generateKey();
  const serverKeys: KeyEntry[] = [{ key: serverKey.key, added: '2026-01-01T00:00:00Z', revoked: null }];
  const agents = new Map<string, Held>();
  const leases = new Map<string, string>();
  const entries: Entry[] = [];
  const sent = new Map<string, { author: string; answer: unknown; servers: unknown[] }>();
  const parts = new Map<string, { bytes: Uint8Array; readers: Set<string> }>();
  const nonces = new NonceCache();
  const recoveries = new Map<string, { key: string; completesAt: number }>();
  const tokens = new Map<string, { address: string; cursor: number }>();
  const signals: { to: string; cursor: number; type: string; from: string; about: string; at: string }[] = [];
  let sequence = 0;
  const webhooks = new Map<string, { address: string; verified: boolean }>();
  const account = (agent: Held) => ({
    address: agent.address,
    keys: agent.keys,
    grants: [],
    recovery: recoveries.has(agent.address)
      ? { completesAt: timestamp(new Date(recoveries.get(agent.address)!.completesAt)), cancellable: true }
      : null,
  });
  const requests: { method: string; path: string; headers: Headers; body: Uint8Array }[] = [];

  /** Claims as this server, their carrier, signs them for one message, with no judgement in them. */
  const signClaims = (claims: Claim[], m: AnyMessage): SignedClaims => {
    const raw = claims.map(({ authoritative: _, ...c }) => c);
    return { claims: raw, signature: sign(serverKey.privateKey, claimsBytes(raw, messageId(m))) };
  };

  const holderOf = (key: string) => [...agents.values()].find(a => a.keys.some(k => k.key === key));

  /** The signing key, checked as spec section 8 says. `fresh` stands in for a key being registered. */
  async function authenticate(req: Request, body: Uint8Array, fresh?: string): Promise<string> {
    const raw = Object.fromEntries(req.headers);
    const headers = readSignedHeaders(raw, now());
    const key = headers['simon-key'];
    const entry =
      holderOf(key)?.keys.find(k => k.key === key) ??
      (key === fresh ? { key, added: timestamp(now()), revoked: null } : null);
    const { target } = splitUrl(req.url);
    await checkSignedRequest({ method: req.method, origin, actor: actorOf(raw), target, body }, headers, {
      now: now(),
      entry,
      nonceSeen: (k, n) => nonces.seen(k, n, now()),
    });
    nonces.record(key, headers['simon-nonce'], headers['simon-timestamp'], now());
    return key;
  }

  function agentFor(key: string): Held {
    const agent = holderOf(key);
    if (!agent) throw refuse(401, 'unknown_key', 'This server does not know this key.');
    return agent;
  }

  async function register(req: Request, raw: Uint8Array) {
    const body = parseJson(raw) as Record<string, string | undefined>;
    const signer = await authenticate(req, raw, body.key);
    if (body.key !== signer) throw refuse(400, 'invalid', 'key must equal the signing key.');
    const holder = holderOf(signer);
    if (holder && body.address === undefined) return account(holder);
    const address = body.address ?? leases.get(signer) ?? `agent-${leases.size + 1}@${domain}`;
    if (body.address === undefined) leases.set(signer, address);
    const existing = agents.get(address);
    if (existing && !existing.keys.some(k => k.key === signer && k.revoked === null))
      throw refuse(409, 'address_in_use', 'Use recovery.');
    if (domainOf(address) !== domain && !existing) {
      if (body.code === undefined) return { status: 'code_sent', address };
      if (body.code !== CODE) throw refuse(422, 'wrong_code', 'That is not the code that was sent.');
    }
    if (existing) {
      if (existing.keys.some(k => k.key === signer && k.revoked === null)) return account(existing);
      throw refuse(409, 'address_in_use', 'Use the dedicated recovery endpoint.');
    }
    if (body.for !== undefined) {
      if (body.pairing === undefined) return { status: 'pairing_required', address };
      if (!verifyPairing(address, body.for, body.pairing))
        throw refuse(401, 'bad_proof', 'The pairing does not verify.');
    }
    const agent: Held = { address, for: body.for, keys: [{ key: signer, added: timestamp(now()), revoked: null }] };
    agents.set(address, agent);
    return account(agent);
  }

  async function recovery(req: Request, raw: Uint8Array) {
    const body = parseJson(raw) as Record<string, string | undefined>;
    const signer = await authenticate(req, raw, body.key);
    if (body.key !== signer) throw refuse(400, 'invalid', 'key must equal the signing key.');
    const existing = agents.get(body.address!);
    if (!existing || existing.retired) throw refuse(404, 'not_found', 'No active agent.');
    if (body.recover !== undefined) {
      if (!existing.for || !verifyRecovery(existing.address, existing.for, signer, body.at!, body.recover))
        throw refuse(401, 'bad_proof', 'Recovery proof does not verify.');
    } else {
      if (body.code === undefined) return { status: 'code_sent', address: existing.address };
      if (body.code !== CODE) throw refuse(422, 'wrong_code', 'Wrong recovery code.');
      if (existing.keys.some(k => k.revoked === null)) {
        let pending = recoveries.get(existing.address);
        if (pending?.key !== signer) {
          pending = { key: signer, completesAt: now().getTime() + RECOVERY_WAIT_MS };
          recoveries.set(existing.address, pending);
        }
        if (now().getTime() < pending.completesAt)
          return {
            status: 'recovery_pending',
            address: existing.address,
            completesAt: timestamp(new Date(pending.completesAt)),
          };
      }
    }
    recoveries.delete(existing.address);
    for (const key of existing.keys) key.revoked ??= timestamp(now());
    if (!existing.keys.some(k => k.key === signer))
      existing.keys.push({ key: signer, added: timestamp(now()), revoked: null });
    return account(existing);
  }

  async function send(req: Request, raw: Uint8Array) {
    const agent = agentFor(await authenticate(req, raw));
    const m = parseMessage(raw);
    checkSupportedVersion(m);
    const id = messageId(m);
    const repeat = sent.get(id);
    if (repeat) return repeat.answer;
    if (m.from !== agent.address) throw refuse(409, 'address_not_served', `This agent is ${agent.address}.`);
    checkPrincipal(m, agent.for === undefined ? { kind: 'solo' } : { kind: 'paired', for: agent.for });
    if (!isFresh(m, now(), SEND_WINDOW_MS))
      throw refuse(400, 'invalid', 'sentAt is out of range.', { field: 'sentAt' });
    for (const p of m.parts) {
      if ('sha256' in p && !parts.get(p.sha256)?.readers.has(agent.address)) {
        throw refuse(400, 'part_not_uploaded', 'This server holds no such part for this agent.', { sha256: p.sha256 });
      }
    }
    const receivedAt = timestamp(now());
    const local = m.to.filter(to => agents.has(to));
    for (const to of new Set([...local, agent.address])) {
      const claims = opts.claims?.(m) ?? [];
      const signed = claims.length ? { signedClaims: signClaims(claims, m) } : {};
      entries.push({ to, cursor: ++sequence, id, message: m, carrier: origin, claims, ...signed, receivedAt });
      for (const p of m.parts) if ('sha256' in p) parts.get(p.sha256)!.readers.add(to);
    }
    const servers = [
      ...(local.length ? [{ server: origin, recipients: local, status: 'delivered' }] : []),
      ...m.to
        .filter(to => !agents.has(to))
        .map(to => ({ server: null, recipients: [to], status: 'failed', reason: 'not_found' })),
    ];
    const answer = { id, receivedAt };
    sent.set(id, { author: agent.address, answer, servers });
    return answer;
  }

  async function route(req: Request): Promise<{ status?: number; json?: unknown; bytes?: Uint8Array }> {
    const raw = new Uint8Array(await req.arrayBuffer());
    requests.push({ method: req.method, path: splitUrl(req.url).target, headers: req.headers, body: raw });
    const url = new URL(req.url);
    const [, base, call, arg] = url.pathname.split('/');
    if (base !== 'simon') throw refuse(404, 'not_found', 'No such call.');
    const name = `${req.method} ${call}`;
    if (name === 'GET server') return { json: serverDocument(origin, serverKeys) };
    if (name === 'GET agents') {
      const agent = agents.get(decodeURIComponent(arg));
      if (!agent) throw refuse(404, 'not_found', 'No such agent.');
      const doc = {
        address: agent.address,
        kind: agent.for ? 'paired' : 'solo',
        keys: agent.keys,
        ...(agent.retired && { retired: agent.retired, ...(agent.unpairing && { unpairing: agent.unpairing }) }),
      } as const;
      return { json: signAgentDocument(doc, serverKey.privateKey) };
    }
    if (name === 'POST register') {
      const r = (await register(req, raw)) as { status: string };
      return { status: 'status' in r ? 202 : 200, json: r };
    }
    if (name === 'POST recovery' && !arg) {
      const result = await recovery(req, raw);
      return { status: 'status' in result ? 202 : 200, json: result };
    }
    if (name === 'POST recovery' && arg === 'cancel') {
      const body = parseJson(raw) as { address?: string; cancelCode?: string };
      if (body.cancelCode !== undefined) {
        const signer = readSignedHeaders(Object.fromEntries(req.headers), now())['simon-key'];
        await authenticate(req, raw, signer);
        if (body.cancelCode !== CANCEL_CODE || !body.address || !recoveries.delete(body.address))
          throw refuse(422, 'wrong_code', 'Wrong cancel code.');
        return { json: { status: 'cancelled', address: body.address } };
      }
    }
    if (name === 'POST send') return { json: await send(req, raw) };
    const agent = agentFor(await authenticate(req, raw));
    if (name === 'GET account') return { json: account(agent) };
    if (name === 'GET recovery') return { json: { recovery: account(agent).recovery } };
    if (name === 'POST keys') {
      const body = parseJson(raw) as { key: string; proof: string; label?: string };
      if (!verify(body.key, addKeyProofString(agent.address, body.key), body.proof))
        throw refuse(401, 'bad_proof', 'Bad add-key proof.');
      if (!agent.keys.some(k => k.key === body.key))
        agent.keys.push({
          key: body.key,
          added: timestamp(now()),
          revoked: null,
          ...(body.label === undefined ? {} : { label: body.label }),
        });
      return { json: account(agent) };
    }
    if (name === 'DELETE keys') {
      const key = agent.keys.find(k => k.key === decodeURIComponent(arg));
      if (!key || key.revoked !== null) throw refuse(404, 'not_found', 'No such active key.');
      if (agent.keys.filter(k => k.revoked === null).length === 1) throw refuse(409, 'last_key', 'Last active key.');
      key.revoked = timestamp(now());
      return { json: account(agent) };
    }
    if (name === 'POST recovery' && arg === 'cancel') {
      if (!recoveries.delete(agent.address)) throw refuse(404, 'not_found', 'No recovery pending.');
      return { json: { status: 'cancelled', address: agent.address } };
    }
    if (name === 'GET sync') {
      const since = url.searchParams.get('since');
      const previous = since === null ? null : tokens.get(since);
      if (since !== null && (!previous || previous.address !== agent.address))
        throw refuse(410, 'token_expired', 'Unknown sync token.');
      const after = previous?.cursor ?? 0;
      const limit = Number(url.searchParams.get('limit') ?? 50);
      const mine = [
        ...entries.filter(e => e.to === agent.address && e.cursor > after),
        ...signals.filter(e => e.to === agent.address && e.cursor > after),
      ].sort((a, b) => a.cursor - b.cursor);
      const selected = mine.slice(0, limit);
      const messages = selected.filter(e => 'message' in e).map(({ to: _, cursor: __, ...e }) => e);
      const notes = selected
        .filter(e => !('message' in e))
        .filter(e => now().getTime() - Date.parse((e as (typeof signals)[number]).at) < 300000)
        .map(({ to: _, cursor: __, ...e }) => e);
      const token = `sync:${tokens.size + 1}:opaque`;
      tokens.set(token, { address: agent.address, cursor: selected.at(-1)?.cursor ?? after });
      return { json: { messages, signals: notes, marks: [], removed: [], token, more: mine.length > limit } };
    }
    if (name === 'POST send-signal') {
      const body = parseJson(raw) as { type: string; about: string; to: string[] };
      const message = entries.find(e => e.id === body.about && e.to === agent.address)?.message;
      if (!message) throw refuse(404, 'not_found', 'No such held message.');
      for (const to of new Set(body.to))
        if (agents.has(to) && [message.from, ...message.to].includes(to))
          signals.push({
            to,
            cursor: ++sequence,
            type: body.type,
            from: agent.address,
            about: body.about,
            at: timestamp(now()),
          });
      return { status: 202, json: { accepted: true } };
    }
    if (name === 'POST webhooks' && !arg) {
      const id = `hook-${webhooks.size + 1}`;
      webhooks.set(id, { address: agent.address, verified: false });
      return { json: { id } };
    }
    if ((name === 'POST webhooks' || name === 'DELETE webhooks') && webhooks.get(arg)?.address === agent.address) {
      if (req.method === 'DELETE') {
        webhooks.delete(arg);
        return { json: { deleted: true } };
      }
      const body = parseJson(raw) as { code: string };
      if (url.pathname.endsWith('/verify') && body.code === CODE) {
        webhooks.get(arg)!.verified = true;
        return { json: { id: arg, verified: true } };
      }
      throw refuse(422, 'wrong_code', 'Wrong webhook verification code.');
    }
    if (name === 'GET sent') {
      const s = sent.get(arg);
      if (s?.author !== agent.address) throw refuse(404, 'not_found', 'No such message.');
      return { json: { id: arg, servers: s.servers } };
    }
    if (name === 'PUT parts') {
      if (sha256Hex(raw) !== arg) throw refuse(400, 'invalid', 'The body does not hash to the path.');
      const held = parts.get(arg) ?? { bytes: raw, readers: new Set<string>() };
      held.readers.add(agent.address);
      parts.set(arg, held);
      return { json: { sha256: arg, size: raw.length } };
    }
    if (name === 'GET parts') {
      const held = parts.get(arg);
      if (!held?.readers.has(agent.address)) throw refuse(404, 'not_found', 'No such part.');
      return { bytes: held.bytes };
    }
    throw refuse(404, 'not_found', 'No such call.');
  }

  async function handle(req: Request): Promise<Response> {
    try {
      const r = await route(req);
      if (r.bytes) return new Response(r.bytes as Uint8Array<ArrayBuffer>, { status: 200 });
      return new Response(new Uint8Array(canonicalBytes(r.json)), {
        status: r.status ?? 200,
        headers: { 'content-type': 'application/json' },
      });
    } catch (e) {
      if (!(e instanceof WireError)) throw e;
      return new Response(JSON.stringify(e.toProblem()), { status: e.status, headers: e.headers });
    }
  }

  /** A delivery whose deadline passed: every server not yet delivered to fails as `expired`. */
  function expire(id: string) {
    const s = sent.get(id);
    if (s) s.servers = s.servers.map(x => ({ ...(x as object), status: 'failed', reason: 'expired' }));
  }

  /** The same message delivered again, as at-least-once delivery may: a new entry with a new cursor. */
  function redeliver(id: string) {
    for (const e of entries.filter(e => e.id === id)) entries.push({ ...e, cursor: ++sequence });
  }

  return {
    origin,
    domain,
    agents,
    requests,
    handle,
    redeliver,
    /** Advance only a pending fixture recovery, without skewing signed-request clocks. */
    completeRecovery(address: string) {
      const pending = recoveries.get(address);
      if (!pending) throw new Error('No pending fixture recovery.');
      pending.completesAt = now().getTime();
    },
    expire,
    signClaims,
    fetch: (url: string, init?: RequestInit) => handle(new Request(url, init)),
  };
}

export type FakeServer = ReturnType<typeof fakeServer>;

/** The fake over HTTP on a free localhost port. */
export async function listen(opts: Omit<FakeOptions, 'origin'> = {}) {
  let fake: FakeServer | undefined;
  const server = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c);
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers.set(k, v);
    const body = req.method === 'GET' ? undefined : Buffer.concat(chunks);
    const r = await fake!.handle(new Request(`${fake!.origin}${req.url}`, { method: req.method, headers, body }));
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(Buffer.from(await r.arrayBuffer()));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as { port: number };
  fake = fakeServer({ ...opts, origin: `http://127.0.0.1:${port}` });
  return { fake, origin: fake.origin, close: () => new Promise(resolve => server.close(resolve)) };
}
