/**
 * A deliberately broken toy server, for testing the suite: just enough of documents, register, sync and
 * deliver to be checked, with planted faults the suite must catch.
 *
 *   1. It publishes recipients: 50, below the minimum of 100.
 *   2. A badly signed request uses up its nonce.
 *   3. Deliver checks freshness before the envelope signature.
 *   4. Deliver answers 404 for an unknown recipient, so policy is not silent.
 *   5. Its server document lists no algorithms.
 *   6. Errors go out as application/json, not application/problem+json.
 *   7. A request-signature 401 carries no WWW-Authenticate.
 *   8. Deliver takes an envelope whatever server it names.
 *   9. Deliver recognises a repeat by message id alone, so a second envelope for a new recipient is dropped.
 *  10. An author whose only keys are of an unknown algorithm is answered bad_signature, not unsupported_algorithm.
 */
import http from 'node:http';
import crypto from 'node:crypto';
import {
  actorOf,
  checkFreshness,
  checkServed,
  checkSignedRequest,
  domainOf,
  forbidden,
  generateKey,
  MINIMUM_LIMITS,
  messageId,
  NonceCache,
  parseEnvelope,
  readAgentDocument,
  readKeys,
  readSignedHeaders,
  signAgentDocument,
  timestamp,
  verifyEnvelope,
  verifyMessage,
  WireError,
  withinRepeatWindow,
  type KeyEntry,
} from '@agnt-sdk/simon-protocol';

/** Optional client faults exercise the migrated suite without changing its protocol faults. */
export interface ClientFaults {
  numericToken?: boolean;
  unknownTokenEmpty?: boolean;
  omitSent?: boolean;
  stalledToken?: boolean;
}
export async function startToy(resolve: Record<string, string>, faults: ClientFaults = {}) {
  const key = generateKey();
  const limits = { ...MINIMUM_LIMITS, recipients: 50 }; // fault 1
  type Entry = { id: string; message: unknown; carrier: string; claims: unknown[]; receivedAt: string };
  type Agent = { address: string; entry: KeyEntry; stream: Entry[] };
  const agents = new Map<string, Agent>();
  const tokens = new Map<string, { address: string; offset: number }>();
  const account = (a: Agent) => ({ address: a.address, keys: [a.entry], grants: [], recovery: null });
  const nonces = new NonceCache();
  const seen = new Set<string>();
  const get = async (url: string) => {
    const res = await fetch(url);
    return res.ok ? Buffer.from(await res.arrayBuffer()) : null;
  };
  let origin = '';
  let leased = 0;

  async function auth(req: http.IncomingMessage, body: Buffer, now: Date, registering?: string) {
    const h = readSignedHeaders(req.headers, now);
    const agent = [...agents.values()].find(a => a.entry.key === h['simon-key']);
    const entry =
      agent?.entry ??
      (registering === h['simon-key'] ? { key: registering, added: timestamp(now), revoked: null } : null);
    const r = { method: req.method!, origin, actor: actorOf(req.headers), target: req.url!, body };
    try {
      await checkSignedRequest(r, h, { now, entry, nonceSeen: (k, n) => nonces.seen(k, n, now) });
    } finally {
      nonces.record(h['simon-key'], h['simon-nonce'], h['simon-timestamp'], now); // fault 2: whatever the outcome
    }
    return { agent, key: h['simon-key'] };
  }

  async function deliver(body: Buffer, now: Date) {
    let named = origin;
    try {
      named = JSON.parse(body.toString()).server ?? origin;
    } catch {
      // Refused by parseEnvelope.
    }
    // Fault 8: whatever server the envelope names is taken for this one.
    const env = parseEnvelope(body, limits, { origin: named, allowHttp: true });
    const m = env.message;
    const server = resolve[domainOf(m.from)];
    if (!server || server === origin) throw forbidden('bad_signature', "The sender's domain names no server.");
    checkFreshness(m, now); // fault 3: step 10 before steps 7 and 9
    const doc = await get(`${server}/simon/server`);
    const parsed = doc && JSON.parse(doc.toString());
    const keys = parsed && readKeys(parsed.keys, now);
    if (!keys) throw new WireError(503, 'unavailable', "The sender's server document is unavailable.");
    if (!verifyEnvelope(env, keys, now)) throw forbidden('bad_signature', 'The envelope does not verify.');
    checkServed(env.recipients, d => d === 'toy.test');
    const id = messageId(m);
    if (seen.has(id) && withinRepeatWindow(m, now)) return; // fault 9: by id alone
    const agentDoc = await get(`${server}/simon/agents/${m.from}`);
    const author = agentDoc && readAgentDocument(agentDoc, m.from, keys, now);
    if (!author || !verifyMessage(m, author.keys)) {
      throw forbidden('bad_signature', 'The message does not verify.'); // fault 10: never unsupported_algorithm
    }
    const here = env.recipients.filter(a => agents.has(a));
    if (here.length < env.recipients.length) throw new WireError(404, 'not_found', 'No such recipient.'); // fault 4
    seen.add(id);
    for (const a of here)
      agents.get(a)!.stream.push({ id, message: m, carrier: server, claims: [], receivedAt: timestamp(now) });
  }

  async function handle(req: http.IncomingMessage, body: Buffer): Promise<[number, unknown]> {
    const now = new Date();
    const path = req.url!.split('?')[0];
    if (path === '/simon/server') {
      const keys = [{ key: key.key, added: '2026-01-01T00:00:00Z', revoked: null }];
      return [200, { server: origin, keys, limits }]; // fault 5: no algorithms
    }
    if (path.startsWith('/simon/agents/')) {
      const a = agents.get(decodeURIComponent(path.slice('/simon/agents/'.length)));
      if (!a) throw new WireError(404, 'not_found', 'No such agent.');
      return [200, signAgentDocument({ address: a.address, kind: 'solo', keys: [a.entry] }, key.privateKey)];
    }
    if (path === '/simon/register') {
      const wanted = JSON.parse(body.toString()).key;
      const { agent } = await auth(req, body, now, wanted);
      if (agent) return [200, account(agent)];
      const address = `a${++leased}@toy.test`;
      agents.set(address, { address, entry: { key: wanted, added: timestamp(now), revoked: null }, stream: [] });
      return [200, account(agents.get(address)!)];
    }
    if (path === '/simon/account') {
      const { agent } = await auth(req, body, now);
      return [200, account(agent!)];
    }
    if (path === '/simon/sync') {
      const { agent } = await auth(req, body, now);
      const query = new URL(req.url!, origin).searchParams;
      for (const [name, min, max] of [
        ['limit', 1, 200],
        ['wait', 0, 60],
      ] as const) {
        const raw = query.get(name);
        if (raw !== null && (!/^\d+$/.test(raw) || Number(raw) < min || Number(raw) > max))
          throw new WireError(400, 'invalid', `Invalid ${name}.`);
      }
      const since = query.get('since');
      const known = since === null ? undefined : tokens.get(since);
      if (since !== null && (!known || known.address !== agent!.address) && !faults.unknownTokenEmpty)
        throw new WireError(410, 'token_expired', 'Unknown sync token.');
      const offset = known?.offset ?? 0;
      const limit = Number(query.get('limit') ?? 50);
      const messages = agent!.stream.slice(offset, offset + limit);
      const next = offset + messages.length;
      const token = faults.stalledToken ? 'stalled' : `toy:${crypto.randomUUID()}/+=?`;
      tokens.set(token, { address: agent!.address, offset: next });
      return [
        200,
        {
          messages,
          marks: [],
          removed: [],
          signals: [],
          token: faults.numericToken ? next : token,
          more: next < agent!.stream.length,
        },
      ];
    }
    if (path === '/simon/send') {
      const { agent } = await auth(req, body, now);
      const m = JSON.parse(body.toString());
      const entry: Entry = { id: messageId(m), message: m, carrier: origin, claims: [], receivedAt: timestamp(now) };
      if (!faults.omitSent) agent!.stream.push(entry);
      for (const to of m.to) if (to !== agent!.address) agents.get(to)?.stream.push(entry);
      return [200, { id: entry.id, receivedAt: entry.receivedAt }];
    }
    if (path === '/simon/deliver') {
      await deliver(body, now);
      return [202, { accepted: true }];
    }
    throw new WireError(404, 'not_found', 'Not implemented by the toy.');
  }

  const server = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c);
    let status: number, out: unknown;
    try {
      [status, out] = await handle(req, Buffer.concat(chunks));
    } catch (e) {
      const err = e instanceof WireError ? e : new WireError(400, 'invalid', String(e));
      [status, out] = [err.status, err.toJSON()];
    }
    // Faults 6 and 7: every answer as application/json, and no WWW-Authenticate on a 401.
    res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(out));
  });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  return { origin, close: () => new Promise(r => server.close(r)) };
}
