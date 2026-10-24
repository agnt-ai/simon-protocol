/** PROTOCOL section 4: the server document and agent documents. */
import {
  addressSegment,
  isJsonObject,
  MAX_DOCUMENT_BYTES,
  MAX_DOCUMENT_KEYS,
  MINIMUM_LIMITS,
  parseStrict,
  readKeys,
  serverOrigin,
  V1_ALGORITHMS,
  validAt,
  type Json,
} from '@agnt-protocol/protocol';
import { TargetAgent } from '../agent.ts';
import type { Ctx } from '../context.ts';
import type { T } from '../harness.ts';
import { agentDocument, def, lists } from './common.ts';
import { requireHosted } from './register.ts';

def(
  {
    id: 'documents.server.readable',
    section: 'PROTOCOL 4',
    level: 'must',
    title: 'The server document is readable, unauthenticated',
    expected: `GET /simon/server without any signature answers 200 with a JSON object under section 5.1's rules, at most ${MAX_DOCUMENT_BYTES} bytes, whose keys are well-formed entries, at most ${MAX_DOCUMENT_KEYS} of them not yet revoked`,
  },
  async (t: T, ctx: Ctx) => {
    const res = await t.http({ method: 'GET', origin: ctx.origin, target: '/simon/server' });
    t.status(res, 200);
    t.assert(res.bytes.length <= MAX_DOCUMENT_BYTES, `the document is ${res.bytes.length} bytes`);
    let v: Json = null;
    try {
      v = parseStrict(res.bytes);
    } catch (e) {
      t.fail(`the body is not JSON under section 5.1's rules: ${(e as Error).message}`);
    }
    if (!isJsonObject(v)) t.fail('the body is not a JSON object');
    t.assert(Array.isArray(v.keys), 'keys is not an array');
    const now = new Date(ctx.now());
    const unrevoked = v.keys.filter(
      k => !isJsonObject(k) || k.revoked === null || Date.parse(String(k.revoked)) > +now,
    );
    t.assert(unrevoked.length <= MAX_DOCUMENT_KEYS, `keys lists ${unrevoked.length} entries not yet revoked`);
    t.assert(
      readKeys(v.keys, now) !== null,
      'some key entry is malformed: each needs key (a key token), added (a timestamp) and revoked (a timestamp or null, never more than 300 seconds ahead)',
    );
  },
);

def(
  {
    id: 'documents.server.origin',
    section: 'PROTOCOL 4',
    level: 'must',
    title: 'The server document names the origin it was fetched from',
    expected:
      '`server` equals the origin of the URL it was fetched from, compared as the URL standard serialises origins',
  },
  async (t: T, ctx: Ctx) => {
    const res = await t.http({ method: 'GET', origin: ctx.origin, target: '/simon/server' });
    t.status(res, 200);
    const server = res.json?.server;
    t.assert(
      serverOrigin(server, true) === ctx.origin,
      `server is ${JSON.stringify(server)}; it was fetched from ${ctx.origin}`,
    );
  },
);

def(
  {
    id: 'documents.server.limits',
    section: 'PROTOCOL 4, 9',
    level: 'must',
    title: 'The server document publishes all four limits, each at least its minimum',
    expected: `limits has messageBytes >= ${MINIMUM_LIMITS.messageBytes}, recipients >= ${MINIMUM_LIMITS.recipients}, requestBodyBytes >= ${MINIMUM_LIMITS.requestBodyBytes} and partBytes >= ${MINIMUM_LIMITS.partBytes}, each a safe integer`,
  },
  async (t: T, ctx: Ctx) => {
    const res = await t.http({ method: 'GET', origin: ctx.origin, target: '/simon/server' });
    t.status(res, 200);
    const limits = res.json?.limits;
    t.assert(isJsonObject(limits), `limits is ${JSON.stringify(limits)}`);
    const wrong = Object.entries(MINIMUM_LIMITS)
      .filter(([k, min]) => !(Number.isSafeInteger(limits[k]) && (limits[k] as number) >= min))
      .map(([k, min]) => `${k} is ${JSON.stringify(limits[k])} (at least ${min})`);
    t.assert(wrong.length === 0, wrong.join('; '));
  },
);

def(
  {
    id: 'documents.server.algorithms',
    section: 'PROTOCOL 2.3, 4',
    level: 'must',
    title: 'The server document lists the signature algorithms it verifies, both of version 1 among them',
    expected: `algorithms is an array of algorithm names (lower-case letters, digits and hyphens) that includes ${V1_ALGORITHMS.join(' and ')}`,
  },
  async (t: T, ctx: Ctx) => {
    const res = await t.http({ method: 'GET', origin: ctx.origin, target: '/simon/server' });
    t.status(res, 200);
    const algorithms = res.json?.algorithms;
    t.assert(
      Array.isArray(algorithms) && algorithms.every(a => typeof a === 'string' && /^[a-z0-9-]+$/.test(a)),
      `algorithms is ${JSON.stringify(algorithms)}`,
    );
    const missing = V1_ALGORITHMS.filter(a => !algorithms.includes(a));
    t.assert(missing.length === 0, `algorithms ${JSON.stringify(algorithms)} lacks ${missing.join(' and ')}`);
  },
);

def(
  {
    id: 'documents.server.key-valid-now',
    section: 'PROTOCOL 2.4, 4',
    level: 'must',
    title: 'The server document lists a key valid now',
    expected:
      'at least one entry of an implemented algorithm is valid at the time of reading, or nothing the server signs can verify',
  },
  async (t: T, ctx: Ctx) => {
    const { doc } = await ctx.serverDoc();
    t.assert(
      doc.keys.some(k => validAt(k, new Date(ctx.now()))),
      `no listed key is valid now: ${JSON.stringify(doc.keys)}`,
    );
  },
);

def(
  {
    id: 'documents.agent.served',
    section: 'PROTOCOL 4',
    level: 'must',
    title: "An agent's document is served at its address, with a literal @, signed by the server",
    expected:
      'GET /simon/agents/<address> (unsigned, `@` literal) answers 200 with the address asked for, and a signature over SIMON-AGENT that verifies with a server key valid now',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    const { res, read } = await agentDocument(t, ctx, a.address);
    t.status(res, 200);
    t.assert(
      res.json?.address === a.address,
      `address is ${JSON.stringify(res.json?.address)}, asked for ${a.address}`,
    );
    t.assert(
      read,
      'the document is unreadable: its signature does not verify with a server key valid now over SIMON-AGENT\\n and the canonical document without signature, or a key entry is malformed',
    );
  },
);

def(
  {
    id: 'documents.agent.address-segment',
    section: 'PROTOCOL 2.1, 4, 8',
    level: 'must',
    title: 'An address in a path is read as one segment, its non-pchar characters percent-encoded',
    expected:
      "for an agent whose hosted name holds every version 1 character that is not an RFC 3986 pchar (# % / ? ^ ` { | }), GET /simon/agents/<the address, those characters percent-encoded with upper-case hex, @ literal> answers 200 with that address, and the agent's own signed request naming its address in the path is answered as any other",
  },
  async (t: T, ctx: Ctx) => {
    const domain = requireHosted(ctx);
    const a = TargetAgent.fresh(ctx.server);
    const address = `${ctx.runId}-a#b%c/d?e^f\`g{h|i}j@${domain}`;
    t.status(await a.register(t, { address }, {}, 'a hosted name with every non-pchar character'), 200, 'register');
    const segment = addressSegment(address);
    const res = await t.http({ method: 'GET', origin: ctx.origin, target: `/simon/agents/${segment}` });
    t.status(res, 200);
    t.assert(res.json?.address === address, `address is ${JSON.stringify(res.json?.address)}, asked for ${address}`);
    const feed = await a.call(t, 'GET', `/simon/feeds/${segment}/posts`, undefined, {}, 'its own feed, signed');
    t.status(feed, 200, 'its own feed, signed by it');
  },
);

def(
  {
    id: 'documents.agent.kind',
    section: 'PROTOCOL 2.2, 4',
    level: 'must',
    title: 'An agent document says paired or solo',
    expected: 'kind is "solo" for an agent registered without `for`',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    const { res } = await agentDocument(t, ctx, a.address);
    t.status(res, 200);
    t.assert(res.json?.kind === 'solo', `kind is ${JSON.stringify(res.json?.kind)}`);
  },
);

def(
  {
    id: 'documents.agent.lists-key',
    section: 'PROTOCOL 4',
    level: 'must',
    title: "An agent document lists the agent's key, valid now",
    expected: 'the key the agent registered appears in keys, with added and revoked making it valid now',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    const { res, read } = await agentDocument(t, ctx, a.address);
    t.status(res, 200);
    if (!read) t.fail('the document is unreadable');
    const entry = read.keys.find(k => k.key === a.token);
    if (!entry) t.fail(`${a.token} is not listed`);
    t.assert(
      validAt(entry, new Date(ctx.now())) && lists(read.keys, a.token),
      `the entry ${JSON.stringify(entry)} is not valid now`,
    );
  },
);

def(
  {
    id: 'documents.agent.unknown',
    section: 'PROTOCOL 4, 9',
    level: 'must',
    title: 'An unknown agent is 404 not_found',
    expected: 'GET /simon/agents/<an address nobody holds> answers 404 not_found in the error shape',
  },
  async (t: T, ctx: Ctx) => {
    const res = await t.http({
      method: 'GET',
      origin: ctx.origin,
      target: `/simon/agents/${ctx.runId}-nobody@${await ctx.domain()}`,
    });
    t.error(res, 404, 'not_found');
  },
);
