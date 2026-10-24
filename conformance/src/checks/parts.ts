/**
 * CLIENT parts and PROTOCOL section 7.2: uploads, who may fetch the bytes (never anyone merely because a
 * message names their hash), and the recipient's server fetching a received message's parts from its
 * carrier on its own, soon after accepting it.
 */
import crypto from 'node:crypto';
import { canonicalize, domainOf, messageId, sha256Hex } from '@agnt-sdk/simon-protocol';
import type { TargetAgent } from '../agent.ts';
import { buildFrom, Prerequisite, type Ctx } from '../context.ts';
import { poll, sleep, type Exchange, type Res, type T } from '../harness.ts';
import type { PartFetch } from '../peer.ts';
import { awaitSync, def } from './common.ts';
import { requireControl } from './deliver.ts';

const S = 'PROTOCOL 7.2';
const OCTETS = { 'content-type': 'application/octet-stream' };

const upload = (t: T, a: TargetAgent, bytes: Buffer, sha = sha256Hex(bytes), label = 'upload') =>
  a.call(t, 'PUT', `/simon/parts/${sha}`, bytes, { headers: OCTETS }, label);

/** A part agent a uploaded and sent to an agent at the simulator, and the delivery that carried it. */
const sentPart = (ctx: Ctx) =>
  ctx.once('a part sent to the simulator', async t => {
    const a = await ctx.agent('a');
    const bytes = crypto.randomBytes(1000);
    const sha256 = sha256Hex(bytes);
    const up = await upload(t, a, bytes);
    if (up.status !== 200) throw new Prerequisite(`uploading a part answered ${up.status}`);
    const m = a.message({
      to: [ctx.peer.address('parts')],
      parts: [{ type: 'application/octet-stream', sha256, size: bytes.length }],
    });
    const res = await a.send(t, m);
    if (res.status !== 200) throw new Prerequisite(`sending a message naming the part answered ${res.status}`);
    const text = canonicalize(m);
    const arrived = await poll(
      async () => ctx.peer.received.find(r => r.messageText === text),
      ctx.opts.deliveryWaitMs,
    );
    if (!arrived) throw new Prerequisite('the message naming the part never reached the simulator');
    return { a, bytes, sha256 };
  });

/** GET the part as the simulator, a server the part was delivered to, with a signed server request. */
function asServer(t: T, ctx: Ctx, sha256: string, from = ctx.peer, label = 'signed server request') {
  const target = `/simon/parts/${sha256}`;
  return t.http(
    () => ({
      method: 'GET',
      origin: ctx.origin,
      target,
      headers: from.serverRequestHeaders('GET', ctx.origin, target),
    }),
    { label },
  );
}

def(
  {
    id: 'parts.upload',
    section: 'CLIENT parts',
    level: 'must',
    title: 'An agent uploads part bytes by their hash',
    expected:
      '200 {"sha256","size"} for PUT /simon/parts/<sha256> with those bytes; the agent then fetches them back unchanged',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    const bytes = crypto.randomBytes(2048);
    const sha256 = sha256Hex(bytes);
    const res = await upload(t, a, bytes);
    t.status(res, 200, 'upload');
    t.assert(res.json?.sha256 === sha256 && res.json?.size === bytes.length, `answered ${res.text}`);
    const back = await a.call(t, 'GET', `/simon/parts/${sha256}`, undefined, {}, 'fetch it back');
    t.status(back, 200, 'fetch it back');
    t.assert(back.bytes.equals(bytes), 'the bytes differ from those uploaded');
  },
);

def(
  {
    id: 'parts.upload-mismatch',
    section: 'CLIENT parts',
    level: 'must',
    title: 'Bytes whose hash is not the one in the path are refused',
    expected: '400 invalid for an upload whose body does not hash to the path',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    t.error(await upload(t, a, crypto.randomBytes(64), sha256Hex('something else')), 400, 'invalid');
  },
);

def(
  {
    id: 'parts.upload-too-large',
    section: 'CLIENT parts',
    level: 'should',
    title: 'An upload over partBytes is refused',
    expected: '413 body_too_large for an upload one byte over the published partBytes (skipped above 64 MiB)',
  },
  async (t: T, ctx: Ctx) => {
    const { partBytes } = await ctx.limits();
    if (partBytes > 64 * 1024 * 1024) t.skip(`partBytes is ${partBytes}`);
    const a = await ctx.agent('a');
    const bytes = Buffer.alloc(partBytes + 1, 1);
    t.error(await upload(t, a, bytes), 413, 'body_too_large');
  },
);

def(
  {
    id: 'parts.private-unsigned',
    section: S,
    level: 'must',
    title: 'A part of a private message is not served to anyone who asks',
    expected: "404 not_found for an unsigned GET of a part only named by a message to the simulator's agents",
  },
  async (t: T, ctx: Ctx) => {
    const { sha256 } = await sentPart(ctx);
    t.error(await t.http({ method: 'GET', origin: ctx.origin, target: `/simon/parts/${sha256}` }), 404, 'not_found');
  },
);

def(
  {
    id: 'parts.server-fetch',
    section: S,
    level: 'must',
    title: 'A server the part was delivered to fetches it with a signed server request',
    expected:
      '200 with exactly the bytes, for GET /simon/parts/<sha256> signed by the simulator (simon-server its origin) after the server delivered it a message naming the part',
  },
  async (t: T, ctx: Ctx) => {
    const { sha256, bytes } = await sentPart(ctx);
    const res = await asServer(t, ctx, sha256);
    t.status(res, 200);
    t.assert(res.bytes.equals(bytes), 'the bytes differ');
  },
);

def(
  {
    id: 'parts.server-request-forged',
    section: `${S}, PROTOCOL 8`,
    level: 'must',
    title: 'A server request not signed by a key of the server it names gets no bytes',
    expected:
      'the 404 not_found every refusal gets, for a part delivered to the simulator, fetched with simon-server naming the simulator but signed by a key its document does not list, or by its revoked key',
  },
  async (t: T, ctx: Ctx) => {
    const { sha256 } = await sentPart(ctx);
    const target = `/simon/parts/${sha256}`;
    const keys: [string, crypto.KeyObject][] = [
      ['an unlisted key', crypto.generateKeyPairSync('ed25519').privateKey],
      ['a revoked key', ctx.peer.revokedKey],
    ];
    for (const [what, key] of keys) {
      const res = await t.http(
        () => ({
          method: 'GET',
          origin: ctx.origin,
          target,
          headers: ctx.peer.serverRequestHeaders('GET', ctx.origin, target, { key }),
        }),
        {
          label: what,
        },
      );
      t.assert(res.status !== 200, `${what}: the server served the bytes`);
      t.error(res, 404, 'not_found', what);
    }
  },
);

def(
  {
    id: 'parts.cross-tenant',
    section: `${S} rule 2, CLIENT send`,
    level: 'must',
    title: "A file is served only from the bytes held for the author of the message naming it, never another agent's",
    expected:
      "agent b uploads a part; agent a's send of a message carrying inline a message that names it answers 400 part_not_uploaded with details.sha256; with a second simulator, b sends it a message naming the part and that server's signed request gets the bytes; the first simulator's signed server request for it, no message delivered to it naming it, is the 404 not_found every refusal gets; b still reads its own upload",
  },
  async (t: T, ctx: Ctx) => {
    const [a, b] = [await ctx.agent('a'), await ctx.agent('b')];
    const bytes = crypto.randomBytes(700);
    const sha256 = sha256Hex(bytes);
    t.status(await upload(t, b, bytes, sha256, "b's upload"), 200, "b's upload");
    // A message, signed by the simulator's agent, that names b's bytes; a carries it whole, inline.
    const inner = buildFrom(ctx.peer.agent('inner'), [a.address], ctx.now(), {
      parts: [{ type: 'application/octet-stream', sha256, size: bytes.length }],
    });
    const carried = { type: 'application/simon-message', data: Buffer.from(canonicalize(inner)).toString('base64') };
    const m = a.message({ to: [ctx.peer.address('tenant')], text: 'a forward', parts: [carried] });
    const err = t.error(await a.send(t, m, {}, "a carries a message naming b's bytes"), 400, 'part_not_uploaded');
    t.assert(err.details?.sha256 === sha256, `details.sha256 is ${JSON.stringify(err.details?.sha256)}`);
    // The serving side: with a second simulator, b sends it a message naming the bytes. That server may fetch
    // them, from b's; the first simulator, to which no message naming them was delivered, still may not.
    const second = ctx.secondPeer;
    if (second) {
      const sent = b.message({
        to: [second.address('tenant')],
        parts: [{ type: 'application/octet-stream', sha256, size: bytes.length }],
      });
      t.status(await b.send(t, sent, {}, 'b sends the second simulator a message naming its bytes'), 200, 'b sends');
      const text = canonicalize(sent);
      const arrived = await poll(
        async () => second.received.find(r => r.messageText === text),
        ctx.opts.deliveryWaitMs,
      );
      t.assert(arrived, 'the message naming the bytes never reached the second simulator');
      t.status(
        await asServer(t, ctx, sha256, second, 'the second simulator asks for them'),
        200,
        'the second simulator',
      );
    }
    t.error(await asServer(t, ctx, sha256, ctx.peer, "the simulator asks for b's bytes"), 404, 'not_found');
    const own = await b.call(t, 'GET', `/simon/parts/${sha256}`, undefined, {}, 'b reads its own upload');
    t.status(own, 200, 'b reads its own upload');
    t.assert(own.bytes.equals(bytes), 'b got other bytes than it uploaded');
  },
);

def(
  {
    id: 'parts.no-hosted-oracle',
    section: `${S} rule 2, PROTOCOL 8`,
    level: 'must',
    title: 'Hosted part authentication refuses unknown keys and identities uniformly',
    expected:
      'Requests routed as hosted client calls receive a uniform minimal 401 bad_signature for an unknown key, an unknown hosted address or an invalid signature, with WWW-Authenticate and serverTime but no signingString; unsigned and failed foreign reads without a public grant remain the same 404 not_found',
  },
  async (t: T, ctx: Ctx) => {
    const { a, sha256 } = await sentPart(ctx);
    const target = `/simon/parts/${sha256}`;
    const unsigned = await t.http({ method: 'GET', origin: ctx.origin, target }, { label: 'unsigned' });
    t.error(unsigned, 404, 'not_found', 'unsigned without a public grant');
    const stranger = crypto.generateKeyPairSync('ed25519').privateKey;
    const answers: [string, Res][] = [
      ['an unknown key', await a.call(t, 'GET', target, undefined, { key: stranger }, 'unknown key')],
      [
        'an unknown hosted address',
        await a.call(
          t,
          'GET',
          target,
          undefined,
          { key: stranger, agent: `${ctx.runId}-unregistered@${domainOf(a.address)}` },
          'unknown hosted address',
        ),
      ],
      [
        'a known key with an invalid signature',
        await a.call(t, 'GET', target, undefined, { signedTarget: `${target}?tampered=1` }, 'invalid signature'),
      ],
    ];
    let first: string | undefined;
    for (const [what, res] of answers) {
      const err = t.error(res, 401, 'bad_signature', what);
      t.assert(res.headers['www-authenticate'] === 'SIMON', `${what}: missing WWW-Authenticate: SIMON`);
      t.assert(Number.isInteger(err.details?.serverTime), `${what}: missing integer serverTime`);
      t.assert(err.detail === 'This request is not authorized.', `${what}: nonuniform detail`);
      t.assert(!Object.hasOwn(err.details ?? {}, 'signingString'), `${what}: exposed signingString`);
      const normalized = canonicalize({ ...res.json, details: { ...res.json.details, serverTime: 0 } });
      if (first === undefined) first = normalized;
      else t.assert(normalized === first, `${what}: hosted refusal differs beyond serverTime`);
    }
    const foreign = await a.call(
      t,
      'GET',
      target,
      undefined,
      { key: stranger, agent: `${ctx.runId}-stranger@${ctx.opts.peerDomain}` },
      'failed foreign reader without a public grant',
    );
    t.error(foreign, 404, 'not_found', 'failed foreign reader');
    t.assert(foreign.text === unsigned.text, 'a failed foreign reader differs from an unsigned refusal');
  },
);

def(
  {
    id: 'parts.refusals-identical',
    section: S,
    level: 'must',
    title: 'Every refusal of a part is the same 404',
    expected:
      'the same 404 not_found body for one part fetched unsigned, by a server it was never delivered to (a signed server request), by a server request whose signature does not verify, and by an agent there that neither sent nor received it; and, apart from the hash, for a hash nobody named',
  },
  async (t: T, ctx: Ctx) => {
    const { sha256 } = await sentPart(ctx);
    const stranger = await ctx.strangerPeer();
    const b = await ctx.agent('b');
    const unknown = sha256Hex(crypto.randomBytes(16));
    const target = `/simon/parts/${sha256}`;
    const forged = crypto.generateKeyPairSync('ed25519').privateKey;
    const answers: [string, Res][] = [
      [
        'unsigned',
        await t.http({ method: 'GET', origin: ctx.origin, target: `/simon/parts/${sha256}` }, { label: 'unsigned' }),
      ],
      ['a stranger server', await asServer(t, ctx, sha256, stranger, 'signed by a server it was not delivered to')],
      [
        'a forged server request',
        await t.http(
          () => ({
            method: 'GET',
            origin: ctx.origin,
            target,
            headers: ctx.peer.serverRequestHeaders('GET', ctx.origin, target, { key: forged }),
          }),
          { label: 'a server request whose signature does not verify' },
        ),
      ],
      [
        'an agent not entitled',
        await b.call(t, 'GET', `/simon/parts/${sha256}`, undefined, {}, 'an agent that neither sent nor received it'),
      ],
    ];
    const unknownRes = await t.http(
      { method: 'GET', origin: ctx.origin, target: `/simon/parts/${unknown}` },
      { label: 'a hash nobody named' },
    );
    for (const [what, res] of answers) t.error(res, 404, 'not_found', what);
    t.error(unknownRes, 404, 'not_found', 'a hash nobody named');
    for (const [what, res] of answers)
      t.assert(
        res.text === answers[0][1].text,
        `${what} answered ${res.text}; unsigned answered ${answers[0][1].text}`,
      );
    t.assert(
      unknownRes.text.replaceAll(unknown, '<sha256>') === answers[0][1].text.replaceAll(sha256, '<sha256>'),
      `a hash nobody named answered ${unknownRes.text}; a refused one ${answers[0][1].text}`,
    );
  },
);

def(
  {
    id: 'parts.public',
    section: S,
    level: 'must',
    title: "A part an agent uploaded is served to anyone once that agent's public message names it",
    expected:
      "200 with exactly the bytes, for an unsigned GET of a part an agent uploaded, after that agent's public message names it",
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    const bytes = crypto.randomBytes(500);
    const sha256 = sha256Hex(bytes);
    t.status(await upload(t, a, bytes), 200, 'upload');
    t.status(
      await a.send(t, a.message({ to: [], parts: [{ type: 'application/octet-stream', sha256, size: bytes.length }] })),
      200,
      'send a public message',
    );
    const res = await t.http(
      { method: 'GET', origin: ctx.origin, target: `/simon/parts/${sha256}` },
      { label: 'unsigned' },
    );
    t.status(res, 200, 'unsigned');
    t.assert(res.bytes.equals(bytes), 'the bytes differ');
  },
);

def(
  {
    id: 'parts.never-by-naming',
    section: `${S}, CLIENT parts`,
    level: 'must',
    title: 'Bytes are never served because a message names their hash',
    expected:
      "for bytes agent b uploaded and never sent, after the simulator delivers agent a a message naming their hash: agent a never gets 200 (503 while its server tries the carrier, or 404), and an unsigned GET and the simulator's signed server request get 404 not_found",
  },
  async (t: T, ctx: Ctx) => {
    await requireControl(ctx);
    const a = await ctx.agent('a');
    const b = await ctx.agent('b');
    const secret = crypto.randomBytes(640);
    const sha256 = sha256Hex(secret);
    t.status(await upload(t, b, secret, sha256, 'agent b uploads bytes it never sends'), 200, "b's upload");
    const p = ctx.peer.agent('names-a-hash');
    const m = buildFrom(p, [a.address], ctx.now(), {
      parts: [{ type: 'application/octet-stream', sha256, size: secret.length }],
    });
    t.status(await ctx.deliver(t, ctx.peer.envelope(m), "a message naming b's hash, to a"), 202, 'delivery');
    t.assert(
      await awaitSync(t, a, messageId(m), ctx.opts.deliveryWaitMs),
      'the message naming the hash never reached the inbox',
    );
    for (let i = 0; i < 3; i++) {
      const res = await a.call(
        t,
        'GET',
        `/simon/parts/${sha256}`,
        undefined,
        {},
        `agent a asks for the bytes (${i + 1})`,
      );
      t.assert(res.status !== 200, `agent a was served ${res.bytes.equals(secret) ? "agent b's bytes" : 'bytes'}`);
      t.assert(
        res.status === 503 || res.status === 404,
        `agent a: expected 503 while its server tries the carrier, or 404, got ${res.status}`,
      );
      await sleep(1000);
    }
    t.error(
      await t.http({ method: 'GET', origin: ctx.origin, target: `/simon/parts/${sha256}` }, { label: 'unsigned' }),
      404,
      'not_found',
      'unsigned',
    );
    t.error(await asServer(t, ctx, sha256, ctx.peer, 'the simulator, as the carrier'), 404, 'not_found', 'the carrier');
  },
);

/** A message from the simulator to agent a naming a part the simulator serves, once it is in a's inbox. */
async function remotePart(t: T, ctx: Ctx, name: string, o: { wrong?: Buffer; declaredSize?: number } = {}) {
  const a = await ctx.agent('a');
  const bytes = crypto.randomBytes(777);
  const { sha256, size } = ctx.peer.offerPart(bytes, [ctx.origin], o.wrong);
  const p = ctx.peer.agent(name);
  const m = buildFrom(p, [a.address], ctx.now(), {
    parts: [{ type: 'application/octet-stream', sha256, size: o.declaredSize ?? size }],
  });
  const res = await ctx.deliver(t, ctx.peer.envelope(m), `deliver a message naming a part (${name})`);
  if (res.status !== 202) throw new Prerequisite(`delivering a message naming a part answered ${res.status}`);
  const at = Date.now();
  // The agent has received the message only once it is in its inbox: fan-out follows the 202 (spec 6.3).
  if (!(await awaitSync(t, a, messageId(m), ctx.opts.deliveryWaitMs)))
    throw new Prerequisite('a message naming a part never reached the inbox');
  return { a, bytes, sha256, id: messageId(m), at };
}

/** A message from the simulator to an address no agent holds, naming a part the simulator serves. */
async function partForNobody(t: T, ctx: Ctx) {
  const bytes = crypto.randomBytes(555);
  const { sha256, size } = ctx.peer.offerPart(bytes, [ctx.origin]);
  const nobody = `${ctx.runId}-nobody-parts@${await ctx.domain()}`;
  const m = buildFrom(ctx.peer.agent('parts-nobody'), [nobody], ctx.now(), {
    parts: [{ type: 'application/octet-stream', sha256, size }],
  });
  const res = await ctx.deliver(t, ctx.peer.envelope(m), 'deliver a message naming a part, to nobody');
  if (res.status !== 202) throw new Prerequisite(`delivering a message to nobody answered ${res.status}`);
  return { bytes, sha256, at: Date.now() };
}

/** The simulator's part endpoint asked for this hash: the first time, within `ms` of `from`. */
const fetchedAt = (ctx: Ctx, sha256: string, from: number, ms: number) =>
  poll(async () => ctx.peer.partFetches.find(f => f.sha256 === sha256), Math.max(0, from + ms - Date.now()), 1000);

/** Agent a fetches the part until it gets 200 or the time runs out; every answer, the exchanges kept apart. */
async function fetchAsAgent(t: T, a: TargetAgent, sha256: string, ms: number, every = 1000) {
  const s = t.scratch();
  const answers: Res[] = [];
  await poll(
    async () => {
      const res = await a.call(s, 'GET', `/simon/parts/${sha256}`, undefined, {}, 'the recipient fetches the part');
      answers.push(res);
      return res.status === 200 ? res : undefined;
    },
    ms,
    every,
  );
  return { answers, exchanges: s.exchanges };
}

interface Watched {
  sha256: string;
  bytes: Buffer;
  /** The simulator's first record of the server asking for the part, if it did within the prefetch wait. */
  fetch?: PartFetch;
  /** What agent a got: every answer while it asked early, or the one answer after the server's fetch. */
  answers: Res[];
  exchanges: Exchange[];
}

/**
 * Messages from the simulator naming parts it holds, delivered to agent a early in the run, and watched
 * while the other checks run, since a server may wait a few minutes before fetching (spec 7.2):
 *
 *   prefetch   no agent asks; the simulator watches for the server's fetch
 *   nobody     likewise, for a message to an address no agent holds
 *   asked      agent a asks at once and keeps asking: 503 with Retry-After until the bytes are here, then 200
 *   wrong      the simulator serves other bytes; agent a asks once the server fetched
 *   sized      the message declares a size the bytes do not have; likewise
 */
export const remoteParts = (ctx: Ctx) =>
  ctx.once('parts the simulator holds', async t => {
    await requireControl(ctx);
    const wait = ctx.opts.prefetchWaitMs;
    const prefetch = await remotePart(t, ctx, 'parts-prefetch');
    const nobody = await partForNobody(t, ctx);
    const asked = await remotePart(t, ctx, 'parts-asked');
    const wrong = await remotePart(t, ctx, 'parts-wrong', { wrong: crypto.randomBytes(777) });
    const sized = await remotePart(t, ctx, 'parts-size', { declaredSize: 778 });
    const watch = async (r: typeof prefetch): Promise<Watched> => {
      const fetch = await fetchedAt(ctx, r.sha256, r.at, wait);
      if (!fetch) return { sha256: r.sha256, bytes: r.bytes, answers: [], exchanges: [] };
      await sleep(2000);
      const { answers, exchanges } = await fetchAsAgent(t.scratch(), r.a, r.sha256, 0);
      return { sha256: r.sha256, bytes: r.bytes, fetch, answers, exchanges };
    };
    const [p, n, w, z, k] = await Promise.all([
      fetchedAt(ctx, prefetch.sha256, prefetch.at, wait).then(fetch => ({
        sha256: prefetch.sha256,
        bytes: prefetch.bytes,
        fetch,
        answers: [],
        exchanges: [],
      })),
      fetchedAt(ctx, nobody.sha256, nobody.at, wait).then(fetch => ({
        sha256: nobody.sha256,
        bytes: nobody.bytes,
        fetch,
        answers: [],
        exchanges: [],
      })),
      fetchAsAgent(t.scratch(), asked.a, asked.sha256, Math.max(0, asked.at + wait - Date.now()), 2000).then(f => ({
        sha256: asked.sha256,
        bytes: asked.bytes,
        fetch: ctx.peer.partFetches.find(x => x.sha256 === asked.sha256),
        ...f,
      })),
      watch(wrong),
      watch(sized),
    ]);
    return { prefetch: p as Watched, nobody: n as Watched, asked: w as Watched, wrong: z, sized: k };
  });

/** Show the simulator's records of the server asking for a part. */
function recordFetches(t: T, ctx: Ctx, sha256: string) {
  const fetches = ctx.peer.partFetches.filter(f => f.sha256 === sha256);
  for (const f of fetches) {
    t.record({
      label: "the server's fetch at the simulator",
      direction: 'from-target',
      at: f.at.toISOString(),
      request: {
        method: 'GET',
        url: `${ctx.peer.origin}${f.target}`,
        headers: Object.fromEntries(Object.entries(f.headers).filter(([k]) => k.startsWith('simon-'))),
      },
      response: { status: f.answer, headers: {} },
      error: f.refusal ?? undefined,
    });
  }
  return fetches;
}

def(
  {
    id: 'parts.prefetch',
    section: S,
    level: 'must',
    title: "The recipient's server fetches a received message's parts on its own",
    expected:
      "after the simulator delivers agent a a message naming a part it holds, the server asks the simulator's /simon/parts/<sha256> for it within the prefetch wait, though no agent asked",
  },
  async (t: T, ctx: Ctx) => {
    const { prefetch } = await remoteParts(ctx);
    recordFetches(t, ctx, prefetch.sha256);
    t.assert(
      prefetch.fetch,
      `the server never asked the simulator for the part within ${ctx.opts.prefetchWaitMs / 1000} s of accepting the message`,
    );
  },
);

def(
  {
    id: 'parts.prefetch-any-recipient',
    section: S,
    level: 'must',
    title: 'The parts of every accepted message are fetched, whoever its recipients are',
    expected:
      "after the simulator delivers a message naming a part it holds to an address no agent holds, the server asks the simulator's /simon/parts/<sha256> for it within the prefetch wait, as it would for an agent: the fetch tells the carrier nothing about who is there",
  },
  async (t: T, ctx: Ctx) => {
    const { nobody } = await remoteParts(ctx);
    recordFetches(t, ctx, nobody.sha256);
    t.assert(
      nobody.fetch,
      `the server never asked the simulator for the part of a message to nobody within ${ctx.opts.prefetchWaitMs / 1000} s`,
    );
  },
);

def(
  {
    id: 'parts.forward-received',
    section: `CLIENT send, ${S}`,
    level: 'must',
    title: 'An agent forwards a part it received without uploading it again',
    expected:
      "once agent a holds a part fetched from the simulator, send answers 200 for a's message naming it to another address at the simulator, with no upload, and the simulator then fetches the bytes from the server with a signed server request",
  },
  async (t: T, ctx: Ctx) => {
    const { asked } = await remoteParts(ctx);
    if (asked.answers.at(-1)?.status !== 200) t.skip('agent a never received the part (see parts.recipient-fetch)');
    const a = await ctx.agent('a');
    const m = a.message({
      to: [ctx.peer.address('forwarded')],
      parts: [{ type: 'application/octet-stream', sha256: asked.sha256, size: asked.bytes.length }],
    });
    t.status(await a.send(t, m, {}, 'forward the received part'), 200, 'send, naming a part a received');
    const text = canonicalize(m);
    const arrived = await poll(
      async () => ctx.peer.received.find(r => r.messageText === text),
      ctx.opts.deliveryWaitMs,
    );
    t.assert(arrived, 'the forwarded message never reached the simulator');
    await sleep(500);
    const res = await asServer(t, ctx, asked.sha256, ctx.peer, 'the simulator fetches the forwarded part');
    t.status(res, 200, 'the forwarded part, to the server it was delivered to');
    t.assert(res.bytes.equals(asked.bytes), 'the bytes differ');
  },
);

def(
  {
    id: 'parts.recipient-fetch',
    section: `CLIENT parts, ${S}`,
    level: 'must',
    title: 'A recipient gets a remote part through its own server',
    expected:
      'the recipient of a message naming a part the simulator holds gets 200 with exactly the bytes within the prefetch wait, and 503 unavailable with Retry-After before then',
  },
  async (t: T, ctx: Ctx) => {
    const { asked } = await remoteParts(ctx);
    t.adopt(asked.exchanges.slice(0, 1));
    t.adopt(asked.exchanges.slice(-1));
    for (const res of asked.answers.filter(r => r.status !== 200)) {
      t.error(res, 503, 'unavailable', 'while fetching');
      t.assert(res.headers['retry-after'] !== undefined, 'a 503 while fetching carries Retry-After');
    }
    const last = asked.answers.at(-1);
    t.assert(last, 'the agent never asked');
    t.status(last, 200, `the fetch, within ${ctx.opts.prefetchWaitMs / 1000} s`);
    t.assert(last.bytes.equals(asked.bytes), 'the bytes differ');
  },
);

def(
  {
    id: 'parts.server-request',
    section: `${S}, PROTOCOL 8`,
    level: 'must',
    title: 'The server fetches remote parts with a signed server request',
    expected:
      "the server's GET at the simulator carries simon-server (its origin) and a signature by a key its document lists valid now, over the simulator's origin and the path",
  },
  async (t: T, ctx: Ctx) => {
    const { prefetch, asked } = await remoteParts(ctx);
    const fetches = [...recordFetches(t, ctx, prefetch.sha256), ...recordFetches(t, ctx, asked.sha256)];
    if (!fetches.length) t.skip('the server never asked the simulator for a part (see parts.prefetch)');
    const bad = fetches.find(f => f.refusal);
    t.assert(!bad, `the simulator refused the server's request: ${bad?.refusal}`);
    t.assert(
      fetches.every(f => f.server === ctx.origin),
      `simon-server was ${fetches.map(f => f.server).join(', ')}`,
    );
  },
);

def(
  {
    id: 'parts.hash-checked',
    section: S,
    level: 'must',
    title: 'Whoever fetches a part checks its hash and size',
    expected:
      'once the server fetched them, the recipient does not get 200 when the simulator serves bytes that do not match the hash, nor when the message declares a size the bytes do not have',
  },
  async (t: T, ctx: Ctx) => {
    const { wrong, sized } = await remoteParts(ctx);
    for (const [what, w] of [
      ['bytes not matching the hash', wrong],
      ['a declared size the bytes do not have', sized],
    ] as const) {
      if (!w.fetch) t.skip(`the server never asked the simulator for the part with ${what} (see parts.prefetch)`);
      recordFetches(t, ctx, w.sha256);
      t.adopt(w.exchanges);
      const served = w.answers.find(r => r.status === 200);
      t.assert(
        !served,
        `${what}: the server served ${served?.bytes.length} bytes hashing to ${served && sha256Hex(served.bytes)}`,
      );
    }
  },
);
