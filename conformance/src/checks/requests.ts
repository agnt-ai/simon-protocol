/** PROTOCOL section 8: signed requests, the order of their refusals, and what a refusal tells the signer. */
import crypto from 'node:crypto';
import { requestSigningString } from '@agnt-sdk/simon-protocol';
import { newNonce, TargetAgent } from '../agent.ts';
import { problem, type Res, type T } from '../harness.ts';
import type { Ctx } from '../context.ts';
import { def } from './common.ts';

/** The call every check here signs: a cheap read that changes nothing. */
const TARGET = '/simon/sync?limit=1';

/** A 401 with this code, in the error shape, with an integer details.serverTime. */
function refused(t: T, res: Res, code: string, what: string) {
  const err = t.error(res, 401, code, what);
  t.assert(Number.isInteger(err.details?.serverTime), `${what}: the 401 has no integer details.serverTime`);
  return err;
}

const ts = (ctx: Ctx, skew = 0) => String(Math.floor(ctx.now() / 1000) + skew);

def(
  {
    id: 'requests.unsigned',
    section: 'PROTOCOL 8',
    level: 'must',
    title: 'An unsigned request is 401 signature_required',
    expected: '401 signature_required with details.serverTime, for a client API call carrying no signature headers',
  },
  async (t: T, ctx: Ctx) => {
    const res = await t.http({ method: 'GET', origin: ctx.origin, target: TARGET });
    refused(t, res, 'signature_required', 'no headers');
  },
);

def(
  {
    id: 'requests.missing-header',
    section: 'PROTOCOL 8',
    level: 'must',
    title: 'Each missing signature header is 401 signature_required',
    expected:
      'dropping any one of simon-key, simon-timestamp, simon-nonce or simon-signature gives 401 signature_required',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    for (const h of ['simon-key', 'simon-timestamp', 'simon-nonce', 'simon-signature']) {
      const res = await a.call(t, 'GET', TARGET, undefined, { override: { [h]: undefined } }, `without ${h}`);
      refused(t, res, 'signature_required', `without ${h}`);
    }
  },
);

def(
  {
    id: 'requests.malformed-header',
    section: 'PROTOCOL 8, Appendix A',
    level: 'must',
    title: 'Each malformed signature header is 401 signature_required',
    expected:
      'a timestamp that is not 1 to 12 digits, a nonce outside 8 to 128 characters of U+0021 to U+007E, a key that is not a key token, or a signature that is not canonical base64url gives 401 signature_required',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    const cases: [string, Record<string, string>][] = [
      ['a 13-digit timestamp', { 'simon-timestamp': '1' + ts(ctx).padStart(12, '0') }],
      ['a timestamp with a sign', { 'simon-timestamp': `+${ts(ctx)}` }],
      ['a 7-character nonce', { 'simon-nonce': 'abcdefg' }],
      ['a 129-character nonce', { 'simon-nonce': 'n'.repeat(129) }],
      ['a nonce with a space', { 'simon-nonce': 'has a space' }],
      ['a key with no algorithm', { 'simon-key': a.token.split(':')[1] }],
      ['a padded signature', { 'simon-signature': 'AAAA=' }],
      ['a signature with a non-base64url character', { 'simon-signature': 'AA+A' }],
    ];
    for (const [what, override] of cases) {
      const res = await a.call(t, 'GET', TARGET, undefined, { override }, what);
      refused(t, res, 'signature_required', what);
    }
  },
);

def(
  {
    id: 'requests.nonce-bounds',
    section: 'PROTOCOL 8, Appendix A',
    level: 'must',
    title: 'Nonces of 8 and of 128 printable characters are accepted',
    expected:
      'a request whose nonce is exactly 8, or exactly 128, characters from U+0021 to U+007E (including ! and ~) answers 200',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    const short = `!${crypto.randomBytes(6).toString('base64url').slice(0, 6)}~`;
    const long = `~${crypto.randomBytes(96).toString('base64url').slice(0, 126)}!`;
    for (const nonce of [short, long]) {
      const res = await a.call(t, 'GET', TARGET, undefined, { nonce }, `a ${nonce.length}-character nonce`);
      t.status(res, 200, `a ${nonce.length}-character nonce`);
    }
  },
);

def(
  {
    id: 'requests.timestamp-window',
    section: 'PROTOCOL 8',
    level: 'must',
    title: 'The timestamp window is 300 seconds either way',
    expected:
      'a timestamp 300 s minus the clock margin from the server clock (either way) answers 200; 300 s plus the margin answers 401 stale_request',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    const m = ctx.opts.clockMarginSeconds;
    for (const skew of [-(300 - m), 300 - m]) {
      const res = await a.call(t, 'GET', TARGET, undefined, { skewSeconds: skew }, `${skew} s`);
      t.status(res, 200, `a timestamp ${skew} s off`);
    }
    for (const skew of [-(300 + m), 300 + m]) {
      const res = await a.call(t, 'GET', TARGET, undefined, { skewSeconds: skew }, `${skew} s`);
      refused(t, res, 'stale_request', `a timestamp ${skew} s off`);
    }
  },
);

def(
  {
    id: 'requests.unknown-key',
    section: 'PROTOCOL 8',
    level: 'must',
    title: 'A key the server does not know is 401 unknown_key',
    expected:
      '401 unknown_key for a well-formed request naming an agent there in simon-agent, signed by a key that agent does not hold',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    const stranger = TargetAgent.fresh(ctx.server);
    const asA = { agent: a.address };
    refused(t, await stranger.call(t, 'GET', TARGET, undefined, asA), 'unknown_key', 'an unknown key');
  },
);

/** Send a request signed over something other than what was sent, and check the expected signing string. */
async function badSignature(
  t: T,
  ctx: Ctx,
  what: string,
  method: string,
  target: string,
  body: string | undefined,
  signed: {
    origin?: string;
    signedTarget?: string;
    signedBody?: string;
    method?: string;
    otherKey?: boolean;
    agent?: string;
  },
) {
  const a = await ctx.agent('a');
  const timestamp = ts(ctx);
  const nonce = newNonce();
  const { method: signedMethod, otherKey, agent: signedAs, ...rest } = signed;
  const signer = a.request(signedMethod ?? method, target, body, { timestamp, nonce, agent: signedAs, ...rest });
  const req = { ...signer(), method };
  // Signed as another address, but sent naming this agent's.
  if (signedAs) req.headers = { ...req.headers, 'simon-agent': a.address };
  if (otherKey) {
    // Signed by another key over the right string, but naming this agent's key.
    const other = TargetAgent.fresh(ctx.server).request(method, target, body, { timestamp, nonce })();
    req.headers = { ...req.headers, 'simon-signature': other.headers!['simon-signature'] };
  }
  const res = await t.http(req, { label: what });
  const err = refused(t, res, 'bad_signature', what);
  const expected = requestSigningString({
    method,
    origin: ctx.origin,
    actor: a.address,
    target,
    timestamp,
    nonce,
    body: body ?? '',
  });
  t.assert(
    err.details?.signingString === expected,
    `${what}: details.signingString is ${JSON.stringify(err.details?.signingString)}; expected ${JSON.stringify(expected)}`,
  );
}

def(
  {
    id: 'requests.bad-signature',
    section: 'PROTOCOL 8',
    level: 'must',
    title: 'A signature that does not verify is 401 bad_signature, with the signing string expected',
    expected:
      '401 bad_signature with details.serverTime and details.signingString exactly the eight lines the server expected: SIMON-REQUEST, the method, its origin, the actor, the request target as sent, the timestamp, the nonce, the body hash',
  },
  async (t: T, ctx: Ctx) => {
    await badSignature(t, ctx, "signed by another key, naming the agent's", 'GET', TARGET, undefined, {
      otherKey: true,
    });
  },
);

def(
  {
    id: 'requests.binds-origin',
    section: 'PROTOCOL 8',
    level: 'must',
    title: 'A request signed for another server is refused',
    expected: "401 bad_signature, the signing string naming this server's own origin",
  },
  async (t: T, ctx: Ctx) => {
    await badSignature(t, ctx, 'signed for https://elsewhere.example', 'GET', TARGET, undefined, {
      origin: 'https://elsewhere.example',
    });
  },
);

def(
  {
    id: 'requests.binds-target',
    section: 'PROTOCOL 8',
    level: 'must',
    title: 'The request target as sent is signed, query included',
    expected:
      '401 bad_signature for a request signed over another query, the signing string naming the target exactly as sent',
  },
  async (t: T, ctx: Ctx) => {
    await badSignature(t, ctx, 'signed over limit=2, sent limit=1', 'GET', TARGET, undefined, {
      signedTarget: '/simon/sync?limit=2',
    });
  },
);

def(
  {
    id: 'requests.binds-actor',
    section: 'PROTOCOL 8',
    level: 'must',
    title: 'Who a request acts as is signed',
    expected:
      '401 bad_signature for a request signed as one address and sent naming another in simon-agent, the signing string naming the address sent',
  },
  async (t: T, ctx: Ctx) => {
    await badSignature(t, ctx, 'signed as another address, sent as the agent', 'GET', TARGET, undefined, {
      agent: 'someone-else@example.invalid',
    });
  },
);

def(
  {
    id: 'requests.binds-method',
    section: 'PROTOCOL 8',
    level: 'must',
    title: 'The method is signed',
    expected: '401 bad_signature for a GET signed as a POST, the signing string naming GET',
  },
  async (t: T, ctx: Ctx) => {
    await badSignature(t, ctx, 'signed as POST, sent as GET', 'GET', TARGET, undefined, { method: 'POST' });
  },
);

def(
  {
    id: 'requests.binds-body',
    section: 'PROTOCOL 8',
    level: 'must',
    title: 'The body is signed by its hash',
    expected:
      '401 bad_signature for a POST whose body differs from the one signed, the signing string ending in the hash of the body as sent',
  },
  async (t: T, ctx: Ctx) => {
    await badSignature(t, ctx, 'body differs from the signed one', 'POST', '/simon/send', '{"note":"sent"}', {
      signedBody: '{"note":"signed"}',
    });
  },
);

def(
  {
    id: 'requests.replayed',
    section: 'PROTOCOL 8',
    level: 'must',
    title: 'A nonce used again by the same key is 401 replayed_request',
    expected: 'the same signed request twice: 200, then 401 replayed_request',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    const req = a.request('GET', TARGET)();
    t.status(await t.http(req, { label: 'first' }), 200, 'first');
    refused(t, await t.http(req, { label: 'again' }), 'replayed_request', 'again');
  },
);

/** A refused request with nonce N, then a good one with N: the good one must succeed. */
async function nonceSurvives(
  t: T,
  ctx: Ctx,
  what: string,
  code: string,
  bad: (a: TargetAgent, nonce: string) => Promise<Res>,
) {
  const a = await ctx.agent('a');
  const nonce = newNonce();
  refused(t, await bad(a, nonce), code, what);
  const good = await a.call(t, 'GET', TARGET, undefined, { nonce }, 'the good request, same nonce');
  t.status(good, 200, `after ${what}, a good request with the same nonce`);
  const again = await a.call(t, 'GET', TARGET, undefined, { nonce }, 'the same nonce a third time');
  refused(t, again, 'replayed_request', 'the nonce once a request with it was accepted');
}

def(
  {
    id: 'requests.nonce-after-bad-signature',
    section: 'PROTOCOL 8',
    level: 'must',
    title: 'A badly signed request does not use up its nonce',
    expected:
      'nonce N with a signature that does not verify: 401 bad_signature; then a good request with N: 200; then N again: 401 replayed_request',
  },
  async (t: T, ctx: Ctx) => {
    await nonceSurvives(t, ctx, 'a bad signature', 'bad_signature', (a, nonce) =>
      a.call(t, 'GET', TARGET, undefined, { nonce, signedTarget: TARGET + '&forged=1' }, 'bad signature, nonce N'),
    );
  },
);

def(
  {
    id: 'requests.nonce-after-unsigned',
    section: 'PROTOCOL 8',
    level: 'must',
    title: 'A request without a signature does not use up its nonce',
    expected: 'nonce N with no simon-signature: 401 signature_required; then a good request with N: 200',
  },
  async (t: T, ctx: Ctx) => {
    await nonceSurvives(t, ctx, 'a missing signature', 'signature_required', (a, nonce) =>
      a.call(
        t,
        'GET',
        TARGET,
        undefined,
        { nonce, override: { 'simon-signature': undefined } },
        'no signature, nonce N',
      ),
    );
  },
);

def(
  {
    id: 'requests.nonce-after-stale',
    section: 'PROTOCOL 8',
    level: 'must',
    title: 'A stale request does not use up its nonce',
    expected: 'nonce N with a timestamp outside the window: 401 stale_request; then a good request with N: 200',
  },
  async (t: T, ctx: Ctx) => {
    await nonceSurvives(t, ctx, 'a stale timestamp', 'stale_request', (a, nonce) =>
      a.call(t, 'GET', TARGET, undefined, { nonce, skewSeconds: -3600 }, 'stale, nonce N'),
    );
  },
);

def(
  {
    id: 'requests.refusal-order',
    section: 'PROTOCOL 8',
    level: 'should',
    title: 'Refusals come in the reference order section 8 lists them',
    expected:
      'malformed header before stale timestamp; stale timestamp before unknown key; unknown key before bad signature; bad signature before replayed nonce',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    const stranger = TargetAgent.fresh(ctx.server);
    refused(
      t,
      await a.call(
        t,
        'GET',
        TARGET,
        undefined,
        { skewSeconds: -3600, override: { 'simon-nonce': 'short' } },
        'malformed nonce and stale',
      ),
      'signature_required',
      'a malformed nonce and a stale timestamp',
    );
    refused(
      t,
      await stranger.call(
        t,
        'GET',
        TARGET,
        undefined,
        { skewSeconds: -3600, agent: a.address },
        'stale and unknown key',
      ),
      'stale_request',
      'a stale timestamp and an unknown key',
    );
    refused(
      t,
      await stranger.call(
        t,
        'GET',
        TARGET,
        undefined,
        { signedTarget: '/elsewhere', agent: a.address },
        'unknown key and bad signature',
      ),
      'unknown_key',
      'an unknown key and a bad signature',
    );
    const used = a.request('GET', TARGET)();
    t.status(await t.http(used, { label: 'use a nonce' }), 200, 'a good request');
    const forged = a.request('GET', TARGET, undefined, {
      nonce: used.headers!['simon-nonce'],
      signedTarget: '/elsewhere',
    })();
    refused(
      t,
      await t.http(forged, { label: 'used nonce, bad signature' }),
      'bad_signature',
      'a used nonce and a bad signature',
    );
  },
);

def(
  {
    id: 'requests.nonce-per-key',
    section: 'PROTOCOL 8',
    level: 'should',
    title: 'A nonce is tracked per key',
    expected: 'two agents using the same nonce, each once, both answer 200',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('a');
    const b = await ctx.agent('b');
    const nonce = newNonce();
    t.status(await a.call(t, 'GET', TARGET, undefined, { nonce }, 'agent a'), 200, 'agent a');
    t.status(
      await b.call(t, 'GET', TARGET, undefined, { nonce }, 'agent b, same nonce'),
      200,
      'agent b with the same nonce',
    );
  },
);

def(
  {
    id: 'requests.server-time',
    section: 'PROTOCOL 8',
    level: 'should',
    title: "details.serverTime is the server's clock in unix seconds",
    expected: "a 401's details.serverTime is within 300 s of the time the suite read it",
  },
  async (t: T, ctx: Ctx) => {
    const before = Math.floor(Date.now() / 1000);
    const res = await t.http({ method: 'GET', origin: ctx.origin, target: TARGET });
    const time = problem(res)?.details?.serverTime;
    t.assert(Number.isInteger(time), `details.serverTime is ${JSON.stringify(time)}`);
    t.assert(Math.abs(time - before) <= 300, `details.serverTime is ${time}; the suite's clock read ${before}`);
  },
);
