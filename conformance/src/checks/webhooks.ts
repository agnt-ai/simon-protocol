/**
 * CLIENT webhooks: a URL that wakes an agent holding no connection open. The simulator is the receiver: it
 * records every post the server under test makes to a webhook, and checks the server request signature of
 * each as section 8 says. A server that offers no webhooks (404 on `POST /simon/webhooks`) skips them all.
 *
 * Not tested here, and why (conformance/readme.md, "What the suite cannot test"): a webhook that has failed
 * for 3 days is switched off (the suite cannot move the server's clock by days), and a webhook made through
 * a grant ends with the grant (a grant is obtained from the agent's principal, which a black-box suite
 * cannot be).
 */
import { canonicalize, messageId } from '@agnt-sdk/simon-protocol';
import type { TargetAgent } from '../agent.ts';
import { buildFrom, type Ctx } from '../context.ts';
import { poll, problem, sleep, type T } from '../harness.ts';
import type { HookPost } from '../peer.ts';
import { def } from './common.ts';
import { requireControl } from './deliver.ts';

const S = 'CLIENT webhooks';

/** How long the suite listens for a post that must not come. A server posts within a second of a change. */
const QUIET_MS = 3000;

interface Hook {
  id: string;
  name: string;
  url: string;
}

let counter = 0;

/** Create a webhook on the simulator for `a`; skips when the server offers none, or takes only https. */
async function create(t: T, ctx: Ctx, a: TargetAgent, label: string): Promise<Hook> {
  const name = `${label}-${++counter}`;
  const url = ctx.peer.hookUrl(name);
  const res = await a.call(t, 'POST', '/simon/webhooks', canonicalize({ url }), {}, `create webhook ${label}`);
  if (res.status === 404 || res.status === 405) t.skip('the server offers no webhooks (POST /simon/webhooks)');
  if (res.status === 400 && problem(res)?.details?.field === 'url' && url.startsWith('http:')) {
    t.skip(
      `the server takes only https webhook URLs and the simulator is at ${ctx.peer.origin}: ` +
        'put it behind a tunnel (--peer-origin) or run the server in development',
    );
  }
  t.status(res, [200, 201], 'creating a webhook');
  t.assert(typeof res.json?.id === 'string' && res.json.id.length > 0, `no id in ${res.text.slice(0, 200)}`);
  return { id: res.json.id, name, url };
}

/** Delete a webhook, ignoring the answer: cleanup for a check that has said what it found. */
const remove = (t: T, a: TargetAgent, h: Hook) =>
  a.call(t.scratch(), 'DELETE', `/simon/webhooks/${h.id}`, undefined, {}, 'delete webhook').catch(() => undefined);

/** The posts to a hook, with a body of this type. */
const ofType = (ctx: Ctx, h: Hook, type: string) => ctx.peer.postsTo(h.name).filter(p => p.json?.type === type);

/** The first post to a hook that satisfies `pred`, within `ms`. */
const awaitPost = (ctx: Ctx, h: Hook, pred: (p: HookPost) => boolean, ms: number) =>
  poll(async () => ctx.peer.postsTo(h.name).find(pred), ms, 100);

/** The code the server posted to a hook, once it does. */
async function verifyCode(t: T, ctx: Ctx, h: Hook): Promise<string> {
  const post = await awaitPost(ctx, h, p => p.json?.type === 'verify', ctx.opts.deliveryWaitMs);
  if (!post) t.fail('the server never posted {"type":"verify","code"} to the webhook URL');
  const code = post.json?.code;
  t.assert(
    typeof code === 'string' && code.length > 0,
    `the verify post has no code: ${post.raw.toString().slice(0, 200)}`,
  );
  return code;
}

const verify = (t: T, a: TargetAgent, h: Hook, code: string, label = 'verify webhook') =>
  a.call(t, 'POST', `/simon/webhooks/${h.id}/verify`, canonicalize({ code }), {}, label);

/** A message from the simulator to `a`, accepted: its id, and when. */
async function arrive(t: T, ctx: Ctx, a: TargetAgent, who: string) {
  const p = ctx.peer.agent(who);
  const m = buildFrom(p, [a.address], ctx.now());
  const res = await ctx.deliver(t, ctx.peer.envelope(m), `a message for ${who}`);
  t.status(res, 202, 'delivering a message to the webhook agent');
  return { id: messageId(m), at: Date.now() };
}

/** The agent webhook checks use, and a delivery from the simulator that is known to work. */
async function hookAgent(ctx: Ctx) {
  await requireControl(ctx);
  return ctx.agent('hooks');
}

/**
 * One webhook that is created, shown its code, refused a wrong one, and then left unverified while a message
 * arrives: what it was sent meanwhile. Two checks read it.
 */
const unverified = (ctx: Ctx) =>
  ctx.once('a webhook that is never verified', async t => {
    const a = await hookAgent(ctx);
    const h = await create(t, ctx, a, 'unverified');
    const code = await verifyCode(t, ctx, h);
    const wrong = await verify(t, a, h, `${code}-wrong`, 'verify with a wrong code');
    await arrive(t, ctx, a, 'while-unverified');
    await sleep(QUIET_MS);
    // Anything but the one verify post is more than the server may send: a changed, or a second code.
    const posts = ctx.peer.postsTo(h.name).filter(p => !(p.json?.type === 'verify' && p.json?.code === code));
    await remove(t, a, h);
    return { posts, wrong, exchanges: t.exchanges.slice(-3) };
  });

def(
  {
    id: 'webhooks.create',
    section: S,
    level: 'must',
    title: 'A webhook is created with its URL and deleted by its id',
    expected:
      '200 or 201 {"id"} for POST /simon/webhooks {"url"} signed by the agent; 400 invalid with details.field "url" for a value that is not a URL; 2xx for DELETE /simon/webhooks/<id>, and 404 not_found for a verify of that id afterwards',
  },
  async (t: T, ctx: Ctx) => {
    const a = await hookAgent(ctx);
    const h = await create(t, ctx, a, 'create');
    const bad = await a.call(
      t,
      'POST',
      '/simon/webhooks',
      canonicalize({ url: 'not a url' }),
      {},
      'a value that is no URL',
    );
    t.error(bad, 400, 'invalid', 'a value that is no URL', { field: 'url' });
    const gone = await a.call(t, 'DELETE', `/simon/webhooks/${h.id}`, undefined, {}, 'delete webhook');
    t.status(gone, [200, 204], 'deleting the webhook');
    t.error(
      await verify(t, a, h, 'anything', 'verify a deleted webhook'),
      404,
      'not_found',
      'verifying a deleted webhook',
    );
  },
);

def(
  {
    id: 'webhooks.verify-first',
    section: `${S} "Verification"`,
    level: 'must',
    title: 'The server first posts a verification code to the URL',
    expected:
      'a post to the webhook URL with the body {"type":"verify","code":"<non-empty string>"} and no other member, within the delivery wait of creating it',
  },
  async (t: T, ctx: Ctx) => {
    const a = await hookAgent(ctx);
    const h = await create(t, ctx, a, 'verify-first');
    try {
      await verifyCode(t, ctx, h);
      const first = ctx.peer.postsTo(h.name)[0]!;
      t.assert(first.json?.type === 'verify', `the first post to the URL was ${first.raw.toString().slice(0, 200)}`);
      const members = Object.keys(first.json).sort().join(',');
      t.assert(members === 'code,type', `the verify post has the members ${members}, expected code and type`);
    } finally {
      await remove(t, a, h);
    }
  },
);

def(
  {
    id: 'webhooks.verify-code',
    section: `${S} "Verification"`,
    level: 'must',
    title: 'The code posted to the URL verifies the webhook, and a wrong one does not',
    expected:
      '4xx for POST /simon/webhooks/<id>/verify with a code that was not posted; 200 for the code that was, answering {"id","verified":true}',
  },
  async (t: T, ctx: Ctx) => {
    const a = await hookAgent(ctx);
    const h = await create(t, ctx, a, 'verify-code');
    try {
      const code = await verifyCode(t, ctx, h);
      const wrong = await verify(t, a, h, `${code}x`, 'verify with a wrong code');
      t.assert(wrong.status >= 400 && wrong.status < 500, `a wrong code was answered ${wrong.status}, expected 4xx`);
      const right = await verify(t, a, h, code);
      t.status(right, 200, 'verifying with the posted code');
      t.assert(right.json?.verified === true, `the answer is ${right.text.slice(0, 200)}, expected "verified":true`);
    } finally {
      await remove(t, a, h);
    }
  },
);

def(
  {
    id: 'webhooks.silent-until-verified',
    section: `${S} "Verification"`,
    level: 'must',
    title: 'The server sends nothing else until the code comes back',
    expected:
      'after the verify post, and after a wrong code was refused, a message that reaches the agent makes the server post nothing more to the URL for three seconds, and the verify post is not repeated with another code',
  },
  async (t: T, ctx: Ctx) => {
    const s = await unverified(ctx);
    t.adopt(s.exchanges);
    t.assert(
      s.posts.length === 0,
      `${s.posts.length} post(s) reached an unverified webhook: ${s.posts.map(p => p.raw.toString().slice(0, 120)).join(' ')}`,
    );
  },
);

def(
  {
    id: 'webhooks.changed',
    section: `${S} "Waking"`,
    level: 'must',
    title: 'A change in the agent’s sync makes the server post changed',
    expected:
      'once verified, a message that reaches the agent is followed by a post {"type":"changed","agent":"<the agent’s address>"} with no other member; the message is then in the agent’s sync',
  },
  async (t: T, ctx: Ctx) => {
    const a = await hookAgent(ctx);
    const h = await create(t, ctx, a, 'changed');
    try {
      t.status(await verify(t, a, h, await verifyCode(t, ctx, h)), 200, 'verifying the webhook');
      const sent = await arrive(t, ctx, a, 'changed');
      const post = await awaitPost(
        ctx,
        h,
        p => p.json?.type === 'changed' && p.at.getTime() >= sent.at,
        ctx.opts.deliveryWaitMs,
      );
      if (!post) t.fail('no {"type":"changed"} post followed a message that reached the agent');
      const members = Object.keys(post.json).sort().join(',');
      t.assert(members === 'agent,type', `the changed post has the members ${members}, expected agent and type`);
      t.assert(
        post.json.agent === a.address,
        `the changed post names ${JSON.stringify(post.json.agent)}, expected ${a.address}`,
      );
      const res = await a.sync(t, 'limit=200', 'sync after the wakeup');
      t.status(res, 200);
      t.assert(
        res.json?.messages?.some((e: { id: string }) => e.id === sent.id),
        'the sync after the wakeup does not show the message that caused it',
      );
    } finally {
      await remove(t, a, h);
    }
  },
);

def(
  {
    id: 'webhooks.signed',
    section: `${S} "Signing", PROTOCOL 8`,
    level: 'must',
    title: 'Every post is a server request signed by the server',
    expected:
      'the verify post and the changed post each carry simon-server equal to the server’s origin and a signature that verifies, with the origin line of the webhook URL’s origin, against a key in the server’s document valid now; neither carries simon-agent',
  },
  async (t: T, ctx: Ctx) => {
    const a = await hookAgent(ctx);
    const h = await create(t, ctx, a, 'signed');
    try {
      t.status(await verify(t, a, h, await verifyCode(t, ctx, h)), 200, 'verifying the webhook');
      await arrive(t, ctx, a, 'signed');
      const changed = await awaitPost(ctx, h, p => p.json?.type === 'changed', ctx.opts.deliveryWaitMs);
      if (!changed) t.fail('no {"type":"changed"} post reached the webhook');
      for (const p of ctx.peer.postsTo(h.name)) {
        const what = `the ${p.json?.type} post`;
        t.assert(p.refusal === null, `${what} is not a valid server request: ${p.refusal}`);
        t.assert(p.server === ctx.origin, `${what} is signed as ${JSON.stringify(p.server)}, expected ${ctx.origin}`);
        t.assert(p.headers['simon-agent'] === undefined, `${what} carries simon-agent`);
      }
    } finally {
      await remove(t, a, h);
    }
  },
);

def(
  {
    id: 'webhooks.json',
    section: `${S} "Signing", PROTOCOL 9`,
    level: 'must',
    title: 'Posts are application/json',
    expected:
      'the verify post and the changed post each have Content-Type application/json (parameters allowed) and a JSON object as body',
  },
  async (t: T, ctx: Ctx) => {
    const a = await hookAgent(ctx);
    const h = await create(t, ctx, a, 'json');
    try {
      t.status(await verify(t, a, h, await verifyCode(t, ctx, h)), 200, 'verifying the webhook');
      await arrive(t, ctx, a, 'json');
      if (!(await awaitPost(ctx, h, p => p.json?.type === 'changed', ctx.opts.deliveryWaitMs)))
        t.fail('no {"type":"changed"} post reached the webhook');
      for (const p of ctx.peer.postsTo(h.name)) {
        const type = (p.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
        t.assert(
          type === 'application/json',
          `a ${p.json?.type} post has Content-Type ${JSON.stringify(p.headers['content-type'])}`,
        );
      }
    } finally {
      await remove(t, a, h);
    }
  },
);

def(
  {
    id: 'webhooks.rate',
    section: `${S} "Waking"`,
    level: 'must',
    title: 'Changed is posted at most once a second',
    expected:
      'twelve messages delivered to the agent in two bursts make no two changed posts less than 0.75 s apart (a second, less the jitter of the suite’s own clock)',
  },
  async (t: T, ctx: Ctx) => {
    const a = await hookAgent(ctx);
    const h = await create(t, ctx, a, 'rate');
    try {
      t.status(await verify(t, a, h, await verifyCode(t, ctx, h)), 200, 'verifying the webhook');
      await Promise.all(Array.from({ length: 6 }, (_, i) => arrive(t, ctx, a, `rate-${i}`)));
      await sleep(1300);
      await Promise.all(Array.from({ length: 6 }, (_, i) => arrive(t, ctx, a, `rate-b${i}`)));
      await sleep(QUIET_MS);
      const times = ofType(ctx, h, 'changed').map(p => p.at.getTime());
      t.assert(times.length > 0, 'no changed post followed twelve messages');
      for (let i = 1; i < times.length; i++) {
        const gap = times[i]! - times[i - 1]!;
        t.assert(gap >= 750, `changed posts ${i} and ${i + 1} reached the webhook ${gap} ms apart`);
      }
    } finally {
      await remove(t, a, h);
    }
  },
);

def(
  {
    id: 'webhooks.delete',
    section: S,
    level: 'must',
    title: 'A deleted webhook is posted to no more',
    expected:
      'after DELETE /simon/webhooks/<id>, a message that reaches the agent makes the server post nothing to that URL for three seconds',
  },
  async (t: T, ctx: Ctx) => {
    const a = await hookAgent(ctx);
    const h = await create(t, ctx, a, 'delete');
    t.status(await verify(t, a, h, await verifyCode(t, ctx, h)), 200, 'verifying the webhook');
    // Let a wakeup the verification itself caused settle before the webhook goes.
    await sleep(1500);
    t.status(await a.call(t, 'DELETE', `/simon/webhooks/${h.id}`, undefined, {}, 'delete webhook'), [200, 204]);
    const before = ctx.peer.postsTo(h.name).length;
    await arrive(t, ctx, a, 'after-delete');
    await sleep(QUIET_MS);
    const after = ctx.peer.postsTo(h.name).slice(before);
    t.assert(
      after.length === 0,
      `${after.length} post(s) reached a deleted webhook: ${after.map(p => p.raw.toString().slice(0, 120)).join(' ')}`,
    );
  },
);

def(
  {
    id: 'webhooks.allowance',
    section: `${S}, CLIENT errors`,
    level: 'should',
    title: 'A full webhook allowance is 409 too_many_webhooks',
    expected:
      'creating webhooks without limit ends, within twelve, with 409 too_many_webhooks (the host’s allowance is its own; a server that takes twelve skips this check)',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('hooks-allowance');
    await requireControl(ctx);
    const made: Hook[] = [];
    try {
      for (let i = 0; i < 12; i++) {
        const name = `allowance-${++counter}`;
        const res = await a.call(
          t,
          'POST',
          '/simon/webhooks',
          canonicalize({ url: ctx.peer.hookUrl(name) }),
          {},
          `create webhook ${i + 1}`,
        );
        if (res.status === 404 || res.status === 405) t.skip('the server offers no webhooks (POST /simon/webhooks)');
        if (res.status === 409) {
          t.error(res, 409, 'too_many_webhooks', `webhook ${i + 1}`);
          return;
        }
        if (res.status === 400 && ctx.peer.origin.startsWith('http:'))
          t.skip('the server takes only https webhook URLs');
        t.status(res, [200, 201], `webhook ${i + 1}`);
        made.push({ id: res.json.id, name, url: ctx.peer.hookUrl(name) });
      }
      t.skip('the server took twelve webhooks for one agent; its allowance is above what the suite creates');
    } finally {
      for (const h of made) await remove(t, a, h);
    }
  },
);
