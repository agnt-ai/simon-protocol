/** CLIENT account and no-op recovery/grant refusals. */
import { parseTimestamp, readKeys } from '@agnt-protocol/protocol';
import type { Ctx } from '../context.ts';
import type { T } from '../harness.ts';
import { def } from './common.ts';

def(
  {
    id: 'account.shape',
    section: 'CLIENT account',
    level: 'must',
    title: 'The account names its agent, keys, grants and any pending recovery',
    expected:
      '200 with the signed-in address, readable keys including its key, a grants array and recovery null on a fresh account',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('account');
    const res = await a.call(t, 'GET', '/simon/account');
    t.status(res, 200);
    const b = res.json;
    t.assert(b?.address === a.address, 'account does not name the authenticated agent');
    const keys = readKeys(b.keys, new Date(ctx.now()));
    t.assert(
      keys?.some(k => k.key === a.token && k.revoked === null),
      'account does not list its active key',
    );
    t.assert(Array.isArray(b.grants), 'grants is not an array');
    for (const g of b.grants)
      t.assert(
        typeof g?.id === 'string' &&
          typeof g.client === 'string' &&
          Array.isArray(g.scopes) &&
          parseTimestamp(g.createdAt) !== null,
        'malformed grant',
      );
    t.assert(b.recovery === null, 'a fresh account has a pending recovery');
  },
);

def(
  {
    id: 'account.unknown-grant',
    section: 'CLIENT ending a grant',
    level: 'must',
    title: 'Ending an unknown grant is 404 not_found',
    expected: '404 not_found for a grant that never existed',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('account');
    t.error(await a.call(t, 'DELETE', `/simon/grants/conformance-${ctx.runId}`), 404, 'not_found');
  },
);

def(
  {
    id: 'account.no-recovery',
    section: 'CLIENT cancelling a recovery',
    level: 'must',
    title: 'Cancelling without a pending recovery is 404 not_found',
    expected: '404 not_found for an agent-key cancellation on a fresh account',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('account');
    t.error(await a.call(t, 'POST', '/simon/recovery/cancel', '{}'), 404, 'not_found');
  },
);

def(
  {
    id: 'account.cancel-code-silence',
    section: 'CLIENT cancelling a recovery',
    level: 'must',
    title: 'A wrong cancel code reveals nothing about an address',
    expected:
      'byte-identical 422 wrong_code for a wrong code at an existing address and an address nobody holds, signed by an unknown key',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('account');
    const { TargetAgent } = await import('../agent.ts');
    const caller = TargetAgent.fresh(ctx.server);
    const answers = [];
    for (const address of [a.address, `conformance-missing-${ctx.runId}@${await ctx.domain()}`]) {
      const res = await caller.call(
        t,
        'POST',
        '/simon/recovery/cancel',
        JSON.stringify({ address, cancelCode: 'wrong-code' }),
      );
      t.error(res, 422, 'wrong_code');
      answers.push(res.text);
    }
    t.assert(answers[0] === answers[1], 'wrong cancel codes reveal whether the address exists');
  },
);
