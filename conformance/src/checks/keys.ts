/** CLIENT device labels and revocation, without imposing host key-ranking policy. */
import { addKeyProofString, parseTimestamp, sign } from '@agnt-protocol/protocol';
import { TargetAgent } from '../agent.ts';
import type { Ctx } from '../context.ts';
import type { T } from '../harness.ts';
import { agentDocument, def } from './common.ts';

const add = (t: T, a: TargetAgent, key: TargetAgent, label: string) =>
  a.call(
    t,
    'POST',
    '/simon/keys',
    JSON.stringify({ key: key.token, proof: sign(key.key, addKeyProofString(a.address, key.token)), label }),
  );

def(
  {
    id: 'keys.labels',
    section: 'CLIENT adding a key',
    level: 'must',
    title: 'A device label is private to the account and bounded to 64 characters',
    expected: 'a 64-character label appears in the account but not the public document; 65 characters is 400 invalid',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('labelled-keys');
    const k = TargetAgent.fresh(ctx.server);
    const label = '📱'.repeat(64);
    t.error(await add(t, a, k, label + 'x'), 400, 'invalid', '65-character label');
    const res = await add(t, a, k, label);
    t.status(res, 200);
    t.assert(
      res.json?.keys?.some((e: { key: string; label?: string }) => e.key === k.token && e.label === label),
      'account omits the device label',
    );
    const { res: doc } = await agentDocument(t, ctx, a.address);
    t.status(doc, 200);
    t.assert(!doc.json?.keys?.some((e: object) => 'label' in e), 'the public document exposes a device label');
  },
);

def(
  {
    id: 'keys.unknown',
    section: 'CLIENT revoking a key',
    level: 'must',
    title: 'An unknown key cannot be revoked',
    expected: '404 not_found for a key the agent never held',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('account');
    t.error(
      await a.call(t, 'DELETE', `/simon/keys/${encodeURIComponent(TargetAgent.fresh(ctx.server).token)}`),
      404,
      'not_found',
    );
  },
);

def(
  {
    id: 'keys.revoke',
    section: 'CLIENT revoking a key',
    level: 'must',
    title: 'Revocation ends a key at the time of the call, and a revoked key never returns',
    expected:
      '200 account marking a second key revoked now, 401 key_revoked when it signs, 404 on repeated revocation and 409 key_in_use on re-adding; host policy may refuse revocation',
  },
  async (t: T, ctx: Ctx) => {
    const a = await ctx.agent('revoke-keys');
    const k = TargetAgent.fresh(ctx.server);
    t.status(await add(t, a, k, 'Revoked device'), 200);
    const before = ctx.now();
    const target = `/simon/keys/${encodeURIComponent(k.token)}`;
    const res = await a.call(t, 'DELETE', target);
    if (res.status === 409) {
      t.assert(
        ['key_senior', 'last_key'].includes(res.json?.code),
        'revocation refused without a documented policy code',
      );
      t.skip('host key policy refuses this revocation');
    }
    t.status(res, 200);
    const entry = res.json?.keys?.find((e: { key: string }) => e.key === k.token);
    const at = parseTimestamp(entry?.revoked);
    t.assert(at !== null && at >= before - 1000 && at <= ctx.now() + 1000, 'revoked is not the time of the call');
    t.error(await a.call(t, 'GET', '/simon/account', undefined, { key: k.key }), 401, 'key_revoked');
    t.error(await a.call(t, 'DELETE', target), 404, 'not_found');
    t.error(await add(t, a, k, 'Revoked device'), 409, 'key_in_use');
    t.assert(res.json.address === a.address && Array.isArray(res.json.grants), 'revocation did not answer the account');
  },
);
