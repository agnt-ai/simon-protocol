/** The discovery profile: lookups answer a signed asker, and tell nothing about who is not there. */
import type { Ctx } from '../context.ts';
import type { T } from '../harness.ts';
import { def } from './common.ts';

const S = 'discovery profile, section 2';
const target = (identifier: string) => `/simon/lookup?identifier=${encodeURIComponent(identifier)}`;

/**
 * An unsigned lookup, which a server that answers lookups refuses with 401. A plain 404 means it answers none:
 * the profile is optional, so its checks are then skipped.
 */
async function unsignedLookup(t: T, ctx: Ctx) {
  const res = await t.http({ method: 'GET', origin: ctx.origin, target: target(`mailto:${ctx.runId}@example.org`) });
  if (res.status === 404) t.skip('the server answers no lookups (the discovery profile is optional)');
  return res;
}

def(
  {
    id: 'discovery.signed',
    section: S,
    level: 'must',
    title: 'A lookup answers only an agent that signs it',
    expected: '401 for an unsigned GET /simon/lookup?identifier=<identifier>',
  },
  async (t: T, ctx: Ctx) => {
    t.status(await unsignedLookup(t, ctx), 401);
  },
);

def(
  {
    id: 'discovery.not-found',
    section: S,
    level: 'must',
    title: 'Every identifier without a record answers alike',
    expected:
      'byte-identical 404 not_found, signed, for an email address on the server\'s own domain nobody listed and for a phone number; 400 invalid with details.field "identifier" for a value that is not one',
  },
  async (t: T, ctx: Ctx) => {
    await unsignedLookup(t, ctx);
    const a = await ctx.agent('a');
    const mail = await a.call(
      t,
      'GET',
      target(`mailto:${ctx.runId}-nobody@${await ctx.domain()}`),
      undefined,
      {},
      'an address',
    );
    const phone = await a.call(t, 'GET', target('tel:+14155550123'), undefined, {}, 'a phone number');
    t.error(mail, 404, 'not_found', 'an address');
    t.assert(mail.text === phone.text, `the answers differ: ${mail.text} and ${phone.text}`);
    t.error(await a.call(t, 'GET', target('nobody'), undefined, {}, 'not an identifier'), 400, 'invalid', '', {
      field: 'identifier',
    });
  },
);
