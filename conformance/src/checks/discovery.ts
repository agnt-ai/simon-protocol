/** The discovery profile: lookups answer a signed asker, and tell nothing about who is not there. */
import type { Ctx } from '../context.ts';
import type { T } from '../harness.ts';
import { def } from './common.ts';

const S = 'discovery profile, section 2';
const target = (identifier: string) => `/simon/lookup?identifier=${encodeURIComponent(identifier)}`;

/**
 * The profile is optional: a server that answers lookups says so with `discovery` in its server document, and
 * its checks are skipped for one that does not.
 */
async function answersLookups(t: T, ctx: Ctx) {
  const { doc } = await ctx.serverDoc();
  if (!doc.discovery) t.skip('the server document does not say discovery (the discovery profile is optional)');
}

const unsignedLookup = (t: T, ctx: Ctx) =>
  t.http({ method: 'GET', origin: ctx.origin, target: target(`mailto:${ctx.runId}@example.org`) });

def(
  {
    id: 'discovery.signed',
    section: S,
    level: 'must',
    title: 'A lookup answers only an agent that signs it',
    expected: '401 for an unsigned GET /simon/lookup?identifier=<identifier>',
  },
  async (t: T, ctx: Ctx) => {
    await answersLookups(t, ctx);
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
    await answersLookups(t, ctx);
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
