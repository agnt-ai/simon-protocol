/**
 * The owner window, for a signed-in person (`/api/me`): who they are, their identifiers, their pairs, and
 * what their agents did. A session sees what belongs to the identifiers proven in it, and their several
 * agents (one pair per identifier) together. Erasing the person takes every identifier proven in the
 * session that erases them.
 */
import { z } from 'zod';
import type { Ctx } from '../../../context.ts';
import { defineRoute, Paged, PageQuery, type ApiRoute, type Caller } from '../../../http/route.ts';
import type { Codes } from '../../../lib/codes.ts';
import { conflict, forbidden, notFound } from '../../../lib/errors.ts';
import { masked } from '../../../lib/principals.ts';
import { pageOf } from '../../../store/db.ts';
import { cardView, type CardStore } from '../../agents/cards.ts';
import { pairView, type Directory } from '../../directory/index.ts';
import { AgentCard, Pair, PersonId, Principal, Profile } from '../../directory/schemas.ts';
import { markConsulted } from '../../nudge/index.ts';
import { ActivityEvent, eventView, type ActivityLog } from '../activity.ts';
import type { OAuth, Session } from '../oauth.ts';

const P = '/api/me';
const MERGE_MS = 15 * 60_000;

export const Me = z
  .object({
    person: PersonId,
    identifiers: z
      .array(z.object({ identifier: z.string(), verifiedAt: z.string() }))
      .meta({ description: 'The identifiers proven in this session.' }),
    profile: Profile,
  })
  .meta({ id: 'Me' });

export const MessageItem = z
  .object({
    id: z.string(),
    direction: z.enum(['sent', 'received']),
    agent: z.string(),
    message: z.unknown().nullable(),
    claims: z.array(z.unknown()),
    at: z.string(),
  })
  .meta({ id: 'OwnerMessage' });

export { AttestationView } from './controls.ts';
const Address = z.object({ address: z.string().max(320) });
const MessageId = z.object({ messageId: z.string().regex(/^[0-9a-f]{64}$/) });

export function meRoutes(o: {
  ctx: Ctx;
  owner: Caller<Session>;
  d: Directory;
  cards: CardStore;
  codes: Codes;
  activity: ActivityLog;
  oauth: OAuth;
}): ApiRoute[] {
  const { ctx, owner, d, cards, codes, activity, oauth } = o;
  const tag = 'Owner';
  const me = async (session: Session) => ({
    person: session.person._id,
    identifiers: (await d.people.store.identifiersOf([session.person._id]))
      .filter(i => session.identifiers.includes(i._id))
      .map(i => ({ identifier: i._id, verifiedAt: i.verifiedAt!.toISOString() })),
    profile: (await d.profiles.read(session.person, session.person._id, 'self'))!,
  });
  /** The session, now that it proved one more identifier. */
  const proven = async (session: Session, identifier: string): Promise<Session> => {
    await oauth.store.prove(session.id, identifier);
    const person = (await d.people.live(session.person._id))!;
    return { ...session, person, identifiers: [...new Set([...session.identifiers, identifier])] };
  };
  return [
    defineRoute({
      method: 'GET',
      path: P,
      operationId: 'getMe',
      tag,
      summary: 'Who I am here: the identifiers this session proved, and my profile',
      caller: owner,
      response: Me,
      handle: ({ caller }) => me(caller),
    }),
    defineRoute({
      method: 'DELETE',
      path: P,
      operationId: 'eraseMe',
      tag,
      summary:
        'Erase me: my identifiers, my agents, the graph to and from me, what was said by and about me, my introductions and my log',
      description:
        'Every agent that speaks for me retires. The session must have proven every identifier of mine here, since all of them go.',
      caller: owner,
      status: 204,
      async handle({ caller }) {
        const all = (await d.people.store.identifiersOf([caller.person._id])).map(i => i._id);
        const unproven = all.filter(i => !caller.identifiers.includes(i));
        if (unproven.length) {
          throw forbidden(
            'prove_every_identifier',
            'Erasing you erases every identifier of yours here; prove each first.',
            {
              unproven: unproven.map(masked),
            },
          );
        }
        for (const pair of await d.people.pairsOf(caller.person._id)) await ctx.retire(pair.address);
        await ctx.erase(caller.person._id);
      },
    }),
    defineRoute({
      method: 'POST',
      path: `${P}/identifiers`,
      operationId: 'addMyIdentifier',
      tag,
      summary: 'Prove an email address or phone number of mine: a code is sent there',
      caller: owner,
      body: z.strictObject({ identifier: Principal }),
      status: 202,
      response: z.object({ sentTo: z.string() }),
      async handle({ caller, body }) {
        await codes.send(
          body.identifier,
          'identifier',
          caller.id,
          code => ({
            subject: `Your AGNT code: ${code}`,
            text: `Someone signed in to AGNT asks to add this address as theirs. Your code is ${code}; it expires in 15 minutes. If it was not you, ignore this message.`,
            sms: `AGNT code ${code}, to add this number to an AGNT account. Ignore it if you did not ask.`,
          }),
          [`session:${caller.id}`, `person:${caller.person._id}`],
        );
        return { sentTo: masked(body.identifier) };
      },
    }),
    defineRoute({
      method: 'POST',
      path: `${P}/identifiers/verify`,
      operationId: 'verifyMyIdentifier',
      tag,
      summary: 'Hand back the code: the identifier is mine, and this session sees what is its',
      description:
        'When the identifier is already another person here, nothing joins yet: the answer is `409 merge_required`, and `POST /api/me/identifiers/merge` within 15 minutes joins them.',
      caller: owner,
      body: z.strictObject({ identifier: Principal, code: z.string().max(20) }),
      response: Me,
      async handle({ caller, body, api }) {
        await codes.check(body.identifier, 'identifier', caller.id, body.code.trim());
        if ((await d.people.prove(caller.person, body.identifier)) === 'merge_required') {
          const until = new Date(api.now().getTime() + MERGE_MS).toISOString();
          await api.store.setValue('owner-merge', `${caller.id}\n${body.identifier}`, true, until);
          throw conflict(
            'merge_required',
            'That identifier is someone else here, which this proof makes you too. Confirm to join the two.',
          );
        }
        return me(await proven(caller, body.identifier));
      },
    }),
    defineRoute({
      method: 'POST',
      path: `${P}/identifiers/merge`,
      operationId: 'mergeMyIdentifier',
      tag,
      summary: 'Confirm: the person an identifier just proven in this session belongs to is me',
      description: 'Their identifiers, agents, graph and log join mine. This session sees only what it proved.',
      caller: owner,
      body: z.strictObject({ identifier: Principal }),
      response: Me,
      async handle({ caller, body, api }) {
        const id = `${caller.id}\n${body.identifier}`;
        if (!(await api.store.value<boolean>('owner-merge', id, api.now().toISOString())))
          throw conflict('proof_required', 'Prove that identifier in this session first.');
        await api.store.setValue('owner-merge', id, null, api.now().toISOString());
        await d.people.merge(caller.person, body.identifier);
        return me(await proven(caller, body.identifier));
      },
    }),
    defineRoute({
      method: 'GET',
      path: `${P}/agents`,
      operationId: 'listMyAgents',
      tag,
      summary: 'The agents that speak for me now: one pair for each identifier and agent',
      caller: owner,
      query: PageQuery,
      response: Paged(z.object({ pair: Pair, agent: AgentCard })),
      async handle({ caller, query, api }) {
        const pairs = (await d.people.pairsOf(caller.person._id, caller.identifiers)).sort((a, b) =>
          a.address.localeCompare(b.address),
        );
        const after = pairs.filter(p => !query.after || p.address > query.after).slice(0, query.limit + 1);
        const items = await Promise.all(
          after.map(async p => ({
            _id: p.address,
            pair: pairView(p),
            agent: cardView((await api.store.agentByAddress(p.address))!, await cards.card(p.address)),
          })),
        );
        return pageOf(items, query, ({ pair, agent }) => ({ pair, agent }));
      },
    }),
    defineRoute({
      method: 'POST',
      path: `${P}/agents/:address/confirm`,
      operationId: 'confirmMyAgent',
      tag,
      summary: 'Confirm an agent that replaced its keys: it may do again all I allowed',
      caller: owner,
      params: Address,
      response: Pair,
      handle: async ({ caller, params }) =>
        pairView(
          await d.pairings.confirm(await d.people.pairOf(caller.person._id, params.address, caller.identifiers)),
        ),
    }),
    defineRoute({
      method: 'DELETE',
      path: `${P}/agents/:address`,
      operationId: 'endMyAgent',
      tag,
      summary: 'End an agent that speaks for me: its address retires',
      caller: owner,
      params: Address,
      status: 204,
      handle: async ({ caller, params }) =>
        d.pairings.end(await d.people.pairOf(caller.person._id, params.address, caller.identifiers), 'owner'),
    }),
    defineRoute({
      method: 'GET',
      path: `${P}/profiles/:personId`,
      operationId: 'getProfileAsMe',
      tag,
      summary: 'Read a profile as myself, at the tier its person allows me',
      caller: owner,
      params: z.object({ personId: PersonId }),
      response: Profile,
      async handle({ caller, params }) {
        const subject = await d.people.live(params.personId);
        const profile = subject && (await d.profiles.read(subject, caller.person._id));
        if (!profile) throw notFound('profile');
        return profile;
      },
    }),
    defineRoute({
      method: 'GET',
      path: `${P}/activity`,
      operationId: 'listMyActivity',
      tag,
      summary: 'Everything my agents did as me, oldest first',
      caller: owner,
      query: PageQuery,
      response: Paged(ActivityEvent),
      handle: async ({ caller, query }) =>
        pageOf(await activity.page(caller.person._id, caller.identifiers, query), query, eventView),
    }),
    defineRoute({
      method: 'GET',
      path: `${P}/messages`,
      operationId: 'listMyMessages',
      tag,
      summary: 'Messages my agents sent and received for me, oldest first',
      description: 'A message past its retention is listed without its body.',
      caller: owner,
      query: PageQuery,
      response: Paged(MessageItem),
      async handle({ caller, query, api }) {
        const entries = await activity.page(caller.person._id, caller.identifiers, query, [
          'message_sent',
          'message_received',
        ]);
        const records = new Map(
          await Promise.all(entries.map(async e => [e._id, await api.store.message(e.message!)] as const)),
        );
        return pageOf(entries, query, e => ({
          id: e.message!,
          direction: e.kind === 'message_sent' ? ('sent' as const) : ('received' as const),
          agent: e.agent!,
          message: records.get(e._id)?.message ?? null,
          claims: records.get(e._id)?.claims ?? [],
          at: e.at.toISOString(),
        }));
      },
    }),
    defineRoute({
      method: 'POST',
      path: `${P}/messages/:messageId/consulted`,
      operationId: 'markConsulted',
      tag,
      summary: 'I saw this thread up to this message: my agent may say a person was consulted when it answers',
      description:
        'The evidence behind a `human-consulted` header on the reply from my agent: without it, the header alone resets no agent-only run.',
      caller: owner,
      params: MessageId,
      status: 204,
      async handle({ caller, params, api }) {
        const record = await api.store.message(params.messageId);
        const m = record?.message;
        const mine = (await d.people.pairsOf(caller.person._id, caller.identifiers))
          .map(p => p.address)
          .filter(a => m && (m.from === a || m.to.includes(a)));
        if (!record || !mine.length) throw notFound('message');
        for (const address of mine) await markConsulted(api, address, record.id, record.expiresAt);
      },
    }),
  ];
}
