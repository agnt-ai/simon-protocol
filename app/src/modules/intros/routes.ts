/** Introductions, for agents: ask for one, see one, carry or decline, accept or decline, list your own. */
import { z } from 'zod';
import type { Ctx } from '../../context.ts';
import { notFound } from '../../lib/errors.ts';
import { spend } from '../../lib/rate.ts';
import { pageOf } from '../../store/db.ts';
import type { Agent } from '@agnt-sdk/simon-server';
import { agent, defineRoute, Paged, PageQuery, type ApiRoute, type Caller } from '../../http/route.ts';
import { idPattern } from '../../lib/ids.ts';
import { Principal } from '../directory/schemas.ts';
import type { Directory } from '../directory/index.ts';
import { requesterView, type Intros } from './intros.ts';

const IntroId = z.object({ introId: z.string().regex(idPattern('intro')) });

const Requester = z.object({
  person: z.string(),
  agent: z.string(),
  name: z.string().nullable(),
  identifier: z.string().nullable(),
});

export const RequesterIntro = z
  .object({
    id: z.string(),
    target: z.string(),
    subject: z.string(),
    state: z.enum(['submitted', 'introduced', 'expired']),
    introducedTo: z.string().nullable(),
    expiresAt: z.string(),
    createdAt: z.string(),
  })
  .meta({
    id: 'RequesterIntro',
    description: 'All a requester ever sees: submitted, then the introduction or the expiry.',
  });

export const ParticipantIntro = z
  .discriminatedUnion('role', [
    z.object({
      id: z.string(),
      role: z.literal('carrier'),
      state: z.string(),
      subject: z.string(),
      brief: z.string(),
      target: z.string(),
      requester: Requester,
    }),
    z.object({
      id: z.string(),
      role: z.literal('target'),
      state: z.string(),
      subject: z.string(),
      brief: z.string(),
      introducedBy: z.string(),
      introducedTo: z.string().nullable(),
      requester: Requester,
    }),
  ])
  .meta({ id: 'ParticipantIntro', description: 'A request your person was asked to carry, or one carried to them.' });

export function introRoutes(ctx: Ctx, intros: Intros, d: Directory, reserved: Caller<Agent>): ApiRoute[] {
  const tag = 'Introductions';
  return [
    defineRoute({
      method: 'POST',
      path: '/api/intros',
      operationId: 'requestIntro',
      tag,
      summary: 'Ask for an introduction',
      description:
        'Write the brief for the person you want to meet. The request is routed later, sealed, through people your person knows. You hear nothing until it succeeds: then an `intro-made` notice names the target agent, which now takes your messages.',
      caller: agent,
      body: z.strictObject({
        target: Principal,
        brief: z.string().min(1).max(2000),
        subject: z.string().max(300).optional(),
        presentAs: Principal.optional(),
      }),
      status: 202,
      response: RequesterIntro,
      async handle({ caller, body, api }) {
        await spend(api, 'intros', ctx.config.rates.intros, caller.address);
        return intros.request(caller, body);
      },
    }),
    defineRoute({
      method: 'GET',
      path: '/api/intros',
      operationId: 'listIntros',
      tag,
      summary: 'Introductions this agent asked for',
      caller: agent,
      query: PageQuery,
      response: Paged(RequesterIntro),
      handle: async ({ caller, query, api }) =>
        pageOf(await intros.store.byRequesterAgent(caller.address, query), query, i => requesterView(i, api.now())),
    }),
    defineRoute({
      method: 'GET',
      path: '/api/intros/:introId',
      operationId: 'getIntro',
      tag,
      summary: 'One introduction request, as you may see it',
      caller: agent,
      params: IntroId,
      response: z.union([RequesterIntro, ParticipantIntro]),
      async handle({ caller, params, api }) {
        const i = await intros.store.get(params.introId);
        if (i?.requesterAgent === caller.address) return requesterView(i, api.now());
        const pairing = await d.people.pairingOf(caller);
        const view =
          i && pairing && (await intros.participantView(i, { person: pairing.person, agents: [caller.address] }));
        if (!view) throw notFound('intro');
        return view;
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/api/intros/:introId/carry',
      operationId: 'carryIntro',
      tag,
      summary: 'As an intermediary: carry or decline',
      description:
        "Principal-reserved: carrying is your person's consent to be named to the target, and to both sides if the introduction is made.",
      caller: reserved,
      params: IntroId,
      body: z.strictObject({ decision: z.enum(['carry', 'decline']) }),
      response: z.object({ id: z.string(), state: z.string() }),
      handle: ({ caller, params, body }) => intros.decideCarry(caller, params.introId, body.decision),
    }),
    defineRoute({
      method: 'POST',
      path: '/api/intros/:introId/respond',
      operationId: 'respondToIntro',
      tag,
      summary: 'As the target: accept or decline',
      description:
        "Principal-reserved: accepting puts the requester's agent on your allow list and tells you both. Declining is never reported to the requester.",
      caller: reserved,
      params: IntroId,
      body: z.strictObject({ decision: z.enum(['accept', 'decline']) }),
      response: z.object({ id: z.string(), state: z.string(), introducedTo: z.string().optional() }),
      handle: ({ caller, params, body }) => intros.decideTarget(caller, params.introId, body.decision),
    }),
  ];
}
