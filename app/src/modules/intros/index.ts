/** Introductions (intros.ts): double-blind, routed through the requester's own contacts. */
import type { Agent } from '@agnt-sdk/simon-server';
import { z } from 'zod';
import type { Activity, Ctx, Module } from '../../context.ts';
import type { Caller } from '../../http/route.ts';
import { retiredRef } from '../../lib/ids.ts';
import type { Directory } from '../directory/index.ts';
import type { Policy } from '../policy/policy.ts';
import { Intros, requesterView } from './intros.ts';
import { introRoutes, ParticipantIntro, RequesterIntro } from './routes.ts';
import { mongoIntros } from './store.ts';

export function introsModule(
  ctx: Ctx,
  deps: { directory: Directory; policy: Policy; activity: Activity; reserved: Caller<Agent> },
) {
  const store = mongoIntros(ctx.db);
  const intros = new Intros(ctx, store, deps.directory, deps.policy, deps.activity);
  deps.directory.people.onMerge((from, to) => store.reassign(from, to));
  const module: Module = {
    name: 'intros',
    routes: introRoutes(ctx, intros, deps.directory, deps.reserved),
    init: () => store.init(),
    work: () => intros.work(),
    forget: { person: id => store.forget(id), agent: address => store.renameAgent(address, retiredRef(address)) },
    home: {
      fields: { introsToAnswer: z.array(ParticipantIntro), introsMade: z.array(RequesterIntro) },
      async build(address) {
        const now = ctx.now();
        const agent = await ctx.api.store.agentByAddress(address);
        const pairing = agent && (await deps.directory.people.pairingOf(agent));
        const waiting = pairing
          ? [...(await store.pendingForCarrier(address, 20)), ...(await store.pendingForTarget(address, 20))]
          : [];
        const views = await Promise.all(
          waiting.map(i => intros.participantView(i, { person: pairing!.person, agents: [address] })),
        );
        const made = (await store.byRequesterAgent(address, { limit: 50 })).filter(
          i => i.state === 'accepted' && now.getTime() - i.introduced!.at.getTime() < 7 * 86_400_000,
        );
        const toAnswer = views.filter(v => v !== null);
        const attention = toAnswer.length
          ? [{ kind: 'intros_waiting', message: `${toAnswer.length} introduction request(s) wait on you.` }]
          : [];
        return { fields: { introsToAnswer: toAnswer, introsMade: made.map(i => requesterView(i, now)) }, attention };
      },
    },
  };
  return { module, intros };
}
