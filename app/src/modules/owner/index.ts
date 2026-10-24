/**
 * The owner window: a person signs in (OAuth 2.1, oauth.ts) and reads and overrides what their agents do
 * as them (`/api/me`), and decides what their agents ask that is theirs to decide (requests.ts). The
 * activity log (activity.ts) it reads is written by every module.
 *
 * Hooks: on.stored and on.inbox, so messages a person's agents sent and received are in their log.
 */
import { z } from 'zod';
import type { Ctx, Module } from '../../context.ts';
import type { Codes } from '../../lib/codes.ts';
import type { Caller } from '../../http/route.ts';
import type { CardStore } from '../agents/cards.ts';
import type { Directory } from '../directory/index.ts';
import type { Intros } from '../intros/intros.ts';
import type { Policy } from '../policy/policy.ts';
import { webhookRoutes, type Webhooks } from '../webhooks/index.ts';
import type { ActivityLog } from './activity.ts';
import { OAuth, type Session } from './oauth.ts';
import type { Requests } from './requests.ts';
import { controlRoutes } from './routes/controls.ts';
import { meRoutes } from './routes/me.ts';
import { oauthRoutes } from './routes/oauth.ts';
import { requestRoutes } from './routes/requests.ts';
import { mongoOwner } from './store.ts';

export function ownerModule(
  ctx: Ctx,
  deps: {
    directory: Directory;
    activity: ActivityLog;
    codes: Codes;
    cards: CardStore;
    requests: Requests;
    policy: Policy | null;
    intros: Intros | null;
    webhooks: Webhooks | null;
  },
): { module: Module } {
  const { directory: d, activity, webhooks, requests } = deps;
  const store = mongoOwner(ctx.db);
  const oauth = new OAuth(ctx, store, d.people, deps.codes, activity);
  const owner: Caller<Session> = { scheme: 'ownerBearer', resolve: req => oauth.authenticate(req) };
  d.people.onMerge(async (from, to) => {
    await store.reassign(from, to);
    await activity.reassign(from, to);
    await webhooks?.reassign(from, to);
  });
  requests.onHeld(async request => {
    const person = await d.people.forPrincipal(request.principal);
    if (person) await activity.record(person._id, 'request_waiting', { agent: request.agent, request: request._id });
  });
  const origin = ctx.config.server.origin;
  return {
    module: {
      name: 'owner',
      routes: [
        ...oauthRoutes(ctx, oauth),
        ...meRoutes({ ctx, owner, d, cards: deps.cards, codes: deps.codes, activity, oauth }),
        ...controlRoutes({ owner, d, policy: deps.policy, intros: deps.intros, oauth }),
        ...requestRoutes(requests, owner),
        ...(webhooks
          ? webhookRoutes(webhooks, {
              prefix: '/api/me',
              tag: 'Owner',
              caller: owner,
              writer: owner,
              owner: s => s.person._id,
              scope: s => s.identifiers,
              ids: 'My',
            })
          : []),
      ],
      hooks: {
        on: {
          stored: ({ message }) =>
            message.carrier === origin
              ? activity.messageEvent(d.people, message.message.from, message, 'message_sent')
              : undefined,
          inbox: ({ address, message }) => activity.messageEvent(d.people, address, message, 'message_received'),
        },
      },
      async init() {
        await store.init();
        await activity.init();
        await requests.init();
      },
      async work() {
        const pruned = await store.prune(new Date(ctx.now().getTime() - 86_400_000));
        return pruned + (await requests.work());
      },
      forget: {
        agent: address => requests.forgetAgent(address),
        async person(id) {
          await store.forget(id);
          await activity.forget(id);
        },
      },
      home: {
        fields: { requestsWaiting: z.number().int() },
        async build(address) {
          const waiting = await requests.waiting(address);
          const attention = waiting
            ? [{ kind: 'requests_waiting', message: `${waiting} request(s) of yours wait for your person to decide.` }]
            : [];
          return { fields: { requestsWaiting: waiting }, attention };
        },
      },
    },
  };
}
