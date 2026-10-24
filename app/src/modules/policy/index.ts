/**
 * Recipient policy (policy.ts): allow and block lists, invites, the opt-in verified-human requirement, the
 * contact tiers of a recipient's person, and inbound limits.
 *
 * Hooks: admit; on.stored and on.inbox, to know who wrote to whom.
 */
import type { Agent } from 'simon-server';
import type { Ctx, Module } from '../../context.ts';
import type { Caller } from '../../http/route.ts';
import type { Directory } from '../directory/index.ts';
import { Policy } from './policy.ts';
import { policyRoutes } from './routes.ts';
import { mongoPolicy } from './store.ts';

export function policyModule(ctx: Ctx, deps: { directory: Directory | null; reserved: Caller<Agent> }) {
  const store = mongoPolicy(ctx.db);
  const policy = new Policy(ctx, store, deps.directory);
  const module: Module = {
    name: 'policy',
    routes: policyRoutes(policy, deps.reserved),
    hooks: {
      admit: arrival => policy.admit(arrival),
      on: {
        stored: ({ message }) =>
          message.carrier === ctx.config.server.origin
            ? policy.correspond(message.message.from, message.message.to, 'wrote')
            : undefined,
        inbox: ({ address, message }) => policy.correspond(address, [message.message.from], 'heard'),
      },
    },
    init: () => store.init(),
    work: () => policy.release(),
    forget: { agent: address => store.forgetAgent(address), person: id => store.forgetOwner(id) },
  };
  return { module, policy };
}
