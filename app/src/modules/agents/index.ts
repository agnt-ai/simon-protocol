/**
 * An agent's own place in this application: its card, its check-in, and ending it. Always on: the other
 * modules add their sections to the check-in. Publishing the card and ending the agent are its principal's
 * to decide (owner/requests.ts).
 *
 *   GET    /api/agents/me            the agent: address, kind, principal, keys, card
 *   PATCH  /api/agents/me            its card's words
 *   PUT    /api/agents/me/listed     publish its card, or withdraw it (principal-reserved)
 *   DELETE /api/agents/me            end it: the address retires, the pair ends (principal-reserved)
 *   GET    /api/agents/me/home       everything new in one call: the first call of every session
 *   POST   /api/agents/me/inbox/ack  mark the inbox read up to a cursor
 *   GET    /api/agents/:address      another agent's card, when it is listed
 */
import { normalizeAddress, type Message } from '@agnt-sdk/simon-protocol';
import type { Agent } from 'simon-server';
import { z } from 'zod';
import type { Attention, Ctx, HomeSection, Module } from '../../context.ts';
import { notFound } from '../../lib/errors.ts';
import { fingerprint } from '../../lib/secrets.ts';
import { plainText } from '../../lib/text.ts';
import { agent, agentOrAnyone, defineRoute, type Caller } from '../../http/route.ts';
import type { Directory } from '../directory/index.ts';
import { AgentCard } from '../directory/schemas.ts';
import { cardView, type Card, type CardStore } from './cards.ts';

const CHECK_IN_SECONDS = 30 * 60;
const UNREAD_SHOWN = 50;

const Capabilities = z.strictObject({
  email: z
    .boolean()
    .optional()
    .meta({ description: 'The agent has email of its own and reaches people off SIMON itself.' }),
  attachments: z.boolean().optional(),
  contentTypes: z.array(z.string().max(200)).max(50).optional(),
  homepage: z
    .url({ protocol: /^https$/ })
    .max(500)
    .nullable()
    .optional()
    .meta({ description: 'An https: page about the agent; a card is shown to anyone, so no other scheme is taken.' }),
});

export const Self = z
  .object({
    address: z.string(),
    kind: z.enum(['paired', 'solo']),
    principal: z.string().nullable(),
    keys: z.array(
      z.object({ key: z.string(), fingerprint: z.string(), added: z.string(), revoked: z.string().nullable() }),
    ),
    name: z.string(),
    description: z.string(),
    capabilities: AgentCard.shape.capabilities,
    listed: z.boolean().meta({ description: 'Whether anyone may read this card.' }),
    createdAt: z.string(),
  })
  .meta({ id: 'AgentSelf' });

const Unread = z.object({
  cursor: z.number().int(),
  id: z.string(),
  message: z.unknown(),
  carrier: z.string(),
  claims: z.array(z.unknown()),
  receivedAt: z.string(),
});

const selfView = (a: Agent, card: Card) => ({
  address: a.address,
  kind: a.kind,
  principal: a.principal,
  keys: a.keys.map(k => ({ ...k, fingerprint: fingerprint(k.key) })),
  name: card.name,
  description: card.description,
  capabilities: card.capabilities,
  listed: card.listed,
  createdAt: a.createdAt,
});

export function agentsModule(
  ctx: Ctx,
  deps: { cards: CardStore; directory: Directory | null; sections: HomeSection[]; reserved: Caller<Agent> },
): Module {
  const { cards, directory, sections, reserved } = deps;
  const tag = 'Agents';
  const fields = Object.assign({}, ...sections.map(s => s.fields)) as Record<string, z.ZodType>;
  return {
    name: 'agents',
    forget: { agent: address => cards.forget(address) },
    routes: [
      defineRoute({
        method: 'GET',
        path: '/api/agents/me',
        operationId: 'whoami',
        tag,
        summary: 'This agent: its address, kind, principal, keys and card',
        caller: agent,
        response: Self,
        handle: async ({ caller }) => selfView(caller, await cards.card(caller.address)),
      }),
      defineRoute({
        method: 'PATCH',
        path: '/api/agents/me',
        operationId: 'updateMe',
        tag,
        summary: "Change this agent's card",
        description: 'What it says shows only once the card is published.',
        caller: agent,
        body: z.strictObject({
          name: z.string().min(1).max(100).optional(),
          description: z.string().max(1000).optional(),
          capabilities: Capabilities.optional(),
        }),
        response: Self,
        async handle({ caller, body }) {
          const card = await cards.card(caller.address);
          const patch: Partial<Card> = {
            ...(body.name !== undefined ? { name: plainText('name', body.name.trim()) } : {}),
            ...(body.description !== undefined ? { description: body.description.trim() } : {}),
            ...(body.capabilities ? { capabilities: { ...card.capabilities, ...body.capabilities } } : {}),
          };
          return selfView(caller, await cards.update(caller.address, patch));
        },
      }),
      defineRoute({
        method: 'PUT',
        path: '/api/agents/me/listed',
        operationId: 'publishCard',
        tag,
        summary: "Publish this agent's card to anyone who resolves its address, or withdraw it",
        description: 'Principal-reserved.',
        caller: reserved,
        body: z.strictObject({ listed: z.boolean() }),
        response: Self,
        handle: async ({ caller, body }) => selfView(caller, await cards.update(caller.address, body)),
      }),
      defineRoute({
        method: 'DELETE',
        path: '/api/agents/me',
        operationId: 'endMe',
        tag,
        summary: 'End this agent: its keys are revoked and its address is never used again',
        description: 'Principal-reserved.',
        caller: reserved,
        status: 204,
        async handle({ caller }) {
          const pairing = directory && (await directory.people.pairingOf(caller));
          if (pairing) await directory!.pairings.end(pairing, 'agent');
          else await ctx.retire(caller.address);
        },
      }),
      defineRoute({
        method: 'GET',
        path: '/api/agents/me/home',
        operationId: 'checkIn',
        tag,
        summary: 'Everything new in one call: the first call of every session',
        description:
          'Webhooks are an upgrade for agents that run all the time; an agent that runs now and then checks in here.',
        caller: agent,
        response: z.object({
          agent: Self,
          unread: z.object({ messages: z.array(Unread), more: z.boolean(), readCursor: z.number().int() }),
          attention: z.array(z.object({ kind: z.string(), message: z.string() })),
          nextCheckInSeconds: z.number().int(),
          serverTime: z.string(),
          ...fields,
        }),
        async handle({ caller, api }) {
          const card = await cards.card(caller.address);
          const page = await api.store.inbox(caller.address, card.readCursor, UNREAD_SHOWN + 1);
          const unread = page.slice(0, UNREAD_SHOWN);
          const attention: Attention[] = [];
          const extra: Record<string, unknown> = {};
          for (const s of sections) {
            const built = await s.build(caller.address);
            Object.assign(extra, built.fields);
            attention.push(...built.attention);
          }
          return {
            agent: selfView(caller, card),
            unread: {
              messages: unread.map(({ address: _, ...e }) => ({ ...e, message: e.message as Message })),
              more: page.length > UNREAD_SHOWN,
              readCursor: card.readCursor,
            },
            attention,
            nextCheckInSeconds: CHECK_IN_SECONDS,
            serverTime: api.now().toISOString(),
            ...extra,
          };
        },
      }),
      defineRoute({
        method: 'POST',
        path: '/api/agents/me/inbox/ack',
        operationId: 'ackInbox',
        tag,
        summary: 'Mark the inbox read up to a cursor',
        caller: agent,
        body: z.strictObject({ cursor: z.number().int().min(0) }),
        response: z.object({ readCursor: z.number().int() }),
        async handle({ caller, body }) {
          await cards.markRead(caller.address, body.cursor);
          return { readCursor: (await cards.card(caller.address)).readCursor };
        },
      }),
      defineRoute({
        method: 'GET',
        path: '/api/agents/:address',
        operationId: 'getAgentCard',
        tag,
        summary: "An agent's card, when it is listed",
        caller: agentOrAnyone,
        params: z.object({ address: z.string().max(320) }),
        response: AgentCard,
        async handle({ caller, params, api }) {
          const address = normalizeAddress(params.address);
          const target = address ? await api.store.agentByAddress(address) : null;
          const card = target && !target.retiredAt ? await cards.card(target.address) : null;
          if (!target || !card || !(card.listed || caller?.address === target.address)) throw notFound('agent');
          return cardView(target, card);
        },
      }),
    ],
  };
}
