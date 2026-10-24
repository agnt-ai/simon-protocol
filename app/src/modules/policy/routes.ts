/** An agent's own policy: its settings, its allow and block lists, invites, and who was held. */
import { z } from 'zod';
import { pageOf } from '../../store/db.ts';
import type { Agent } from 'simon-server';
import { agent, defineRoute, Paged, PageQuery, type ApiRoute, type Caller } from '../../http/route.ts';
import type { Policy } from './policy.ts';
import type { Entry, Held } from './store.ts';

const P = '/api/agents/me';
const Kind = z.enum(['address', 'domain', 'server']);
const ListParam = z.object({ list: z.enum(['allow', 'block']) });

export const Settings = z
  .object({
    accept: z
      .enum(['anyone', 'known'])
      .meta({ description: '`known`: only invites, the allow list and correspondents.' }),
    requireVerifiedHuman: z
      .boolean()
      .meta({ description: 'Refuse senders no verified principal stands behind. Off by default.' }),
  })
  .meta({ id: 'PolicySettings' });

export const EntryView = z
  .object({ kind: Kind, value: z.string(), source: z.string(), createdAt: z.string() })
  .meta({ id: 'ListEntry', description: 'One entry of an allow or block list; `source` says who wrote it.' });

export const HeldView = z
  .object({
    agent: z.string(),
    sender: z.string(),
    for: z.string().nullable(),
    count: z.number().int(),
    firstAt: z.string(),
    lastAt: z.string(),
  })
  .meta({ id: 'Held', description: 'A sender a policy held back, and how often. Nothing it sent was delivered.' });

export const EntriesIn = z.strictObject({
  entries: z
    .array(z.strictObject({ kind: Kind, value: z.string().min(1).max(300) }))
    .min(1)
    .max(500),
});

export const entryView = (e: Entry) => ({
  kind: e.kind,
  value: e.value,
  source: e.source,
  createdAt: e.createdAt.toISOString(),
});
export const heldView = (h: Held) => ({
  agent: h.agent,
  sender: h.sender,
  for: h.for,
  count: h.count,
  firstAt: h.firstAt.toISOString(),
  lastAt: h.lastAt.toISOString(),
});

/** An entry in a path: `<kind>:<value>`, such as `domain:example.com`. */
export const EntryParam = z.object({
  entry: z
    .string()
    .max(320)
    .regex(/^(address|domain|server):.+$/)
    .meta({ description: '`<kind>:<value>`, such as `domain:example.com`.' }),
});
export const splitEntry = (entry: string) => {
  const at = entry.indexOf(':');
  return { kind: entry.slice(0, at) as Entry['kind'], value: entry.slice(at + 1) };
};

/** Reading an agent's policy takes its key; changing it is principal-reserved (owner/requests.ts). */
export function policyRoutes(policy: Policy, reserved: Caller<Agent>): ApiRoute[] {
  const tag = 'Policy';
  return [
    defineRoute({
      method: 'GET',
      path: `${P}/policy`,
      operationId: 'getPolicy',
      tag,
      summary: "This agent's policy settings",
      caller: agent,
      response: Settings,
      handle: async ({ caller }) => {
        const { accept, requireVerifiedHuman } = await policy.store.settings(caller.address);
        return { accept, requireVerifiedHuman };
      },
    }),
    defineRoute({
      method: 'PATCH',
      path: `${P}/policy`,
      operationId: 'updatePolicy',
      tag,
      summary: "Change this agent's policy settings",
      description: 'Principal-reserved.',
      caller: reserved,
      body: z.strictObject({
        accept: z.enum(['anyone', 'known']).optional(),
        requireVerifiedHuman: z.boolean().optional(),
      }),
      response: Settings,
      handle: async ({ caller, body }) => {
        const { accept, requireVerifiedHuman } = await policy.store.setSettings(caller.address, body);
        return { accept, requireVerifiedHuman };
      },
    }),
    defineRoute({
      method: 'GET',
      path: `${P}/contacts/:list`,
      operationId: 'listContacts',
      tag,
      summary: 'The allow or block list',
      caller: agent,
      params: ListParam,
      query: PageQuery,
      response: Paged(EntryView),
      handle: async ({ caller, params, query }) =>
        pageOf(await policy.store.entries(caller.address, params.list, query), query, entryView),
    }),
    defineRoute({
      method: 'POST',
      path: `${P}/contacts/:list`,
      operationId: 'addContacts',
      tag,
      summary: 'Add addresses, domains (with their subdomains) or servers to the allow or block list',
      description: 'Principal-reserved.',
      caller: reserved,
      params: ListParam,
      body: EntriesIn,
      response: z.object({ added: z.number().int() }),
      handle: async ({ caller, params, body }) => ({
        added: await policy.addEntries(caller.address, params.list, body.entries, 'agent'),
      }),
    }),
    defineRoute({
      method: 'DELETE',
      path: `${P}/contacts/:list/:entry`,
      operationId: 'removeContact',
      tag,
      summary: 'Remove one entry from the allow or block list',
      description: 'Principal-reserved.',
      caller: reserved,
      params: ListParam.extend(EntryParam.shape),
      status: 204,
      handle: async ({ caller, params }) => {
        const { kind, value } = splitEntry(params.entry);
        await policy.removeEntry(caller.address, params.list, kind, value);
      },
    }),
    defineRoute({
      method: 'POST',
      path: `${P}/invites`,
      operationId: 'issueInvite',
      tag,
      summary: 'A one-time code for someone this agent wants to hear from',
      description:
        'Principal-reserved. The sender passes it as a hint for this agent (`simon-hints: {"<this address>":{"invite":"<code>"}}` on /simon/send): it lets one message through, past everything but the block lists.',
      caller: reserved,
      body: z.strictObject({ ttlHours: z.number().int().min(1).max(720).default(168) }),
      status: 201,
      response: z.object({ code: z.string(), address: z.string(), expiresAt: z.string() }),
      handle: ({ caller, body }) => policy.invite(caller.address, body.ttlHours),
    }),
    defineRoute({
      method: 'GET',
      path: `${P}/held`,
      operationId: 'listHeld',
      tag,
      summary: "Senders this agent's policy held back, and how often",
      caller: agent,
      query: PageQuery,
      response: Paged(HeldView),
      handle: async ({ caller, query }) => pageOf(await policy.store.held([caller.address], query), query, heldView),
    }),
  ];
}
