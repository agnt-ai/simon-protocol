/** Discovery: resolve an identifier, search by facet and relationship, and ask whether someone is reachable. */
import { z } from 'zod';
import type { Ctx } from '../../../context.ts';
import { spend } from '../../../lib/rate.ts';
import { agent, defineRoute, type ApiRoute } from '../../../http/route.ts';
import type { Directory } from '../index.ts';
import { edgeOwner } from '../people.ts';
import { Fact, Note, PersonId, Principal, Profile, Relationship, ResolvedAgent } from '../schemas.ts';

export const Resolved = z
  .object({
    found: z.boolean(),
    person: PersonId.optional(),
    name: z.string().nullable().optional(),
    profile: Profile.nullable().optional(),
    relationship: Relationship.optional(),
    agents: z.array(ResolvedAgent).optional(),
  })
  .meta({ id: 'Resolved' });

export const SearchQuery = z.strictObject({
  company: z.array(z.string().max(200)).max(10).optional().meta({ description: 'Domains, entity ids or names.' }),
  school: z.array(z.string().max(200)).max(10).optional(),
  title: z.string().max(100).optional(),
  location: z.string().max(100).optional(),
  text: z.string().max(100).optional(),
  relation: z.enum(['self', 'connection', 'second_degree']).optional(),
  minStrength: z.number().int().min(1).max(5).optional(),
  limit: z.number().int().min(1).max(25).default(25),
});

export const SearchResults = z
  .object({
    results: z.array(
      z.object({
        person: PersonId,
        name: z.string().nullable(),
        matched: z.array(z.object({ field: z.string(), value: z.unknown(), provenance: z.string() })),
        facts: z.array(Fact),
        relationship: Relationship,
        yourNote: Note,
      }),
    ),
  })
  .meta({ id: 'SearchResults' });

export const Reach = z
  .object({
    reachable: z.boolean(),
    degree: z.union([z.literal(1), z.literal(2)]).nullable(),
    yourNote: Note,
  })
  .meta({ id: 'Reach' });

export function discoveryRoutes(ctx: Ctx, d: Directory): ApiRoute[] {
  const tag = 'Directory';
  /** Who a read runs as; every one counts against the agent's discovery limit. */
  const reader = async (caller: Parameters<typeof d.people.actor>[0]) => {
    await spend(ctx.api, 'discovery', ctx.config.rates.discovery, caller.address);
    return edgeOwner(await d.people.actor(caller));
  };
  return [
    defineRoute({
      method: 'POST',
      path: '/api/resolve',
      operationId: 'resolve',
      tag,
      summary: 'Resolve an identifier to a person, and the agents you may write to',
      description:
        "Only what the person's tiers let you see; anything else is `found: false`, the same as nobody. An unlisted person is found only by their connections.",
      caller: agent,
      body: z.strictObject({ identifier: Principal }),
      response: Resolved,
      handle: async ({ caller, body }) => d.discovery.resolve(await reader(caller), body.identifier),
    }),
    defineRoute({
      method: 'POST',
      path: '/api/search',
      operationId: 'searchPeople',
      tag,
      summary: 'Search listed people by facet and relationship',
      description:
        'Facets (company, school, title, location) and text, over profiles you may see. Turn a request into facets yourself: this server runs no model. `relation` and `minStrength` filter by relationship, with facets or alone.',
      caller: agent,
      body: SearchQuery,
      response: SearchResults,
      handle: async ({ caller, body }) => d.discovery.search(await reader(caller), body),
    }),
    defineRoute({
      method: 'POST',
      path: '/api/reach',
      operationId: 'canReach',
      tag,
      summary: 'Whether you may write to someone, and the degree your own edges reach them at',
      description: 'Never says whether an introduction could reach them, nor names an intermediary.',
      caller: agent,
      body: z.strictObject({ identifier: Principal }),
      response: Reach,
      handle: async ({ caller, body }) => d.discovery.reach(await reader(caller), body.identifier),
    }),
  ];
}
