/** The graph: submit your person's edges, remove one, and ask who your person knows. */
import { z } from 'zod';
import type { Ctx } from '../../../context.ts';
import type { Agent } from 'simon-server';
import { agent, defineRoute, type ApiRoute, type Caller } from '../../../http/route.ts';
import { spend } from '../../../lib/rate.ts';
import type { Directory } from '../index.ts';
import { edgeOwner } from '../people.ts';
import { Connection, EdgeId, EdgeIn } from '../schemas.ts';

export function graphRoutes(ctx: Ctx, d: Directory, reserved: Caller<Agent>): ApiRoute[] {
  const tag = 'Graph';
  return [
    defineRoute({
      method: 'PUT',
      path: '/api/edges',
      operationId: 'submitEdges',
      tag,
      summary: "Submit your person's relationship edges",
      description:
        'Principal-reserved. One strength per person, rated by your agent from its own mail, calendar and contacts with the rubric in skill/grade.js. Only the number, and a private note, reach this server. An agent speaking for no one writes its own.',
      caller: reserved,
      body: z.strictObject({ edges: z.array(EdgeIn).min(1).max(1000) }),
      response: z.object({
        results: z.array(
          z.object({
            id: EdgeId.nullable(),
            identifier: z.string(),
            strength: z.number().int(),
            status: z.enum(['stored', 'skipped_self']),
          }),
        ),
      }),
      async handle({ caller, body, api }) {
        await spend(api, 'directoryWrites', ctx.config.rates.directoryWrites, caller.address);
        const { principal, identifier } = await d.people.actor(caller);
        return {
          results: await d.graph.submit(caller.address, { from: principal, principal: identifier }, body.edges),
        };
      },
    }),
    defineRoute({
      method: 'DELETE',
      path: '/api/edges/:edgeId',
      operationId: 'deleteEdge',
      tag,
      summary: "Remove one of your person's edges",
      description: 'Principal-reserved.',
      caller: reserved,
      params: z.object({ edgeId: EdgeId }),
      status: 204,
      handle: async ({ caller, params }) => d.graph.remove(edgeOwner(await d.people.actor(caller)), params.edgeId),
    }),
    defineRoute({
      method: 'POST',
      path: '/api/graph',
      operationId: 'searchConnections',
      tag,
      summary: 'Who does your person know?',
      description: `Your person's own edges joined to what you may see of each person: "who do I know at Example".`,
      caller: agent,
      body: z.strictObject({
        company: z.array(z.string().max(200)).max(10).optional(),
        text: z.string().max(100).optional(),
        minStrength: z.number().int().min(1).max(5).optional(),
        limit: z.number().int().min(1).max(200).default(50),
      }),
      response: z.object({ connections: z.array(Connection) }),
      async handle({ caller, body, api }) {
        await spend(api, 'discovery', ctx.config.rates.discovery, caller.address);
        const owner = edgeOwner(await d.people.actor(caller));
        const entities = body.company?.length ? await d.entities.named(body.company, 'company') : undefined;
        if (entities && !entities.length) return { connections: [] };
        return {
          connections: await d.graph.connections(owner, {
            entities,
            text: body.text,
            minStrength: body.minStrength,
            limit: body.limit,
          }),
        };
      },
    }),
  ];
}
