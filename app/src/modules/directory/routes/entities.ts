/** Entities: find or name one, read it, claim it by DNS, name it, and attest who works there. */
import { z } from 'zod';
import type { Ctx } from '../../../context.ts';
import type { Agent } from '@agnt-protocol/server';
import { agent, anyone, defineRoute, type ApiRoute, type Caller } from '../../../http/route.ts';
import { spend } from '../../../lib/rate.ts';
import { entityView } from '../entities.ts';
import type { Directory } from '../index.ts';
import { Entity, EntityId, Principal } from '../schemas.ts';
import { ENTITY_KINDS } from '../vocab.ts';

export function entityRoutes(ctx: Ctx, d: Directory, reserved: Caller<Agent>): ApiRoute[] {
  const tag = 'Entities';
  const Id = z.object({ entityId: EntityId });
  return [
    defineRoute({
      method: 'POST',
      path: '/api/entities/resolve',
      operationId: 'resolveEntity',
      tag,
      summary: 'Find or create a company, school or organisation',
      description: 'By domain (consumer mail domains are refused), or by exact name for one with no domain.',
      caller: agent,
      body: z.strictObject({
        domain: z.string().max(253).optional(),
        name: z.string().max(200).optional(),
        kind: z.enum(ENTITY_KINDS).optional(),
      }),
      response: Entity,
      handle: async ({ body }) => entityView(await d.entities.findOrCreate(body)),
    }),
    defineRoute({
      method: 'GET',
      path: '/api/entities/:entityId',
      operationId: 'getEntity',
      tag,
      summary: 'Read an entity',
      caller: anyone,
      params: Id,
      response: Entity,
      handle: async ({ params }) => entityView(await d.entities.get(params.entityId)),
    }),
    defineRoute({
      method: 'POST',
      path: '/api/entities/:entityId/claim',
      operationId: 'startEntityClaim',
      tag,
      summary: 'Start claiming an entity for your person: a DNS TXT record to publish',
      caller: agent,
      params: Id,
      body: z.strictObject({ domain: z.string().max(253) }),
      response: z.object({ record: z.string(), type: z.literal('TXT'), value: z.string() }),
      handle: async ({ caller, params, body }) =>
        d.entities.startClaim((await d.people.personOf(caller)).person, params.entityId, body.domain),
    }),
    defineRoute({
      method: 'POST',
      path: '/api/entities/:entityId/claim/complete',
      operationId: 'completeEntityClaim',
      tag,
      summary: 'Finish claiming an entity, once the TXT record is published',
      caller: agent,
      params: Id,
      response: Entity,
      async handle({ caller, params }) {
        const { person } = await d.people.personOf(caller);
        return entityView(await d.entities.completeClaim(person, caller.address, params.entityId));
      },
    }),
    defineRoute({
      method: 'PATCH',
      path: '/api/entities/:entityId',
      operationId: 'renameEntity',
      tag,
      summary: 'Name a claimed entity: its display name and aliases, which search matches',
      caller: agent,
      params: Id,
      body: z.strictObject({
        name: z.string().min(1).max(200).optional(),
        aliases: z.array(z.string().max(200)).max(20).optional(),
      }),
      response: Entity,
      handle: async ({ caller, params, body }) =>
        entityView(await d.entities.rename((await d.people.personOf(caller)).person, params.entityId, body)),
    }),
    defineRoute({
      method: 'POST',
      path: '/api/entities/:entityId/roster',
      operationId: 'attestRoster',
      tag,
      summary: 'Attest who works at a claimed entity',
      description: 'Principal-reserved. Each member confirms their own affiliation before anyone else sees it.',
      caller: reserved,
      params: Id,
      body: z.strictObject({
        members: z
          .array(
            z.strictObject({
              identifier: Principal,
              title: z.string().max(200).nullable().optional(),
              start: z.string().max(20).nullable().optional(),
              end: z.string().max(20).nullable().optional(),
            }),
          )
          .min(1)
          .max(500),
      }),
      response: z.object({ attested: z.number().int() }),
      async handle({ caller, params, body, api }) {
        await spend(api, 'directoryWrites', ctx.config.rates.directoryWrites, caller.address);
        const { person, pairing } = await d.people.personOf(caller);
        const members = body.members;
        return {
          attested: await d.entities.attestRoster(person, caller.address, pairing.principal, params.entityId, members),
        };
      },
    }),
  ];
}
