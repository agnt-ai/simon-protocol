/** Profiles: read one, attest facts about someone, retract your own, dispose of those about your person. */
import { z } from 'zod';
import type { Ctx } from '../../../context.ts';
import { notFound } from '../../../lib/errors.ts';
import { clientKey, spend } from '../../../lib/rate.ts';
import type { Agent } from '@agnt-sdk/simon-server';
import { agentOrAnyone, defineRoute, type ApiRoute, type Caller } from '../../../http/route.ts';
import type { Directory } from '../index.ts';
import { AttestationId, AttestationIn, Disposal, PersonId, Principal, Profile } from '../schemas.ts';
import { DISPOSITIONS } from '../vocab.ts';

export function profileRoutes(ctx: Ctx, d: Directory, reserved: Caller<Agent>): ApiRoute[] {
  const tag = 'Profiles';
  const Id = z.object({ attestationId: AttestationId });
  return [
    defineRoute({
      method: 'GET',
      path: '/api/profiles/:personId',
      operationId: 'getProfile',
      tag,
      summary: 'Read a profile, at the tier its person allows you',
      description: 'Signed, it reads as the person the agent speaks for (or the agent itself); unsigned, as anyone.',
      caller: agentOrAnyone,
      params: z.object({ personId: PersonId }),
      response: Profile,
      async handle({ caller, params, req, api }) {
        if (caller) await spend(api, 'discovery', ctx.config.rates.discovery, caller.address);
        else await spend(api, 'publicReads', ctx.config.rates.publicReads, clientKey(req.ip));
        const reader = caller ? (await d.people.actor(caller)).principal : null;
        const subject = await d.people.live(params.personId);
        const profile = subject && (await d.profiles.read(subject, reader));
        if (!profile) throw notFound('profile');
        return profile;
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/api/profiles/attestations',
      operationId: 'attest',
      tag,
      summary: 'Attest facts about your person (self-reported) or, as a name, title or affiliation, anyone else',
      description:
        'Principal-reserved. Attestations stack; nothing is overwritten. About anyone else, they wait for their subject to confirm them, and until then are yours alone, used only for your own matching; unconfirmed after 90 days, they are gone.',
      caller: reserved,
      body: z.strictObject({
        subject: z.union([z.strictObject({ person: PersonId }), z.strictObject({ identifier: Principal })]),
        attestations: z.array(AttestationIn).min(1).max(100),
      }),
      status: 201,
      response: z.object({
        attestations: z.array(
          z.object({ id: AttestationId, subject: PersonId, field: z.string(), provenance: z.string() }),
        ),
      }),
      async handle({ caller, body, api }) {
        await spend(api, 'directoryWrites', ctx.config.rates.directoryWrites, caller.address);
        const written = await d.profiles.attest(
          caller.address,
          await d.people.actor(caller),
          body.subject,
          body.attestations,
        );
        return {
          attestations: written.map(a => ({ id: a._id, subject: a.subject, field: a.field, provenance: a.provenance })),
        };
      },
    }),
    defineRoute({
      method: 'DELETE',
      path: '/api/profiles/attestations/:attestationId',
      operationId: 'retractAttestation',
      tag,
      summary: 'Retract an attestation you made',
      description: 'Principal-reserved.',
      caller: reserved,
      params: Id,
      status: 204,
      handle: async ({ caller, params }) =>
        d.profiles.retract((await d.people.actor(caller)).principal, params.attestationId),
    }),
    defineRoute({
      method: 'PATCH',
      path: '/api/profiles/attestations/:attestationId',
      operationId: 'disposeAttestation',
      tag,
      summary: 'Confirm, hide or dispute an attestation about your person',
      description: 'Principal-reserved. Only a confirmed attestation by someone else is shown to anyone.',
      caller: reserved,
      params: Id,
      body: Disposal,
      response: z.object({ id: AttestationId, disposition: z.enum(DISPOSITIONS) }),
      async handle({ caller, params, body }) {
        const { person } = await d.people.personOf(caller);
        const a = await d.profiles.dispose(person._id, params.attestationId, body.disposition);
        return { id: a._id, disposition: a.disposition };
      },
    }),
  ];
}
