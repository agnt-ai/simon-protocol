/**
 * What a person controls in the owner window: who may reach them (held senders, their own blocks, their
 * listing), the marks their agents left (edges, attestations), introductions, and API keys. Their listing,
 * their blocks and what others say about them are the whole person's; the rest is shown only for the
 * identifiers the session proved.
 */
import { z } from 'zod';
import { defineRoute, Paged, PageQuery, type ApiRoute, type Caller } from '../../../http/route.ts';
import { pageOf } from '../../../store/db.ts';
import { edgeView } from '../../directory/graph.ts';
import type { Directory } from '../../directory/index.ts';
import { affiliationView } from '../../directory/profiles.ts';
import { listingView } from '../../directory/people.ts';
import { Disposal, Edge, EdgeId, Listing, ListingPatch } from '../../directory/schemas.ts';
import { DISPOSITIONS } from '../../directory/vocab.ts';
import type { EdgeOwner } from '../../directory/graph-store.ts';
import type { Affiliation, Attestation } from '../../directory/graph-store.ts';
import { requesterView, type Intros } from '../../intros/intros.ts';
import { ParticipantIntro, RequesterIntro } from '../../intros/routes.ts';
import type { Policy } from '../../policy/policy.ts';
import { EntriesIn, EntryParam, EntryView, entryView, HeldView, heldView, splitEntry } from '../../policy/routes.ts';
import { apiKeyView, type OAuth, type Session } from '../oauth.ts';

const P = '/api/me';

/** A page of records already in memory, in `_id` order. */
const pageIn = <T extends { _id: string }>(records: T[], page: { after?: string; limit: number }) =>
  records
    .filter(r => !page.after || r._id > page.after)
    .sort((a, b) => (a._id < b._id ? -1 : 1))
    .slice(0, page.limit + 1);

export const AttestationView = z
  .object({
    id: z.string(),
    subject: z.string(),
    field: z.string(),
    value: z.unknown(),
    author: z.object({ agent: z.string(), principal: z.string() }),
    provenance: z.string(),
    disposition: z.enum(DISPOSITIONS),
    createdAt: z.string(),
  })
  .meta({ id: 'AttestationView' });

/** The session's own edges: those its proven identifiers' agents wrote. */
const edgesOf = (s: Session): EdgeOwner => ({ from: s.person._id, principals: s.identifiers });

export function controlRoutes(o: {
  owner: Caller<Session>;
  d: Directory;
  policy: Policy | null;
  intros: Intros | null;
  oauth: OAuth;
}): ApiRoute[] {
  const { owner, d, policy, intros, oauth } = o;
  const tag = 'Owner';
  /** The agents speaking now for the identifiers the session proved. */
  const addresses = async (s: Session) => (await d.people.pairsOf(s.person._id, s.identifiers)).map(p => p.address);
  const routes: ApiRoute[] = [
    defineRoute({
      method: 'GET',
      path: `${P}/listing`,
      operationId: 'getMyListing',
      tag,
      summary: 'My listing in the directory',
      caller: owner,
      response: Listing,
      handle: async ({ caller }) => listingView(caller.person.listing),
    }),
    defineRoute({
      method: 'PATCH',
      path: `${P}/listing`,
      operationId: 'updateMyListing',
      tag,
      summary: 'Change my listing',
      caller: owner,
      body: ListingPatch,
      response: Listing,
      handle: async ({ caller, body }) => listingView((await d.people.updateListing(caller.person, body, {})).listing),
    }),
    defineRoute({
      method: 'GET',
      path: `${P}/edges`,
      operationId: 'listMyEdges',
      tag,
      summary: "My relationship marks, whichever of my identifiers' agents wrote them, hidden ones too",
      caller: owner,
      query: PageQuery,
      response: Paged(Edge),
      handle: async ({ caller, query }) => {
        const { from, principals } = edgesOf(caller);
        const edges = await d.graphStore.edges({ from: [from], principals, includeHidden: true });
        return pageOf(pageIn(edges, query), query, edgeView);
      },
    }),
    defineRoute({
      method: 'PATCH',
      path: `${P}/edges/:edgeId`,
      operationId: 'updateMyEdge',
      tag,
      summary: 'Hide an edge, or stop it carrying introductions',
      caller: owner,
      params: z.object({ edgeId: EdgeId }),
      body: z.strictObject({ hidden: z.boolean().optional(), introduceOk: z.boolean().optional() }),
      response: Edge,
      handle: async ({ caller, params, body }) => edgeView(await d.graph.change(edgesOf(caller), params.edgeId, body)),
    }),
    defineRoute({
      method: 'DELETE',
      path: `${P}/edges/:edgeId`,
      operationId: 'deleteMyEdge',
      tag,
      summary: 'Remove an edge',
      caller: owner,
      params: z.object({ edgeId: EdgeId }),
      status: 204,
      handle: ({ caller, params }) => d.graph.remove(edgesOf(caller), params.edgeId),
    }),
    defineRoute({
      method: 'DELETE',
      path: `${P}/edges`,
      operationId: 'clearMyEdges',
      tag,
      summary: 'Clear stale marks: every edge one agent wrote last, and/or every edge not rewritten since a time',
      description: 'Ending an agent removes none of its marks; this is how they go.',
      caller: owner,
      query: z.object({ writtenBy: z.string().max(320).optional(), before: z.iso.datetime().optional() }),
      response: z.object({ removed: z.number().int() }),
      handle: async ({ caller, query }) => ({
        removed: await d.graph.clear(edgesOf(caller), {
          writtenBy: query.writtenBy,
          before: query.before ? new Date(query.before) : undefined,
        }),
      }),
    }),
    defineRoute({
      method: 'GET',
      path: `${P}/attestations`,
      operationId: 'listMyAttestations',
      tag,
      summary: 'Attestations about me, or those my agents made',
      caller: owner,
      query: PageQuery.extend({ which: z.enum(['about', 'by']).default('about') }),
      response: Paged(AttestationView),
      async handle({ caller, query }) {
        const found =
          query.which === 'about'
            ? await d.graphStore.attestations({ subjects: [caller.person._id] })
            : (await d.graphStore.attestations({ authorPrincipal: caller.person._id })).filter(a =>
                caller.identifiers.includes(a.authorIdentifier),
              );
        const page = pageIn(found, query);
        const entities = await d.profiles.entitiesOf(page);
        return pageOf(page, query, (a: Attestation) => ({
          id: a._id,
          subject: a.subject,
          field: a.field,
          value: a.field === 'affiliation' ? affiliationView(a.value as Affiliation, entities) : a.value,
          author: { agent: a.authorAgent, principal: a.authorPrincipal },
          provenance: a.provenance,
          disposition: a.disposition,
          createdAt: a.createdAt.toISOString(),
        }));
      },
    }),
    defineRoute({
      method: 'PATCH',
      path: `${P}/attestations/:attestationId`,
      operationId: 'disposeMyAttestation',
      tag,
      summary: 'Confirm, hide or dispute an attestation about me',
      description: 'What others say about me is shown to anyone only once I confirm it.',
      caller: owner,
      params: z.object({ attestationId: z.string().max(40) }),
      body: Disposal,
      response: z.object({ id: z.string(), disposition: z.enum(DISPOSITIONS) }),
      async handle({ caller, params, body }) {
        const a = await d.profiles.dispose(caller.person._id, params.attestationId, body.disposition);
        return { id: a._id, disposition: a.disposition };
      },
    }),
    defineRoute({
      method: 'GET',
      path: `${P}/api-keys`,
      operationId: 'listMyApiKeys',
      tag,
      summary: 'My API keys that hold nothing this session did not prove',
      caller: owner,
      query: PageQuery,
      response: Paged(z.object({ id: z.string(), label: z.string().nullable(), createdAt: z.string() })),
      handle: async ({ caller, query }) => pageOf(pageIn(await oauth.apiKeys(caller), query), query, apiKeyView),
    }),
    defineRoute({
      method: 'POST',
      path: `${P}/api-keys`,
      operationId: 'createMyApiKey',
      tag,
      summary: 'Make an API key for scripts, holding what this session proved; it is shown once',
      caller: owner,
      body: z.strictObject({ label: z.string().max(100).optional() }),
      status: 201,
      response: z.object({ id: z.string(), key: z.string(), label: z.string().nullable(), createdAt: z.string() }),
      handle: ({ caller, body }) => oauth.createApiKey(caller, body.label ?? null),
    }),
    defineRoute({
      method: 'DELETE',
      path: `${P}/api-keys/:keyId`,
      operationId: 'revokeMyApiKey',
      tag,
      summary: 'Revoke an API key',
      caller: owner,
      params: z.object({ keyId: z.string().max(40) }),
      status: 204,
      handle: ({ caller, params }) => oauth.revokeApiKey(caller, params.keyId),
    }),
  ];
  if (policy) {
    routes.push(
      defineRoute({
        method: 'GET',
        path: `${P}/held`,
        operationId: 'listMyHeld',
        tag,
        summary: "Who my agents' policies held back, and how often",
        description: 'Nothing they sent was delivered. Allow them, or widen a policy, to hear from them.',
        caller: owner,
        query: PageQuery,
        response: Paged(HeldView),
        handle: async ({ caller, query }) =>
          pageOf(await policy.store.held(await addresses(caller), query), query, heldView),
      }),
      defineRoute({
        method: 'GET',
        path: `${P}/blocks`,
        operationId: 'listMyBlocks',
        tag,
        summary: 'My blocks, which every agent speaking for me keeps, now and later',
        caller: owner,
        query: PageQuery,
        response: Paged(EntryView),
        handle: async ({ caller, query }) =>
          pageOf(await policy.store.entries(caller.person._id, 'block', query), query, entryView),
      }),
      defineRoute({
        method: 'POST',
        path: `${P}/blocks`,
        operationId: 'blockSenders',
        tag,
        summary: 'Block senders, domains or servers on every agent that speaks for me',
        caller: owner,
        body: EntriesIn,
        response: z.object({ added: z.number().int() }),
        async handle({ caller, body }) {
          const added = await policy.addEntries(caller.person._id, 'block', body.entries, 'owner');
          return { added };
        },
      }),
      defineRoute({
        method: 'DELETE',
        path: `${P}/blocks/:entry`,
        operationId: 'unblock',
        tag,
        summary: 'Remove one of my blocks',
        caller: owner,
        params: EntryParam,
        status: 204,
        handle: async ({ caller, params }) => {
          const { kind, value } = splitEntry(params.entry);
          await policy.removeEntry(caller.person._id, 'block', kind, value);
        },
      }),
    );
  }
  if (intros) {
    routes.push(
      defineRoute({
        method: 'GET',
        path: `${P}/intros`,
        operationId: 'listMyIntros',
        tag,
        summary: 'Introductions my agents asked for (with the brief), were asked to carry, or received',
        caller: owner,
        query: PageQuery,
        response: Paged(
          z.union([RequesterIntro.extend({ role: z.literal('requester'), brief: z.string() }), ParticipantIntro]),
        ),
        async handle({ caller, query, api }) {
          const person = caller.person._id;
          const mine = new Set(await addresses(caller));
          const page = await intros.store.involving(person, query);
          const views = await Promise.all(
            page.map(async i => ({
              _id: i._id,
              view:
                i.requesterPerson === person
                  ? mine.has(i.requesterAgent)
                    ? { role: 'requester' as const, ...requesterView(i, api.now()), brief: i.brief }
                    : null
                  : await intros.participantView(i, { person, agents: [...mine] }),
            })),
          );
          // The store found what involves the person; a view is null for a carrier never told, or for
          // what only agents of identifiers this session did not prove took part in.
          const shown = { ...pageOf(views, query, x => x.view) };
          return { ...shown, items: shown.items.filter(v => v !== null) };
        },
      }),
    );
  }
  return routes;
}
