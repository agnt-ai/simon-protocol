/**
 * The directory: people and their identifiers, pairing agents with email and phone principals, profiles
 * and entities, the relationship graph, and discovery. Other modules build on it: policy reads its contact
 * tiers, introductions route through its graph, the owner window shows a person their pairs.
 *
 * What it keeps, it keeps for a while: an edge nobody rewrites for a year, an attestation its subject
 * never confirmed for 90 days, and a person nobody claimed for 90 days, with everything said about them,
 * are gone. A retired agent leaves only a hash of its address on what outlives it.
 *
 * Hooks: verifyPrincipal and claimsFor (pairing), on.recovered (an agent recovered by its mailbox only
 * converses).
 */
import type { Agent, Arrival } from 'simon-server';
import { z } from 'zod';
import type { Activity, Ctx, Module } from '../../context.ts';
import type { Caller } from '../../http/route.ts';
import type { Codes } from '../../lib/codes.ts';
import { retiredRef } from '../../lib/ids.ts';
import type { CardStore } from '../agents/cards.ts';
import { Discovery, findable } from './discovery.ts';
import { Entities } from './entities.ts';
import { mongoGraph, type EdgeOwner, type GraphStore } from './graph-store.ts';
import { Graph } from './graph.ts';
import { Pairings } from './pairing.ts';
import { edgeOwner, People } from './people.ts';
import { Profiles, displayName } from './profiles.ts';
import { contactAllows, Relations } from './relations.ts';
import { discoveryRoutes } from './routes/discovery.ts';
import { entityRoutes } from './routes/entities.ts';
import { graphRoutes } from './routes/graph.ts';
import { profileRoutes } from './routes/profiles.ts';
import { personRoutes, recoveryRoutes } from './routes/person.ts';
import { Pair } from './schemas.ts';
import { mongoPeople, type Pairing } from './store.ts';
import { gradeOf, rankOf } from './vocab.ts';

const DAY_MS = 86_400_000;
const EDGE_TTL_MS = 365 * DAY_MS;
const PENDING_TTL_MS = 90 * DAY_MS;
const UNCLAIMED_TTL_MS = 90 * DAY_MS;

export interface Directory {
  people: People;
  pairings: Pairings;
  relations: Relations;
  profiles: Profiles;
  entities: Entities;
  graph: Graph;
  graphStore: GraphStore;
  discovery: Discovery;
  /** The contact tier of the person a recipient here speaks for, against the sender's relation to them. */
  contactAllows(arrival: Arrival): Promise<boolean>;
}

export const pairView = (p: Pairing) => ({
  address: p.address,
  identifier: p.principal,
  person: p.person,
  scope: p.scope,
  verifiedAt: p.verifiedAt.toISOString(),
  recoveredAt: p.recoveredAt?.toISOString() ?? null,
});

export function directoryModule(
  ctx: Ctx,
  deps: { cards: CardStore; activity: Activity; codes: Codes; reserved: Caller<Agent> },
) {
  const { activity } = deps;
  const peopleStore = mongoPeople(ctx.db);
  const graphStore = mongoGraph(ctx.db);
  const people = new People(ctx, peopleStore, activity);
  const relations = new Relations(graphStore, people);
  const entities = new Entities(ctx, graphStore, people);
  const profiles = new Profiles(ctx, graphStore, people, entities, relations, activity);
  const graph = new Graph(ctx, graphStore, people, profiles, relations, activity);
  const discovery = new Discovery(ctx, {
    graph: graphStore,
    people,
    profiles,
    relations,
    entities,
    edges: graph,
    cards: deps.cards,
  });
  const pairings = new Pairings(ctx, people, deps.codes, activity);
  people.onMerge((from, to) => graphStore.reassign(from, to));
  // What others said about someone waits for them: they hear of it when they first claim themselves.
  people.onClaim(async person => {
    const count = await profiles.pending(person._id);
    if (count) await activity.record(person._id, 'attestations_to_review', { count });
  });

  const directory: Directory = {
    people,
    pairings,
    relations,
    profiles,
    entities,
    graph,
    graphStore,
    discovery,
    async contactAllows(arrival) {
      const recipient = await ctx.api.store.agentByAddress(arrival.recipient);
      const pairing = recipient && (await people.pairingOf(recipient));
      const person = pairing && (await people.live(pairing.person));
      if (!person) return true;
      const sender =
        arrival.carrier === ctx.config.server.origin ? await ctx.api.store.agentByAddress(arrival.message.from) : null;
      const from = sender ? (await people.actor(sender)).principal : null;
      return contactAllows(person.listing.contact, from ? await relations.of(from, person._id) : 'none');
    },
  };

  /** Retention: what nobody renewed, nobody confirmed, or nobody claimed. */
  async function expire(): Promise<number> {
    const now = ctx.now().getTime();
    const edges = await graphStore.deleteEdges({ before: new Date(now - EDGE_TTL_MS) });
    const pending = await graphStore.dropPending(new Date(now - PENDING_TTL_MS));
    const unclaimed = await peopleStore.unclaimed(new Date(now - UNCLAIMED_TTL_MS), 100);
    if (unclaimed.length) {
      await graphStore.forget(unclaimed);
      await peopleStore.deletePeople(unclaimed);
    }
    return edges + pending + unclaimed.length;
  }

  const module: Module = {
    name: 'directory',
    routes: [
      ...personRoutes(directory, deps.reserved),
      ...discoveryRoutes(ctx, directory),
      ...profileRoutes(ctx, directory, deps.reserved),
      ...entityRoutes(ctx, directory, deps.reserved),
      ...graphRoutes(ctx, directory, deps.reserved),
      ...recoveryRoutes(ctx, directory),
    ],
    hooks: {
      verifyPrincipal: request => pairings.verify(request),
      claimsFor: (_, agent) => pairings.claims(agent),
      on: {
        // A key principal's recovery is the principal's own act; only the mailbox's narrows the pair.
        recovered: async ({ address, key, by }) => {
          if (by === 'mailbox') await pairings.recovered(address, key);
        },
      },
    },
    async init() {
      await peopleStore.init();
      await graphStore.init();
    },
    work: expire,
    forget: {
      async agent(address) {
        await peopleStore.deletePairings(address);
        // What an agent wrote as itself was its own; what it wrote for its person stays theirs.
        await graphStore.forget([`agent:${address}`]);
        await graphStore.renameAgent(address, retiredRef(address));
      },
      async person(id) {
        await graphStore.forget([id]);
        await peopleStore.deletePeople([id]);
      },
    },
    home: {
      fields: {
        pair: Pair.nullable(),
        suggestions: z.array(z.object({ person: z.string(), name: z.string().nullable(), grade: z.string() })),
      },
      async build(address) {
        const agent = (await ctx.api.store.agentByAddress(address))!;
        const pairing = await people.pairingOf(agent);
        const attention = [];
        if (pairing?.recoveredAt) {
          attention.push({
            kind: 'recovery_pending',
            message: 'Your keys were replaced by a code; until your person confirms, you only converse for them.',
          });
        }
        const actor = await people.actor(agent);
        if (actor.person && !actor.person.listing.listed) {
          attention.push({
            kind: 'not_listed',
            message:
              'Your person is not listed, so nobody finds them in search. Listing is their choice: ask before turning it on.',
          });
        }
        const toReview = actor.person ? await profiles.pending(actor.person._id) : 0;
        if (toReview) {
          attention.push({
            kind: 'attestations_to_review',
            message: `${toReview} attestation(s) by others about your person wait for them to confirm or hide.`,
          });
        }
        return {
          fields: {
            pair: pairing ? pairView(pairing) : null,
            suggestions: actor.person ? await suggestions(directory, edgeOwner(actor)) : [],
          },
          attention,
        };
      },
    },
  };
  return { module, directory };
}

/** A few strong ties from the agent's own edges whom it may write to: worth a look. */
async function suggestions(d: Directory, asker: EdgeOwner) {
  const strong = (
    await d.graphStore.edges({ from: [asker.from], principals: asker.principals, minStrength: rankOf('strong') })
  ).sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime());
  const out: { person: string; name: string | null; grade: string }[] = [];
  for (const e of strong) {
    if (out.length >= 5 || out.some(s => s.person === e.to)) continue;
    const p = await d.people.live(e.to);
    const rel = p && (await d.relations.of(asker.from, p._id));
    if (!p || !rel || !findable(p, rel) || !(await d.discovery.contactable(p, rel)).length) continue;
    const profile = await d.profiles.read(p, asker.from, rel);
    out.push({ person: p._id, name: profile ? displayName(profile.facts) : null, grade: gradeOf(e.strength) });
  }
  return out;
}
