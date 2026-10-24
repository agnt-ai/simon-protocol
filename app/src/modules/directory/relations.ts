/**
 * The visibility rule. What an asker may see of a person, and whether it may write to them, depends on
 * how they are related, and only edges the asker cannot write itself widen anything:
 *
 *   connection     the target's own edge to the asker (the target vouches for knowing them)
 *   second degree  an intermediary who opted in, with its own edge to the asker and its own to the target
 *
 * The asker's own edges never widen what it sees. Hidden edges count for nothing.
 *
 * What the asker is told about its relationship to someone (its grade, its degree) comes from its own edges
 * alone, and from intermediaries who opted in: never from the target's edges, which are the target's.
 */
import type { EdgeOwner, GraphStore } from './graph-store.ts';
import type { People } from './people.ts';
import type { Person } from './store.ts';
import { ANY_EDGE, gradeOf, type ContactTier, type Discoverability, type Grade } from './vocab.ts';

export type Relation = 'self' | 'connection' | 'second_degree' | 'none';

const RANK: Record<Relation, number> = { none: 0, second_degree: 1, connection: 2, self: 3 };

export const atLeast = (rel: Relation, min: Relation) => RANK[rel] >= RANK[min];

export interface RelationshipSummary {
  /** The asker's own best edge to them. */
  grade: Grade;
  /** 1 through the asker's own edge; 2 through its own edge to an intermediary who opted in and knows them. */
  degree: 1 | 2 | null;
}

export class Relations {
  readonly #graph: GraphStore;
  readonly #people: People;

  constructor(graph: GraphStore, people: People) {
    this.#graph = graph;
    this.#people = people;
  }

  /** How each target is related to the asker, in three queries however many targets there are. */
  async from(asker: string, targets: string[]): Promise<Map<string, Relation>> {
    const out = new Map<string, Relation>();
    if (targets.includes(asker)) out.set(asker, 'self');
    const rest = [...new Set(targets)].filter(t => t !== asker);
    if (!rest.length) return out;
    for (const e of await this.#graph.edges({ from: rest, to: [asker], minStrength: ANY_EDGE }))
      out.set(e.from, 'connection');
    const remaining = rest.filter(t => !out.has(t));
    if (remaining.length) {
      const xs = await this.intermediaries(asker);
      if (xs.length) {
        for (const e of await this.#graph.edges({ from: xs, to: remaining, minStrength: ANY_EDGE })) {
          if (!out.has(e.to)) out.set(e.to, 'second_degree');
        }
      }
    }
    for (const t of rest) if (!out.has(t)) out.set(t, 'none');
    return out;
  }

  async of(asker: string, target: string): Promise<Relation> {
    return (await this.from(asker, [target])).get(target)!;
  }

  /** People whose own edge vouches for the asker and who opted in to second degree. */
  async intermediaries(asker: string): Promise<string[]> {
    const vouchers = (await this.#graph.edges({ to: [asker], minStrength: ANY_EDGE }))
      .map(e => e.from)
      .filter(x => x !== asker);
    return optedIn(await this.#people.store.people([...new Set(vouchers)]));
  }

  /** The asker's own relationship to each target: its best edge's grade, and the degree its edges reach. */
  async summaries(asker: EdgeOwner, targets: string[]): Promise<Map<string, RelationshipSummary>> {
    const own = await this.#graph.edges({ from: [asker.from], principals: asker.principals, minStrength: ANY_EDGE });
    const best = new Map<string, number>();
    for (const e of own) best.set(e.to, Math.max(best.get(e.to) ?? 0, e.strength));
    const rest = targets.filter(t => !best.has(t));
    const xs = optedIn(await this.#people.store.people([...new Set(own.map(e => e.to))]));
    const second = new Set(
      rest.length && xs.length
        ? (await this.#graph.edges({ from: xs, to: rest, minStrength: ANY_EDGE })).map(e => e.to)
        : [],
    );
    return new Map(
      targets.map(t => [t, { grade: gradeOf(best.get(t) ?? 0), degree: best.has(t) ? 1 : second.has(t) ? 2 : null }]),
    );
  }
}

/** Claimed people who opted in to carrying second-degree relationships. */
export const optedIn = (people: Person[]) =>
  people.filter(p => p.claimed && !p.mergedInto && p.listing.secondDegreeOptIn).map(p => p._id);

/** Whether an asker at `rel` may find the person. Unlisted or unclaimed people are visible only to themselves. */
export function canDiscover(person: Person, rel: Relation): boolean {
  if (rel === 'self') return true;
  return person.claimed && person.listing.listed && tierAllows(person.listing.discoverability, rel);
}

export function tierAllows(tier: Discoverability, rel: Relation): boolean {
  if (tier === 'everyone') return true;
  if (tier === 'connections') return atLeast(rel, 'connection');
  if (tier === 'second_degree') return atLeast(rel, 'second_degree');
  return rel === 'self';
}

/** Whether a sender at `rel` may write to someone at this contact tier. An introduction gets past it. */
export function contactAllows(tier: ContactTier, rel: Relation): boolean {
  if (rel === 'self' || tier === 'anyone') return true;
  if (tier === 'connections') return atLeast(rel, 'connection');
  if (tier === 'second_degree') return atLeast(rel, 'second_degree');
  return false;
}
