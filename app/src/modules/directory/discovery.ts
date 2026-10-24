/**
 * Discovery: resolve an identifier, search profiles by facet and relationship, ask whether someone is
 * reachable, and find who could carry an introduction. Every query runs as one asker (a person, or an
 * agent as itself, through the identifier its agent speaks for), because what is visible depends on who
 * asks. Someone the asker may not find is indistinguishable from nobody: an unlisted person is found only
 * by their connections, and their agents' cards are shown only once published.
 */
import type { Agent } from '@agnt-protocol/server';
import type { Ctx } from '../../context.ts';
import type { CardStore } from '../agents/cards.ts';
import type { Entities } from './entities.ts';
import type { Attestation, EdgeOwner, GraphStore } from './graph-store.ts';
import type { Graph } from './graph.ts';
import type { People } from './people.ts';
import { displayName, type Profiles } from './profiles.ts';
import { atLeast, canDiscover, contactAllows, optedIn, type Relation, type Relations } from './relations.ts';
import type { Person } from './store.ts';
import { ANY_EDGE, CARRY_MIN, gradeOf, rankOf, type Grade, type ProfileField } from './vocab.ts';

export interface SearchInput {
  company?: string[];
  school?: string[];
  title?: string;
  location?: string;
  text?: string;
  /** Only people at least this close; `self` is the asker's own person. */
  relation?: 'self' | 'connection' | 'second_degree';
  /** Only people the asker's own edge rates at least this strong. */
  minStrength?: number;
  limit: number;
}

export interface Carrier {
  person: Person;
  /** An agent speaking for the carrier now, which is asked. */
  agent: string;
  grade: Grade;
}

/** Whether an asker at `rel` may know the person is here: their listing allows it, or the person knows them. */
export const findable = (person: Person, rel: Relation) => canDiscover(person, rel) || atLeast(rel, 'connection');

export class Discovery {
  readonly #ctx: Ctx;
  readonly #graph: GraphStore;
  readonly #people: People;
  readonly #profiles: Profiles;
  readonly #relations: Relations;
  readonly #entities: Entities;
  readonly #edges: Graph;
  readonly #cards: CardStore;

  constructor(
    ctx: Ctx,
    deps: {
      graph: GraphStore;
      people: People;
      profiles: Profiles;
      relations: Relations;
      entities: Entities;
      edges: Graph;
      cards: CardStore;
    },
  ) {
    this.#ctx = ctx;
    this.#graph = deps.graph;
    this.#people = deps.people;
    this.#profiles = deps.profiles;
    this.#relations = deps.relations;
    this.#entities = deps.entities;
    this.#edges = deps.edges;
    this.#cards = deps.cards;
  }

  /** The agents speaking for a person that a sender at `rel` may write to, by their person's contact tier. */
  async contactable(person: Person, rel: Relation): Promise<Agent[]> {
    if (!person.claimed || !contactAllows(person.listing.contact, rel)) return [];
    const agents = await Promise.all(
      (await this.#people.pairsOf(person._id)).map(p => this.#ctx.api.store.agentByAddress(p.address)),
    );
    return agents.filter(a => a !== null);
  }

  /**
   * An identifier: the person, with the agents the asker may write to; `found: false` for anyone it may not
   * find. An agent's card shows only once it is published.
   */
  async resolve(asker: EdgeOwner, identifier: string) {
    const person = await this.#people.forPrincipal(identifier);
    const rel = person ? await this.#relations.of(asker.from, person._id) : 'none';
    if (!person || !findable(person, rel)) return { found: false };
    const profile = canDiscover(person, rel) ? await this.#profiles.read(person, asker.from, rel) : null;
    const agents = await Promise.all(
      (await this.contactable(person, rel)).map(async a => {
        const card = await this.#cards.card(a.address);
        const { name, description, capabilities } = card;
        return { address: a.address, card: card.listed ? { name, description, capabilities } : null };
      }),
    );
    return {
      found: true,
      person: person._id,
      name: profile ? displayName(profile.facts) : null,
      profile,
      relationship: (await this.#relations.summaries(asker, [person._id])).get(person._id)!,
      agents,
    };
  }

  async search(asker: EdgeOwner, input: SearchInput) {
    const principal = asker.from;
    const facets: Set<string>[] = [];
    const matched = new Map<string, Set<string>>();
    // Facets match what readers may see, and what the asker itself wrote.
    const facet = (list: Attestation[]) => {
      const subjects = new Set<string>();
      for (const a of list.filter(x => x.disposition === 'confirmed' || x.authorPrincipal === principal)) {
        subjects.add(a.subject);
        matched.set(a.subject, (matched.get(a.subject) ?? new Set()).add(a._id));
      }
      facets.push(subjects);
    };
    const text = (fields: ProfileField[], value: string) =>
      this.#graph.attestations({ fields, normContains: value.slice(0, 100) });
    for (const kind of ['company', 'school'] as const) {
      if (!input[kind]?.length) continue;
      const entities = await this.#entities.named(input[kind], kind);
      facet(entities.length ? await this.#graph.attestations({ fields: ['affiliation'], entities }) : []);
    }
    if (input.title) facet(await text(['title', 'affiliation', 'headline'], input.title));
    if (input.location) facet(await text(['location'], input.location));
    if (input.text) facet(await text(['name', 'headline', 'bio', 'skill', 'interest', 'title'], input.text));
    if (input.minStrength) {
      const own = await this.#graph.edges({
        from: [principal],
        principals: asker.principals,
        minStrength: input.minStrength,
      });
      facets.push(new Set(own.map(e => e.to)));
    }
    if (input.relation) facets.push(await this.#candidates(principal, input.relation));
    if (!facets.length) return { results: [] };

    const ids = [...facets[0]].filter(id => facets.every(s => s.has(id)));
    const people = (await this.#people.store.people(ids)).filter(p => p.claimed && p.listing.listed && !p.mergedInto);
    const rels = await this.#relations.from(
      principal,
      people.map(p => p._id),
    );
    const visible = people
      .filter(p => canDiscover(p, rels.get(p._id)!))
      .filter(
        p =>
          !input.relation ||
          (atLeast(rels.get(p._id)!, input.relation) && (input.relation === 'self' || p._id !== principal)),
      )
      .slice(0, input.limit);
    const summaries = await this.#relations.summaries(
      asker,
      visible.map(p => p._id),
    );
    const notes = await this.#edges.notes(
      asker,
      visible.map(p => p._id),
    );
    const attestations = await this.#graph.attestations({ subjects: visible.map(p => p._id) });
    const results = [];
    for (const p of visible) {
      const facts = await this.#profiles.facts(
        p,
        principal,
        attestations.filter(a => a.subject === p._id),
      );
      const hits = matched.get(p._id) ?? new Set();
      results.push({
        person: p._id,
        name: displayName(facts),
        matched: facts
          .filter(f => hits.has(f.id))
          .map(f => ({ field: f.field, value: f.value, provenance: f.provenance })),
        facts,
        relationship: summaries.get(p._id)!,
        yourNote: notes.get(p._id) ?? null,
      });
    }
    // Closest first: degree, then the asker's own grade.
    results.sort(
      (a, b) =>
        (a.relationship.degree ?? 9) - (b.relationship.degree ?? 9) ||
        rankOf(b.relationship.grade) - rankOf(a.relationship.grade),
    );
    return { results };
  }

  /** Everyone who could be at least `relation` from the asker, from edges the visibility rule trusts. */
  async #candidates(asker: string, relation: 'self' | 'connection' | 'second_degree'): Promise<Set<string>> {
    if (relation === 'self') return new Set([asker]);
    const out = new Set(
      (await this.#graph.edges({ to: [asker], minStrength: ANY_EDGE })).map(e => e.from).filter(x => x !== asker),
    );
    if (relation === 'second_degree') {
      const xs = await this.#relations.intermediaries(asker);
      for (const e of await this.#graph.edges({ from: xs, minStrength: ANY_EDGE })) if (e.to !== asker) out.add(e.to);
    }
    return out;
  }

  /**
   * Whether the asker may write to someone, and the degree its own edges reach them at. Whether an
   * introduction could reach them is never said: no path and a refusal look the same.
   */
  async reach(asker: EdgeOwner, identifier: string) {
    const nobody = { reachable: false, degree: null, yourNote: null };
    const target = await this.#people.forPrincipal(identifier);
    if (!target?.claimed || target._id === asker.from) return nobody;
    const rel = await this.#relations.of(asker.from, target._id);
    if (!findable(target, rel)) return nobody;
    return {
      reachable: (await this.contactable(target, rel)).length > 0,
      degree: (await this.#relations.summaries(asker, [target._id])).get(target._id)!.degree,
      yourNote: (await this.#edges.notes(asker, [target._id])).get(target._id) ?? null,
    };
  }

  /**
   * Who could carry an introduction from requester to target, strongest first: people whose own edge to
   * the requester says they know it, and whose own edge to the target is at least working and may carry
   * introductions, who opted in to second degree, allow carrying, and have an agent. The requester's claim
   * to know someone never makes them a carrier. Never shown to the requester.
   */
  async carriers(requester: string, target: string): Promise<Carrier[]> {
    const near = (await this.#graph.edges({ from: [requester], minStrength: ANY_EDGE })).map(e => e.to);
    const firstDegree = [...new Set(near)].filter(x => x !== target && x !== requester);
    const legs = (await this.#graph.edges({ from: firstDegree, to: [target], minStrength: CARRY_MIN })).filter(
      e => e.introduceOk,
    );
    const candidates = [...new Set(legs.map(e => e.from))];
    const vouching = new Set(
      (await this.#graph.edges({ from: candidates, to: [requester], minStrength: ANY_EDGE })).map(e => e.from),
    );
    const xs = (await this.#people.store.people(candidates.filter(x => vouching.has(x)))).filter(
      p => optedIn([p]).length && p.listing.introCarrying !== 'never',
    );
    const out: Carrier[] = [];
    for (const person of xs) {
      const [pair] = await this.#people.pairsOf(person._id);
      if (!pair) continue;
      const grade = gradeOf(Math.max(...legs.filter(e => e.from === person._id).map(e => e.strength)));
      out.push({ person, agent: pair.address, grade });
    }
    return out.sort((a, b) => rankOf(b.grade) - rankOf(a.grade));
  }
}
