/**
 * The relationship graph. Each agent rates its person's relationships itself (1 to 5, with the published
 * rubric in skill/grade.js) and sends only the number, its provenance and an optional private note. An
 * edge is the person's, one per identifier they speak through and per identifier they know someone by,
 * whichever of that identifier's agents wrote it last. An agent, or an owner session, sees the edges of the
 * identifiers it speaks for or proved; who may see and write to whom counts every edge of the person.
 * Ending a pair removes none of its edges; the person clears stale ones in the owner window, and an edge
 * nobody rewrites in a year expires. Edges drive visibility, matching and introductions, and are never
 * shown to anyone else.
 */
import type { Activity, Ctx } from '../../context.ts';
import { invalid, notFound } from '../../lib/errors.ts';
import { plainText } from '../../lib/text.ts';
import type { Edge, EdgeOwner, GraphStore } from './graph-store.ts';
import type { People } from './people.ts';
import { displayName, type Fact, type Profile, type Profiles } from './profiles.ts';
import { canDiscover, type Relations } from './relations.ts';
import { gradeOf, UNOBSERVED_CAP, type EdgeProvenance, type Grade } from './vocab.ts';

export interface EdgeInput {
  identifier: string;
  strength: number;
  provenance?: EdgeProvenance;
  introduceOk?: boolean;
  /** Left out, the edge keeps its note; null clears it. */
  summary?: string | null;
}

/** The owner's own strength and note about someone, returned only to the owner. */
export interface Note {
  strength: number;
  summary: string | null;
}

export interface Connection {
  /** Null for someone the asker may not find: such entries are one per identifier. */
  person: string | null;
  name: string | null;
  identifiers: string[];
  grade: Grade;
  profile: Profile | null;
  facts: Fact[];
  yourNote: Note | null;
}

export const edgeView = (e: Edge) => ({
  id: e._id,
  to: e.to,
  identifier: e.via,
  writtenBy: e.writtenBy,
  strength: e.strength,
  grade: gradeOf(e.strength),
  provenance: e.provenance,
  introduceOk: e.introduceOk,
  summary: e.summary,
  hidden: !!e.hiddenAt,
  updatedAt: e.updatedAt.toISOString(),
});

/** The strongest, then latest, of someone's edges to one person, as a note. */
export function noteOf(edges: Edge[]): Note | null {
  const e = [...edges].sort((a, b) => b.strength - a.strength || b.updatedAt.getTime() - a.updatedAt.getTime())[0];
  return e ? { strength: e.strength, summary: e.summary } : null;
}

export class Graph {
  readonly #ctx: Ctx;
  readonly #graph: GraphStore;
  readonly #people: People;
  readonly #profiles: Profiles;
  readonly #relations: Relations;
  readonly #activity: Activity;

  constructor(
    ctx: Ctx,
    graph: GraphStore,
    people: People,
    profiles: Profiles,
    relations: Relations,
    activity: Activity,
  ) {
    this.#ctx = ctx;
    this.#graph = graph;
    this.#people = people;
    this.#profiles = profiles;
    this.#relations = relations;
    this.#activity = activity;
  }

  /** Write the edges of `owner`, a person or an agent as itself, through `principal`, as `agent` wrote them. */
  async submit(agent: string, owner: { from: string; principal: string }, inputs: EdgeInput[]) {
    const at = this.#ctx.now();
    const results: { id: string | null; identifier: string; strength: number; status: 'stored' | 'skipped_self' }[] =
      [];
    const summaries = inputs.map(e => (typeof e.summary === 'string' ? cleanNote(e.summary) : e.summary));
    for (const [i, e] of inputs.entries()) {
      const target = (await this.#people.forPrincipal(e.identifier, true))!;
      if (target._id === owner.from) {
        results.push({ id: null, identifier: e.identifier, strength: 0, status: 'skipped_self' });
        continue;
      }
      const provenance = e.provenance ?? 'observed';
      const strength = provenance === 'observed' ? e.strength : Math.min(e.strength, UNOBSERVED_CAP);
      const edge = await this.#graph.writeEdge({
        ...owner,
        to: target._id,
        via: e.identifier,
        writtenBy: agent,
        strength,
        provenance,
        introduceOk: e.introduceOk,
        summary: summaries[i],
        at,
      });
      results.push({ id: edge._id, identifier: e.identifier, strength, status: 'stored' });
    }
    await this.#activity.record(owner.from, 'edges_submitted', {
      agent,
      count: results.filter(r => r.status === 'stored').length,
    });
    return results;
  }

  /** One of `owner`'s edges, whichever of its agents wrote it. */
  async own(owner: EdgeOwner, id: string): Promise<Edge> {
    const e = await this.#graph.edge(id);
    if (!e || e.from !== owner.from || !owner.principals.includes(e.principal))
      throw notFound('edge', 'No such edge of yours.');
    return e;
  }

  async remove(owner: EdgeOwner, id: string): Promise<void> {
    await this.own(owner, id);
    await this.#graph.deleteEdges({ id });
    await this.#activity.record(owner.from, 'edge_removed', { edge: id });
  }

  /** The owner hides an edge, or stops it carrying introductions. */
  async change(owner: EdgeOwner, id: string, patch: { hidden?: boolean; introduceOk?: boolean }): Promise<Edge> {
    await this.own(owner, id);
    const set: Partial<Edge> = {};
    if (patch.hidden !== undefined) set.hiddenAt = patch.hidden ? this.#ctx.now() : null;
    if (patch.introduceOk !== undefined) set.introduceOk = patch.introduceOk;
    await this.#activity.record(owner.from, 'edge_changed', { edge: id, ...patch });
    return (await this.#graph.updateEdge(id, set))!;
  }

  /** Clear stale marks: every edge one agent wrote last, and/or every edge not rewritten since a time. */
  async clear(owner: EdgeOwner, q: { writtenBy?: string; before?: Date }): Promise<number> {
    if (!q.writtenBy && !q.before) throw invalid('Name writtenBy, before, or both.', { field: 'writtenBy' });
    const removed = await this.#graph.deleteEdges({ owner, ...q });
    await this.#activity.record(owner.from, 'edges_cleared', { count: removed });
    return removed;
  }

  /** The owner's notes about each target. */
  async notes(owner: EdgeOwner, targets: string[]): Promise<Map<string, Note>> {
    const edges = await this.#graph.edges({ from: [owner.from], principals: owner.principals, to: targets });
    return new Map(
      targets.flatMap(t => {
        const n = noteOf(edges.filter(e => e.to === t));
        return n ? [[t, n] as const] : [];
      }),
    );
  }

  /**
   * "Who do I know at Example": the owner's edges joined to what the owner may see of each person. Someone
   * the owner may find is one entry with their profile; anyone else is one entry per identifier, with only
   * the owner's own attestations made through it, so two identifiers of one hidden member never meet.
   */
  async connections(
    owner: EdgeOwner,
    filter: { entities?: string[]; text?: string; minStrength?: number; limit: number },
  ): Promise<Connection[]> {
    const edges = (
      await this.#graph.edges({
        from: [owner.from],
        principals: owner.principals,
        minStrength: filter.minStrength ?? 1,
      })
    ).sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime());
    const people = new Map((await this.#people.store.people([...new Set(edges.map(e => e.to))])).map(p => [p._id, p]));
    const rels = await this.#relations.from(owner.from, [...people.keys()]);
    const attestations = await this.#graph.attestations({ subjects: [...people.keys()] });
    const matches = (list: typeof attestations) =>
      (!filter.entities?.length && !filter.text) ||
      list.some(
        a =>
          (!filter.entities?.length ||
            (a.field === 'affiliation' && filter.entities.includes((a.value as { entity: string }).entity))) &&
          (!filter.text || a.norm.includes(filter.text.toLowerCase())),
      );
    const out: Connection[] = [];
    const seen = new Set<string>();
    for (const e of edges) {
      const p = people.get(e.to);
      if (!p || out.length >= filter.limit) continue;
      const rel = rels.get(p._id) ?? 'none';
      if (canDiscover(p, rel)) {
        const visible = attestations.filter(
          a => a.subject === p._id && (a.authorPrincipal === owner.from || a.disposition === 'confirmed'),
        );
        if (seen.has(p._id) || !matches(visible)) continue;
        seen.add(p._id);
        const mine = edges.filter(x => x.to === p._id);
        const profile = await this.#profiles.read(p, owner.from, rel);
        out.push({
          person: p._id,
          name: profile ? displayName(profile.facts) : null,
          identifiers: [...new Set(mine.map(x => x.via))],
          grade: gradeOf(mine[0].strength),
          profile,
          facts: profile?.facts ?? [],
          yourNote: noteOf(mine),
        });
      } else {
        const mine = attestations.filter(
          a => a.subject === p._id && a.authorPrincipal === owner.from && a.via === e.via,
        );
        if (!matches(mine)) continue;
        const facts = await this.#profiles.asWritten(mine);
        out.push({
          person: null,
          name: writtenName(facts),
          identifiers: [e.via],
          grade: gradeOf(e.strength),
          profile: null,
          facts,
          yourNote: noteOf([e]),
        });
      }
    }
    return out;
  }
}

/** The name the owner itself gave someone, its latest. */
function writtenName(facts: Fact[]): string | null {
  const name = facts.filter(f => f.field === 'name').at(-1)?.value;
  return typeof name === 'string' ? name : null;
}

/** A note is for its owner: one plain line, no links, addresses or numbers. */
function cleanNote(raw: string): string | null {
  const s = raw.replace(/\s+/g, ' ').trim();
  return s ? plainText('summary', s.slice(0, 200)) : null;
}
