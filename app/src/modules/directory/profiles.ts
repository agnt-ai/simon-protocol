/**
 * Profiles as stacks of attestations. Nothing is overwritten: a new attestation stacks on the old, a
 * retraction marks it, and the subject's disposition sits on top.
 *
 * A person says what they like about themselves. Others may say only a name, a title or an affiliation,
 * and what they say waits, `pending`, until its subject confirms it; until then it is shown to its author
 * alone and used for nothing else, and after 90 days unconfirmed it is gone. A person is told what waits
 * for them when they first claim themselves, and whenever more arrives.
 *
 * Readers see each fact with its provenance: `domain_verified` when the subject holds a verified address
 * at an affiliation's domain, or a colleague there names them; `corroborated` when authors at three
 * distinct verified domains say the same thing, so a crowd of throwaway agents corroborates nothing. A
 * hidden member and someone who never joined look the same to a reader.
 */
import type { Activity, Ctx } from '../../context.ts';
import { forbidden, invalid, notFound } from '../../lib/errors.ts';
import { newId } from '../../lib/ids.ts';
import { plainText } from '../../lib/text.ts';
import type { Entities } from './entities.ts';
import type { Affiliation, Attestation, Entity, GraphStore } from './graph-store.ts';
import type { People } from './people.ts';
import { canDiscover, type Relation, type Relations } from './relations.ts';
import type { Person } from './store.ts';
import {
  ATTESTABLE_BY_OTHERS,
  PROVENANCE,
  type Decision,
  type Disposition,
  type EntityKind,
  type ProfileField,
  type Provenance,
} from './vocab.ts';

const CORROBORATING_DOMAINS = 3;

export interface AttestationInput {
  field: ProfileField;
  value?: string;
  affiliation?: {
    domain?: string | null;
    name?: string | null;
    kind?: EntityKind | null;
    title?: string | null;
    start?: string | null;
    end?: string | null;
  };
  provenance?: 'imported' | 'observed';
}

export interface Fact {
  id: string;
  field: string;
  value: unknown;
  provenance: Provenance;
  /** Whether the subject said it about themselves. */
  self: boolean;
  disposition: Disposition;
  createdAt: string;
}

export interface Profile {
  person: string;
  claimed: boolean;
  facts: Fact[];
}

const clip = (s: string | null | undefined, n: number) => s?.trim().slice(0, n) || null;

export class Profiles {
  readonly #ctx: Ctx;
  readonly #graph: GraphStore;
  readonly #people: People;
  readonly #entities: Entities;
  readonly #relations: Relations;
  readonly #activity: Activity;

  constructor(
    ctx: Ctx,
    graph: GraphStore,
    people: People,
    entities: Entities,
    relations: Relations,
    activity: Activity,
  ) {
    this.#ctx = ctx;
    this.#graph = graph;
    this.#people = people;
    this.#entities = entities;
    this.#relations = relations;
    this.#activity = activity;
  }

  /**
   * Write attestations about a subject (a person id, or an identifier) as `author`, a principal, through the
   * identifier its agent speaks for.
   */
  async attest(
    agent: string,
    by: { principal: string; identifier: string },
    subjectRef: { person: string } | { identifier: string },
    inputs: AttestationInput[],
  ) {
    const author = by.principal;
    const subject =
      'person' in subjectRef
        ? await this.#people.live(subjectRef.person)
        : await this.#people.forPrincipal(subjectRef.identifier, true);
    if (!subject) throw notFound('person');
    const self = subject._id === author;
    const now = this.#ctx.now();
    const records: Attestation[] = [];
    for (const input of inputs) {
      if (!self && !ATTESTABLE_BY_OTHERS.includes(input.field)) {
        throw invalid(`About someone else, attest only ${ATTESTABLE_BY_OTHERS.join(', ')}.`, { field: 'field' });
      }
      let value: Attestation['value'];
      let norm: string;
      if (input.field === 'affiliation') {
        const entity = await this.#entities.findOrCreate(input.affiliation ?? {});
        const title = clip(input.affiliation?.title, 200);
        value = {
          entity: entity._id,
          title,
          start: clip(input.affiliation?.start, 20),
          end: clip(input.affiliation?.end, 20),
        };
        norm = `${entity._id}|${(title ?? '').toLowerCase()}`;
      } else {
        const text = clip(input.value, input.field === 'bio' ? 4000 : 500);
        if (!text) throw invalid(`A ${input.field} attestation needs a value.`, { field: 'value' });
        value = input.field === 'name' ? plainText('value', text) : text;
        norm = text.toLowerCase();
      }
      records.push({
        _id: newId('attestation'),
        subject: subject._id,
        field: input.field,
        value,
        norm,
        authorAgent: agent,
        authorPrincipal: author,
        authorIdentifier: by.identifier,
        via: 'identifier' in subjectRef ? subjectRef.identifier : null,
        // What a writer says is self-reported, imported or observed; stronger classes are computed on read.
        provenance: self ? 'self_reported' : input.provenance === 'observed' ? 'observed' : 'imported',
        disposition: self ? 'confirmed' : 'pending',
        retractedAt: null,
        createdAt: now,
      });
    }
    await this.#graph.insertAttestations(records);
    await this.#activity.record(author, 'attestations_written', { agent, subject: subject._id, count: records.length });
    if (!self && subject.claimed)
      await this.#activity.record(subject._id, 'attestations_to_review', { count: records.length });
    return records;
  }

  async retract(author: string, id: string): Promise<void> {
    const a = await this.#graph.attestation(id);
    if (!a || a.authorPrincipal !== author || a.retractedAt)
      throw notFound('attestation', 'No such attestation of yours.');
    await this.#graph.updateAttestation(id, { retractedAt: this.#ctx.now() });
  }

  /** The subject confirms, hides or disputes an attestation about them. */
  async dispose(subject: string, id: string, decision: Decision): Promise<Attestation> {
    const a = await this.#graph.attestation(id);
    if (!a || a.subject !== subject || a.retractedAt) throw notFound('attestation', 'No such attestation about you.');
    if (a.authorPrincipal === subject && decision === 'disputed') {
      throw forbidden('own_attestation', 'Retract your own attestation instead of disputing it.');
    }
    await this.#activity.record(subject, 'attestation_disposed', { attestation: id, disposition: decision });
    return (await this.#graph.updateAttestation(id, { disposition: decision }))!;
  }

  /** How many attestations by others wait on a person's decision. */
  async pending(subject: string): Promise<number> {
    return (await this.#graph.attestations({ subjects: [subject], dispositions: ['pending'] })).length;
  }

  /** A profile as `reader` (a principal; null for anyone) may see it, or null when it may not. */
  async read(subject: Person, reader: string | null, rel?: Relation): Promise<Profile | null> {
    rel ??= reader ? await this.#relations.of(reader, subject._id) : 'none';
    const visible = reader
      ? canDiscover(subject, rel)
      : subject.claimed && subject.listing.listed && subject.listing.discoverability === 'everyone';
    if (visible) return { person: subject._id, claimed: subject.claimed, facts: await this.facts(subject, reader) };
    if (!reader) return null;
    // Not theirs to see: they see their own attestations, exactly as for someone who never joined.
    const own = await this.#graph.attestations({ subjects: [subject._id], authorPrincipal: reader });
    return own.length ? { person: subject._id, claimed: false, facts: await this.asWritten(own) } : null;
  }

  /** Attestations as their author wrote them: no provenance computed, so nothing hints the subject joined. */
  async asWritten(attestations: Attestation[]): Promise<Fact[]> {
    const entities = await this.entitiesOf(attestations);
    return attestations.map(a => this.#fact(a, entities, false));
  }

  /**
   * The facts a reader may see about a subject, with provenance computed: everything, to the subject; to
   * anyone else, the subject's own and those the subject confirmed, and what the reader itself wrote.
   */
  async facts(subject: Person, reader: string | null, attestations?: Attestation[]): Promise<Fact[]> {
    const all = attestations ?? (await this.#graph.attestations({ subjects: [subject._id] }));
    const isSubject = reader === subject._id;
    const shown = all.filter(
      a =>
        isSubject ||
        (reader !== null && a.authorPrincipal === reader) ||
        (subject.claimed && a.disposition === 'confirmed'),
    );
    if (!shown.length) return [];
    const standing = all.filter(a => a.disposition !== 'hidden' && a.disposition !== 'disputed');
    const domains = await this.#people.verifiedDomains([subject._id, ...new Set(standing.map(a => a.authorPrincipal))]);
    const subjectDomains = domains.get(subject._id)!;
    const authors = new Map<string, Set<string>>();
    for (const a of standing.filter(x => x.authorPrincipal !== subject._id)) {
      const k = `${a.field}|${a.norm}`;
      authors.set(k, (authors.get(k) ?? new Set()).add(a.authorPrincipal));
    }
    const entities = await this.entitiesOf(shown);
    return shown.map(a => {
      const self = a.authorPrincipal === subject._id;
      const fact = this.#fact(a, entities, self);
      // A reader's own fact that its subject has not confirmed keeps the provenance it was written with:
      // computing it would tell the reader which domains the subject verified.
      if (!isSubject && !self && a.disposition !== 'confirmed') return fact;
      const entity = a.field === 'affiliation' ? entities.get((a.value as Affiliation).entity) : undefined;
      const colleague = [...(domains.get(a.authorPrincipal) ?? [])].some(d => subjectDomains.has(d));
      let provenance = a.provenance;
      if (entity?.domains.some(d => subjectDomains.has(d)) || (!self && a.field === 'name' && colleague))
        provenance = 'domain_verified';
      if (distinctDomains(authors.get(`${a.field}|${a.norm}`), domains) >= CORROBORATING_DOMAINS)
        provenance = 'corroborated';
      return {
        ...fact,
        provenance: PROVENANCE.indexOf(provenance) < PROVENANCE.indexOf(a.provenance) ? a.provenance : provenance,
      };
    });
  }

  async entitiesOf(attestations: Attestation[]): Promise<Map<string, Entity>> {
    const ids = [
      ...new Set(attestations.filter(a => a.field === 'affiliation').map(a => (a.value as Affiliation).entity)),
    ];
    const found = await Promise.all(ids.map(id => this.#graph.entity(id)));
    return new Map(found.filter(e => e !== null).map(e => [e._id, e]));
  }

  #fact(a: Attestation, entities: Map<string, Entity>, self: boolean): Fact {
    return {
      id: a._id,
      field: a.field,
      value: a.field === 'affiliation' ? affiliationView(a.value as Affiliation, entities) : a.value,
      provenance: a.provenance,
      self,
      disposition: a.disposition,
      createdAt: a.createdAt.toISOString(),
    };
  }
}

/** How many distinct verified domains stand behind these authors, each author counted at one domain at most. */
function distinctDomains(authors: Set<string> | undefined, domains: Map<string, Set<string>>): number {
  const used = new Set<string>();
  for (const author of authors ?? []) {
    const domain = [...(domains.get(author) ?? [])].find(d => !used.has(d));
    if (domain) used.add(domain);
  }
  return used.size;
}

/** An affiliation as people read it: the entity's name and first domain beside the title and dates. */
export function affiliationView(a: Affiliation, entities: Map<string, Entity>) {
  const e = entities.get(a.entity);
  return {
    entity: a.entity,
    name: e?.name ?? null,
    domain: e?.domains[0] ?? null,
    title: a.title,
    start: a.start,
    end: a.end,
  };
}

/** The name the subject gives themselves, their latest. */
export function selfName(facts: Fact[]): string | null {
  const name = facts.filter(f => f.field === 'name' && f.self).at(-1)?.value;
  return typeof name === 'string' ? name : null;
}

/**
 * A display name: the subject's own latest `name`, else one a verified domain stands behind. A name only
 * someone else gave is never shown as who a person is.
 */
export function displayName(facts: Fact[]): string | null {
  const vouched = facts.filter(
    f =>
      f.field === 'name' &&
      f.disposition === 'confirmed' &&
      PROVENANCE.indexOf(f.provenance) >= PROVENANCE.indexOf('domain_verified'),
  );
  const name = vouched.at(-1)?.value;
  return selfName(facts) ?? (typeof name === 'string' ? name : null);
}
