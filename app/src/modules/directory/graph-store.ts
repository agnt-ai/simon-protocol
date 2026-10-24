/**
 * What people say about each other: attestations (profile facts), entities (companies, schools), and
 * edges (who knows whom, how well). Kept in `directory.attestations`, `directory.entities` and
 * `directory.edges`. An author or an edge's owner is a principal: a person id, or `agent:<address>`.
 */
import type { Db, Filter } from 'mongodb';
import { insertOnce, isDuplicate } from '../../store/db.ts';
import { newId } from '../../lib/ids.ts';
import type { Disposition, EdgeProvenance, EntityKind, ProfileField, Provenance } from './vocab.ts';

export interface Affiliation {
  entity: string;
  title: string | null;
  start: string | null;
  end: string | null;
}

export interface Attestation {
  _id: string;
  subject: string;
  field: ProfileField;
  /** Text, or an affiliation for `affiliation`. */
  value: string | Affiliation;
  /** Lower-case comparison key, for corroboration and search. */
  norm: string;
  authorAgent: string;
  authorPrincipal: string;
  /** The identifier whose agent wrote it (`agent:<address>` for an agent as itself), for the owner window. */
  authorIdentifier: string;
  /** The identifier the author named the subject by: its own knowledge, shown back only to it. */
  via: string | null;
  provenance: Provenance;
  disposition: Disposition;
  retractedAt: Date | null;
  createdAt: Date;
}

export interface Entity {
  _id: string;
  kind: EntityKind;
  name: string;
  aliases: string[];
  domains: string[];
  claimedBy: { agent: string; person: string; at: Date } | null;
  /** One DNS challenge per person claiming: whoever's record is found first wins. */
  challenges: { token: string; person: string; domain: string; expiresAt: Date }[];
  createdAt: Date;
}

export interface Edge {
  _id: string;
  /** Whose relationship it is: a person, or an agent as itself. */
  from: string;
  /**
   * The identifier whose agents wrote it (`agent:<address>` for an agent as itself): one edge per (from,
   * principal, via), so what one identifier's agents know never passes to another's, nor to an owner
   * session that did not prove it.
   */
  principal: string;
  to: string;
  /** The identifier it was written by: two identifiers of one person stay two edges. */
  via: string;
  writtenBy: string;
  strength: number;
  provenance: EdgeProvenance;
  introduceOk: boolean;
  /** The owner's private note, returned only to them. */
  summary: string | null;
  /** Hidden by the owner: kept for their own view, used for nothing else. */
  hiddenAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

/** Whose edges: a person's (or an agent's as itself), as written by some of its identifiers. */
export interface EdgeOwner {
  from: string;
  principals: string[];
}

export interface AttestationQuery {
  subjects?: string[];
  fields?: ProfileField[];
  entities?: string[];
  normContains?: string;
  authorPrincipal?: string;
  dispositions?: Disposition[];
}

export interface EdgeWrite {
  from: string;
  principal: string;
  to: string;
  via: string;
  writtenBy: string;
  strength: number;
  provenance: EdgeProvenance;
  /** Left out, the edge keeps what it had: a new agent inherits the old note until it writes its own. */
  introduceOk?: boolean;
  summary?: string | null;
  at: Date;
}

export interface EdgeQuery {
  from?: string[];
  principals?: string[];
  to?: string[];
  minStrength?: number;
  includeHidden?: boolean;
}

export interface GraphStore {
  init(): Promise<void>;
  attestation(id: string): Promise<Attestation | null>;
  insertAttestations(records: Attestation[]): Promise<void>;
  /** Unretracted attestations, oldest first. */
  attestations(q: AttestationQuery): Promise<Attestation[]>;
  updateAttestation(id: string, patch: Partial<Attestation>): Promise<Attestation | null>;
  entity(id: string): Promise<Entity | null>;
  entityByDomain(domain: string): Promise<Entity | null>;
  entitiesNamed(prefix: string, limit: number): Promise<Entity[]>;
  /** Insert, or answer the entity that already holds the domain. */
  insertEntity(e: Entity): Promise<Entity>;
  updateEntity(id: string, patch: Partial<Entity>): Promise<Entity | null>;
  /** This person's challenge, replacing theirs and dropping expired ones. */
  setChallenge(id: string, challenge: Entity['challenges'][number], now: Date): Promise<void>;
  /** Claim it if nobody has; null when someone did. */
  claimEntity(id: string, by: NonNullable<Entity['claimedBy']>): Promise<Entity | null>;
  edge(id: string): Promise<Edge | null>;
  writeEdge(e: EdgeWrite): Promise<Edge>;
  updateEdge(id: string, patch: Partial<Edge>): Promise<Edge | null>;
  deleteEdges(filter: { id?: string; owner?: EdgeOwner; writtenBy?: string; before?: Date }): Promise<number>;
  /** Edges not hidden (unless asked), matching every condition given. */
  edges(q: EdgeQuery): Promise<Edge[]>;
  /** Move a person's attestations and edges to another. */
  reassign(from: string, to: string): Promise<void>;
  /** Every edge from or to these principals, and every attestation by or about them; their entity claims end. */
  forget(principals: string[]): Promise<void>;
  /** Where records outlive an agent, its address becomes `ref`. */
  renameAgent(address: string, ref: string): Promise<void>;
  /** Others' attestations still pending, written before a time. */
  dropPending(before: Date): Promise<number>;
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function mongoGraph(db: Db): GraphStore {
  const attestations = db.collection<Attestation>('directory.attestations');
  const entities = db.collection<Entity>('directory.entities');
  const edges = db.collection<Edge>('directory.edges');
  const edgeFilter = (q: EdgeQuery): Filter<Edge> => {
    const f: Filter<Edge> = {};
    if (q.from) f.from = { $in: q.from };
    if (q.principals) f.principal = { $in: q.principals };
    if (q.to) f.to = { $in: q.to };
    if (q.minStrength) f.strength = { $gte: q.minStrength };
    if (!q.includeHidden) f.hiddenAt = null;
    return f;
  };
  return {
    async init() {
      await attestations.createIndex({ subject: 1, field: 1 });
      await attestations.createIndex({ field: 1, 'value.entity': 1 });
      await attestations.createIndex({ authorPrincipal: 1 });
      await attestations.createIndex({ authorAgent: 1 });
      await attestations.createIndex({ disposition: 1, createdAt: 1 });
      await entities.createIndex(
        { domains: 1 },
        { unique: true, partialFilterExpression: { 'domains.0': { $exists: true } } },
      );
      await entities.createIndex({ name: 1 });
      await edges.createIndex({ from: 1, principal: 1, via: 1 }, { unique: true });
      await edges.createIndex({ to: 1, strength: 1 });
      await edges.createIndex({ writtenBy: 1 });
      await edges.createIndex({ updatedAt: 1 });
    },
    attestation: id => attestations.findOne({ _id: id }),
    insertAttestations: async records => void (records.length && (await attestations.insertMany(records))),
    attestations(q) {
      const f: Filter<Attestation> = { retractedAt: null };
      if (q.subjects) f.subject = { $in: q.subjects };
      if (q.fields) f.field = { $in: q.fields };
      if (q.entities) Object.assign(f, { 'value.entity': { $in: q.entities } });
      if (q.normContains) f.norm = { $regex: escape(q.normContains.toLowerCase()) };
      if (q.authorPrincipal) f.authorPrincipal = q.authorPrincipal;
      if (q.dispositions) f.disposition = { $in: q.dispositions };
      return attestations.find(f).sort({ _id: 1 }).limit(5000).toArray();
    },
    updateAttestation: (id, patch) =>
      attestations.findOneAndUpdate({ _id: id }, { $set: patch }, { returnDocument: 'after' }),
    entity: id => entities.findOne({ _id: id }),
    entityByDomain: domain => entities.findOne({ domains: domain }),
    entitiesNamed(prefix, limit) {
      const rx = new RegExp(`^${escape(prefix.trim())}`, 'i');
      return entities
        .find({ $or: [{ name: rx }, { aliases: rx }] })
        .limit(limit)
        .toArray();
    },
    async insertEntity(e) {
      if (await insertOnce(() => entities.insertOne(e), 'domains')) return e;
      return (await entities.findOne({ domains: e.domains[0] }))!;
    },
    updateEntity: (id, patch) => entities.findOneAndUpdate({ _id: id }, { $set: patch }, { returnDocument: 'after' }),
    /** Written only over the list it was computed from, and computed again when another write got there first. */
    async setChallenge(id, challenge, now) {
      for (;;) {
        const doc = await entities.findOne({ _id: id }, { projection: { challenges: 1 } });
        if (!doc) return;
        const challenges = [
          ...(doc.challenges ?? []).filter(c => c.person !== challenge.person && c.expiresAt > now),
          challenge,
        ];
        const r = await entities.updateOne({ _id: id, challenges: doc.challenges }, { $set: { challenges } });
        if (r.matchedCount) return;
      }
    },
    claimEntity: (id, by) =>
      entities.findOneAndUpdate(
        { _id: id, claimedBy: null },
        { $set: { claimedBy: by, challenges: [] } },
        { returnDocument: 'after' },
      ),
    edge: id => edges.findOne({ _id: id }),
    async writeEdge({ introduceOk, summary, at, ...fields }) {
      const set: Partial<Edge> = { ...fields, updatedAt: at };
      const onInsert: Partial<Edge> = { _id: newId('edge'), createdAt: at, hiddenAt: null };
      (introduceOk === undefined ? onInsert : set).introduceOk = introduceOk ?? true;
      (summary === undefined ? onInsert : set).summary = summary ?? null;
      for (;;) {
        try {
          return (await edges.findOneAndUpdate(
            { from: fields.from, principal: fields.principal, via: fields.via },
            { $set: set, $setOnInsert: onInsert },
            { upsert: true, returnDocument: 'after' },
          ))!;
        } catch (e) {
          // Two first writes raced to insert: the loser writes again, onto the winner's edge.
          if (!isDuplicate(e)) throw e;
        }
      }
    },
    updateEdge: (id, patch) => edges.findOneAndUpdate({ _id: id }, { $set: patch }, { returnDocument: 'after' }),
    async deleteEdges(q) {
      const f: Filter<Edge> = q.owner ? { from: q.owner.from, principal: { $in: q.owner.principals } } : {};
      if (q.id) f._id = q.id;
      if (q.writtenBy) f.writtenBy = q.writtenBy;
      if (q.before) f.updatedAt = { $lt: q.before };
      return (await edges.deleteMany(f)).deletedCount;
    },
    edges: q => edges.find(edgeFilter(q)).limit(50_000).toArray(),
    async reassign(from, to) {
      await attestations.updateMany({ subject: from }, { $set: { subject: to } });
      await attestations.updateMany({ authorPrincipal: from }, { $set: { authorPrincipal: to } });
      await edges.updateMany({ to: from }, { $set: { to } });
      // Where the other person already holds an edge by the same identifier, theirs stays.
      for (const e of await edges.find({ from }).toArray()) {
        try {
          await edges.updateOne({ _id: e._id }, { $set: { from: to } });
        } catch (err) {
          if (!isDuplicate(err)) throw err;
          await edges.deleteOne({ _id: e._id });
        }
      }
      await edges.deleteMany({ $expr: { $eq: ['$from', '$to'] } });
    },
    async forget(principals) {
      await edges.deleteMany({ $or: [{ from: { $in: principals } }, { to: { $in: principals } }] });
      await attestations.deleteMany({
        $or: [{ subject: { $in: principals } }, { authorPrincipal: { $in: principals } }],
      });
      await entities.updateMany({ 'claimedBy.person': { $in: principals } }, { $set: { claimedBy: null } });
      await entities.updateMany(
        { 'challenges.person': { $in: principals } },
        { $pull: { challenges: { person: { $in: principals } } } },
      );
    },
    async renameAgent(address, ref) {
      await edges.updateMany({ writtenBy: address }, { $set: { writtenBy: ref } });
      await attestations.updateMany({ authorAgent: address }, { $set: { authorAgent: ref } });
      await entities.updateMany({ 'claimedBy.agent': address }, { $set: { 'claimedBy.agent': ref } });
    },
    dropPending: async before =>
      (await attestations.deleteMany({ disposition: 'pending', createdAt: { $lt: before } })).deletedCount,
  };
}
