/**
 * The directory's people: a person, the identifiers (principals) that are theirs, and the pairs whose
 * principal is one of them. Kept in `directory.people`, `directory.identifiers` and `directory.pairings`.
 */
import type { Db } from 'mongodb';
import { insertOnce } from '../../store/db.ts';
import type { ContactTier, Discoverability, Grade, IntroCarrying, ScopeAction } from './vocab.ts';

export interface Listing {
  /** Listing is the person's explicit act: until then nobody finds them. */
  listed: boolean;
  listedAt: Date | null;
  discoverability: Discoverability;
  contact: ContactTier;
  /** Whether the person's own edges may carry others' second-degree relationships: their explicit opt-in. */
  secondDegreeOptIn: boolean;
  introCarrying: IntroCarrying;
  introAutoMinGrade: Grade;
}

export interface Person {
  _id: string;
  /** Someone proved an identifier of theirs: by a code, by pairing, or by a key principal's signature. */
  claimed: boolean;
  /** Set when this record was merged into another, which is the person now. */
  mergedInto: string | null;
  listing: Listing;
  createdAt: Date;
}

/** An identifier, by its principal: the person it belongs to, and when it was last proven theirs. */
export interface Identifier {
  _id: string;
  person: string;
  verifiedAt: Date | null;
  createdAt: Date;
}

/** A pair this server verified: the agent at `address` speaks for `principal`, a person's identifier. */
export interface Pairing {
  _id: string;
  address: string;
  principal: string;
  person: string;
  scope: ScopeAction[];
  verifiedAt: Date;
  /** The agent's keys were replaced by a code to its address; until the person confirms, it only converses. */
  recoveredAt: Date | null;
  /** The one-time link in the notice sent after a recovery. */
  reconfirm: { tokenHash: string; expiresAt: Date } | null;
}

export interface PeopleStore {
  init(): Promise<void>;
  person(id: string): Promise<Person | null>;
  people(ids: string[]): Promise<Person[]>;
  insertPerson(p: Person): Promise<void>;
  updatePerson(id: string, patch: Partial<Omit<Person, '_id'>>): Promise<Person | null>;
  /** Delete people, with their identifiers and pairs, and the records merged into them. */
  deletePeople(ids: string[]): Promise<void>;
  /** People nobody claimed, made before a time: oldest first. */
  unclaimed(before: Date, limit: number): Promise<string[]>;
  identifier(principal: string): Promise<Identifier | null>;
  identifiersOf(persons: string[]): Promise<Identifier[]>;
  /** False when the principal is already someone's. */
  insertIdentifier(i: Identifier): Promise<boolean>;
  /** Proven again now. */
  verifyIdentifier(principal: string, at: Date): Promise<void>;
  /** Give an identifier to another person. */
  moveIdentifier(principal: string, to: string): Promise<void>;
  pairing(address: string, principal: string): Promise<Pairing | null>;
  pairingsOf(person: string): Promise<Pairing[]>;
  pairingByToken(tokenHash: string): Promise<Pairing | null>;
  putPairing(p: Pairing): Promise<void>;
  updatePairing(id: string, patch: Partial<Omit<Pairing, '_id'>>): Promise<Pairing | null>;
  deletePairings(address: string): Promise<void>;
  /** Move identifiers and pairs from one person to another. */
  reassign(from: string, to: string): Promise<void>;
}

export const pairingId = (address: string, principal: string) => `${address} ${principal}`;

export function mongoPeople(db: Db): PeopleStore {
  const people = db.collection<Person>('directory.people');
  const identifiers = db.collection<Identifier>('directory.identifiers');
  const pairings = db.collection<Pairing>('directory.pairings');
  return {
    async init() {
      await people.createIndex({ claimed: 1, createdAt: 1 });
      await people.createIndex({ mergedInto: 1 }, { sparse: true });
      await identifiers.createIndex({ person: 1 });
      await pairings.createIndex({ person: 1 });
      await pairings.createIndex({ address: 1 });
      await pairings.createIndex({ 'reconfirm.tokenHash': 1 }, { sparse: true });
    },
    person: id => people.findOne({ _id: id }),
    people: ids => people.find({ _id: { $in: ids } }).toArray(),
    insertPerson: async p => void (await people.insertOne(p)),
    updatePerson: (id, patch) => people.findOneAndUpdate({ _id: id }, { $set: patch }, { returnDocument: 'after' }),
    async deletePeople(ids) {
      const merged = (await people.find({ mergedInto: { $in: ids } }, { projection: { _id: 1 } }).toArray()).map(
        p => p._id,
      );
      const all = [...ids, ...merged];
      await identifiers.deleteMany({ person: { $in: all } });
      await pairings.deleteMany({ person: { $in: all } });
      await people.deleteMany({ _id: { $in: all } });
    },
    unclaimed: async (before, limit) =>
      (
        await people
          .find({ claimed: false, mergedInto: null, createdAt: { $lt: before } }, { projection: { _id: 1 } })
          .sort({ createdAt: 1 })
          .limit(limit)
          .toArray()
      ).map(p => p._id),
    identifier: principal => identifiers.findOne({ _id: principal }),
    identifiersOf: persons =>
      identifiers
        .find({ person: { $in: persons } })
        .sort({ createdAt: 1 })
        .toArray(),
    insertIdentifier: i => insertOnce(() => identifiers.insertOne(i), '_id'),
    verifyIdentifier: async (principal, at) =>
      void (await identifiers.updateOne({ _id: principal }, { $set: { verifiedAt: at } })),
    moveIdentifier: async (principal, to) =>
      void (await identifiers.updateOne({ _id: principal }, { $set: { person: to } })),
    pairing: (address, principal) => pairings.findOne({ _id: pairingId(address, principal) }),
    pairingsOf: person => pairings.find({ person }).sort({ verifiedAt: 1 }).toArray(),
    pairingByToken: tokenHash => pairings.findOne({ 'reconfirm.tokenHash': tokenHash }),
    putPairing: async p => void (await pairings.replaceOne({ _id: p._id }, p, { upsert: true })),
    updatePairing: (id, patch) => pairings.findOneAndUpdate({ _id: id }, { $set: patch }, { returnDocument: 'after' }),
    deletePairings: async address => void (await pairings.deleteMany({ address })),
    async reassign(from, to) {
      await identifiers.updateMany({ person: from }, { $set: { person: to } });
      await pairings.updateMany({ person: from }, { $set: { person: to } });
    },
  };
}
