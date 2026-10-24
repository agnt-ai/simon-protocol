/** Introduction requests, in `intros.requests`. Every change is compare-and-set on state and revision. */
import type { Db, Filter } from 'mongodb';

export interface Seat {
  /** The agent asked, by address, and the person it speaks for. */
  agent: string;
  person: string;
  /** queued: in a wave not yet opened, and never told of the request unless it opens. */
  state: 'queued' | 'pending' | 'carried' | 'declined' | 'withdrawn';
  auto: boolean;
  notifiedAt: Date | null;
  decidedAt: Date | null;
}

export interface Intro {
  _id: string;
  requesterAgent: string;
  requesterPerson: string;
  /** The identifier the requester named. */
  target: string;
  targetPerson: string | null;
  brief: string;
  subject: string;
  /** The requester only ever sees `submitted`, then the introduction or the expiry. */
  state: 'submitted' | 'routed' | 'carried' | 'accepted' | 'closed';
  carriers: Seat[];
  carriedBy: string | null;
  targetAgents: string[];
  targetDecision: { agent: string; decision: 'accept' | 'decline'; at: Date } | null;
  /** The one verified identifier the requester chose to be known by. */
  presentAs: string | null;
  introduced: { requester: string; target: string; at: Date } | null;
  routeAfter: Date;
  nextWaveAt: Date | null;
  expiresAt: Date;
  closedReason: string | null;
  createdAt: Date;
  rev: number;
}

export interface IntroStore {
  init(): Promise<void>;
  get(id: string): Promise<Intro | null>;
  insert(i: Intro): Promise<void>;
  /** Change it only if it is in one of `from` states (and at revision `rev`, when given); raises `rev`. */
  transition(id: string, from: Intro['state'][], patch: Partial<Intro>, rev?: number): Promise<Intro | null>;
  dueForRouting(now: Date, limit: number): Promise<Intro[]>;
  dueWaves(now: Date, limit: number): Promise<Intro[]>;
  expired(now: Date, limit: number): Promise<Intro[]>;
  byRequesterAgent(agent: string, page: { after?: string; limit: number }): Promise<Intro[]>;
  pendingForCarrier(agent: string, limit: number): Promise<Intro[]>;
  pendingForTarget(agent: string, limit: number): Promise<Intro[]>;
  /** What a person asked for, was asked to carry (once told), or received. */
  involving(person: string, page: { after?: string; limit: number }): Promise<Intro[]>;
  reassign(from: string, to: string): Promise<void>;
  /** Drop requests that expired before a time. Answers how many. */
  prune(before: Date): Promise<number>;
  /** Drop every request a person asked for, carried, or was asked about. */
  forget(person: string): Promise<void>;
  /** Name a retired agent by `ref` wherever an introduction outlives it. */
  renameAgent(address: string, ref: string): Promise<void>;
}

const OPEN: Intro['state'][] = ['submitted', 'routed', 'carried'];

export function mongoIntros(db: Db): IntroStore {
  const intros = db.collection<Intro>('intros.requests');
  const after = (page: { after?: string }): Filter<Intro> => (page.after ? { _id: { $gt: page.after } } : {});
  return {
    async init() {
      await intros.createIndex({ state: 1, routeAfter: 1 });
      await intros.createIndex({ state: 1, nextWaveAt: 1 });
      await intros.createIndex({ requesterPerson: 1 });
      await intros.createIndex({ 'carriers.agent': 1, state: 1 });
      await intros.createIndex({ targetAgents: 1, state: 1 });
      await intros.createIndex({ expiresAt: 1 });
    },
    get: id => intros.findOne({ _id: id }),
    insert: async i => void (await intros.insertOne(i)),
    transition: (id, from, patch, rev) =>
      intros.findOneAndUpdate(
        { _id: id, state: { $in: from }, ...(rev === undefined ? {} : { rev }) },
        { $set: patch, $inc: { rev: 1 } },
        { returnDocument: 'after' },
      ),
    dueForRouting: (now, limit) =>
      intros
        .find({ state: 'submitted', routeAfter: { $lte: now } })
        .limit(limit)
        .toArray(),
    dueWaves: (now, limit) =>
      intros
        .find({ state: 'routed', nextWaveAt: { $lte: now } })
        .limit(limit)
        .toArray(),
    expired: (now, limit) =>
      intros
        .find({ state: { $in: OPEN }, expiresAt: { $lte: now } })
        .limit(limit)
        .toArray(),
    byRequesterAgent: (agent, page) =>
      intros
        .find({ requesterAgent: agent, ...after(page) })
        .sort({ _id: 1 })
        .limit(page.limit + 1)
        .toArray(),
    pendingForCarrier: (agent, limit) =>
      intros
        .find({ state: 'routed', carriers: { $elemMatch: { agent, state: 'pending' } } })
        .sort({ _id: 1 })
        .limit(limit)
        .toArray(),
    pendingForTarget: (agent, limit) =>
      intros.find({ state: 'carried', targetAgents: agent }).sort({ _id: 1 }).limit(limit).toArray(),
    involving: (person, page) =>
      intros
        .find({
          ...after(page),
          $or: [
            { requesterPerson: person },
            { targetPerson: person, state: { $in: ['carried', 'accepted'] } },
            {
              carriers: {
                $elemMatch: { person, $or: [{ notifiedAt: { $ne: null } }, { auto: true, state: 'carried' }] },
              },
            },
          ],
        })
        .sort({ _id: 1 })
        .limit(page.limit + 1)
        .toArray(),
    async reassign(from, to) {
      await intros.updateMany({ requesterPerson: from }, { $set: { requesterPerson: to } });
      await intros.updateMany({ targetPerson: from }, { $set: { targetPerson: to } });
      await intros.updateMany(
        { 'carriers.person': from },
        { $set: { 'carriers.$[seat].person': to } },
        { arrayFilters: [{ 'seat.person': from }] },
      );
    },
    prune: async before => (await intros.deleteMany({ expiresAt: { $lt: before } })).deletedCount,
    async renameAgent(address, ref) {
      await intros.updateMany({ requesterAgent: address }, { $set: { requesterAgent: ref } });
      await intros.updateMany(
        { targetAgents: address },
        { $set: { 'targetAgents.$[a]': ref } },
        { arrayFilters: [{ a: address }] },
      );
      await intros.updateMany(
        { 'carriers.agent': address },
        { $set: { 'carriers.$[c].agent': ref } },
        { arrayFilters: [{ 'c.agent': address }] },
      );
      await intros.updateMany({ 'targetDecision.agent': address }, { $set: { 'targetDecision.agent': ref } });
      await intros.updateMany({ 'introduced.requester': address }, { $set: { 'introduced.requester': ref } });
      await intros.updateMany({ 'introduced.target': address }, { $set: { 'introduced.target': ref } });
    },
    forget: async person =>
      void (await intros.deleteMany({
        $or: [{ requesterPerson: person }, { targetPerson: person }, { 'carriers.person': person }],
      })),
  };
}
