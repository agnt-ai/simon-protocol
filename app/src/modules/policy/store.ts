/**
 * Recipient policy's records: each agent's settings and allow and block lists, a person's own blocks,
 * invites, who was held and how often, who wrote to whom, and messages waiting for a limit to reopen.
 * Kept in `policy.*`.
 */
import type { Db } from 'mongodb';
import { insertOnce, upsert } from '../../store/db.ts';

export interface Settings {
  _id: string;
  /** `known`: only invites, the allow list and correspondents. */
  accept: 'anyone' | 'known';
  /** Refuse senders no verified principal stands behind. Off unless the agent turns it on. */
  requireVerifiedHuman: boolean;
}

export type EntryKind = 'address' | 'domain' | 'server';

/** One entry of a list, kept by an agent (`owner` its address) or by a person (`owner` their id). */
export interface Entry {
  _id: string;
  owner: string;
  list: 'allow' | 'block';
  kind: EntryKind;
  value: string;
  /** Who wrote it: `agent`, `owner` (the person), or a module, such as `intros`. */
  source: string;
  createdAt: Date;
}

export interface Invite {
  _id: string;
  agent: string;
  codeHash: string;
  expiresAt: Date;
  /** The message it let in: a retry of that message is let in again, and nothing else. */
  usedFor: string | null;
}

export interface Held {
  _id: string;
  agent: string;
  sender: string;
  /** The principal the sender spoke for, by its `for` header: its word, not a claim. */
  for: string | null;
  count: number;
  firstAt: Date;
  lastAt: Date;
}

/** A message a limit held back, offered again once the limit's window reopens. */
export interface Waiting {
  _id: string;
  agent: string;
  id: string;
  at: Date;
}

export interface PolicyStore {
  init(): Promise<void>;
  settings(agent: string): Promise<Settings>;
  setSettings(agent: string, patch: Partial<Omit<Settings, '_id'>>): Promise<Settings>;
  /** Whether any of these (kind, value) pairs is on one of the owners' list. */
  listed(owners: string[], list: Entry['list'], keys: { kind: EntryKind; value: string }[]): Promise<boolean>;
  entries(owner: string, list: Entry['list'], page: { after?: string; limit: number }): Promise<Entry[]>;
  /** True when the entry is new. */
  addEntry(e: Entry): Promise<boolean>;
  removeEntry(id: string): Promise<boolean>;
  insertInvite(i: Invite): Promise<void>;
  /** Use an unexpired invite for one message; true when it was unused, or used for this same message. */
  redeem(agent: string, codeHash: string, message: string, now: Date): Promise<boolean>;
  bumpHeld(h: Pick<Held, 'agent' | 'sender' | 'for'>, at: Date): Promise<void>;
  held(agents: string[], page: { after?: string; limit: number }): Promise<Held[]>;
  /** Record that `agent` wrote to `peer`, or heard from it. */
  correspond(agent: string, peer: string, how: 'wrote' | 'heard'): Promise<void>;
  corresponded(agent: string, peer: string): Promise<{ wrote: boolean; heard: boolean }>;
  /** Hold a message, or hold it again from a later moment. */
  wait(w: Waiting): Promise<void>;
  waiting(limit: number): Promise<Waiting[]>;
  /** Stop holding a message, unless it was held again after `at`. */
  doneWaiting(id: string, at: Date): Promise<void>;
  /** Everything kept for a retired agent, and about it in others' records. */
  forgetAgent(address: string): Promise<void>;
  /** A person's own lists. */
  forgetOwner(owner: string): Promise<void>;
}

export const entryId = (owner: string, list: string, kind: string, value: string) =>
  `${owner} ${list} ${kind}:${value}`;

export function mongoPolicy(db: Db): PolicyStore {
  const settings = db.collection<Settings>('policy.settings');
  const entries = db.collection<Entry>('policy.entries');
  const invites = db.collection<Invite>('policy.invites');
  const held = db.collection<Held>('policy.held');
  const contacts = db.collection<{ _id: string; agent: string; peer: string; wrote?: boolean; heard?: boolean }>(
    'policy.contacts',
  );
  const waiting = db.collection<Waiting>('policy.waiting');
  const defaults = (agent: string): Settings => ({ _id: agent, accept: 'anyone', requireVerifiedHuman: false });
  return {
    async init() {
      await entries.createIndex({ owner: 1, list: 1, kind: 1, value: 1 });
      await invites.createIndex({ agent: 1, codeHash: 1 });
      await held.createIndex({ agent: 1 });
      await held.createIndex({ sender: 1 });
      await contacts.createIndex({ agent: 1 });
      await contacts.createIndex({ peer: 1 });
    },
    settings: async agent => ({ ...defaults(agent), ...(await settings.findOne({ _id: agent })) }),
    async setSettings(agent, patch) {
      await upsert(() => settings.updateOne({ _id: agent }, { $set: patch }, { upsert: true }));
      return { ...defaults(agent), ...(await settings.findOne({ _id: agent })) };
    },
    async listed(owners, list, keys) {
      if (!owners.length || !keys.length) return false;
      return (await entries.countDocuments({ owner: { $in: owners }, list, $or: keys }, { limit: 1 })) > 0;
    },
    entries: (owner, list, page) =>
      entries
        .find({ owner, list, ...(page.after ? { _id: { $gt: page.after } } : {}) })
        .sort({ _id: 1 })
        .limit(page.limit + 1)
        .toArray(),
    addEntry: e => insertOnce(() => entries.insertOne(e), '_id'),
    removeEntry: async id => (await entries.deleteOne({ _id: id })).deletedCount === 1,
    insertInvite: async i => void (await invites.insertOne(i)),
    async redeem(agent, codeHash, message, now) {
      const r = await invites.updateOne(
        { agent, codeHash, expiresAt: { $gt: now }, $or: [{ usedFor: null }, { usedFor: message }] },
        { $set: { usedFor: message } },
      );
      return r.matchedCount === 1;
    },
    async bumpHeld({ agent, sender, for: forValue }, at) {
      await upsert(() =>
        held.updateOne(
          { _id: `${agent} ${sender}` },
          { $inc: { count: 1 }, $set: { lastAt: at, for: forValue }, $setOnInsert: { agent, sender, firstAt: at } },
          { upsert: true },
        ),
      );
    },
    held: (agents, page) =>
      held
        .find({ agent: { $in: agents }, ...(page.after ? { _id: { $gt: page.after } } : {}) })
        .sort({ _id: 1 })
        .limit(page.limit + 1)
        .toArray(),
    async correspond(agent, peer, how) {
      await upsert(() =>
        contacts.updateOne({ _id: `${agent} ${peer}` }, { $set: { agent, peer, [how]: true } }, { upsert: true }),
      );
    },
    async corresponded(agent, peer) {
      const c = await contacts.findOne({ _id: `${agent} ${peer}` });
      return { wrote: !!c?.wrote, heard: !!c?.heard };
    },
    wait: async w => void (await upsert(() => waiting.replaceOne({ _id: w._id }, w, { upsert: true }))),
    waiting: limit => waiting.find().sort({ at: 1 }).limit(limit).toArray(),
    doneWaiting: async (id, at) => void (await waiting.deleteOne({ _id: id, at })),
    async forgetAgent(address) {
      await settings.deleteOne({ _id: address });
      // Its own lists, and every entry naming it: a retired address is never anyone's again.
      await entries.deleteMany({ $or: [{ owner: address }, { kind: 'address', value: address }] });
      await invites.deleteMany({ agent: address });
      await held.deleteMany({ $or: [{ agent: address }, { sender: address }] });
      await contacts.deleteMany({ $or: [{ agent: address }, { peer: address }] });
      await waiting.deleteMany({ agent: address });
    },
    forgetOwner: async owner => void (await entries.deleteMany({ owner })),
  };
}
