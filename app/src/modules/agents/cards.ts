/**
 * Agent cards: what an agent says about itself (a name, a description, what it can do), declared and not
 * verified, and whether anyone may read it. Kept in `agents.cards`, with the agent's read cursor.
 */
import type { Agent } from '@agnt-protocol/server';
import type { Db } from 'mongodb';
import { fingerprint } from '../../lib/secrets.ts';
import { isDuplicate } from '../../store/db.ts';

export interface Capabilities {
  email: boolean;
  attachments: boolean;
  contentTypes: string[];
  homepage: string | null;
}

export interface Card {
  _id: string;
  name: string;
  description: string;
  capabilities: Capabilities;
  /** Readable by anyone who resolves the agent's address. */
  listed: boolean;
  /** The highest inbox cursor the agent marked read. */
  readCursor: number;
}

export interface CardStore {
  card(address: string): Promise<Card>;
  update(address: string, patch: Partial<Omit<Card, '_id'>>): Promise<Card>;
  /** Raise the read cursor; never lower it. */
  markRead(address: string, cursor: number): Promise<void>;
  forget(address: string): Promise<void>;
}

const blank = (address: string): Card => ({
  _id: address,
  name: '',
  description: '',
  capabilities: { email: false, attachments: false, contentTypes: [], homepage: null },
  listed: false,
  readCursor: 0,
});

export function mongoCards(db: Db): CardStore {
  const cards = db.collection<Card>('agents.cards');
  // A card is stored once the agent changes it; until then, and for any field it never set, the blank one.
  const card = async (address: string) => ({ ...blank(address), ...(await cards.findOne({ _id: address })) });
  return {
    card,
    async update(address, patch) {
      await cards.updateOne({ _id: address }, { $set: patch }, { upsert: true });
      return card(address);
    },
    markRead: async (address, cursor) =>
      void (await cards.updateOne({ _id: address }, { $max: { readCursor: cursor } }, { upsert: true }).catch(e => {
        // Two first reads at once: the one that made the card won; raise it now.
        if (!isDuplicate(e, '_id')) throw e;
        return cards.updateOne({ _id: address }, { $max: { readCursor: cursor } });
      })),
    forget: async address => void (await cards.deleteOne({ _id: address })),
  };
}

/** What anyone allowed to read an agent's card sees. */
export const cardView = (agent: Agent, card: Card) => ({
  address: agent.address,
  kind: agent.kind,
  name: card.name,
  description: card.description,
  capabilities: card.capabilities,
  keys: agent.keys.filter(k => !k.revoked).map(k => ({ key: k.key, fingerprint: fingerprint(k.key) })),
  createdAt: agent.createdAt,
});
