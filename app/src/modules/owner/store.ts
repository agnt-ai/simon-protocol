/** The owner window's sign-in records: OAuth clients, sign-ins under way, and tokens. Kept in `owner.*`. */
import type { Db } from 'mongodb';

export interface Client {
  _id: string;
  name: string;
  redirectUris: string[];
  createdAt: Date;
}

/** A sign-in under way, from the authorization request to the code handed back to the client. */
export interface Login {
  _id: string;
  client: string;
  redirectUri: string;
  codeChallenge: string;
  state: string | null;
  /** The identifier a code was sent to, or a key principal asked to sign. */
  identifier: string | null;
  /** What a key principal signs to sign in. */
  challenge: string | null;
  /** Set once the identifier is proven: the authorization code's hash, and whose it is. */
  authCodeHash: string | null;
  person: string | null;
  expiresAt: Date;
}

export interface Token {
  _id: string;
  tokenHash: string;
  kind: 'access' | 'refresh' | 'api_key';
  person: string;
  /** The sign-in it came from: its tokens share what is proven in it. An API key is a session of its own. */
  session: string;
  /** The identifiers proven in the session: all the owner window shows it, while each is fresh. */
  identifiers: string[];
  client: string | null;
  label: string | null;
  expiresAt: Date | null;
  revokedAt: Date | null;
  createdAt: Date;
}

export interface OwnerStore {
  init(): Promise<void>;
  client(id: string): Promise<Client | null>;
  insertClient(c: Client): Promise<void>;
  login(id: string): Promise<Login | null>;
  insertLogin(l: Login): Promise<void>;
  updateLogin(id: string, patch: Partial<Login>): Promise<void>;
  /** Spend an authorization code: the login it was for, once, or null. */
  spendAuthCode(hash: string, now: Date): Promise<Login | null>;
  token(hash: string): Promise<Token | null>;
  insertToken(t: Token): Promise<void>;
  /** Revoke it if it is not yet; true for the one call that did. */
  revoke(id: string, at: Date): Promise<boolean>;
  /** An identifier proven in a session, for every token of it. */
  prove(session: string, identifier: string): Promise<void>;
  /** A person's API keys whose identifiers all lie within these. */
  apiKeys(person: string, within: string[]): Promise<Token[]>;
  reassign(from: string, to: string): Promise<void>;
  /** Every token of a person. */
  forget(person: string): Promise<void>;
  /** Sign-ins and tokens that expired before a time. Answers how many. */
  prune(before: Date): Promise<number>;
}

export function mongoOwner(db: Db): OwnerStore {
  const clients = db.collection<Client>('owner.clients');
  const logins = db.collection<Login>('owner.logins');
  const tokens = db.collection<Token>('owner.tokens');
  return {
    async init() {
      await logins.createIndex({ authCodeHash: 1 }, { sparse: true });
      await tokens.createIndex({ tokenHash: 1 }, { unique: true });
      await tokens.createIndex({ person: 1, kind: 1 });
      await tokens.createIndex({ session: 1 });
      await tokens.createIndex({ expiresAt: 1 });
      await logins.createIndex({ expiresAt: 1 });
    },
    client: id => clients.findOne({ _id: id }),
    insertClient: async c => void (await clients.insertOne(c)),
    login: id => logins.findOne({ _id: id }),
    insertLogin: async l => void (await logins.insertOne(l)),
    updateLogin: async (id, patch) => void (await logins.updateOne({ _id: id }, { $set: patch })),
    spendAuthCode: (hash, now) =>
      logins.findOneAndUpdate(
        { authCodeHash: hash, expiresAt: { $gt: now } },
        { $set: { authCodeHash: null, expiresAt: now } },
      ),
    token: hash => tokens.findOne({ tokenHash: hash }),
    insertToken: async t => void (await tokens.insertOne(t)),
    revoke: async (id, at) =>
      (await tokens.updateOne({ _id: id, revokedAt: null }, { $set: { revokedAt: at } })).modifiedCount === 1,
    prove: async (session, identifier) =>
      void (await tokens.updateMany({ session }, { $addToSet: { identifiers: identifier } })),
    apiKeys: (person, within) =>
      tokens
        .find({ person, kind: 'api_key', revokedAt: null, identifiers: { $not: { $elemMatch: { $nin: within } } } })
        .sort({ _id: 1 })
        .toArray(),
    reassign: async (from, to) => void (await tokens.updateMany({ person: from }, { $set: { person: to } })),
    async forget(person) {
      await tokens.deleteMany({ person });
      await logins.deleteMany({ person });
    },
    async prune(before) {
      const signIns = await logins.deleteMany({ expiresAt: { $lt: before } });
      const spent = await tokens.deleteMany({ expiresAt: { $ne: null, $lt: before } });
      return signIns.deletedCount + spent.deletedCount;
    },
  };
}
