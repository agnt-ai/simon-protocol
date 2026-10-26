/**
 * The server's Store on MongoDB and Amazon DocumentDB, verified by the shared contract suite
 * (test/store.test.ts). Each rule is one atomic document write or a unique index:
 *
 *   core.agents      one document per address; a unique index on `keys.key` gives a key to one agent
 *   core.messages    one per id, the message and claims kept as canonical JSON text (a later version's
 *                    members may be anything); a published one numbered from one counter, to page by; one
 *                    written here with its position in its author's sync stream
 *   core.deliveries  one per (id, domain), claimed by a findOneAndUpdate that sets its lease
 *   core.arrivals    one per (id, recipient)
 *   core.inbox       one per (address, id), its inbox event a field of it
 *   core.signals     one per position, gone once it expires (a TTL index, and every new signal)
 *                    every position in sync streams comes from one counter
 *   core.webhooks    one per id, in one of its agent's numbered places, unique per agent, so a cap holds
 *   core.parts       bytes by (sha256, source), in chunks under MongoDB's document limit
 *   core.fetches     one per (sha256, carrier)
 *   core.marks, core.counters, core.values   scoped by name, each with its expiry
 *
 * A message and its rows are stored as one by writing the rows into the message's own document first
 * (`rows`), in the single insert that commits it, and copying them out to their collections afterwards.
 * A crash between the two leaves the rows in the message, where the next claim copies them out.
 */
import { randomUUID } from 'node:crypto';
import {
  Binary,
  MongoServerError,
  type Collection,
  type CreateIndexesOptions,
  type Db,
  type Document,
  type Filter,
  type IndexSpecification,
} from 'mongodb';
import {
  canonicalize,
  header,
  namedFiles,
  type AnyMessage,
  type Claim,
  type Hints,
  type SignedClaims,
  VERSION,
} from '@agnt-sdk/simon-protocol';
import type {
  Agent,
  AgentKey,
  AgentAdmission,
  Delivery,
  HeldSignal,
  Page,
  PartFetch,
  PartSource,
  QueuedArrival,
  Store,
  StoredMessage,
  SweepCounts,
  SyncEntry,
  Webhook,
} from '@agnt-sdk/simon-server';
import {
  MAX_STORED_KEYS,
  StoreCapacityError,
  resolveRetractionCapacity,
  type RetractionCapacity,
} from '@agnt-sdk/simon-server';
import { insertOnce, isDuplicate } from './db.ts';

interface AgentDoc extends Omit<Agent, 'address'> {
  _id: string;
  recoveryMigrated?: boolean;
  recovery?: { value: string; expires: Date | null } | null;
}
interface MessageDoc {
  _id: string;
  generation?: string;
  revision?: number;
  deleted?: boolean;
  json: string;
  from: string;
  to: string[];
  public: boolean;
  /** Its place among published messages, newest highest; only on a published message. */
  seq?: number;
  /** Distinguishes actual sent history from public listing cursor backfill. */
  written?: boolean;
  inReplyTo: string | null;
  carrier: string;
  claims: string;
  signedClaims: string | null;
  receivedAt: string;
  expires: Date;
  parts: { sha256: string; size: number }[];
  /** False for a received message no arrival has kept yet. */
  kept: boolean;
  /** A message written here: its position in its author's sync stream, and when it entered it. */
  cursor?: number;
  settled?: boolean;
  taken?: Date;
  /** Rows stored with the message and not yet copied out to their collections. */
  rows?: { deliveries: DeliveryDoc[]; arrivals: ArrivalDoc[] };
  pendingRows?: Record<string, { deliveries: DeliveryDoc[]; arrivals: ArrivalDoc[] }>;
  retractions?: { owner: string; target: string; author: string; retraction: string }[];
}
/** What telling who holds a part needs of a message that names it. */
type NamingDoc = Pick<MessageDoc, '_id' | 'from' | 'carrier' | 'parts' | 'generation'>;
interface InboxDoc {
  _id: string;
  messageGeneration?: string;
  cursor: number;
  address: string;
  id: string;
  taken: Date;
  /** Whether its inbox event is still to be told. */
  event: boolean;
  /** False until its writer has settled its cursor; absent on an entry an earlier version wrote. */
  settled?: boolean;
  /** The hashes of the files its message names, so the parts held for an agent are found from its own entries. */
  parts?: string[];
}
interface SignalDoc extends Omit<HeldSignal, 'cursor'> {
  /** Its position. */
  _id: string;
  cursor: number;
  settled?: boolean;
  address: string;
  expires: Date;
}
interface WebhookDoc extends Omit<Webhook, 'id'> {
  _id: string;
  /** Its place among its agent's webhooks, unique per agent. */
  slot: number;
  due: Date | null;
  quietUntil: Date;
  lease?: string | null;
  leaseUntil?: Date | null;
}
interface DeliveryDoc extends Omit<Delivery, 'hints' | 'nextAttemptAt'> {
  _id: string;
  messageGeneration?: string;
  hints: string;
  nextAttemptAt: Date;
  lease: string | null;
}
interface ArrivalDoc {
  done?: boolean;
  _id: string;
  messageGeneration?: string;
  id: string;
  recipient: string;
  hints: string;
  attempts: number;
  due: Date;
}
interface PartDoc {
  _id: string;
  sha256: string;
  /** The uploader's address, or the carrier's origin. */
  source: string;
  fetched: boolean;
  size: number;
  chunks: number;
  created: Date;
}
interface FetchDoc {
  _id: string;
  sha256: string;
  carrier: string;
  size: number;
  attempts: number;
  due: Date;
  token?: string | null;
  exhausted?: Date | null;
  revision?: number;
  generation?: string;
}
interface Sequence {
  _id: string;
  n: number;
  /** Cursors handed out whose entries are not written yet, each with when the database handed it out. */
  pending?: Record<string, Date>;
  /** The database's clock at the last read, stamped by that read. */
  now?: Date;
  /** Positions committed before their entries were marked settled; removed only after that write. */
  committed?: Record<string, boolean>;
}
interface Expiring {
  _id: string;
  n?: number;
  value?: string;
  expires: Date | null;
}

interface RetractionReceipt {
  record: StoredMessage | null;
  author: string;
  markers: { owner: string; target: string; author: string; retraction: string }[];
  generation: string;
  active: boolean;
  materialized: boolean;
  written: boolean;
  kept: boolean;
  keptReported: boolean;
  outstandingArrivals: string[];
  expiresAt: string;
  knownDeliveries: string[];
  knownArrivals: string[];
  pendingDeliveries: Record<string, Delivery>;
  pendingArrivals: Record<string, QueuedArrival>;
}
interface RetractionAdmission {
  _id: string;
  revision: number;
  body: string;
}
const ADMISSION = 'listing-retraction-admission-v1';

const CHUNK_BYTES = 8 * 1024 * 1024;
/** A cursor still unwritten after this long, by the database's clock, belongs to a writer that crashed. */
const ABANDONED_MS = 60_000;

const date = (iso: string) => new Date(iso);
/** When an entry an earlier version wrote was received, as `$toDate` read it: null if it has no time. */
const receivedAt = (e: object) => {
  const at = (e as { receivedAt?: string | Date | null }).receivedAt;
  return (at == null ? null : new Date(at)) as Date;
};
/** Mongo's legacy null equality matches either an absent epoch or BSON null; preserve that CAS predicate. */
const authoritySnapshot = (version: AgentDoc['authorityVersion']): Filter<AgentDoc> =>
  version == null
    ? { $or: [{ authorityVersion: { $exists: false } }, { authorityVersion: { $type: 'null' } }] }
    : { authorityVersion: version };

/** After a read-then-write that another write beat: a short random wait, longer each time, before reading again. */
const backoff = (attempt: number) =>
  new Promise(resolve => setTimeout(resolve, Math.random() * Math.min(100, 2 ** attempt)));
const key = (scope: string, id: string) => `${scope}\n${id}`;
/** Inbox entries naming one part read for one holder, at most (heldFor). */
const HELD_ENTRIES = 1000;
/** Rows of each child collection examined for a missing message per sweep, resuming where the last stopped. */
const ORPHAN_SCAN = 5000;
/** Fetch rows examined for a message still naming them per sweep, resuming where the last stopped. */
const FETCH_SCAN = 5000;

const sourceKey = (s: PartSource) => ('uploader' in s ? s.uploader : s.carrier);

/** Sources found along more than one path, once each. */
const uniqueSources = <T extends PartSource & { size: number }>(sources: T[]) => [
  ...new Map(sources.map(s => [`${'uploader' in s ? 'u' : 'c'} ${sourceKey(s)} ${s.size}`, s])).values(),
];

/** A version 1 message's `inReplyTo`. Other versions point at nothing the server can see. */
const inReplyTo = (m: AnyMessage) =>
  m.v === VERSION ? ((m as { inReplyTo?: string | null }).inReplyTo ?? null) : null;

/**
 * Where a page continues: below `position`, the place of the record whose id is `before`; everywhere for
 * null; nowhere when `before` names none of the records.
 */
const below = (before: string | null, position: number | null | undefined) =>
  before === null ? Number.MAX_SAFE_INTEGER : (position ?? 0);

/** A page of messages, newest first, read one beyond `limit` to tell whether there are more; ids are cursors. */
const page = (messages: StoredMessage[], limit: number): Page => ({
  records: messages.slice(0, limit).map(message => ({ cursor: message.id, message })),
  more: messages.length > limit,
});

/** The files a version 1 message names by content address, its own and those of messages it carries whole. */
const namedParts = (m: AnyMessage) => namedFiles(m);

const deliveryDoc = (d: Delivery): DeliveryDoc => ({
  ...structuredClone(d),
  _id: key(d.id, d.domain),
  hints: JSON.stringify(d.hints),
  nextAttemptAt: date(d.nextAttemptAt),
  lease: null,
});

const arrivalDoc = (a: QueuedArrival): ArrivalDoc => ({
  _id: key(a.id, a.recipient),
  id: a.id,
  recipient: a.recipient,
  hints: JSON.stringify(a.hints),
  attempts: a.attempts,
  due: date(a.dueAt),
});

/** How `init` tries again an index build another process's build refused (DocumentDB builds one at a time). */
export interface IndexBuildRetry {
  /** Tries per index, the first included (default 12). */
  attempts?: number;
  /** The longest first wait, in milliseconds, doubling with each try (default 250). */
  delayMs?: number;
  /** The longest wait, in milliseconds (default 5000). */
  maxDelayMs?: number;
}

export interface MongoStoreOptions {
  /** Limits on stored listing retractions (the server's `RetractionCapacity`). */
  retractions?: Partial<RetractionCapacity>;
  /** How `init` waits out index builds that collide with another process's. */
  indexBuilds?: IndexBuildRetry;
}

const DEFAULT_INDEX_BUILD_RETRY: Required<IndexBuildRetry> = { attempts: 12, delayMs: 250, maxDelayMs: 5000 };

/** Error names of a build refused or abandoned because another build or a collection's creation was underway. */
const INDEX_BUILD_CONFLICTS = new Set([
  'IndexBuildAlreadyInProgress',
  'IndexBuildAborted',
  'BackgroundOperationInProgressForNamespace',
  'BackgroundOperationInProgressForDatabase',
  'ConflictingOperationInProgress',
  'NamespaceExists',
  'WriteConflict',
  'LockTimeout',
]);
/** The same by number, for servers that send no name. */
const INDEX_BUILD_CONFLICT_CODES = new Set([12586, 12587, 117, 276, 48, 112, 24]);

/**
 * Whether an index build failed only because another was underway on the collection: by error name or
 * number, or by the "in progress" DocumentDB words its refusal with. An invalid or conflicting index
 * definition is none of these, and is not tried again.
 */
export function isIndexBuildConflict(e: unknown): boolean {
  if (!(e instanceof MongoServerError)) return false;
  if (e.codeName && INDEX_BUILD_CONFLICTS.has(e.codeName)) return true;
  if (typeof e.code === 'number' && INDEX_BUILD_CONFLICT_CODES.has(e.code)) return true;
  return /in progress|currently being built/i.test(e.message);
}

export class MongoStore implements Store {
  readonly #admission: Collection<RetractionAdmission>;
  readonly #retractionCapacity: RetractionCapacity;
  readonly #retractions: Collection<{ _id: string; owner: string; target: string; author: string; retraction: string }>;
  readonly #agents: Collection<AgentDoc>;
  readonly #messages: Collection<MessageDoc>;
  readonly #inbox: Collection<InboxDoc>;
  readonly #signals: Collection<SignalDoc>;
  readonly #webhooks: Collection<WebhookDoc>;
  readonly #deliveries: Collection<DeliveryDoc>;
  readonly #arrivals: Collection<ArrivalDoc>;
  readonly #parts: Collection<PartDoc>;
  readonly #chunks: Collection<{ _id: string; data: Binary }>;
  readonly #fetches: Collection<FetchDoc>;
  readonly #sequences: Collection<Sequence>;
  readonly #marks: Collection<Expiring>;
  readonly #counters: Collection<Expiring>;
  readonly #values: Collection<Expiring>;
  readonly #close: () => Promise<void>;
  readonly #indexBuilds: Required<IndexBuildRetry>;

  /**
   * A store on `db`, a database of a client connected with reads from the primary (`connect` makes one).
   * `close` is what `close()` runs, the client's own close for a store that owns its client.
   */
  constructor(db: Db, close: () => Promise<void> = async () => {}, options: MongoStoreOptions = {}) {
    this.#retractionCapacity = resolveRetractionCapacity(options.retractions);
    this.#indexBuilds = { ...DEFAULT_INDEX_BUILD_RETRY, ...options.indexBuilds };
    const collection = <T extends Document>(name: string) => db.collection<T>(name, { readPreference: 'primary' });
    this.#retractions = collection('core.listing_retractions');
    this.#admission = collection('core.retraction_admission');
    this.#agents = collection('core.agents');
    this.#messages = collection('core.messages');
    this.#inbox = collection('core.inbox');
    this.#signals = collection('core.signals');
    this.#webhooks = collection('core.webhooks');
    this.#deliveries = collection('core.deliveries');
    this.#arrivals = collection('core.arrivals');
    this.#parts = collection('core.parts');
    this.#chunks = collection('core.part_chunks');
    this.#fetches = collection('core.fetches');
    this.#sequences = collection('core.sequences');
    this.#marks = collection('core.marks');
    this.#counters = collection('core.counters');
    this.#values = collection('core.values');
    this.#close = close;
  }

  /** One index, made or found made, its build tried again while another build holds its collection. */
  async #index(collection: Collection<never>, keys: IndexSpecification, options: CreateIndexesOptions = {}) {
    const { attempts, delayMs, maxDelayMs } = this.#indexBuilds;
    for (let attempt = 1; ; attempt++) {
      try {
        await collection.createIndex(keys, options);
        return;
      } catch (e) {
        if (attempt >= attempts || !isIndexBuildConflict(e)) throw e;
        // Full jitter: processes that collided once spread out instead of colliding again.
        const ceiling = Math.min(maxDelayMs, delayMs * 2 ** (attempt - 1));
        await new Promise(resolve => setTimeout(resolve, Math.random() * ceiling));
      }
    }
  }

  /**
   * Create the indexes the rules rest on, and upgrade what older versions left. Run at startup; repeating it
   * changes nothing, and several processes may run it at once: DocumentDB builds one index on a collection
   * at a time and refuses a second build meanwhile, so a refused build is tried again after a jittered wait,
   * and an index another process made first is simply there.
   */
  async init(): Promise<this> {
    const indexes: [Collection<never>, IndexSpecification, CreateIndexesOptions?][] = [
      [this.#retractions, { owner: 1, target: 1, author: 1 }],
      [this.#agents, { 'keys.key': 1 }, { unique: true }],
      [this.#messages, { 'parts.sha256': 1 }],
      [this.#messages, { carrier: 1, 'parts.sha256': 1 }],
      [this.#messages, { expires: 1 }],
      [this.#messages, { rows: 1 }, { partialFilterExpression: { rows: { $exists: true } } }],
      [this.#messages, { pendingRows: 1 }, { partialFilterExpression: { pendingRows: { $exists: true } } }],
      [this.#messages, { from: 1, cursor: -1 }, { partialFilterExpression: { public: true } }],
      [this.#messages, { from: 1, to: 1 }],
      [this.#messages, { inReplyTo: 1 }],
      [this.#messages, { from: 1, cursor: 1 }, { partialFilterExpression: { cursor: { $exists: true } } }],
      [this.#inbox, { address: 1, cursor: 1 }],
      [this.#inbox, { address: 1, parts: 1 }],
      [this.#signals, { address: 1, cursor: 1 }],
      [this.#signals, { expires: 1 }, { expireAfterSeconds: 0 }],
      [this.#webhooks, { address: 1, slot: 1 }, { unique: true }],
      [this.#webhooks, { due: 1 }],
      [this.#inbox, { id: 1 }],
      [this.#inbox, { cursor: 1 }, { partialFilterExpression: { event: true } }],
      [this.#deliveries, { status: 1, nextAttemptAt: 1 }],
      [this.#deliveries, { id: 1 }],
      [this.#arrivals, { due: 1 }],
      [this.#arrivals, { id: 1 }],
      [this.#fetches, { due: 1 }],
      [this.#fetches, { carrier: 1, due: 1 }],
      [this.#marks, { expires: 1 }],
      [this.#counters, { expires: 1 }],
      [this.#values, { expires: 1 }],
    ] as never;
    for (const [collection, keys, options] of indexes) await this.#index(collection, keys, options);
    // Older versions' documents are upgraded by plain operators, one document at a time, as DocumentDB has no
    // update pipelines. Array reservations keep their live writers: each is rewritten only while unchanged.
    // Rolling mixed-version writers are not supported.
    for (let stuck: string | null = null; ; ) {
      const s = await this.#sequences.findOne({ pending: { $type: 'array' } });
      if (!s) break;
      const legacy = s.pending as unknown as { seq: number; at: Date }[];
      const r = await this.#sequences.updateOne(
        { _id: s._id, pending: legacy as never },
        { $set: { pending: Object.fromEntries(legacy.map(p => [String(p.seq), p.at])) } },
      );
      // A lost race reads again; the same counter refused twice in a row is one this cannot rewrite.
      if (r.matchedCount === 0 && stuck === s._id) throw new Error(`Cannot upgrade the reservations of ${s._id}.`);
      stuck = r.matchedCount === 0 ? s._id : null;
    }
    for await (const e of this.#inbox.find({ taken: { $exists: false } }))
      await this.#inbox.updateOne({ _id: e._id, taken: { $exists: false } }, { $set: { taken: receivedAt(e) } });
    // Entries an earlier version wrote learn their message's file hashes, a batch of messages at a time.
    for (;;) {
      const batch = await this.#inbox
        .find({ parts: { $exists: false } }, { projection: { _id: 1, id: 1 } })
        .limit(500)
        .toArray();
      if (!batch.length) break;
      const named = new Map(
        (
          await this.#messages
            .find({ _id: { $in: batch.map(e => e.id) } }, { projection: { _id: 1, parts: 1 } })
            .toArray()
        ).map(m => [m._id, m.parts.map(p => p.sha256)]),
      );
      for (const e of batch)
        await this.#inbox.updateOne(
          { _id: e._id, parts: { $exists: false } },
          { $set: { parts: named.get(e.id) ?? [] } },
        );
    }
    for await (const s of this.#signals.find({ cursor: { $exists: false } }))
      await this.#signals.updateOne({ _id: s._id, cursor: { $exists: false } }, { $set: { cursor: s._id as never } });
    await this.#fetches.updateMany({ revision: { $exists: false } }, { $set: { revision: 0 } });
    for await (const f of this.#fetches.find({ generation: { $exists: false } }))
      await this.#fetches.updateOne(
        { _id: f._id, generation: { $exists: false } },
        { $set: { generation: randomUUID() } },
      );
    // Startup migration is drained/exclusive. A permanent checkpoint excludes future new accounts.
    const checkpoint = key('migration', 'sync-history-gap-v1');
    if (!(await this.#values.findOne({ _id: checkpoint }))) {
      const ambiguous = await this.#messages.findOne({
        deleted: { $ne: true },
        $or: [
          { written: { $exists: false }, $or: [{ cursor: { $exists: false } }, { taken: { $exists: false } }] },
          { written: false, generation: { $exists: false } },
        ],
      });
      if (ambiguous)
        for await (const a of this.#agents.find({}))
          await insertOnce(
            () => this.#values.insertOne({ _id: key('sync-history-gap', a._id), value: 'true', expires: null }),
            '_id',
          );
      await insertOnce(() => this.#values.insertOne({ _id: checkpoint, value: 'true', expires: null }), '_id');
    }
    await this.#bootstrapRetractions();
    // Older public records receive listing-only positions in their previous publication order. They are
    // not asserted to be sent history: the old schema did not record enough authority to reconstruct it.
    for await (const doc of this.#messages
      .find({ public: true, cursor: { $exists: false } })
      .sort({ seq: 1, _id: 1 })) {
      const cursor = await this.#nextPending('inbox');
      const r = await this.#messages.updateOne(
        { _id: doc._id, cursor: { $exists: false } },
        { $set: { cursor, settled: false, written: false } },
      );
      if (!r.matchedCount) await this.#releaseCursor(cursor);
      else await this.#settle(this.#messages as unknown as Collection<Document>, doc._id);
    }
    return this;
  }

  // Agents

  #agent(doc: AgentDoc | null): Agent | null {
    if (!doc) return null;
    const { _id, recovery: _recovery, recoveryMigrated: _migrated, authorityVersion, recoveryEpoch, ...rest } = doc;
    return structuredClone({
      address: _id,
      ...rest,
      ...(authorityVersion ? { authorityVersion } : {}),
      ...(recoveryEpoch ? { recoveryEpoch } : {}),
      unpairing: rest.unpairing ?? null,
    });
  }

  async createAgent(agent: Agent, admit?: AgentAdmission) {
    if (agent.keys.filter(k => k.revoked === null).length > 32 || (admit && !admit(structuredClone(agent))))
      return 'too_many_keys' as const;
    const { address, ...rest } = agent;
    try {
      await this.#agents.insertOne({
        _id: address,
        ...structuredClone(rest),
        authorityVersion: 0,
        recoveryMigrated: true,
        recovery: null,
      });
      return 'created' as const;
    } catch (e) {
      if (isDuplicate(e, '_id')) return 'address_taken' as const;
      if (isDuplicate(e, 'keys.key')) return 'key_in_use' as const;
      throw e;
    }
  }

  async agentByAddress(address: string) {
    return this.#agent(await this.#agents.findOne({ _id: address }));
  }

  async agentByKey(key: string) {
    return this.#agent(await this.#agents.findOne({ 'keys.key': key }));
  }

  async addKey(address: string, entry: AgentKey, maxActive: number, admit?: AgentAdmission) {
    for (let attempt = 0; ; await backoff(++attempt)) {
      if (await this.agentByKey(entry.key)) return 'key_in_use' as const;
      const doc = await this.#agents.findOne({ _id: address });
      if (
        !doc ||
        doc.retiredAt ||
        doc.keys.filter(k => k.revoked === null).length >= Math.min(maxActive, 32) ||
        doc.keys.length >= MAX_STORED_KEYS
      )
        return 'too_many_keys' as const;
      const keys = [...doc.keys, structuredClone(entry)];
      if (admit && !admit({ ...this.#agent(doc)!, keys })) return 'too_many_keys' as const;
      try {
        const r = await this.#agents.updateOne(
          { _id: address, keys: doc.keys, retiredAt: null, ...authoritySnapshot(doc.authorityVersion) },
          {
            $set: {
              keys,
              ...(doc.authorizedKeys === undefined ? {} : { authorizedKeys: [...doc.authorizedKeys, entry.key] }),
            },
            $inc: { authorityVersion: 1 },
          },
        );
        if (r.matchedCount) return 'added' as const;
      } catch (e) {
        if (isDuplicate(e, 'keys.key')) return 'key_in_use' as const;
        throw e;
      }
    }
  }

  async revokeKey(address: string, key: string, at: string, admit?: AgentAdmission) {
    for (let attempt = 0; ; await backoff(++attempt)) {
      const doc = await this.#agents.findOne({ _id: address });
      if (
        !doc ||
        doc.retiredAt ||
        (admit && !admit(this.#agent(doc)!)) ||
        !doc.keys.some(k => k.key === key && k.revoked === null)
      )
        return 'not_found' as const;
      if (doc.keys.filter(k => k.revoked === null).length === 1) return 'last_key' as const;
      const keys = doc.keys.map(k => (k.key === key ? { ...k, revoked: at } : k));
      const r = await this.#agents.updateOne(
        { _id: address, keys: doc.keys, retiredAt: null, ...authoritySnapshot(doc.authorityVersion) },
        {
          $set: {
            keys,
            ...(doc.authorizedKeys === undefined ? {} : { authorizedKeys: doc.authorizedKeys.filter(k => k !== key) }),
          },
          $inc: { authorityVersion: 1 },
        },
      );
      if (r.matchedCount) return 'revoked' as const;
    }
  }

  async replaceKeys(address: string, entry: AgentKey, admit?: AgentAdmission) {
    for (let attempt = 0; ; await backoff(++attempt)) {
      const doc = await this.#recoveryAgent(address);
      if (!doc || doc.retiredAt) return 'retired' as const;
      if (await this.agentByKey(entry.key)) return 'key_in_use' as const;
      const keys = [...doc.keys.map(k => ({ ...k, revoked: k.revoked ?? entry.added })), structuredClone(entry)];
      if (admit && !admit({ ...this.#agent(doc)!, keys })) return 'too_many_keys' as const;
      try {
        const r = await this.#agents.updateOne(
          { _id: address, keys: doc.keys, retiredAt: null, ...authoritySnapshot(doc.authorityVersion) },
          {
            $set: { keys, recovery: null, authorizedKeys: [entry.key] },
            $inc: { authorityVersion: 1, recoveryEpoch: 1 },
          },
        );
        if (r.matchedCount) return 'replaced' as const;
      } catch (e) {
        if (isDuplicate(e, 'keys.key')) return 'key_in_use' as const;
        throw e;
      }
    }
  }

  async keepOnlyKey(address: string, key: string, at: string) {
    for (let attempt = 0; ; await backoff(++attempt)) {
      const doc = await this.#recoveryAgent(address);
      if (!doc || doc.retiredAt || !doc.keys.some(k => k.key === key && k.revoked === null)) return 'not_held' as const;
      const keys = doc.keys.map(k => (k.key === key ? { ...k } : { ...k, revoked: k.revoked ?? at }));
      const r = await this.#agents.updateOne(
        { _id: address, keys: doc.keys, retiredAt: null, ...authoritySnapshot(doc.authorityVersion) },
        { $set: { keys, recovery: null, authorizedKeys: [key] }, $inc: { authorityVersion: 1, recoveryEpoch: 1 } },
      );
      if (r.matchedCount) return 'kept' as const;
    }
  }

  async succeedPrincipal(address: string, from: string, to: string) {
    const r = await this.#agents.updateOne(
      { _id: address, principal: from, retiredAt: null },
      { $set: { principal: to }, $inc: { authorityVersion: 1 } },
    );
    return r.matchedCount === 1;
  }

  async retireAgent(address: string, at: string, unpairing?: string) {
    for (let attempt = 0; ; await backoff(++attempt)) {
      const doc = await this.#recoveryAgent(address);
      // Only the first retirement counts: its time, its revocations and its unpairing stay as they were.
      if (!doc || doc.retiredAt) return;
      const keys = doc.keys.map(k => ({ ...k, revoked: k.revoked ?? at }));
      const r = await this.#agents.updateOne(
        { _id: address, keys: doc.keys, retiredAt: null, ...authoritySnapshot(doc.authorityVersion) },
        {
          $set: { keys, retiredAt: at, unpairing: unpairing ?? null, recovery: null, authorizedKeys: [] },
          $inc: { authorityVersion: 1, recoveryEpoch: 1 },
        },
      );
      if (r.matchedCount) return;
    }
  }

  /** One-time primary CAS migration. Successful principal changes cannot be followed by a stale import. */
  async #recoveryAgent(address: string): Promise<AgentDoc | null> {
    for (let attempt = 0; ; await backoff(++attempt)) {
      const doc = await this.#agents.findOne({ _id: address });
      if (!doc || doc.recoveryMigrated) return doc;
      const legacy = await this.#values.findOne({ _id: key('recovery', address) });
      const r = await this.#agents.updateOne(
        {
          _id: address,
          recoveryMigrated: { $ne: true },
          keys: doc.keys,
          retiredAt: doc.retiredAt,
          ...authoritySnapshot(doc.authorityVersion),
        },
        {
          $set: {
            recoveryMigrated: true,
            authorityVersion: doc.authorityVersion ?? 0,
            recovery: legacy ? { value: legacy.value!, expires: legacy.expires ?? null } : null,
          },
        },
      );
      if (!r.matchedCount) continue;
      if (legacy) await this.#values.deleteOne({ _id: legacy._id, value: legacy.value, expires: legacy.expires });
    }
  }

  #liveRecovery(doc: AgentDoc, now: string) {
    return doc.recovery && (doc.recovery.expires === null || doc.recovery.expires > date(now)) ? doc.recovery : null;
  }

  async beginRecovery(address: string, value: unknown, expiresAt: string | null, now: string, admit?: AgentAdmission) {
    for (let attempt = 0; ; await backoff(++attempt)) {
      const doc = await this.#recoveryAgent(address);
      if (!doc || doc.retiredAt || (admit && !admit(this.#agent(doc)!))) return null;
      const held = this.#liveRecovery(doc, now);
      if (held) return JSON.parse(held.value) as unknown;
      const recovery = { value: JSON.stringify(value), expires: expiresAt === null ? null : date(expiresAt) };
      const r = await this.#agents.updateOne(
        {
          _id: address,
          keys: doc.keys,
          retiredAt: null,
          authorityVersion: doc.authorityVersion,
          recovery: doc.recovery ?? null,
        },
        { $set: { recovery } },
      );
      if (r.matchedCount) return structuredClone(value);
    }
  }

  async activateRecovery(address: string, expectedRecovery: unknown, now: string) {
    if (
      !expectedRecovery ||
      typeof expectedRecovery !== 'object' ||
      Array.isArray(expectedRecovery) ||
      (expectedRecovery as { defended?: unknown }).defended !== false
    )
      return false;
    const expected = JSON.stringify(expectedRecovery),
      activated = JSON.stringify({ ...JSON.parse(expected), defended: true });
    for (let attempt = 0; ; await backoff(++attempt)) {
      const doc = await this.#recoveryAgent(address);
      if (!doc || doc.retiredAt) return false;
      const proof = this.#liveRecovery(doc, now);
      if (!proof || proof.value !== expected) return false;
      const recovery = { ...proof, value: activated };
      const r = await this.#agents.updateOne(
        {
          _id: address,
          keys: doc.keys,
          retiredAt: null,
          authorityVersion: doc.authorityVersion,
          recovery: doc.recovery,
        },
        { $set: { recovery } },
      );
      if (r.matchedCount) return true;
    }
  }

  async completeRecovery(address: string, entry: AgentKey, expectedRecovery: unknown, admit?: AgentAdmission) {
    if (
      !expectedRecovery ||
      typeof expectedRecovery !== 'object' ||
      (expectedRecovery as { key?: unknown }).key !== entry.key
    )
      return 'not_pending' as const;
    const expected = JSON.stringify(expectedRecovery);
    for (let attempt = 0; ; await backoff(++attempt)) {
      const doc = await this.#recoveryAgent(address);
      if (!doc || doc.retiredAt) return 'retired' as const;
      const proof = this.#liveRecovery(doc, entry.added);
      if (!proof || proof.value !== expected || (JSON.parse(proof.value) as { defended?: unknown }).defended === false)
        return 'not_pending' as const;
      if (await this.agentByKey(entry.key)) return 'key_in_use' as const;
      const keys = [...doc.keys.map(k => ({ ...k, revoked: k.revoked ?? entry.added })), structuredClone(entry)];
      if (admit && !admit({ ...this.#agent(doc)!, keys })) return 'too_many_keys' as const;
      try {
        const r = await this.#agents.updateOne(
          {
            _id: address,
            keys: doc.keys,
            retiredAt: null,
            authorityVersion: doc.authorityVersion,
            recovery: doc.recovery,
          },
          {
            $set: { keys, recovery: null, authorizedKeys: [entry.key] },
            $inc: { authorityVersion: 1, recoveryEpoch: 1 },
          },
        );
        if (r.matchedCount) return 'replaced' as const;
      } catch (e) {
        if (isDuplicate(e, 'keys.key')) return 'key_in_use' as const;
        throw e;
      }
    }
  }

  async cancelRecovery(
    address: string,
    expectedRecovery: unknown,
    now: string,
    admit?: AgentAdmission,
    keyCancelledAt?: string,
  ) {
    const expected = JSON.stringify(expectedRecovery);
    for (let attempt = 0; ; await backoff(++attempt)) {
      const doc = await this.#recoveryAgent(address);
      if (!doc || doc.retiredAt || (admit && !admit(this.#agent(doc)!))) return false;
      const proof = this.#liveRecovery(doc, now);
      if (!proof || proof.value !== expected) return false;
      const r = await this.#agents.updateOne(
        {
          _id: address,
          keys: doc.keys,
          retiredAt: null,
          authorityVersion: doc.authorityVersion,
          recovery: doc.recovery,
        },
        {
          $set: { recovery: null, ...(keyCancelledAt === undefined ? {} : { recoveryKeyCancelledAt: keyCancelledAt }) },
          $inc: { authorityVersion: 1, recoveryEpoch: 1 },
        },
      );
      if (r.matchedCount) return true;
    }
  }

  // Messages

  #message(doc: MessageDoc): StoredMessage {
    return {
      id: doc._id,
      message: JSON.parse(doc.json) as AnyMessage,
      carrier: doc.carrier,
      claims: JSON.parse(doc.claims) as Claim[],
      signedClaims: doc.signedClaims === null ? null : (JSON.parse(doc.signedClaims) as SignedClaims),
      receivedAt: doc.receivedAt,
      expiresAt: doc.expires.toISOString(),
    };
  }

  async #admissionState() {
    const doc = await this.#admission.findOne({ _id: ADMISSION });
    return { doc, receipts: JSON.parse(doc?.body ?? '{}') as Record<string, RetractionReceipt> };
  }

  async #saveAdmission(doc: RetractionAdmission | null, receipts: Record<string, RetractionReceipt>, check = true) {
    const body = canonicalize(receipts),
      entries = Object.values(receipts),
      limits = this.#retractionCapacity;
    const authors = new Map<string, number>();
    for (const r of entries) authors.set(r.author, (authors.get(r.author) ?? 0) + 1);
    // Journals are charged before acceptance; reserve enough for internal boolean transitions.
    if (
      check &&
      (entries.length > limits.maxRecords ||
        [...authors.values()].some(n => n > limits.maxPerAuthor) ||
        Buffer.byteLength(body) + 16 * entries.length > limits.maxBytes)
    )
      throw new StoreCapacityError();
    if (!doc) return insertOnce(() => this.#admission.insertOne({ _id: ADMISSION, revision: 0, body }), '_id');
    return (
      (
        await this.#admission.updateOne(
          { _id: ADMISSION, revision: doc.revision },
          { $set: { body }, $inc: { revision: 1 } },
        )
      ).matchedCount === 1
    );
  }

  async #admitRetraction(record: StoredMessage, rows: { deliveries?: Delivery[]; arrivals?: QueuedArrival[] }) {
    if (!this.#retractionsOf(record).length) return null;
    for (;;) {
      const { doc, receipts } = await this.#admissionState();
      let r = Object.hasOwn(receipts, record.id) ? receipts[record.id] : undefined;
      if (r && !r.active) return r;
      let changed = !r;
      if (!r)
        r = {
          record: structuredClone(record),
          author: record.message.from,
          markers: this.#retractionsOf(record),
          generation: randomUUID(),
          active: true,
          materialized: false,
          written: !rows.arrivals,
          kept: !rows.arrivals,
          keptReported: !rows.arrivals,
          outstandingArrivals: [],
          expiresAt: date(record.expiresAt).toISOString(),
          knownDeliveries: [],
          knownArrivals: [],
          pendingDeliveries: {},
          pendingArrivals: {},
        };
      for (const row of rows.deliveries ?? [])
        if (!r.knownDeliveries.includes(row.domain)) {
          r.knownDeliveries.push(row.domain);
          r.pendingDeliveries[row.domain] = structuredClone(row);
          changed = true;
        }
      for (const row of rows.arrivals ?? [])
        if (!r.knownArrivals.includes(row.recipient)) {
          r.knownArrivals.push(row.recipient);
          r.outstandingArrivals.push(row.recipient);
          r.pendingArrivals[row.recipient] = structuredClone(row);
          changed = true;
        }
      if (!changed) return r;
      receipts[record.id] = r;
      if (await this.#saveAdmission(doc, receipts)) return r;
    }
  }

  async #bootstrapRetractions() {
    // Import all retained envelopes and marker-only legacy evidence before accepting new work.
    for await (const doc of this.#messages.find({ inReplyTo: { $ne: null }, deleted: { $ne: true } })) {
      const record = this.#message(doc);
      if (!this.#retractionsOf(record).length) continue;
      for (;;) {
        const state = await this.#admissionState();
        if (Object.hasOwn(state.receipts, doc._id)) break;
        const deliveries = [
          ...(await this.#deliveries
            .find({ id: doc._id, messageGeneration: doc.generation ?? { $exists: false } })
            .toArray()),
          ...(doc.rows?.deliveries ?? []),
          ...Object.values(doc.pendingRows ?? {}).flatMap(r => r.deliveries),
        ];
        const arrivals = [
          ...(await this.#arrivals
            .find({ id: doc._id, messageGeneration: doc.generation ?? { $exists: false } })
            .toArray()),
          ...(doc.rows?.arrivals ?? []),
          ...Object.values(doc.pendingRows ?? {}).flatMap(r => r.arrivals),
        ];
        state.receipts[doc._id] = {
          record,
          author: record.message.from,
          markers: this.#retractionsOf(record),
          generation: doc.generation ?? 'legacy',
          active: true,
          materialized: true,
          written: doc.written ?? (doc.cursor !== undefined && doc.taken !== undefined),
          kept: doc.kept,
          keptReported: doc.kept,
          outstandingArrivals: arrivals.filter(a => !a.done).map(a => a.recipient),
          expiresAt: date(record.expiresAt).toISOString(),
          knownDeliveries: deliveries.map(d => d.domain),
          knownArrivals: arrivals.map(a => a.recipient),
          pendingDeliveries: {},
          pendingArrivals: {},
        };
        if (await this.#saveAdmission(state.doc, state.receipts)) break;
      }
    }
    for await (const marker of this.#retractions.find({}))
      for (;;) {
        const { doc, receipts } = await this.#admissionState();
        let r = Object.hasOwn(receipts, marker.retraction) ? receipts[marker.retraction] : undefined;
        if (!r)
          r = {
            record: null,
            author: marker.author,
            markers: [],
            generation: randomUUID(),
            active: false,
            materialized: true,
            written: false,
            kept: false,
            keptReported: false,
            outstandingArrivals: [],
            expiresAt: '1970-01-01T00:00:00.000Z',
            knownDeliveries: [],
            knownArrivals: [],
            pendingDeliveries: {},
            pendingArrivals: {},
          };
        if (r.markers.some(m => m.owner === marker.owner && m.target === marker.target && m.author === marker.author))
          break;
        r.markers.push({
          owner: marker.owner,
          target: marker.target,
          author: marker.author,
          retraction: marker.retraction,
        });
        receipts[marker.retraction] = r;
        if (await this.#saveAdmission(doc, receipts)) break;
      }
    // Revalidate configured bounds even when lowering them for an existing host.
    const state = await this.#admissionState();
    await this.#saveAdmission(state.doc, state.receipts);
    await this.#recoverRetractions();
  }

  async #materializeRetraction(id: string, r: RetractionReceipt) {
    if (
      r.active &&
      r.materialized &&
      !Object.keys(r.pendingDeliveries).length &&
      !Object.keys(r.pendingArrivals).length
    )
      return;
    if (!r.active) {
      if (r.materialized) return;
      const tombstone = {
        generation: `deleted:${r.generation}`,
        deleted: true,
        public: false,
        from: '',
        to: [],
        parts: [],
        inReplyTo: null,
        kept: true,
        expires: new Date('9999-01-01T00:00:00.000Z'),
      };
      await this.#messages.updateOne(
        { _id: id },
        {
          $set: tombstone,
          $unset: {
            cursor: '',
            taken: '',
            rows: '',
            pendingRows: '',
            settled: '',
            json: '',
            claims: '',
            signedClaims: '',
            carrier: '',
            receivedAt: '',
            revision: '',
            retractions: '',
            written: '',
          },
        },
        { upsert: true },
      );
      for (const c of [this.#inbox, this.#deliveries, this.#arrivals] as unknown as Collection<Document>[])
        await c.deleteMany({ id, messageGeneration: r.generation === 'legacy' ? { $exists: false } : r.generation });
      for (;;) {
        const state = await this.#admissionState(),
          current = state.receipts[id];
        if (!current || current.active || current.generation !== r.generation || current.materialized) return;
        current.materialized = true;
        if (await this.#saveAdmission(state.doc, state.receipts, false)) return;
      }
    }
    if (!r.record) return;
    const m = r.record,
      generation = r.generation === 'legacy' ? undefined : r.generation;
    if (!(await this.#messages.findOne({ _id: id }))) {
      const d: MessageDoc = {
        _id: id,
        ...(generation === undefined ? {} : { generation }),
        revision: 0,
        json: canonicalize(m.message),
        from: m.message.from,
        to: m.message.to,
        public: m.message.to.length === 0,
        inReplyTo: inReplyTo(m.message),
        carrier: m.carrier,
        claims: JSON.stringify(m.claims),
        signedClaims: m.signedClaims && JSON.stringify(m.signedClaims),
        receivedAt: m.receivedAt,
        expires: date(r.expiresAt),
        parts: namedParts(m.message),
        kept: r.kept,
        written: r.written,
        ...(r.written ? { taken: date(m.receivedAt) } : {}),
      };
      if (r.written || d.public) await this.#streamInsert(this.#messages as unknown as Collection<Document>, d);
      else await insertOnce(() => this.#messages.insertOne(d), '_id');
    }
    await this.#messages.updateOne(
      { _id: id, deleted: { $ne: true }, generation: generation ?? { $exists: false } },
      { $max: { expires: date(r.expiresAt) }, ...(r.kept ? { $set: { kept: true } } : {}) },
    );
    for (const recipient of r.knownArrivals.filter(a => !r.outstandingArrivals.includes(a)))
      for (;;) {
        try {
          await this.#arrivals.updateOne(
            { _id: this.#childId(key(id, recipient), generation) },
            {
              $set: {
                id,
                recipient,
                ...(generation === undefined ? {} : { messageGeneration: generation }),
                done: true,
                hints: '{}',
              },
            },
            { upsert: true },
          );
          break;
        } catch (e) {
          if (!isDuplicate(e, '_id')) throw e;
        }
      }
    for (const d of Object.values(r.pendingDeliveries))
      await this.#copyChild(deliveryDoc(d), generation, row => this.#deliveries.insertOne(row));
    for (const a of Object.values(r.pendingArrivals))
      await this.#copyChild(arrivalDoc(a), generation, row => this.#arrivals.insertOne(row));
    for (;;) {
      const state = await this.#admissionState(),
        current = state.receipts[id];
      if (!current?.active || current.generation !== r.generation) return;
      if (current.materialized && !Object.keys(r.pendingDeliveries).length && !Object.keys(r.pendingArrivals).length)
        return;
      current.materialized =
        current.expiresAt === r.expiresAt &&
        current.kept === r.kept &&
        canonicalize(current.outstandingArrivals) === canonicalize(r.outstandingArrivals);
      for (const [k, v] of Object.entries(r.pendingDeliveries))
        if (canonicalize(current.pendingDeliveries[k] ?? null) === canonicalize(v)) delete current.pendingDeliveries[k];
      for (const [k, v] of Object.entries(r.pendingArrivals))
        if (canonicalize(current.pendingArrivals[k] ?? null) === canonicalize(v)) delete current.pendingArrivals[k];
      if (await this.#saveAdmission(state.doc, state.receipts, false)) return;
    }
  }

  async #recoverRetractions() {
    const { receipts } = await this.#admissionState();
    for (const [id, r] of Object.entries(receipts))
      if (!r.materialized || Object.keys(r.pendingDeliveries).length || Object.keys(r.pendingArrivals).length)
        await this.#materializeRetraction(id, r);
  }

  async putMessage(
    m: StoredMessage,
    rows: { deliveries?: Delivery[]; arrivals?: QueuedArrival[] } = {},
  ): Promise<StoredMessage> {
    const receipt = await this.#admitRetraction(m, rows);
    if (receipt) {
      await this.#materializeRetraction(m.id, receipt);
      return structuredClone(receipt.record ?? m);
    }
    const deliveries = (rows.deliveries ?? []).map(deliveryDoc);
    const arrivals = (rows.arrivals ?? []).map(arrivalDoc);
    const batch = randomUUID();
    const pendingRows = { [batch]: { deliveries, arrivals } };
    const doc: MessageDoc = {
      _id: m.id,
      generation: randomUUID(),
      revision: 0,
      json: canonicalize(m.message),
      from: m.message.from,
      to: m.message.to,
      public: m.message.to.length === 0,
      inReplyTo: inReplyTo(m.message),
      carrier: m.carrier,
      claims: JSON.stringify(m.claims),
      signedClaims: m.signedClaims && JSON.stringify(m.signedClaims),
      receivedAt: m.receivedAt,
      expires: date(m.expiresAt),
      parts: namedParts(m.message),
      kept: !rows.arrivals,
      written: !rows.arrivals,
      pendingRows,
      retractions: this.#retractionsOf(m),
      ...(!rows.arrivals ? { taken: date(m.receivedAt) } : {}),
    };
    const inserted =
      rows.arrivals && !doc.public
        ? await insertOnce(() => this.#messages.insertOne(doc), '_id')
        : await this.#streamInsert(this.#messages as unknown as Collection<Document>, doc);
    let accepted = doc;
    if (!inserted) {
      // Journal this repeat's additional rows in the authoritative message before any collection copies.
      // Each batch is removed independently; a racing repeat cannot erase another writer's journal.
      const held = await this.#messages.findOneAndUpdate(
        { _id: m.id },
        { $set: { [`pendingRows.${batch}`]: { deliveries, arrivals } }, $inc: { revision: 1 } },
        { returnDocument: 'after' },
      );
      if (!held) return this.putMessage(m, rows);
      accepted = held;
    }
    await this.#copyBatch(m.id, batch, deliveries, arrivals, accepted.generation);
    // The accepted incarnation may have been deleted concurrently; do not recreate it after deletion.
    return this.#message(accepted);
  }

  #sameGeneration(message: MessageDoc | null, generation: string | undefined) {
    return message !== null && !message.deleted && (message.generation ?? undefined) === (generation ?? undefined);
  }

  #childId(id: string, generation: string | undefined) {
    return generation === undefined ? id : `${id}\n${generation}`;
  }

  async #copyChild<T extends { _id: string; id: string }>(
    row: T,
    generation: string | undefined,
    insert: (row: T) => Promise<unknown>,
  ) {
    if (!this.#sameGeneration(await this.#messages.findOne({ _id: row.id }), generation)) return;
    // Each incarnation has separate child IDs. A paused old copier cannot overwrite a recreated row.
    const next = {
      ...row,
      _id: this.#childId(row._id, generation),
      ...(generation === undefined ? {} : { messageGeneration: generation }),
    };
    await insertOnce(() => insert(next), '_id');
  }

  async #copyBatch(id: string, batch: string, deliveries: DeliveryDoc[], arrivals: ArrivalDoc[], generation?: string) {
    const original = await this.#messages.findOne({ _id: id });
    if (!this.#sameGeneration(original, generation)) return;
    for (const d of deliveries) await this.#copyChild(d, generation, row => this.#deliveries.insertOne(row));
    for (const a of arrivals) await this.#copyChild(a, generation, row => this.#arrivals.insertOne(row));
    await this.#messages.updateOne(
      { _id: id, generation: generation ?? { $exists: false }, [`pendingRows.${batch}`]: { $exists: true } },
      { $unset: { [`pendingRows.${batch}`]: '' }, $inc: { revision: 1 } },
    );
    await this.#messages.updateOne(
      { _id: id, generation: generation ?? { $exists: false }, pendingRows: {} },
      { $unset: { pendingRows: '' } },
    );
  }

  async #recover() {
    await this.#recoverRetractions();
    for (const doc of await this.#messages
      .find({ $or: [{ rows: { $exists: true } }, { pendingRows: { $exists: true } }] })
      .limit(100)
      .toArray()) {
      if (doc.rows) {
        // Conditional clearing preserves the exact legacy journal being copied.
        await this.#copyBatch(doc._id, 'legacy', doc.rows.deliveries, doc.rows.arrivals, doc.generation);
        await this.#messages.updateOne(
          { _id: doc._id, generation: doc.generation ?? { $exists: false }, rows: doc.rows },
          { $unset: { rows: '' } },
        );
      }
      for (const [batch, rows] of Object.entries(doc.pendingRows ?? {}))
        await this.#copyBatch(doc._id, batch, rows.deliveries, rows.arrivals, doc.generation);
      await this.#messages.updateOne(
        { _id: doc._id, generation: doc.generation ?? { $exists: false }, pendingRows: {} },
        { $unset: { pendingRows: '' } },
      );
    }
  }

  async message(id: string) {
    await this.#recoverRetractions();
    const doc = await this.#messages.findOne({ _id: id, deleted: { $ne: true } });
    return doc ? this.#message(doc) : null;
  }

  /** The messages with these ids that are still held, by id. */
  async #messagesById(ids: string[]): Promise<Map<string, MessageDoc>> {
    return new Map(
      (await this.#messages.find({ _id: { $in: ids }, deleted: { $ne: true } }).toArray()).map(d => [d._id, d]),
    );
  }

  async published(author: string, before: string | null, limit: number) {
    const { top, committed } = await this.#watermark();
    const after = before === null ? null : await this.#messages.findOne({ _id: before, from: author, public: true });
    const docs = await this.#messages
      .find({
        from: author,
        public: true,
        cursor: { $lte: top, $lt: below(before, after?.cursor) },
        ...this.#visible(committed),
      })
      .sort({ cursor: -1 })
      .limit(limit + 1)
      .toArray();
    return page(
      docs.map(d => this.#message(d)),
      limit,
    );
  }

  /**
   * The first `limit` rows matching `match` in `sort` order whose message is still held, in the incarnation
   * the row belongs to, each with that message. Rows are read in sorted pages and checked against messages
   * by one `$in` per page, so a page costs about the rows it returns, never the rest of the collection; a
   * page some of whose rows are stale reads on from the last row it read. `sort` is unique on what it names
   * (a cursor, or a time and `_id`), so reading on skips and repeats nothing.
   */
  async #liveChildren<T extends Document & { _id: string; id: string; messageGeneration?: string }>(
    collection: Collection<T>,
    match: Document,
    sort: Record<string, 1 | -1>,
    limit: number,
  ): Promise<(T & { authority: MessageDoc[] })[]> {
    const live: (T & { authority: MessageDoc[] })[] = [];
    const keys = Object.entries(sort);
    let after: Document | null = null;
    while (live.length < limit) {
      const want = Math.min(Math.max(2 * (limit - live.length), 32), 1000);
      const rows = (await collection
        .find((after ? { $and: [match, after] } : match) as Filter<T>)
        .sort(sort)
        .limit(want)
        .toArray()) as T[];
      const messages = await this.#messagesById([...new Set(rows.map(r => r.id))]);
      for (const row of rows) {
        const doc = messages.get(row.id) ?? null;
        if (!this.#sameGeneration(doc, row.messageGeneration)) continue;
        live.push({ ...row, authority: [doc!] });
        if (live.length === limit) break;
      }
      if (rows.length < want) break;
      const last = rows.at(-1)! as Document;
      // Past the last row read, in sort order: later on the first key, or equal on it and later on the next.
      const past = (i: number): Document => {
        const [k, dir] = keys[i];
        const beyond = { [k]: { [dir === 1 ? '$gt' : '$lt']: last[k] } };
        return i === keys.length - 1 ? beyond : { $or: [beyond, { [k]: last[k], ...past(i + 1) }] };
      };
      after = past(0);
    }
    return live;
  }

  async repliesTo(address: string, id: string, before: string | null, limit: number) {
    const { top, committed } = await this.#watermark();
    const beforeMessage = before === null ? null : await this.#messages.findOne({ _id: before });
    const after =
      beforeMessage === null
        ? null
        : await this.#inbox.findOne({ _id: this.#childId(key(address, before!), beforeMessage.generation) });
    const replies = await this.#messages.find({ inReplyTo: id }, { projection: { _id: 1 } }).toArray();
    const entries = await this.#liveChildren(
      this.#inbox,
      {
        address,
        id: { $in: replies.map(r => r._id) },
        cursor: { $lte: top, $lt: below(before, after?.cursor) },
        ...this.#visible(committed),
      },
      { cursor: -1 },
      limit + 1,
    );
    return page(
      entries.map(e => this.#message(e.authority[0])),
      limit,
    );
  }

  #retractionsOf(record: StoredMessage) {
    const m = record.message;
    const target = inReplyTo(m);
    if (m.v !== VERSION || header(m as never, 'rel') !== 'retract' || !target) return [];
    return (m.to.length ? m.to : ['*']).map(owner => ({ owner, target, author: m.from, retraction: record.id }));
  }

  async listingRetracted(ownerAddress: string, id: string, replyAuthor: string) {
    const { receipts } = await this.#admissionState();
    return Object.values(receipts).some(r =>
      r.markers.some(m => (m.owner === ownerAddress || m.owner === '*') && m.target === id && m.author === replyAuthor),
    );
  }

  async deleteMessage(id: string) {
    await this.#deleteMessages([id]);
  }

  async #deleteMessages(ids: string[], expected?: Map<string, MessageDoc>, onlyUnkept = false) {
    await this.#recoverRetractions();
    let removed = 0;
    for (const id of ids) {
      const doc = expected?.get(id) ?? (await this.#messages.findOne({ _id: id }));
      if (!doc) continue;
      if (doc.deleted) continue;
      // Retraction authority and its permanent suppression receipt share one CAS boundary.
      let retracted = false;
      for (;;) {
        const state = await this.#admissionState(),
          r = state.receipts[id];
        if (!r) break;
        if (!r.active) {
          await this.#materializeRetraction(id, r);
          retracted = true;
          break;
        }
        if (expected && r.expiresAt !== doc.expires.toISOString()) break;
        if (
          onlyUnkept &&
          (r.kept ||
            r.outstandingArrivals.length ||
            Object.keys(r.pendingDeliveries).length ||
            Object.keys(r.pendingArrivals).length)
        )
          break;
        r.active = false;
        r.materialized = false;
        r.pendingDeliveries = {};
        r.pendingArrivals = {};
        if (await this.#saveAdmission(state.doc, state.receipts, false)) {
          await this.#materializeRetraction(id, r);
          removed++;
          retracted = true;
          break;
        }
      }
      if (retracted) continue;
      // A guarded retraction that failed the expiry/journal check must remain live.
      if (Object.hasOwn((await this.#admissionState()).receipts, id)) continue;
      const generation = doc.generation ?? { $exists: false };
      // Remove authority first. A paused copy may leave a physical child, but consumers require the same
      // live incarnation, so it is never work; sweep removes it without touching a recreated incarnation.
      const deleted = await this.#messages.findOneAndDelete({
        _id: id,
        generation,
        ...(expected ? { expires: doc.expires } : {}),
        ...(onlyUnkept
          ? {
              kept: false,
              revision: doc.revision ?? { $exists: false },
              rows: { $exists: false },
              $or: [{ pendingRows: { $exists: false } }, { pendingRows: {} }],
            }
          : {}),
      });
      if (!deleted) continue;
      removed++;
      for (const collection of [this.#inbox, this.#deliveries, this.#arrivals])
        await (collection as unknown as Collection<Document>).deleteMany({ id, messageGeneration: generation });
    }
    return removed;
  }

  // Arrivals

  async arrivals(now: string, limit: number) {
    await this.#recover();
    const due = await this.#liveChildren(
      this.#arrivals,
      { done: { $ne: true }, due: { $lte: date(now) } },
      { due: 1, _id: 1 },
      limit,
    );
    return due.map(a => ({
      arrival: {
        id: a.id,
        recipient: a.recipient,
        hints: JSON.parse(a.hints),
        attempts: a.attempts,
        dueAt: a.due.toISOString(),
      },
      message: this.#message(a.authority[0]),
      generation: a.authority[0].generation ?? 'legacy',
    }));
  }

  async arrivalRetry(id: string, recipient: string, at: string, generation?: string) {
    const message = await this.#messages.findOne({ _id: id });
    if (!message || message.deleted || (generation !== undefined && (message.generation ?? 'legacy') !== generation))
      return;
    await this.#arrivals.updateOne(
      { _id: this.#childId(key(id, recipient), message.generation), done: { $ne: true } },
      { $inc: { attempts: 1 }, $set: { due: date(at) } },
    );
  }

  async arrivalDone(id: string, recipient: string, kept: boolean, expectedGeneration?: string) {
    let retractionKept = false;
    // Retraction retention and outstanding arrival grants are authority in the admission CAS.
    // A concurrent last drop cannot beat another recipient's accepted keep or inbox admission.
    for (;;) {
      const state = await this.#admissionState(),
        r = state.receipts[id];
      if (!r) break;
      if (!r.active || (expectedGeneration !== undefined && r.generation !== expectedGeneration)) return null;
      if (!r.outstandingArrivals.includes(recipient)) return null;
      retractionKept = kept && !r.keptReported;
      r.outstandingArrivals = r.outstandingArrivals.filter(a => a !== recipient);
      r.kept = r.kept || kept;
      r.keptReported = r.keptReported || kept;
      r.materialized = false;
      delete r.pendingArrivals[recipient];
      if (await this.#saveAdmission(state.doc, state.receipts, false)) {
        await this.#materializeRetraction(id, r);
        break;
      }
    }
    const message = await this.#messages.findOne({ _id: id });
    if (
      !message ||
      message.deleted ||
      (expectedGeneration !== undefined && (message.generation ?? 'legacy') !== expectedGeneration)
    )
      return null;
    const generation = message.generation ?? { $exists: false };
    // Keep authority before dropping queue work, so a crash never loses an accepted received message.
    const changed = kept
      ? await this.#messages.updateOne({ _id: id, generation, kept: false }, { $set: { kept: true } })
      : null;
    // Keep a terminal receipt: a copier paused before settlement must not recreate completed work.
    await this.#arrivals.updateOne(
      { _id: this.#childId(key(id, recipient), message.generation) },
      { $set: { done: true, hints: '{}' } },
    );
    if (kept) return retractionKept || changed!.modifiedCount ? ('kept' as const) : null;
    // Capture before checking child counts; a new journal batch changes revision even if it copies quickly.
    const current = await this.#messages.findOne({ _id: id, generation });
    const waiting = await this.#arrivals.countDocuments(
      { id, messageGeneration: generation, done: { $ne: true } },
      { limit: 1 },
    );
    const held = await this.#inbox.countDocuments({ id, messageGeneration: generation }, { limit: 1 });
    // A pending journal may still copy more arrivals: never discard its authoritative message.
    if (waiting || held || !current || current.kept || current.rows || Object.keys(current.pendingRows ?? {}).length)
      return null;
    return (await this.#deleteMessages([id], new Map([[id, current]]), true)) ? ('dropped' as const) : null;
  }

  // Sync

  #streamCollections() {
    return [this.#inbox, this.#messages, this.#signals] as unknown as Collection<Document>[];
  }

  async #releaseCursor(cursor: number) {
    const path = `pending.${cursor}`;
    await this.#sequences.updateOne({ _id: 'inbox' }, { $unset: { [path]: '' } });
  }

  /**
   * Publish a fully written entry by replacing its reservation with a commit marker in ONE sequence
   * write. Readers expire a reservation by CAS against its timestamp, so an expired writer cannot publish
   * below a returned watermark. Helpers move a stale entry only by CAS over its old cursor; duplicate
   * helpers and the original late writer never overwrite the winner's new position.
   */
  async #settle(collection: Collection<Document>, id: string) {
    for (;;) {
      const entry = await collection.findOne({ _id: id as never });
      if (!entry || entry.settled !== false) return;
      const cursor = entry.cursor as number;
      const seq = await this.#sequences.findOne({ _id: 'inbox' });
      const pending = seq?.pending?.[cursor];
      let committed = seq?.committed?.[cursor] === true;
      if (!committed && pending) {
        const r = await this.#sequences.updateOne(
          { _id: 'inbox', [`pending.${cursor}`]: pending },
          { $unset: { [`pending.${cursor}`]: '' }, $set: { [`committed.${cursor}`]: true } },
        );
        committed = r.matchedCount === 1;
        if (!committed) continue;
      }
      if (committed) {
        await collection.updateOne({ _id: id as never, cursor, settled: false }, { $set: { settled: true } });
        // A marker is removed only after the entry is durable and visibly settled.
        await this.#sequences.updateOne({ _id: 'inbox' }, { $unset: { [`committed.${cursor}`]: '' } });
        return;
      }
      const next = await this.#nextPending('inbox');
      try {
        const r = await collection.updateOne({ _id: id as never, cursor, settled: false }, { $set: { cursor: next } });
        if (!r.matchedCount) await this.#releaseCursor(next);
      } catch (e) {
        await this.#releaseCursor(next);
        throw e;
      }
    }
  }

  async #streamInsert(collection: Collection<Document>, doc: Document) {
    const cursor = await this.#nextPending('inbox');
    let inserted: boolean;
    try {
      inserted = await insertOnce(() => collection.insertOne({ ...doc, cursor, settled: false }), '_id');
    } catch (e) {
      await this.#releaseCursor(cursor);
      throw e;
    }
    if (!inserted) await this.#releaseCursor(cursor);
    await this.#settle(collection, doc._id as string);
    return inserted;
  }

  /** Expire reservations before taking the snapshot that bounds a page. */
  async #watermark() {
    await this.#recoverRetractions();
    // Recover entries whose process stopped after insert or commit, so commit markers do not accumulate.
    for (const collection of this.#streamCollections()) {
      for (const entry of await collection.find({ settled: false }).limit(100).toArray()) {
        await this.#settle(collection, entry._id as unknown as string);
      }
    }
    const timed = await this.#sequences.findOneAndUpdate(
      { _id: 'inbox' },
      { $currentDate: { now: true } },
      { returnDocument: 'after' },
    );
    for (const [cursor, at] of Object.entries(timed?.pending ?? {})) {
      if (at.getTime() <= timed!.now!.getTime() - ABANDONED_MS) {
        await this.#sequences.updateOne(
          { _id: 'inbox', [`pending.${cursor}`]: at },
          { $unset: { [`pending.${cursor}`]: '' } },
        );
      }
    }
    const seq = await this.#sequences.findOne({ _id: 'inbox' });
    // A deletion or signal expiry may remove an entry after commit; its bridge marker is then unnecessary.
    for (const cursor of Object.keys(seq?.committed ?? {}).map(Number)) {
      let exists = false;
      for (const collection of this.#streamCollections()) {
        const entry = await collection.findOne({ cursor }, { projection: { _id: 1, settled: 1 } });
        if (entry) {
          exists = true;
          if (entry.settled !== false)
            await this.#sequences.updateOne({ _id: 'inbox' }, { $unset: { [`committed.${cursor}`]: '' } });
          break;
        }
      }
      if (!exists) await this.#sequences.updateOne({ _id: 'inbox' }, { $unset: { [`committed.${cursor}`]: '' } });
    }
    return {
      top: seq ? Math.min(seq.n + 1, ...Object.keys(seq.pending ?? {}).map(Number)) - 1 : 0,
      committed: Object.keys(seq?.committed ?? {}).map(Number),
    };
  }

  #visible(committed: number[]) {
    return { $or: [{ settled: { $ne: false } }, { cursor: { $in: committed } }] };
  }

  async addToInbox(address: string, id: string, at: string, generation?: string, minExpiresAt?: string) {
    await this.#recoverRetractions();
    if (minExpiresAt !== undefined) minExpiresAt = date(minExpiresAt).toISOString();
    for (;;) {
      const state = await this.#admissionState(),
        r = state.receipts[id];
      if (!r) break;
      if (!r.active || (generation !== undefined && r.generation !== generation)) return false;
      if (r.kept && (minExpiresAt === undefined || r.expiresAt >= minExpiresAt)) break;
      r.kept = true;
      r.materialized = false;
      if (minExpiresAt !== undefined && r.expiresAt < minExpiresAt) r.expiresAt = minExpiresAt;
      if (await this.#saveAdmission(state.doc, state.receipts, false)) break;
    }
    let message = await this.#messages.findOne({ _id: id });
    if (!message || message.deleted || (generation !== undefined && (message.generation ?? 'legacy') !== generation))
      return false;
    if (minExpiresAt !== undefined) {
      message = await this.#messages.findOneAndUpdate(
        { _id: id, deleted: { $ne: true }, generation: message.generation ?? { $exists: false } },
        { $max: { expires: date(minExpiresAt) } },
        { returnDocument: 'after' },
      );
      if (!message || message.deleted) return false;
    }
    const added = await this.#streamInsert(this.#inbox as unknown as Collection<Document>, {
      _id: this.#childId(key(address, id), message.generation),
      address,
      id,
      ...(message.generation == null ? {} : { messageGeneration: message.generation }),
      taken: date(at),
      event: true,
      parts: [...new Set(message.parts.map(p => p.sha256))],
    });
    return added;
  }

  async inbox(address: string, after: number, limit: number) {
    const { top, committed } = await this.#watermark();
    const entries = await this.#liveChildren(
      this.#inbox,
      { address, cursor: { $gt: after, $lte: top }, ...this.#visible(committed) },
      { cursor: 1 },
      limit,
    );
    return entries.map(e => ({
      ...this.#entryOf(e.authority[0]),
      cursor: e.cursor,
      address: e.address,
      receivedAt: e.taken.toISOString(),
    }));
  }

  async sync(address: string, after: number, limit: number, now: string, from?: string) {
    const { top, committed } = await this.#watermark();
    const range = {
      cursor: { $gt: after, $lte: top },
      ...this.#visible(committed),
      ...(from === undefined ? {} : { taken: { $gte: date(from) } }),
    };
    const received = await this.#inbox
      .find({ address, ...range })
      .sort({ cursor: 1 })
      .limit(limit + 1)
      .toArray();
    const written = await this.#messages
      .find({ from: address, written: { $ne: false }, ...range })
      .sort({ cursor: 1 })
      .limit(limit + 1)
      .toArray();
    // Page over reserved positions before resolving their messages: deletion or a stale child must not
    // turn a truncated query into an exhausted page that advances past valid positions beyond its limit.
    const candidates = [
      ...received.map(entry => ({ cursor: entry.cursor, inbox: entry, written: null as MessageDoc | null })),
      ...written.map(doc => ({ cursor: doc.cursor!, inbox: null as InboxDoc | null, written: doc })),
    ]
      .sort((a, b) => a.cursor - b.cursor)
      .slice(0, limit + 1);
    const more = candidates.length > limit;
    const selected = candidates.slice(0, limit);
    const messages = [
      ...(await this.#entries(selected.flatMap(c => (c.inbox ? [c.inbox] : [])))),
      ...selected.flatMap(c => (c.written ? [this.#written(c.written)] : [])),
    ].sort((a, b) => a.cursor - b.cursor);
    const cursor = more ? selected.at(-1)!.cursor : top;
    const signals = await this.#signals
      .find({ address, cursor: { $gt: after, $lte: cursor }, ...this.#visible(committed), expires: { $gt: date(now) } })
      .sort({ cursor: 1 })
      .toArray();
    return {
      messages,
      signals: signals.map(({ cursor, type, from, about, at }) => ({ cursor, type, from, about, at })),
      cursor,
      more,
    };
  }

  async holdSignal(address: string, signal: Omit<HeldSignal, 'cursor'>, expiresAt: string, now: string) {
    await this.#signals.deleteMany({ expires: { $lte: date(now) } });
    await this.#streamInsert(this.#signals as unknown as Collection<Document>, {
      _id: randomUUID(),
      address,
      ...signal,
      expires: date(expiresAt),
    });
  }

  async inInbox(address: string, id: string) {
    await this.#recoverRetractions();
    const message = await this.#messages.findOne({ _id: id });
    if (!message || message.deleted) return false;
    return (
      (await this.#inbox.countDocuments(
        {
          _id: this.#childId(key(address, id), message.generation),
          messageGeneration: message.generation ?? { $exists: false },
        },
        { limit: 1 },
      )) > 0
    );
  }

  async wroteTo(author: string, recipient: string, self: string) {
    return (await this.#messages.countDocuments({ from: author, to: recipient, carrier: self }, { limit: 1 })) > 0;
  }

  async inboxEvents(limit: number) {
    const { top, committed } = await this.#watermark();
    const entries = await this.#liveChildren(
      this.#inbox,
      { event: true, cursor: { $lte: top }, ...this.#visible(committed) },
      { cursor: 1 },
      limit,
    );
    return entries.map(e => ({
      ...this.#entryOf(e.authority[0]),
      cursor: e.cursor,
      address: e.address,
      receivedAt: e.taken.toISOString(),
    }));
  }

  async inboxEventDone(cursor: number) {
    await this.#inbox.updateOne({ cursor }, { $set: { event: false } });
  }

  async #entries(entries: InboxDoc[]): Promise<SyncEntry[]> {
    const messages = await this.#messagesById(entries.map(e => e.id));
    return entries.flatMap(e => {
      const doc = messages.get(e.id);
      if (!this.#sameGeneration(doc ?? null, e.messageGeneration)) return [];
      return [{ ...this.#entryOf(doc!), cursor: e.cursor, address: e.address, receivedAt: e.taken.toISOString() }];
    });
  }

  /** A message written here, in its author's stream. */
  #written(doc: MessageDoc): SyncEntry {
    return { ...this.#entryOf(doc), cursor: doc.cursor!, address: doc.from, receivedAt: doc.taken!.toISOString() };
  }

  #entryOf(doc: MessageDoc) {
    const m = this.#message(doc);
    return { id: m.id, message: m.message, carrier: m.carrier, claims: m.claims, signedClaims: m.signedClaims };
  }

  // Webhooks

  #webhook({ _id, slot: _, due: __, quietUntil: ___, lease: ____, leaseUntil: _____, ...rest }: WebhookDoc): Webhook {
    return { id: _id, ...rest };
  }

  /** Each webhook takes a free place of its agent's `max`; a place is unique per agent, so racing adds never pass it. */
  async addWebhook(w: Webhook, max: number) {
    const { id, ...rest } = w;
    for (let slot = 0; slot < max; slot++) {
      const doc = { _id: id, ...rest, slot, due: null, quietUntil: new Date(0) };
      if (await insertOnce(() => this.#webhooks.insertOne(doc), 'slot')) return true;
    }
    return false;
  }

  async webhook(id: string) {
    const doc = await this.#webhooks.findOne({ _id: id });
    return doc ? this.#webhook(doc) : null;
  }

  async verifyWebhook(id: string) {
    await this.#webhooks.updateOne({ _id: id }, { $set: { verified: true } });
  }

  async deleteWebhook(id: string) {
    await this.#webhooks.deleteOne({ _id: id });
  }

  async wakeWebhooks(address: string, at: string) {
    // Due at `at`, or when its quiet ends if that is later; by plain operators, as DocumentDB has no update pipelines.
    const waiting = { address, verified: true, due: null };
    await this.#webhooks.updateMany(
      { ...waiting, quietUntil: { $not: { $gt: date(at) } } },
      { $set: { due: date(at) } },
    );
    for await (const w of this.#webhooks.find({ ...waiting, quietUntil: { $gt: date(at) } }))
      await this.#webhooks.updateOne({ _id: w._id, due: null }, { $set: { due: w.quietUntil } });
  }

  /** Each webhook is claimed by one findOneAndUpdate, so two claims never take the same one. */
  async claimWebhooks(now: string, limit: number, quietUntil: string, lease: { token: string; until: string }) {
    const claimed: Webhook[] = [];
    while (claimed.length < limit) {
      const doc = await this.#webhooks.findOneAndUpdate(
        {
          verified: true,
          quietUntil: { $lte: date(now) },
          $and: [
            { $or: [{ leaseUntil: null }, { leaseUntil: { $lte: date(now) } }] },
            { $or: [{ due: { $lte: date(now) } }, { leaseUntil: { $lte: date(now) } }] },
          ],
        },
        { $set: { due: null, quietUntil: date(quietUntil), lease: lease.token, leaseUntil: date(lease.until) } },
        { sort: { due: 1 } },
      );
      if (!doc) break;
      claimed.push(this.#webhook(doc));
    }
    return claimed;
  }

  async settleWebhook(id: string, failingSince: string | null, retryAt: string | null, token: string, disable = false) {
    if (disable) return (await this.#webhooks.deleteOne({ _id: id, lease: token })).deletedCount === 1;
    // A due time a wake set while it ran is kept; otherwise it is due at `retryAt`. Plain operators in two writes,
    // as DocumentDB has no update pipelines: a wake between them leaves its due time, as it should.
    const settled = { failingSince, lease: null, leaseUntil: null };
    const unwoken = await this.#webhooks.updateOne(
      { _id: id, lease: token, due: null },
      { $set: { ...settled, due: retryAt ? date(retryAt) : null } },
    );
    if (unwoken.matchedCount === 1) return true;
    return (await this.#webhooks.updateOne({ _id: id, lease: token }, { $set: settled })).matchedCount === 1;
  }

  /**
   * The next number of a sequence, recorded as pending, stamped by the database's clock, in the same write
   * that takes it. That write lands only over the counter it read, so two writers never take one number;
   * the one that lost reads again.
   */
  async #nextPending(name: string): Promise<number> {
    for (let attempt = 0; ; await backoff(++attempt)) {
      const seq = await this.#sequences.findOne({ _id: name }, { projection: { n: 1 } });
      const n = (seq?.n ?? 0) + 1;
      try {
        const r = await this.#sequences.updateOne(
          { _id: name, n: seq ? seq.n : { $exists: false } },
          { $set: { n }, $currentDate: { [`pending.${n}`]: true } },
          { upsert: !seq },
        );
        if (r.matchedCount || r.upsertedCount) return n;
      } catch (e) {
        if (!isDuplicate(e, '_id')) throw e;
      }
    }
  }

  // Deliveries

  #delivery({ _id, hints, nextAttemptAt, lease, messageGeneration: _, ...rest }: DeliveryDoc): Delivery {
    return { ...rest, hints: JSON.parse(hints) as Hints, nextAttemptAt: nextAttemptAt.toISOString() };
  }

  /** Each row is claimed by one findOneAndUpdate, so two claims never take the same one. */
  async claimDeliveries(now: string, limit: number, skip: string[], lease: { token: string; until: string }) {
    await this.#recover();
    const claimed: Delivery[] = [];
    while (claimed.length < limit) {
      const doc = await this.#deliveries.findOneAndUpdate(
        { status: 'pending', nextAttemptAt: { $lte: date(now) }, server: { $nin: skip } },
        { $set: { lease: lease.token, nextAttemptAt: date(lease.until) } },
        { sort: { nextAttemptAt: 1 }, returnDocument: 'after' },
      );
      if (!doc) break;
      if (!this.#sameGeneration(await this.#messages.findOne({ _id: doc.id }), doc.messageGeneration)) {
        await this.#deliveries.deleteOne({
          _id: doc._id,
          messageGeneration: doc.messageGeneration ?? { $exists: false },
        });
        continue;
      }
      claimed.push(this.#delivery(doc));
    }
    return claimed;
  }

  async settleDelivery(d: Delivery, token: string) {
    const message = await this.#messages.findOne({ _id: d.id });
    if (!message || message.deleted) return false;
    const r = await this.#deliveries.updateOne(
      { _id: this.#childId(key(d.id, d.domain), message.generation), status: 'pending', lease: token },
      {
        $set: {
          server: d.server,
          status: d.status,
          reason: d.reason,
          attempts: d.attempts,
          nextAttemptAt: date(d.nextAttemptAt),
          lease: null,
          // Hints are kept only while the delivery may still be attempted.
          ...(d.status === 'pending' ? {} : { hints: '{}' }),
        },
      },
    );
    return r.matchedCount === 1;
  }

  async deliveries(id: string) {
    await this.#recoverRetractions();
    const message = await this.#messages.findOne({ _id: id });
    if (!message || message.deleted) return [];
    return (
      await this.#deliveries
        .find({ id, messageGeneration: message.generation ?? { $exists: false } })
        .sort({ domain: 1 })
        .toArray()
    ).map(d => this.#delivery(d));
  }

  // Parts

  async putPart(sha256: string, bytes: Buffer, source: PartSource, at: string) {
    const _id = key(sha256, sourceKey(source));
    if (await this.#parts.findOne({ _id })) {
      await this.#parts.updateOne({ _id }, { $set: { created: date(at) } });
      return;
    }
    const chunks = Math.max(1, Math.ceil(bytes.length / CHUNK_BYTES));
    for (let i = 0; i < chunks; i++) {
      const data = new Binary(bytes.subarray(i * CHUNK_BYTES, (i + 1) * CHUNK_BYTES));
      await this.#chunks.updateOne({ _id: `${_id}:${i}` }, { $set: { data } }, { upsert: true });
    }
    const part: PartDoc = {
      _id,
      sha256,
      source: sourceKey(source),
      fetched: 'carrier' in source,
      size: bytes.length,
      chunks,
      created: date(at),
    };
    await insertOnce(() => this.#parts.insertOne(part), '_id');
  }

  async part(sha256: string, source: PartSource) {
    const meta = await this.#parts.findOne({ _id: key(sha256, sourceKey(source)) });
    if (!meta) return null;
    const ids = Array.from({ length: meta.chunks }, (_, i) => `${meta._id}:${i}`);
    const chunks = new Map((await this.#chunks.find({ _id: { $in: ids } }).toArray()).map(c => [c._id, c.data]));
    return Buffer.concat(ids.map(id => Buffer.from(chunks.get(id)!.buffer)));
  }

  async heldFor(sha256: string, address: string, self: string) {
    const sources: (PartSource & { size: number })[] = [];
    const seen = new Set<string>();
    const pending = [address];
    // Traverse only generation-matched inbox grants for this hash; never cross a remote-carrier edge.
    for (const holder of pending) {
      if (seen.has(holder)) continue;
      seen.add(holder);
      const received = await this.#inboxed(holder, sha256);
      for (const source of await this.#held(sha256, holder, received, self)) {
        sources.push(source);
        if (source.uploader !== undefined && !seen.has(source.uploader)) pending.push(source.uploader);
      }
    }
    return uniqueSources(sources);
  }

  /**
   * The messages in an agent's inbox naming a part, found from its own entries (as SQLite joins from its inbox),
   * never from every message naming the hash. At most HELD_ENTRIES entries are read: the sources they grant
   * are few (one per carrier or local author), however many messages repeat them.
   */
  async #inboxed(address: string, sha256: string): Promise<NamingDoc[]> {
    const entries = await this.#inbox
      .find({ address, parts: sha256 }, { projection: { id: 1, messageGeneration: 1 } })
      .sort({ cursor: -1 })
      .limit(HELD_ENTRIES)
      .toArray();
    if (!entries.length) return [];
    const naming = await this.#messages
      .find(
        { _id: { $in: entries.map(e => e.id) }, 'parts.sha256': sha256 },
        { projection: { _id: 1, from: 1, carrier: 1, parts: 1, generation: 1 } },
      )
      .toArray();
    return naming.filter(m => entries.some(e => e.id === m._id && e.messageGeneration === m.generation));
  }

  /**
   * An agent's own upload of a part, and for each message in its inbox naming it (`received`), the carrier's
   * bytes, or the author's upload when the carrier is `self`.
   */
  async #held(sha256: string, address: string, received: NamingDoc[], self: string) {
    const own = await this.#parts.findOne({ _id: key(sha256, address), fetched: false });
    const sources = received.map(m => {
      const size = m.parts.find(p => p.sha256 === sha256)!.size;
      return m.carrier === self ? { uploader: m.from, size } : { carrier: m.carrier, size };
    });
    return [...(own ? [{ uploader: address, size: own.size }] : []), ...sources];
  }

  async partNamers(sha256: string, viewer: { published: true } | { server: string }, self: string) {
    const published = 'published' in viewer ? { public: true } : {};
    const naming = await this.#messages
      .find({ 'parts.sha256': sha256, carrier: self, ...published }, { projection: { _id: 1, from: 1, json: 1 } })
      .toArray();
    const delivered =
      'server' in viewer
        ? await this.#deliveries
            .find({ id: { $in: naming.map(m => m._id) }, server: viewer.server, status: 'delivered' })
            .toArray()
        : null;
    const ids = delivered && new Set(delivered.map(d => d.id));
    const seen = ids ? naming.filter(m => ids.has(m._id)) : naming;
    const live = new Set(
      (
        await this.#agents
          .find({ _id: { $in: seen.map(m => m.from) }, retiredAt: null }, { projection: { _id: 1 } })
          .toArray()
      ).map(a => a._id),
    );
    return seen.filter(m => live.has(m.from)).map(m => ({ author: m.from, message: JSON.parse(m.json) as AnyMessage }));
  }

  // Part fetches

  #fetch = ({ _id, due, token: _, exhausted: __, ...f }: FetchDoc): PartFetch => ({ ...f, dueAt: due.toISOString() });

  queueFetch(f: PartFetch, now?: string): Promise<PartFetch>;
  queueFetch(f: PartFetch, now: string | undefined, max: number): Promise<PartFetch | null>;
  async queueFetch(f: PartFetch, now?: string, max?: number): Promise<PartFetch | null> {
    const _id = key(f.sha256, f.carrier);
    const { dueAt, ...rest } = f;
    if (now !== undefined) await this.#fetches.deleteOne({ _id, exhausted: { $lte: date(now) } });
    if (max !== undefined) {
      const queued = await this.#fetches.findOne({ _id });
      if (queued) return this.#fetch(queued);
      // Racing queuers of one carrier may each pass by one: the cap bounds the queue, not to the row.
      if ((await this.#fetches.countDocuments({ carrier: f.carrier, exhausted: null }, { limit: max })) >= max)
        return null;
    }
    // Return the row from the same atomic operation; a worker may delete it immediately afterwards.
    // A duplicate-key loser retries with a fresh generation instead of dereferencing a separate null read.
    for (;;) {
      try {
        const doc = await this.#fetches.findOneAndUpdate(
          { _id },
          { $setOnInsert: { ...rest, revision: 0, generation: randomUUID(), due: date(dueAt) } },
          { upsert: true, returnDocument: 'after' },
        );
        if (doc) return this.#fetch(doc);
      } catch (e) {
        if (!isDuplicate(e, '_id')) throw e;
      }
    }
  }

  async fetches(now: string, limit: number) {
    // The turns are counted here, as DocumentDB has no window functions. Only the `limit` carriers waiting
    // longest can have a row in the answer, since each has a first turn; and with k of them, no row past turn
    // limit - k + 1 can.
    const due = { due: { $lte: date(now) }, exhausted: null };
    const carriers = await this.#fetches
      .aggregate<{
        _id: string;
      }>([
        { $match: due },
        { $sort: { due: 1, _id: 1 } },
        { $group: { _id: '$carrier', due: { $first: '$due' }, row: { $first: '$_id' } } },
        { $sort: { due: 1, row: 1 } },
        { $limit: limit },
      ])
      .toArray();
    const turns = await Promise.all(
      carriers.map(c =>
        this.#fetches
          .find({ ...due, carrier: c._id })
          .sort({ due: 1, _id: 1 })
          .limit(limit - carriers.length + 1)
          .toArray(),
      ),
    );
    return turns
      .flatMap(rows => rows.map((doc, turn) => ({ doc, turn })))
      .sort((a, b) => a.turn - b.turn || +a.doc.due - +b.doc.due || (a.doc._id < b.doc._id ? -1 : 1))
      .slice(0, limit)
      .map(({ doc }) => this.#fetch(doc));
  }

  async claimFetch(f: PartFetch, now: string, lease: { token: string; until: string }) {
    if (!f.generation || date(f.dueAt) > date(now) || date(lease.until) <= date(now)) return false;
    const r = await this.#fetches.updateOne(
      {
        _id: key(f.sha256, f.carrier),
        attempts: f.attempts,
        due: date(f.dueAt),
        revision: f.revision ?? 0,
        generation: f.generation,
        exhausted: null,
      },
      { $set: { due: date(lease.until), token: lease.token }, $inc: { revision: 1 } },
    );
    return r.matchedCount === 1;
  }

  async renewFetch(sha256: string, carrier: string, token: string, now: string, until: string) {
    if (date(until) <= date(now)) return false;
    const r = await this.#fetches.updateOne(
      { _id: key(sha256, carrier), token, due: { $gt: date(now) }, exhausted: null },
      { $set: { due: date(until) }, $inc: { revision: 1 } },
    );
    return r.matchedCount === 1;
  }

  async fetchRetry(sha256: string, carrier: string, at: string, token: string) {
    const r = await this.#fetches.updateOne(
      { _id: key(sha256, carrier), token, exhausted: null },
      { $inc: { attempts: 1, revision: 1 }, $set: { due: date(at), token: null } },
    );
    return r.matchedCount === 1;
  }

  async fetchDefer(sha256: string, carrier: string, at: string, token: string) {
    const r = await this.#fetches.updateOne(
      { _id: key(sha256, carrier), token, exhausted: null },
      { $set: { due: date(at), token: null }, $inc: { revision: 1 } },
    );
    return r.matchedCount === 1;
  }

  async fetchDone(sha256: string, carrier: string, token: string) {
    return (await this.#fetches.deleteOne({ _id: key(sha256, carrier), token, exhausted: null })).deletedCount === 1;
  }

  async fetchGiveUp(sha256: string, carrier: string, token: string, expiresAt: string) {
    const r = await this.#fetches.updateOne(
      { _id: key(sha256, carrier), token, exhausted: null },
      { $set: { exhausted: date(expiresAt), token: null }, $inc: { revision: 1 } },
    );
    return r.matchedCount === 1;
  }

  async fetchExhausted(sha256: string, carrier: string, now: string) {
    return (
      (await this.#fetches.countDocuments({ _id: key(sha256, carrier), exhausted: { $gt: date(now) } }, { limit: 1 })) >
      0
    );
  }

  // Marks, counters and values

  async mark(scope: string, id: string, expiresAt: string, now: string) {
    try {
      const r = await this.#marks.updateOne(
        { _id: key(scope, id), expires: { $lte: date(now) } },
        { $set: { expires: date(expiresAt) } },
        { upsert: true },
      );
      return r.matchedCount + r.upsertedCount === 1;
    } catch (e) {
      if (isDuplicate(e, '_id')) return false;
      throw e;
    }
  }

  async marked(scope: string, id: string, now: string) {
    return (await this.#marks.countDocuments({ _id: key(scope, id), expires: { $gt: date(now) } })) > 0;
  }

  async count(scope: string, id: string, expiresAt: string, now: string, by = 1): Promise<number> {
    const _id = key(scope, id);
    await this.#counters.deleteOne({ _id, expires: { $lte: date(now) } });
    for (;;) {
      try {
        const doc = await this.#counters.findOneAndUpdate(
          { _id },
          { $inc: { n: by }, $setOnInsert: { expires: date(expiresAt) } },
          { upsert: true, returnDocument: 'after' },
        );
        return doc!.n!;
      } catch (e) {
        // Two first counts raced to insert: the loser counts again, on the winner's document.
        if (!isDuplicate(e, '_id')) throw e;
      }
    }
  }

  async value<T>(scope: string, id: string, now: string) {
    if (scope === 'recovery') {
      const doc = await this.#recoveryAgent(id);
      const held = doc ? this.#liveRecovery(doc, now) : null;
      return held ? (JSON.parse(held.value) as T) : null;
    }
    const doc = await this.#values.findOne({
      _id: key(scope, id),
      $or: [{ expires: null }, { expires: { $gt: date(now) } }],
    });
    return doc ? (JSON.parse(doc.value!) as T) : null;
  }

  async setValue(scope: string, id: string, value: unknown, expiresAt: string | null) {
    if (scope === 'recovery')
      throw new Error('The recovery scope is reserved; use beginRecovery, completeRecovery or cancelRecovery.');
    const expires = expiresAt === null ? null : date(expiresAt);
    await this.#values.updateOne(
      { _id: key(scope, id) },
      { $set: { value: JSON.stringify(value), expires } },
      { upsert: true },
    );
  }

  async releaseValue(scope: string, id: string, value: unknown) {
    if (scope === 'recovery')
      throw new Error('The recovery scope is reserved; use beginRecovery, completeRecovery or cancelRecovery.');
    const r = await this.#values.deleteOne({ _id: key(scope, id), value: JSON.stringify(value) });
    return r.deletedCount === 1;
  }

  async renewValue(scope: string, id: string, value: unknown, expiresAt: string) {
    if (scope === 'recovery')
      throw new Error('The recovery scope is reserved; use beginRecovery, completeRecovery or cancelRecovery.');
    const r = await this.#values.updateOne(
      { _id: key(scope, id), value: JSON.stringify(value) },
      { $set: { expires: date(expiresAt) } },
    );
    return r.matchedCount === 1;
  }

  async valueOnce<T>(scope: string, id: string, value: T, expiresAt: string | null, now: string) {
    if (scope === 'recovery')
      throw new Error('The recovery scope is reserved; use beginRecovery, completeRecovery or cancelRecovery.');
    const expires = expiresAt === null ? null : date(expiresAt);
    try {
      // Replace only an expired value; with none there, the upsert inserts.
      await this.#values.updateOne(
        { _id: key(scope, id), expires: { $ne: null, $lte: date(now) } },
        { $set: { value: JSON.stringify(value), expires } },
        { upsert: true },
      );
    } catch (e) {
      if (!isDuplicate(e, '_id')) throw e;
    }
    return (await this.value<T>(scope, id, now))!;
  }

  /**
   * Up to `limit` rows of a collection, in `_id` order from where the last sweep stopped (kept in core.values
   * under `name`), starting over from the first once the end is reached. Each sweep thus examines a bounded
   * slice, and every row in turn.
   */
  async #sweepSlice<T extends { _id: string }>(
    collection: Collection<T>,
    name: string,
    limit: number,
    projection: Document,
  ): Promise<T[]> {
    const mark = key('sweep-position', name);
    const from = await this.#values.findOne({ _id: mark });
    const after = from?.value ? (JSON.parse(from.value) as string) : null;
    const rows = (await collection
      .find((after === null ? {} : { _id: { $gt: after } }) as Filter<T>, { projection })
      .sort({ _id: 1 })
      .limit(limit)
      .toArray()) as T[];
    const next = rows.length < limit ? null : rows.at(-1)!._id;
    await this.#values.updateOne(
      { _id: mark },
      { $set: { value: JSON.stringify(next), expires: null } },
      { upsert: true },
    );
    return rows;
  }

  async sweep(now: string, uploadsBefore: string): Promise<SweepCounts> {
    const t = date(now);
    await this.#fetches.deleteMany({ exhausted: { $lte: t } });
    // Rows a crash or a paused copy left behind their message: a slice of each collection per sweep, each
    // row's message looked up by `_id` with one `$in` per batch, never a join over the whole collection.
    for (const [name, collection] of [
      ['inbox', this.#inbox],
      ['arrivals', this.#arrivals],
      ['deliveries', this.#deliveries],
    ] as unknown as [string, Collection<{ _id: string; id: string; messageGeneration?: string }>][]) {
      const rows = await this.#sweepSlice(collection, name, ORPHAN_SCAN, { _id: 1, id: 1, messageGeneration: 1 });
      for (let i = 0; i < rows.length; i += 500) {
        const batch = rows.slice(i, i + 500);
        const held = new Map(
          (
            await this.#messages
              .find({ _id: { $in: [...new Set(batch.map(r => r.id))] } }, { projection: { _id: 1, generation: 1 } })
              .toArray()
          ).map(m => [m._id, m.generation ?? null]),
        );
        for (const row of batch) {
          if (held.has(row.id) && held.get(row.id) === (row.messageGeneration ?? null)) continue;
          await collection.deleteOne({ _id: row._id, messageGeneration: row.messageGeneration ?? { $exists: false } });
        }
      }
    }
    let messages = 0;
    for (;;) {
      const batch = await this.#messages
        .find({ expires: { $lte: t }, deleted: { $ne: true } })
        .limit(500)
        .toArray();
      if (!batch.length) break;
      messages += await this.#deleteMessages(
        batch.map(m => m._id),
        new Map(batch.map(m => [m._id, m])),
      );
    }
    // Fetches no message names any more, from its carrier: a slice per sweep, each a point lookup.
    for (const f of await this.#sweepSlice(this.#fetches, 'fetches', FETCH_SCAN, { _id: 1, sha256: 1, carrier: 1 })) {
      const named = await this.#messages.findOne(
        { carrier: f.carrier, 'parts.sha256': f.sha256 },
        { projection: { _id: 1 } },
      );
      if (!named) await this.#fetches.deleteOne({ _id: f._id });
    }
    let parts = 0;
    const candidates = this.#parts.find({ $or: [{ fetched: true }, { created: { $lt: date(uploadsBefore) } }] });
    for await (const p of candidates) {
      const by = p.fetched ? { carrier: p.source } : { from: p.source };
      if (await this.#messages.findOne({ 'parts.sha256': p.sha256, ...by }, { projection: { _id: 1 } })) continue;
      await this.#chunks.deleteMany({ _id: { $in: Array.from({ length: p.chunks }, (_, i) => `${p._id}:${i}`) } });
      parts += (await this.#parts.deleteOne({ _id: p._id })).deletedCount;
    }
    let marks = (
      await this.#agents.updateMany(
        { 'recovery.expires': { $ne: null, $lte: t } },
        { $set: { recovery: null }, $inc: { authorityVersion: 1, recoveryEpoch: 1 } },
      )
    ).modifiedCount;
    for (const c of [this.#marks, this.#counters, this.#values]) {
      marks += (await c.deleteMany({ expires: { $ne: null, $lte: t } })).deletedCount;
    }
    const signals = (await this.#signals.deleteMany({ expires: { $lte: t } })).deletedCount;
    return { messages, parts, marks, signals };
  }

  async close() {
    await this.#close();
  }
}
