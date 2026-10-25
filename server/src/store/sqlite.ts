/**
 * The Store on node:sqlite. One connection, WAL, and every multi-statement change in one IMMEDIATE
 * transaction, so each method is atomic for this process and serialised against any other process sharing
 * the file. Times are stored as epoch milliseconds, so comparisons never depend on how a timestamp is spelled.
 */
import { randomUUID } from 'node:crypto';
import type { DatabaseSync, SQLInputValue } from 'node:sqlite';
import { canonicalize, header, namedFiles, VERSION, type AnyMessage } from '@agnt-sdk/simon-protocol';
import { MAX_STORED_KEYS, StoreCapacityError, resolveRetractionCapacity, type RetractionCapacity } from './store.ts';
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
} from './store.ts';

/** The schema's version, kept in `PRAGMA user_version`. A file made by another version is refused. */
const SCHEMA_VERSION = 9;

const SCHEMA = `
CREATE TABLE agents (address TEXT PRIMARY KEY, kind TEXT NOT NULL, principal TEXT, mailbox INTEGER NOT NULL,
  created_at TEXT NOT NULL, retired_at TEXT, unpairing TEXT, authority_version INTEGER NOT NULL DEFAULT 0, recovery_key_cancelled_at TEXT, authorized_keys TEXT,
  recovery_epoch INTEGER NOT NULL DEFAULT 0);
CREATE TABLE agent_keys (key TEXT PRIMARY KEY, address TEXT NOT NULL, added TEXT NOT NULL, revoked TEXT,
  seq INTEGER NOT NULL, label TEXT);
CREATE INDEX agent_keys_address ON agent_keys (address);
CREATE TABLE messages (id TEXT PRIMARY KEY, json TEXT NOT NULL, from_address TEXT NOT NULL, public INTEGER NOT NULL,
  in_reply_to TEXT, carrier TEXT NOT NULL, claims TEXT NOT NULL, signed_claims TEXT, received_at TEXT NOT NULL,
  expires INTEGER NOT NULL, kept INTEGER NOT NULL, cursor INTEGER, taken INTEGER, generation TEXT NOT NULL);
CREATE INDEX messages_expires ON messages (expires);
CREATE INDEX messages_written ON messages (from_address, cursor) WHERE cursor IS NOT NULL;
CREATE INDEX messages_published ON messages (from_address) WHERE public = 1;
CREATE INDEX messages_in_reply_to ON messages (in_reply_to);
CREATE TABLE message_parts (id TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, PRIMARY KEY (id, sha256));
CREATE INDEX message_parts_sha ON message_parts (sha256);
CREATE TABLE retraction_admission(singleton INTEGER PRIMARY KEY CHECK(singleton=1),body TEXT NOT NULL);
INSERT INTO retraction_admission VALUES(1,'{}');
CREATE TABLE listing_retractions(owner TEXT NOT NULL,target TEXT NOT NULL,author TEXT NOT NULL,retraction TEXT NOT NULL,
  PRIMARY KEY(owner,retraction));
CREATE INDEX listing_retractions_target ON listing_retractions(owner,target,author);
CREATE TABLE arrivals (id TEXT NOT NULL, recipient TEXT NOT NULL, hints TEXT NOT NULL, attempts INTEGER NOT NULL,
  due INTEGER NOT NULL, PRIMARY KEY (id, recipient));
CREATE INDEX arrivals_due ON arrivals (due);
CREATE TABLE positions (n INTEGER NOT NULL);
INSERT INTO positions VALUES (0);
CREATE TABLE inbox (cursor INTEGER PRIMARY KEY, address TEXT NOT NULL, id TEXT NOT NULL, taken INTEGER NOT NULL,
  event INTEGER NOT NULL, UNIQUE (address, id));
CREATE INDEX inbox_address ON inbox (address, cursor);
CREATE INDEX inbox_id ON inbox (id);
CREATE INDEX inbox_events ON inbox (cursor) WHERE event = 1;
CREATE TABLE signals (cursor INTEGER PRIMARY KEY, address TEXT NOT NULL, signal TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE INDEX signals_address ON signals (address, cursor);
CREATE INDEX signals_expires ON signals (expires);
CREATE TABLE webhooks (id TEXT PRIMARY KEY, address TEXT NOT NULL, url TEXT NOT NULL, code_hash TEXT NOT NULL,
  verified INTEGER NOT NULL, created_at TEXT NOT NULL, failing_since TEXT, due INTEGER, quiet_until INTEGER NOT NULL, lease TEXT, lease_until INTEGER);
CREATE INDEX webhooks_address ON webhooks (address);
CREATE INDEX webhooks_due ON webhooks (due) WHERE due IS NOT NULL;
CREATE TABLE deliveries (id TEXT NOT NULL, domain TEXT NOT NULL, recipients TEXT NOT NULL, hints TEXT NOT NULL,
  server TEXT, status TEXT NOT NULL, reason TEXT, attempts INTEGER NOT NULL, next_attempt INTEGER NOT NULL,
  created_at TEXT NOT NULL, deadline TEXT NOT NULL, lease TEXT, PRIMARY KEY (id, domain));
CREATE INDEX deliveries_due ON deliveries (status, next_attempt);
CREATE TABLE parts (sha256 TEXT NOT NULL, source TEXT NOT NULL, fetched INTEGER NOT NULL, size INTEGER NOT NULL,
  bytes BLOB NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (sha256, source));
CREATE TABLE fetches (sha256 TEXT NOT NULL, carrier TEXT NOT NULL, size INTEGER NOT NULL, attempts INTEGER NOT NULL,
  due INTEGER NOT NULL, token TEXT, exhausted INTEGER, revision INTEGER NOT NULL DEFAULT 0, generation TEXT NOT NULL, PRIMARY KEY (sha256, carrier));
CREATE INDEX fetches_due ON fetches (due);
CREATE TABLE marks (scope TEXT NOT NULL, id TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY (scope, id));
CREATE TABLE counters (scope TEXT NOT NULL, id TEXT NOT NULL, n INTEGER NOT NULL, expires INTEGER NOT NULL,
  PRIMARY KEY (scope, id));
CREATE TABLE vals (scope TEXT NOT NULL, id TEXT NOT NULL, value TEXT NOT NULL, expires INTEGER,
  PRIMARY KEY (scope, id));
PRAGMA user_version = ${SCHEMA_VERSION};
`;

type Row = Record<string, SQLInputValue>;

const ms = (t: string) => {
  const n = Date.parse(t);
  if (Number.isNaN(n)) throw new TypeError(`Not a timestamp: ${t}`);
  return n;
};
const iso = (n: SQLInputValue) => new Date(n as number).toISOString();

/** A part's source as one column: the uploader's address, or the carrier's origin (never an address). */
const sourceKey = (s: PartSource) => ('uploader' in s ? s.uploader : s.carrier);

/** Sources found along more than one path, once each. */
const uniqueSources = <T extends PartSource & { size: number }>(sources: T[]) => [
  ...new Map(sources.map(s => [`${'uploader' in s ? 'u' : 'c'} ${sourceKey(s)} ${s.size}`, s])).values(),
];

/** A version 2 message's `inReplyTo`. Other versions point at nothing the server can see. */
const inReplyTo = (m: AnyMessage) =>
  m.v === VERSION ? ((m as { inReplyTo?: string | null }).inReplyTo ?? null) : null;

/** A page of rows, newest first, fetched one beyond `limit` to tell whether there are more. */
const page = (rows: Row[], limit: number, record: (r: Row) => StoredMessage): Page => ({
  records: rows.slice(0, limit).map(r => ({ cursor: r.id as string, message: record(r) })),
  more: rows.length > limit,
});

/**
 * The files a version 2 message names by content address, its own and those of messages it carries whole
 * (`namedFiles`). Other versions name none the server can see.
 */
const namedParts = (m: AnyMessage) => namedFiles(m);

interface RetractionReceipt {
  record: StoredMessage | null;
  author: string;
  markers: { owner: string; target: string; author: string; retraction: string }[];
  generation: string;
  active: boolean;
  materialized: boolean;
  knownDeliveries: string[];
  knownArrivals: string[];
  pendingDeliveries: Record<string, Delivery>;
  pendingArrivals: Record<string, QueuedArrival>;
}

export class SqliteStore implements Store {
  readonly #retractionCapacity: RetractionCapacity;
  readonly #db: DatabaseSync;

  constructor(path = ':memory:', options: { retractions?: Partial<RetractionCapacity> } = {}) {
    this.#retractionCapacity = resolveRetractionCapacity(options.retractions);
    // node:sqlite is loaded when a SqliteStore is made, never on import: an application on another Store never
    // loads it, nor sees the warnings some Node versions print for it.
    const { DatabaseSync } = process.getBuiltinModule('node:sqlite');
    this.#db = new DatabaseSync(path);
    this.#db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = OFF;');
    try {
      this.#tx(() => {
        // Creation and upgrade both recheck state under the same write lock.
        if (!this.#get("SELECT 1 FROM sqlite_master WHERE type='table'")) {
          this.#db.exec(SCHEMA);
          return;
        }
        // Inspect and migrate again under the write lock: another opener may have upgraded first.
        const locked = this.#get('PRAGMA user_version')!.user_version as number;
        if (locked === SCHEMA_VERSION) return;
        if (locked !== 3 && locked !== 4 && locked !== 5 && locked !== 6 && locked !== 7 && locked !== 8) {
          throw new Error(
            `${path} was made by another version of this server (schema ${locked}, not ${SCHEMA_VERSION}).`,
          );
        }
        const columns = (table: string) => this.#all(`PRAGMA table_info(${table})`).map(c => c.name);
        if (!columns('agents').includes('unpairing')) this.#db.exec('ALTER TABLE agents ADD COLUMN unpairing TEXT;');
        if (!columns('agents').includes('authority_version'))
          this.#db.exec('ALTER TABLE agents ADD COLUMN authority_version INTEGER NOT NULL DEFAULT 0;');
        if (!columns('agents').includes('recovery_key_cancelled_at'))
          this.#db.exec('ALTER TABLE agents ADD COLUMN recovery_key_cancelled_at TEXT;');
        if (!columns('agents').includes('authorized_keys'))
          this.#db.exec('ALTER TABLE agents ADD COLUMN authorized_keys TEXT;');
        if (!columns('agents').includes('recovery_epoch'))
          this.#db.exec('ALTER TABLE agents ADD COLUMN recovery_epoch INTEGER NOT NULL DEFAULT 0;');
        if (!columns('agent_keys').includes('label')) this.#db.exec('ALTER TABLE agent_keys ADD COLUMN label TEXT;');
        const historicalInboxTop = this.#get("SELECT 1 FROM sqlite_master WHERE name='sqlite_sequence'")
          ? ((this.#get("SELECT seq FROM sqlite_sequence WHERE name='inbox'")?.seq as number | undefined) ?? 0)
          : 0;
        const messageColumns = columns('messages');
        if (!messageColumns.includes('cursor')) {
          this.#db.exec(
            'ALTER TABLE messages ADD COLUMN cursor INTEGER; ALTER TABLE messages ADD COLUMN taken INTEGER;',
          );
        }
        if (!columns('messages').includes('generation')) {
          this.#db.exec('ALTER TABLE messages ADD COLUMN generation TEXT;');
          for (const row of this.#all('SELECT id FROM messages'))
            this.#run('UPDATE messages SET generation=? WHERE id=?', randomUUID(), row.id);
        }
        if (!columns('inbox').includes('taken')) {
          this.#db.exec(`ALTER TABLE inbox RENAME TO inbox_legacy;
              CREATE TABLE inbox(cursor INTEGER PRIMARY KEY, address TEXT NOT NULL, id TEXT NOT NULL, taken INTEGER NOT NULL,
                event INTEGER NOT NULL, UNIQUE(address,id));
              INSERT INTO inbox SELECT cursor,address,id,CAST(ROUND((julianday(received_at)-2440587.5)*86400000) AS INTEGER),event FROM inbox_legacy;
              DROP TABLE inbox_legacy;
              CREATE INDEX inbox_id ON inbox(id);
              CREATE INDEX inbox_events ON inbox(cursor) WHERE event=1;
              CREATE INDEX inbox_address ON inbox(address,cursor);`);
        }
        this.#db.exec(`CREATE TABLE IF NOT EXISTS positions (n INTEGER NOT NULL);
            INSERT INTO positions SELECT COALESCE((SELECT MAX(cursor) FROM inbox), 0) WHERE NOT EXISTS (SELECT 1 FROM positions);
            CREATE INDEX IF NOT EXISTS messages_written ON messages(from_address, cursor) WHERE cursor IS NOT NULL;
            CREATE TABLE IF NOT EXISTS signals(cursor INTEGER PRIMARY KEY, address TEXT NOT NULL, signal TEXT NOT NULL, expires INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS signals_address ON signals(address, cursor);
            CREATE INDEX IF NOT EXISTS signals_expires ON signals(expires);
            CREATE TABLE IF NOT EXISTS webhooks(id TEXT PRIMARY KEY, address TEXT NOT NULL, url TEXT NOT NULL, code_hash TEXT NOT NULL,
              verified INTEGER NOT NULL, created_at TEXT NOT NULL, failing_since TEXT, due INTEGER, quiet_until INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS webhooks_address ON webhooks(address);
            CREATE INDEX IF NOT EXISTS webhooks_due ON webhooks(due) WHERE due IS NOT NULL;`);
        const high = this.#get('SELECT MAX(n) AS n FROM positions')?.n as number | null;
        const surviving = this.#get(
          'SELECT MAX(n) AS n FROM (SELECT MAX(cursor) AS n FROM inbox UNION ALL SELECT MAX(cursor) FROM messages UNION ALL SELECT MAX(cursor) FROM signals)',
        )?.n as number | null;
        this.#run('DELETE FROM positions');
        this.#run('INSERT INTO positions VALUES(?)', Math.max(historicalInboxTop, high ?? 0, surviving ?? 0));
        if (!columns('fetches').includes('revision'))
          this.#db.exec('ALTER TABLE fetches ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;');
        if (!columns('fetches').includes('generation')) {
          this.#db.exec('ALTER TABLE fetches ADD COLUMN generation TEXT;');
          for (const row of this.#all('SELECT sha256,carrier FROM fetches'))
            this.#run(
              'UPDATE fetches SET generation=? WHERE sha256=? AND carrier=?',
              randomUUID(),
              row.sha256,
              row.carrier,
            );
        }
        if (!columns('fetches').includes('token'))
          this.#db.exec('ALTER TABLE fetches ADD COLUMN token TEXT; ALTER TABLE fetches ADD COLUMN exhausted INTEGER;');
        if (!columns('webhooks').includes('lease'))
          this.#db.exec(
            'ALTER TABLE webhooks ADD COLUMN lease TEXT; ALTER TABLE webhooks ADD COLUMN lease_until INTEGER;',
          );
        this.#db
          .exec(`CREATE TABLE IF NOT EXISTS listing_retractions(owner TEXT NOT NULL,target TEXT NOT NULL,author TEXT NOT NULL,retraction TEXT NOT NULL,PRIMARY KEY(owner,retraction));
            CREATE INDEX IF NOT EXISTS listing_retractions_target ON listing_retractions(owner,target,author);
            CREATE TABLE IF NOT EXISTS retraction_admission(singleton INTEGER PRIMARY KEY CHECK(singleton=1),body TEXT NOT NULL);
            INSERT OR IGNORE INTO retraction_admission VALUES(1,'{}');
            PRAGMA user_version = ${SCHEMA_VERSION};`);
        if (locked < 8)
          this.#run(
            "INSERT OR IGNORE INTO vals(scope,id,value,expires) SELECT 'sync-history-gap',address,'true',NULL FROM agents",
          );
      });
      this.#tx(() => this.#bootstrapRetractions());
      // Indexes that change no row: made on every open, so a store of any schema version has them.
      this.#db.exec('CREATE INDEX IF NOT EXISTS fetches_carrier ON fetches (carrier, exhausted);');
    } catch (e) {
      this.#db.close();
      throw e;
    }
  }

  #all(sql: string, ...params: SQLInputValue[]): Row[] {
    return this.#db.prepare(sql).all(...params) as Row[];
  }
  #get(sql: string, ...params: SQLInputValue[]): Row | undefined {
    return this.#db.prepare(sql).get(...params) as Row | undefined;
  }
  #run(sql: string, ...params: SQLInputValue[]) {
    return this.#db.prepare(sql).run(...params);
  }
  #tx<T>(work: () => T): T {
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const result = work();
      this.#db.exec('COMMIT');
      return result;
    } catch (e) {
      this.#db.exec('ROLLBACK');
      throw e;
    }
  }

  // Agents

  #agent(address: string): Agent | null {
    const a = this.#get('SELECT * FROM agents WHERE address = ?', address);
    if (!a) return null;
    const keys = this.#all('SELECT key, added, revoked, label FROM agent_keys WHERE address = ? ORDER BY seq', address);
    return {
      address: a.address as string,
      ...(a.authorized_keys == null ? {} : { authorizedKeys: JSON.parse(a.authorized_keys as string) as string[] }),
      ...((a.authority_version as number) > 0 ? { authorityVersion: a.authority_version as number } : {}),
      ...((a.recovery_epoch as number) > 0 ? { recoveryEpoch: a.recovery_epoch as number } : {}),
      ...(a.recovery_key_cancelled_at ? { recoveryKeyCancelledAt: a.recovery_key_cancelled_at as string } : {}),
      kind: a.kind as Agent['kind'],
      principal: a.principal as string | null,
      keys: keys.map(k => ({
        key: k.key as string,
        added: k.added as string,
        revoked: k.revoked as string | null,
        ...(k.label === null ? {} : { label: k.label as string }),
      })),
      mailbox: a.mailbox === 1,
      createdAt: a.created_at as string,
      retiredAt: a.retired_at as string | null,
      unpairing: (a.unpairing as string | null) ?? null,
    };
  }

  #keyTaken = (key: string) => this.#get('SELECT 1 FROM agent_keys WHERE key = ?', key) !== undefined;
  #insertKey(address: string, k: AgentKey) {
    const seq = this.#get('SELECT COUNT(*) AS n FROM agent_keys WHERE address = ?', address)!.n as number;
    this.#run(
      'INSERT INTO agent_keys VALUES (?, ?, ?, ?, ?, ?)',
      k.key,
      address,
      k.added,
      k.revoked,
      seq,
      k.label ?? null,
    );
  }
  #activeKeys = (address: string) =>
    this.#get('SELECT COUNT(*) AS n FROM agent_keys WHERE address = ? AND revoked IS NULL', address)!.n as number;

  async createAgent(agent: Agent, admit?: AgentAdmission) {
    return this.#tx(() => {
      if (this.#get('SELECT 1 FROM agents WHERE address = ?', agent.address)) return 'address_taken' as const;
      if (agent.keys.some(k => this.#keyTaken(k.key))) return 'key_in_use' as const;
      if (agent.keys.filter(k => k.revoked === null).length > 32 || (admit && !admit(structuredClone(agent))))
        return 'too_many_keys' as const;
      this.#run(
        'INSERT INTO agents(address,kind,principal,mailbox,created_at,retired_at,unpairing,authority_version,recovery_key_cancelled_at,authorized_keys) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, ?)',
        agent.address,
        agent.kind,
        agent.principal,
        agent.mailbox ? 1 : 0,
        agent.createdAt,
        agent.retiredAt,
        agent.unpairing ?? null,
        agent.authorizedKeys === undefined ? null : JSON.stringify(agent.authorizedKeys),
      );
      for (const k of agent.keys) this.#insertKey(agent.address, k);
      return 'created' as const;
    });
  }

  async agentByAddress(address: string) {
    return this.#agent(address);
  }

  async agentByKey(key: string) {
    const row = this.#get('SELECT address FROM agent_keys WHERE key = ?', key);
    return row ? this.#agent(row.address as string) : null;
  }

  async addKey(address: string, entry: AgentKey, maxActive: number, admit?: AgentAdmission) {
    return this.#tx(() => {
      if (this.#keyTaken(entry.key)) return 'key_in_use' as const;
      const agent = this.#agent(address);
      if (
        !agent ||
        agent.retiredAt ||
        this.#activeKeys(address) >= Math.min(32, maxActive) ||
        agent.keys.length >= MAX_STORED_KEYS ||
        (admit && !admit({ ...agent, keys: [...agent.keys, structuredClone(entry)] }))
      )
        return 'too_many_keys' as const;
      this.#insertKey(address, entry);
      if (agent.authorizedKeys !== undefined)
        this.#run(
          'UPDATE agents SET authorized_keys=? WHERE address=?',
          JSON.stringify([...agent.authorizedKeys, entry.key]),
          address,
        );
      this.#bumpAuthority(address);
      return 'added' as const;
    });
  }

  async revokeKey(address: string, key: string, at: string, admit?: AgentAdmission) {
    return this.#tx(() => {
      const current = this.#agent(address);
      if (!current || current.retiredAt || (admit && !admit(current))) return 'not_found' as const;
      if (!this.#get('SELECT 1 FROM agent_keys WHERE key = ? AND address = ? AND revoked IS NULL', key, address)) {
        return 'not_found' as const;
      }
      if (this.#activeKeys(address) === 1) return 'last_key' as const;
      this.#run('UPDATE agent_keys SET revoked = ? WHERE key = ?', at, key);
      const agent = this.#agent(address)!;
      if (agent.authorizedKeys !== undefined)
        this.#run(
          'UPDATE agents SET authorized_keys=? WHERE address=?',
          JSON.stringify(agent.authorizedKeys.filter(k => k !== key)),
          address,
        );
      this.#bumpAuthority(address);
      return 'revoked' as const;
    });
  }

  async replaceKeys(address: string, entry: AgentKey, admit?: AgentAdmission) {
    return this.#tx(() => {
      const agent = this.#agent(address);
      if (!agent || agent.retiredAt) return 'retired' as const;
      if (this.#keyTaken(entry.key)) return 'key_in_use' as const;
      const keys = [...agent.keys.map(k => ({ ...k, revoked: k.revoked ?? entry.added })), structuredClone(entry)];
      if (admit && !admit({ ...agent, keys })) return 'too_many_keys' as const;
      this.#run('UPDATE agent_keys SET revoked = ? WHERE address = ? AND revoked IS NULL', entry.added, address);
      this.#insertKey(address, entry);
      this.#clearRecovery(address);
      this.#run('UPDATE agents SET authorized_keys=? WHERE address=?', JSON.stringify([entry.key]), address);
      this.#bumpAuthority(address);
      this.#advanceRecoveryEpoch(address);
      return 'replaced' as const;
    });
  }

  async keepOnlyKey(address: string, key: string, at: string) {
    return this.#tx(() => {
      const held = this.#get(
        `SELECT 1 FROM agent_keys k JOIN agents a ON a.address = k.address
         WHERE k.key = ? AND k.address = ? AND k.revoked IS NULL AND a.retired_at IS NULL`,
        key,
        address,
      );
      if (!held) return 'not_held' as const;
      this.#run(
        'UPDATE agent_keys SET revoked = ? WHERE address = ? AND revoked IS NULL AND key <> ?',
        at,
        address,
        key,
      );
      this.#clearRecovery(address);
      this.#run('UPDATE agents SET authorized_keys=? WHERE address=?', JSON.stringify([key]), address);
      this.#bumpAuthority(address);
      this.#advanceRecoveryEpoch(address);
      return 'kept' as const;
    });
  }

  async retireAgent(address: string, at: string, unpairing?: string) {
    this.#tx(() => {
      if (!this.#get('SELECT 1 FROM agents WHERE address = ? AND retired_at IS NULL', address)) return;
      this.#run('UPDATE agent_keys SET revoked = ? WHERE address = ? AND revoked IS NULL', at, address);
      this.#run(
        "UPDATE agents SET retired_at = ?, unpairing = ?, authorized_keys='[]' WHERE address = ?",
        at,
        unpairing ?? null,
        address,
      );
      this.#clearRecovery(address);
      this.#bumpAuthority(address);
      this.#advanceRecoveryEpoch(address);
    });
  }

  #bumpAuthority(address: string) {
    this.#run('UPDATE agents SET authority_version=authority_version+1 WHERE address=?', address);
  }
  /** A recovery ended or authority was reset: every mailbox code issued before now binds nothing. */
  #advanceRecoveryEpoch(address: string) {
    this.#run('UPDATE agents SET recovery_epoch=recovery_epoch+1 WHERE address=?', address);
  }
  #clearRecovery(address: string) {
    this.#run("DELETE FROM vals WHERE scope='recovery' AND id=?", address);
  }

  async beginRecovery(address: string, value: unknown, expiresAt: string | null, now: string, admit?: AgentAdmission) {
    return this.#tx(() => {
      const agent = this.#agent(address);
      if (!agent || agent.retiredAt || (admit && !admit(agent))) return null;
      const held = this.#get(
        "SELECT value FROM vals WHERE scope='recovery' AND id=? AND (expires IS NULL OR expires>?)",
        address,
        ms(now),
      );
      if (held) return JSON.parse(held.value as string) as unknown;
      this.#run(
        "INSERT INTO vals(scope,id,value,expires) VALUES('recovery',?,?,?) ON CONFLICT(scope,id) DO UPDATE SET value=excluded.value,expires=excluded.expires",
        address,
        JSON.stringify(value),
        expiresAt === null ? null : ms(expiresAt),
      );
      return structuredClone(value);
    });
  }

  async activateRecovery(address: string, expectedRecovery: unknown, now: string) {
    if (
      !expectedRecovery ||
      typeof expectedRecovery !== 'object' ||
      Array.isArray(expectedRecovery) ||
      (expectedRecovery as { defended?: unknown }).defended !== false
    )
      return false;
    return this.#tx(() => {
      const agent = this.#agent(address);
      if (!agent || agent.retiredAt) return false;
      const value = JSON.stringify(expectedRecovery),
        next = JSON.stringify({ ...JSON.parse(value), defended: true });
      return (
        this.#run(
          "UPDATE vals SET value=? WHERE scope='recovery' AND id=? AND value=? AND (expires IS NULL OR expires>?)",
          next,
          address,
          value,
          ms(now),
        ).changes === 1
      );
    });
  }

  async completeRecovery(address: string, entry: AgentKey, expectedRecovery: unknown, admit?: AgentAdmission) {
    return this.#tx(() => {
      const agent = this.#agent(address);
      if (!agent || agent.retiredAt) return 'retired' as const;
      if (
        !expectedRecovery ||
        typeof expectedRecovery !== 'object' ||
        (expectedRecovery as { key?: unknown }).key !== entry.key
      )
        return 'not_pending' as const;
      const proof = JSON.stringify(expectedRecovery);
      const pending = this.#get(
        "SELECT value FROM vals WHERE scope='recovery' AND id=? AND value=? AND (expires IS NULL OR expires>?)",
        address,
        proof,
        ms(entry.added),
      );
      if (!pending || (JSON.parse(pending.value as string) as { defended?: unknown }).defended === false)
        return 'not_pending' as const;
      if (this.#keyTaken(entry.key)) return 'key_in_use' as const;
      const keys = [...agent.keys.map(k => ({ ...k, revoked: k.revoked ?? entry.added })), structuredClone(entry)];
      if (admit && !admit({ ...agent, keys })) return 'too_many_keys' as const;
      this.#run('UPDATE agent_keys SET revoked=? WHERE address=? AND revoked IS NULL', entry.added, address);
      this.#insertKey(address, entry);
      this.#clearRecovery(address);
      this.#run('UPDATE agents SET authorized_keys=? WHERE address=?', JSON.stringify([entry.key]), address);
      this.#bumpAuthority(address);
      this.#advanceRecoveryEpoch(address);
      return 'replaced' as const;
    });
  }

  async cancelRecovery(
    address: string,
    expectedRecovery: unknown,
    now: string,
    admit?: AgentAdmission,
    keyCancelledAt?: string,
  ) {
    return this.#tx(() => {
      const agent = this.#agent(address);
      if (!agent || agent.retiredAt || (admit && !admit(agent))) return false;
      const r = this.#run(
        "DELETE FROM vals WHERE scope='recovery' AND id=? AND value=? AND (expires IS NULL OR expires>?)",
        address,
        JSON.stringify(expectedRecovery),
        ms(now),
      );
      if (!r.changes) return false;
      this.#bumpAuthority(address);
      this.#advanceRecoveryEpoch(address);
      if (keyCancelledAt !== undefined)
        this.#run('UPDATE agents SET recovery_key_cancelled_at=? WHERE address=?', keyCancelledAt, address);
      return true;
    });
  }

  #isRetraction(record: StoredMessage) {
    return (
      record.message.v === VERSION &&
      header(record.message as never, 'rel') === 'retract' &&
      inReplyTo(record.message) !== null
    );
  }
  #receipts(): Record<string, RetractionReceipt> {
    return JSON.parse(this.#get('SELECT body FROM retraction_admission WHERE singleton=1')!.body as string);
  }
  #saveReceipts(receipts: Record<string, RetractionReceipt>) {
    this.#run('UPDATE retraction_admission SET body=? WHERE singleton=1', canonicalize(receipts));
  }
  #admitRetraction(
    record: StoredMessage,
    rows: { deliveries?: Delivery[]; arrivals?: QueuedArrival[] },
  ): RetractionReceipt | null {
    if (!this.#isRetraction(record)) return null;
    const receipts = this.#receipts();
    let receipt = Object.hasOwn(receipts, record.id) ? receipts[record.id] : undefined;
    if (receipt && !receipt.active) return receipt;
    if (!receipt)
      receipt = {
        record: structuredClone(record),
        author: record.message.from,
        markers: this.#retractionsOf(record),
        generation: randomUUID(),
        active: true,
        materialized: false,
        knownDeliveries: [],
        knownArrivals: [],
        pendingDeliveries: {},
        pendingArrivals: {},
      };
    let changed = !Object.hasOwn(receipts, record.id);
    for (const row of rows.deliveries ?? [])
      if (!receipt.knownDeliveries.includes(row.domain)) {
        receipt.knownDeliveries.push(row.domain);
        receipt.pendingDeliveries[row.domain] = structuredClone(row);
        changed = true;
      }
    for (const row of rows.arrivals ?? [])
      if (!receipt.knownArrivals.includes(row.recipient)) {
        receipt.knownArrivals.push(row.recipient);
        receipt.pendingArrivals[row.recipient] = structuredClone(row);
        changed = true;
      }
    if (!changed) return receipt;
    receipts[record.id] = receipt;
    const entries = Object.values(receipts),
      body = canonicalize(receipts),
      limits = this.#retractionCapacity;
    // Reserve fixed space for future internal state changes; pending journals are included before acceptance.
    if (
      entries.length > limits.maxRecords ||
      entries.filter(r => r.author === record.message.from).length > limits.maxPerAuthor ||
      Buffer.byteLength(body) + 16 * entries.length > limits.maxBytes
    )
      throw new StoreCapacityError();
    this.#saveReceipts(receipts);
    return receipt;
  }
  #bootstrapRetractions() {
    for (const row of this.#all('SELECT * FROM messages WHERE in_reply_to IS NOT NULL'))
      this.#admitRetraction(this.#message(row), {});
    const receipts = this.#receipts();
    for (const [id, r] of Object.entries(receipts))
      if (r.active) {
        r.knownDeliveries = [
          ...new Set([
            ...r.knownDeliveries,
            ...this.#all('SELECT domain FROM deliveries WHERE id=?', id).map(d => d.domain as string),
          ]),
        ];
        r.knownArrivals = [
          ...new Set([
            ...r.knownArrivals,
            ...this.#all('SELECT recipient FROM arrivals WHERE id=?', id).map(a => a.recipient as string),
          ]),
        ];
        r.materialized = true;
      }
    for (const row of this.#all('SELECT * FROM listing_retractions')) {
      const id = row.retraction as string;
      if (!Object.hasOwn(receipts, id))
        receipts[id] = {
          record: null,
          author: row.author as string,
          markers: [],
          generation: randomUUID(),
          active: false,
          materialized: true,
          knownDeliveries: [],
          knownArrivals: [],
          pendingDeliveries: {},
          pendingArrivals: {},
        };
      const marker = {
        owner: row.owner as string,
        target: row.target as string,
        author: row.author as string,
        retraction: id,
      };
      if (
        !receipts[id].markers.some(
          m => m.owner === marker.owner && m.target === marker.target && m.author === marker.author,
        )
      )
        receipts[id].markers.push(marker);
    }
    const entries = Object.values(receipts),
      limits = this.#retractionCapacity;
    const authors = new Map<string, number>();
    for (const r of entries) authors.set(r.author, (authors.get(r.author) ?? 0) + 1);
    if (
      entries.length > limits.maxRecords ||
      [...authors.values()].some(n => n > limits.maxPerAuthor) ||
      Buffer.byteLength(canonicalize(receipts)) + 16 * entries.length > limits.maxBytes
    )
      throw new StoreCapacityError();
    this.#saveReceipts(receipts);
  }

  // Messages

  #message(row: Row): StoredMessage {
    return {
      id: row.id as string,
      message: JSON.parse(row.json as string),
      carrier: row.carrier as string,
      claims: JSON.parse(row.claims as string),
      signedClaims: row.signed_claims === null ? null : JSON.parse(row.signed_claims as string),
      receivedAt: row.received_at as string,
      expiresAt: iso(row.expires),
    };
  }

  async putMessage(m: StoredMessage, rows: { deliveries?: Delivery[]; arrivals?: QueuedArrival[] } = {}) {
    return this.#tx(() => {
      const receipt = this.#admitRetraction(m, rows);
      if (receipt && !receipt.active) return structuredClone(receipt.record ?? m);
      if (receipt?.record) m = receipt.record;
      const existing = this.#get('SELECT * FROM messages WHERE id = ?', m.id);
      if (!existing) {
        const written = !rows.arrivals;
        this.#run(
          'INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
          m.id,
          canonicalize(m.message),
          m.message.from,
          m.message.to.length === 0 ? 1 : 0,
          inReplyTo(m.message),
          m.carrier,
          JSON.stringify(m.claims),
          m.signedClaims && JSON.stringify(m.signedClaims),
          m.receivedAt,
          ms(m.expiresAt),
          written ? 1 : 0,
          written ? this.#position() : null,
          written ? ms(m.receivedAt) : null,
          randomUUID(),
        );
        for (const p of namedParts(m.message)) {
          this.#run('INSERT OR IGNORE INTO message_parts VALUES (?, ?, ?)', m.id, p.sha256, p.size);
        }
      }
      for (const d of receipt ? Object.values(receipt.pendingDeliveries) : (rows.deliveries ?? [])) {
        this.#run(
          'INSERT OR IGNORE INTO deliveries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)',
          d.id,
          d.domain,
          JSON.stringify(d.recipients),
          JSON.stringify(d.hints),
          d.server,
          d.status,
          d.reason,
          d.attempts,
          ms(d.nextAttemptAt),
          d.createdAt,
          d.deadline,
        );
      }
      for (const a of receipt ? Object.values(receipt.pendingArrivals) : (rows.arrivals ?? [])) {
        this.#run(
          'INSERT OR IGNORE INTO arrivals VALUES (?, ?, ?, ?, ?)',
          a.id,
          a.recipient,
          JSON.stringify(a.hints),
          a.attempts,
          ms(a.dueAt),
        );
      }
      if (receipt) {
        const receipts = this.#receipts();
        receipts[m.id] = { ...receipt, materialized: true, pendingDeliveries: {}, pendingArrivals: {} };
        this.#saveReceipts(receipts);
      }
      return existing ? this.#message(existing) : structuredClone(m);
    });
  }

  async message(id: string) {
    const row = this.#get('SELECT * FROM messages WHERE id = ?', id);
    return row ? this.#message(row) : null;
  }

  #retractionsOf(record: StoredMessage) {
    if (!this.#isRetraction(record)) return [];
    return (record.message.to.length ? record.message.to : ['*']).map(owner => ({
      owner,
      target: inReplyTo(record.message)!,
      author: record.message.from,
      retraction: record.id,
    }));
  }

  async listingRetracted(ownerAddress: string, id: string, replyAuthor: string) {
    return Object.values(this.#receipts()).some(r =>
      r.markers.some(m => (m.owner === ownerAddress || m.owner === '*') && m.target === id && m.author === replyAuthor),
    );
  }

  async deleteMessage(id: string) {
    this.#tx(() => this.#deleteMessages('id = ?', id));
  }

  async published(author: string, before: string | null, limit: number) {
    const after = this.#get(
      'SELECT rowid FROM messages WHERE id = ? AND from_address = ? AND public = 1',
      before,
      author,
    );
    const rows = this.#all(
      'SELECT * FROM messages WHERE from_address = ? AND public = 1 AND rowid < ? ORDER BY rowid DESC LIMIT ?',
      author,
      before === null ? Number.MAX_SAFE_INTEGER : ((after?.rowid as number | undefined) ?? 0),
      limit + 1,
    );
    return page(rows, limit, r => this.#message(r));
  }

  async repliesTo(address: string, id: string, before: string | null, limit: number) {
    const after = this.#get('SELECT cursor FROM inbox WHERE address = ? AND id = ?', address, before);
    const rows = this.#all(
      `SELECT m.* FROM inbox i JOIN messages m ON m.id = i.id
       WHERE i.address = ? AND m.in_reply_to = ? AND i.cursor < ? ORDER BY i.cursor DESC LIMIT ?`,
      address,
      id,
      before === null ? Number.MAX_SAFE_INTEGER : ((after?.cursor as number | undefined) ?? 0),
      limit + 1,
    );
    return page(rows, limit, r => this.#message(r));
  }

  /** Delete the messages a WHERE clause selects, and everything tied to them. */
  #deleteMessages(where: string, ...params: SQLInputValue[]): number {
    const ids = `SELECT id FROM messages WHERE ${where}`;
    const receipts = this.#receipts();
    let changed = false;
    for (const row of this.#all(`SELECT id FROM messages WHERE ${where}`, ...params)) {
      const receipt = receipts[row.id as string];
      if (receipt) {
        receipt.active = false;
        receipt.pendingDeliveries = {};
        receipt.pendingArrivals = {};
        changed = true;
      }
    }
    if (changed) this.#saveReceipts(receipts);
    for (const table of ['inbox', 'deliveries', 'arrivals', 'message_parts']) {
      this.#run(`DELETE FROM ${table} WHERE id IN (${ids})`, ...params);
    }
    return Number(this.#run(`DELETE FROM messages WHERE ${where}`, ...params).changes);
  }

  // Arrivals

  async arrivals(now: string, limit: number) {
    const rows = this.#all(
      `SELECT m.*, a.recipient, a.hints, a.attempts, a.due FROM arrivals a JOIN messages m ON m.id = a.id
       WHERE a.due <= ? ORDER BY a.due, a.rowid LIMIT ?`,
      ms(now),
      limit,
    );
    return rows.map(r => ({
      arrival: {
        id: r.id as string,
        recipient: r.recipient as string,
        hints: JSON.parse(r.hints as string),
        attempts: r.attempts as number,
        dueAt: iso(r.due),
      },
      message: this.#message(r),
      generation: r.generation as string,
    }));
  }

  async arrivalRetry(id: string, recipient: string, at: string, generation?: string) {
    if (generation !== undefined && !this.#get('SELECT 1 FROM messages WHERE id=? AND generation=?', id, generation))
      return;
    this.#run(
      'UPDATE arrivals SET attempts = attempts + 1, due = ? WHERE id = ? AND recipient = ? AND EXISTS(SELECT 1 FROM messages WHERE id=? AND (? IS NULL OR generation=?))',
      ms(at),
      id,
      recipient,
      id,
      generation ?? null,
      generation ?? null,
    );
  }

  async arrivalDone(id: string, recipient: string, kept: boolean, generation?: string) {
    return this.#tx(() => {
      if (generation !== undefined && !this.#get('SELECT 1 FROM messages WHERE id=? AND generation=?', id, generation))
        return null;
      this.#run('DELETE FROM arrivals WHERE id = ? AND recipient = ?', id, recipient);
      if (kept) {
        return Number(this.#run('UPDATE messages SET kept = 1 WHERE id = ? AND kept = 0', id).changes) ? 'kept' : null;
      }
      const unwanted = `id = ? AND kept = 0 AND NOT EXISTS (SELECT 1 FROM arrivals a WHERE a.id = messages.id)
        AND NOT EXISTS (SELECT 1 FROM inbox i WHERE i.id = messages.id)`;
      return this.#deleteMessages(unwanted, id) ? 'dropped' : null;
    });
  }

  // Sync

  /** The next position of the stream; positions are taken and written in one transaction. */
  #position(): number {
    return this.#get('UPDATE positions SET n = n + 1 RETURNING n')!.n as number;
  }

  async addToInbox(address: string, id: string, at: string, generation?: string, minExpiresAt?: string) {
    return this.#tx(() => {
      if (
        !this.#get(
          'SELECT 1 FROM messages WHERE id=? AND (? IS NULL OR generation=?)',
          id,
          generation ?? null,
          generation ?? null,
        )
      )
        return false;
      if (minExpiresAt !== undefined)
        this.#run('UPDATE messages SET expires=MAX(expires,?) WHERE id=?', ms(minExpiresAt), id);
      if (this.#get('SELECT 1 FROM inbox WHERE address = ? AND id = ?', address, id)) return false;
      this.#run('INSERT INTO inbox VALUES (?, ?, ?, ?, 1)', this.#position(), address, id, ms(at));
      return true;
    });
  }

  /** A row of a message with its place in a stream: `position`, `holder` and `entered`. */
  #entry(r: Row): SyncEntry {
    const m = this.#message(r);
    return {
      cursor: r.position as number,
      address: r.holder as string,
      id: m.id,
      message: m.message,
      carrier: m.carrier,
      claims: m.claims,
      signedClaims: m.signedClaims,
      receivedAt: iso(r.entered),
    };
  }

  async sync(address: string, after: number, limit: number, now: string, from?: string) {
    // Read first: every position up to it is written, since a position is taken in the write that uses it.
    const top = this.#get('SELECT n FROM positions')!.n as number;
    const since = from === undefined ? Number.MIN_SAFE_INTEGER : ms(from);
    const rows = this.#all(
      `SELECT m.*, s.position, ? AS holder, s.taken AS entered FROM (
         SELECT cursor AS position, id, taken FROM inbox
         WHERE address = ? AND cursor > ? AND cursor <= ? AND taken >= ?
         UNION ALL
         SELECT cursor, id, taken FROM messages
         WHERE from_address = ? AND cursor > ? AND cursor <= ? AND taken >= ?
       ) s JOIN messages m ON m.id = s.id ORDER BY s.position LIMIT ?`,
      address,
      address,
      after,
      top,
      since,
      address,
      after,
      top,
      since,
      limit + 1,
    );
    const more = rows.length > limit;
    const messages = rows.slice(0, limit).map(r => this.#entry(r));
    const cursor = more ? messages.at(-1)!.cursor : top;
    const signals = this.#all(
      'SELECT cursor, signal FROM signals WHERE address = ? AND cursor > ? AND cursor <= ? AND expires > ? ORDER BY cursor',
      address,
      after,
      cursor,
      ms(now),
    ).map(r => ({ cursor: r.cursor as number, ...JSON.parse(r.signal as string) }) as HeldSignal);
    return { messages, signals, cursor, more };
  }

  async holdSignal(address: string, signal: Omit<HeldSignal, 'cursor'>, expiresAt: string, now: string) {
    this.#tx(() => {
      this.#run('DELETE FROM signals WHERE expires <= ?', ms(now));
      const { type, from, about, at } = signal;
      const held = JSON.stringify({ type, from, about, at });
      this.#run('INSERT INTO signals VALUES (?, ?, ?, ?)', this.#position(), address, held, ms(expiresAt));
    });
  }

  async inbox(address: string, after: number, limit: number) {
    return this.#all(
      `SELECT m.*, i.cursor AS position, i.address AS holder, i.taken AS entered
      FROM inbox i JOIN messages m ON m.id=i.id WHERE i.address=? AND i.cursor>? ORDER BY i.cursor LIMIT ?`,
      address,
      after,
      limit,
    ).map(r => this.#entry(r));
  }

  async inInbox(address: string, id: string) {
    return !!this.#get('SELECT 1 FROM inbox WHERE address = ? AND id = ?', address, id);
  }

  async wroteTo(author: string, recipient: string, self: string) {
    return !!this.#get(
      `SELECT 1 FROM messages m, json_each(m.json, '$.to') t
       WHERE m.from_address = ? AND m.carrier = ? AND t.value = ? LIMIT 1`,
      author,
      self,
      recipient,
    );
  }

  async inboxEvents(limit: number) {
    return this.#all(
      `SELECT m.*, i.cursor AS position, i.address AS holder, i.taken AS entered
       FROM inbox i JOIN messages m ON m.id = i.id WHERE i.event = 1 ORDER BY i.cursor LIMIT ?`,
      limit,
    ).map(r => this.#entry(r));
  }

  async inboxEventDone(cursor: number) {
    this.#run('UPDATE inbox SET event = 0 WHERE cursor = ?', cursor);
  }

  // Webhooks

  #webhook = (r: Row): Webhook => ({
    id: r.id as string,
    address: r.address as string,
    url: r.url as string,
    codeHash: r.code_hash as string,
    verified: r.verified === 1,
    createdAt: r.created_at as string,
    failingSince: r.failing_since as string | null,
  });

  async addWebhook(w: Webhook, max: number) {
    return this.#tx(() => {
      if ((this.#get('SELECT COUNT(*) AS n FROM webhooks WHERE address = ?', w.address)!.n as number) >= max) {
        return false;
      }
      this.#run(
        'INSERT INTO webhooks VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0, NULL, NULL)',
        w.id,
        w.address,
        w.url,
        w.codeHash,
        w.verified ? 1 : 0,
        w.createdAt,
        w.failingSince,
      );
      return true;
    });
  }

  async webhook(id: string) {
    const row = this.#get('SELECT * FROM webhooks WHERE id = ?', id);
    return row ? this.#webhook(row) : null;
  }

  async verifyWebhook(id: string) {
    this.#run('UPDATE webhooks SET verified = 1 WHERE id = ?', id);
  }

  async deleteWebhook(id: string) {
    this.#run('DELETE FROM webhooks WHERE id = ?', id);
  }

  async wakeWebhooks(address: string, at: string) {
    this.#run(
      'UPDATE webhooks SET due = MAX(?, quiet_until) WHERE address = ? AND verified = 1 AND due IS NULL',
      ms(at),
      address,
    );
  }

  async claimWebhooks(now: string, limit: number, quietUntil: string, lease: { token: string; until: string }) {
    return this.#tx(() => {
      // A crashed post remains due via its expired lease even if no new event woke it.
      const rows = this.#all(
        `SELECT * FROM webhooks WHERE verified=1 AND (lease_until IS NULL OR lease_until<=?)
        AND quiet_until<=? AND (due<=? OR lease_until<=?) ORDER BY COALESCE(due,lease_until) LIMIT ?`,
        ms(now),
        ms(now),
        ms(now),
        ms(now),
        limit,
      );
      for (const row of rows)
        this.#run(
          'UPDATE webhooks SET due=NULL,quiet_until=?,lease=?,lease_until=? WHERE id=?',
          ms(quietUntil),
          lease.token,
          ms(lease.until),
          row.id,
        );
      return rows.map(this.#webhook);
    });
  }

  async settleWebhook(id: string, failingSince: string | null, retryAt: string | null, token: string, disable = false) {
    if (disable) return Number(this.#run('DELETE FROM webhooks WHERE id=? AND lease=?', id, token).changes) === 1;
    return (
      Number(
        this.#run(
          `UPDATE webhooks SET failing_since=?, due=COALESCE(due,?), lease=NULL,lease_until=NULL WHERE id=? AND lease=?`,
          failingSince,
          retryAt === null ? null : ms(retryAt),
          id,
          token,
        ).changes,
      ) === 1
    );
  }

  // Deliveries

  #delivery(r: Row): Delivery {
    return {
      id: r.id as string,
      domain: r.domain as string,
      recipients: JSON.parse(r.recipients as string),
      hints: JSON.parse(r.hints as string),
      server: r.server as string | null,
      status: r.status as Delivery['status'],
      reason: r.reason as string | null,
      attempts: r.attempts as number,
      nextAttemptAt: iso(r.next_attempt),
      createdAt: r.created_at as string,
      deadline: r.deadline as string,
    };
  }

  async claimDeliveries(now: string, limit: number, skip: string[], lease: { token: string; until: string }) {
    return this.#tx(() =>
      this.#all(
        `UPDATE deliveries SET lease = ?, next_attempt = ? WHERE rowid IN (
           SELECT rowid FROM deliveries WHERE status = 'pending' AND next_attempt <= ?
           AND (server IS NULL OR server NOT IN (SELECT value FROM json_each(?)))
           ORDER BY next_attempt LIMIT ?)
         RETURNING *`,
        lease.token,
        ms(lease.until),
        ms(now),
        JSON.stringify(skip),
        limit,
      ).map(r => this.#delivery(r)),
    );
  }

  async settleDelivery(d: Delivery, token: string) {
    const settled = this.#run(
      `UPDATE deliveries SET server = ?, status = ?, reason = ?, attempts = ?, next_attempt = ?, lease = NULL,
       hints = CASE WHEN ? = 'pending' THEN hints ELSE '{}' END
       WHERE id = ? AND domain = ? AND status = 'pending' AND lease = ?`,
      d.server,
      d.status,
      d.reason,
      d.attempts,
      ms(d.nextAttemptAt),
      d.status,
      d.id,
      d.domain,
      token,
    );
    return Number(settled.changes) === 1;
  }

  async deliveries(id: string) {
    return this.#all('SELECT * FROM deliveries WHERE id = ? ORDER BY domain', id).map(r => this.#delivery(r));
  }

  // Parts

  async putPart(sha256: string, bytes: Buffer, source: PartSource, at: string) {
    this.#run(
      `INSERT INTO parts VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (sha256, source) DO UPDATE SET created = excluded.created`,
      sha256,
      sourceKey(source),
      'carrier' in source ? 1 : 0,
      bytes.length,
      bytes,
      ms(at),
    );
  }

  async part(sha256: string, source: PartSource) {
    const row = this.#get('SELECT bytes FROM parts WHERE sha256 = ? AND source = ?', sha256, sourceKey(source));
    return row ? Buffer.from(row.bytes as Uint8Array) : null;
  }

  async heldFor(sha256: string, address: string, self: string) {
    const sources: (PartSource & { size: number })[] = [];
    const seen = new Set<string>();
    const pending = [address];
    // Follow only inbox-author grants for this hash. Every address is visited once, even in a cycle.
    for (const holder of pending) {
      if (seen.has(holder)) continue;
      seen.add(holder);
      for (const source of this.#held(sha256, holder, self)) {
        sources.push(source);
        if ('uploader' in source && !seen.has(source.uploader)) pending.push(source.uploader);
      }
    }
    return uniqueSources(sources);
  }

  /**
   * An agent's own upload of a part, and for each message in its inbox naming it, the carrier's bytes, or the
   * author's upload when the carrier is `self`.
   */
  #held(sha256: string, address: string, self: string): (PartSource & { size: number })[] {
    const own = this.#get('SELECT size FROM parts WHERE sha256 = ? AND source = ? AND fetched = 0', sha256, address);
    const received = this.#all(
      `SELECT DISTINCT m.carrier, m.from_address, mp.size FROM message_parts mp JOIN messages m ON m.id = mp.id
       JOIN inbox i ON i.id = m.id AND i.address = ? WHERE mp.sha256 = ?`,
      address,
      sha256,
    );
    return [
      ...(own ? [{ uploader: address, size: own.size as number }] : []),
      ...received.map(r =>
        r.carrier === self
          ? { uploader: r.from_address as string, size: r.size as number }
          : { carrier: r.carrier as string, size: r.size as number },
      ),
    ];
  }

  async partNamers(sha256: string, viewer: { published: true } | { server: string }, self: string) {
    const seen =
      'published' in viewer
        ? 'm.public = 1'
        : `EXISTS (SELECT 1 FROM deliveries d WHERE d.id = m.id AND d.server = ? AND d.status = 'delivered')`;
    const rows = this.#all(
      `SELECT DISTINCT m.from_address, m.json FROM message_parts mp JOIN messages m ON m.id = mp.id
       WHERE mp.sha256 = ? AND m.carrier = ? AND ${seen}
       AND m.from_address IN (SELECT address FROM agents WHERE retired_at IS NULL)`,
      sha256,
      self,
      ...('server' in viewer ? [viewer.server] : []),
    );
    return rows.map(r => ({ author: r.from_address as string, message: JSON.parse(r.json as string) as AnyMessage }));
  }

  // Part fetches

  #fetch = (r: Row): PartFetch => ({
    sha256: r.sha256 as string,
    carrier: r.carrier as string,
    size: r.size as number,
    attempts: r.attempts as number,
    dueAt: iso(r.due),
    revision: r.revision as number,
    generation: r.generation as string,
  });

  queueFetch(f: PartFetch, now?: string): Promise<PartFetch>;
  queueFetch(f: PartFetch, now: string | undefined, max: number): Promise<PartFetch | null>;
  async queueFetch(f: PartFetch, now?: string, max?: number): Promise<PartFetch | null> {
    return this.#tx(() => {
      if (now !== undefined)
        this.#run('DELETE FROM fetches WHERE sha256=? AND carrier=? AND exhausted<=?', f.sha256, f.carrier, ms(now));
      if (
        max !== undefined &&
        !this.#get('SELECT 1 FROM fetches WHERE sha256=? AND carrier=?', f.sha256, f.carrier) &&
        (this.#get(
          'SELECT COUNT(*) AS n FROM (SELECT 1 FROM fetches WHERE carrier=? AND exhausted IS NULL LIMIT ?)',
          f.carrier,
          max,
        )!.n as number) >= max
      )
        return null;
      this.#run(
        'INSERT OR IGNORE INTO fetches(sha256,carrier,size,attempts,due,token,exhausted,revision,generation) VALUES (?, ?, ?, ?, ?, NULL, NULL, 0, ?)',
        f.sha256,
        f.carrier,
        f.size,
        f.attempts,
        ms(f.dueAt),
        randomUUID(),
      );
      return this.#fetch(this.#get('SELECT * FROM fetches WHERE sha256 = ? AND carrier = ?', f.sha256, f.carrier)!);
    });
  }

  async fetches(now: string, limit: number) {
    return this.#all(
      `SELECT * FROM (SELECT *, rowid AS seq, ROW_NUMBER() OVER (PARTITION BY carrier ORDER BY due, rowid) AS turn FROM fetches
       WHERE due <= ? AND exhausted IS NULL) ORDER BY turn, due, seq LIMIT ?`,
      ms(now),
      limit,
    ).map(this.#fetch);
  }

  async claimFetch(f: PartFetch, now: string, lease: { token: string; until: string }) {
    if (!f.generation || ms(lease.until) <= ms(now)) return false;
    return (
      Number(
        this.#run(
          `UPDATE fetches SET due=?,token=?,revision=revision+1 WHERE sha256=? AND carrier=? AND due=? AND due<=? AND attempts=? AND revision=? AND generation=? AND exhausted IS NULL`,
          ms(lease.until),
          lease.token,
          f.sha256,
          f.carrier,
          ms(f.dueAt),
          ms(now),
          f.attempts,
          f.revision ?? 0,
          f.generation,
        ).changes,
      ) === 1
    );
  }

  async renewFetch(sha256: string, carrier: string, token: string, now: string, until: string) {
    if (ms(until) <= ms(now)) return false;
    return (
      Number(
        this.#run(
          'UPDATE fetches SET due=?,revision=revision+1 WHERE sha256=? AND carrier=? AND token=? AND due>? AND exhausted IS NULL',
          ms(until),
          sha256,
          carrier,
          token,
          ms(now),
        ).changes,
      ) === 1
    );
  }

  async fetchRetry(sha256: string, carrier: string, at: string, token: string) {
    return (
      Number(
        this.#run(
          'UPDATE fetches SET due=?,attempts=attempts+1,token=NULL,revision=revision+1 WHERE sha256=? AND carrier=? AND token=? AND exhausted IS NULL',
          ms(at),
          sha256,
          carrier,
          token,
        ).changes,
      ) === 1
    );
  }

  async fetchDefer(sha256: string, carrier: string, at: string, token: string) {
    return (
      Number(
        this.#run(
          'UPDATE fetches SET due=?,token=NULL,revision=revision+1 WHERE sha256=? AND carrier=? AND token=? AND exhausted IS NULL',
          ms(at),
          sha256,
          carrier,
          token,
        ).changes,
      ) === 1
    );
  }

  async fetchDone(sha256: string, carrier: string, token: string) {
    return (
      Number(
        this.#run(
          'DELETE FROM fetches WHERE sha256=? AND carrier=? AND token=? AND exhausted IS NULL',
          sha256,
          carrier,
          token,
        ).changes,
      ) === 1
    );
  }

  async fetchGiveUp(sha256: string, carrier: string, token: string, expiresAt: string) {
    return (
      Number(
        this.#run(
          'UPDATE fetches SET exhausted=?,token=NULL,revision=revision+1 WHERE sha256=? AND carrier=? AND token=? AND exhausted IS NULL',
          ms(expiresAt),
          sha256,
          carrier,
          token,
        ).changes,
      ) === 1
    );
  }

  async fetchExhausted(sha256: string, carrier: string, now: string) {
    return !!this.#get('SELECT 1 FROM fetches WHERE sha256=? AND carrier=? AND exhausted>?', sha256, carrier, ms(now));
  }

  // Marks, counters, values

  async mark(scope: string, id: string, expiresAt: string, now: string) {
    return this.#tx(() => {
      if (this.#get('SELECT 1 FROM marks WHERE scope = ? AND id = ? AND expires > ?', scope, id, ms(now))) return false;
      this.#run('INSERT OR REPLACE INTO marks VALUES (?, ?, ?)', scope, id, ms(expiresAt));
      return true;
    });
  }

  async marked(scope: string, id: string, now: string) {
    return !!this.#get('SELECT 1 FROM marks WHERE scope = ? AND id = ? AND expires > ?', scope, id, ms(now));
  }

  async count(scope: string, id: string, expiresAt: string, now: string, by = 1) {
    return this.#tx(() => {
      this.#run('DELETE FROM counters WHERE scope = ? AND id = ? AND expires <= ?', scope, id, ms(now));
      this.#run(
        'INSERT INTO counters VALUES (?, ?, ?, ?) ON CONFLICT (scope, id) DO UPDATE SET n = n + excluded.n',
        scope,
        id,
        by,
        ms(expiresAt),
      );
      return this.#get('SELECT n FROM counters WHERE scope = ? AND id = ?', scope, id)!.n as number;
    });
  }

  async value<T>(scope: string, id: string, now: string) {
    const row = this.#get(
      'SELECT value FROM vals WHERE scope = ? AND id = ? AND (expires IS NULL OR expires > ?)',
      scope,
      id,
      ms(now),
    );
    return row ? (JSON.parse(row.value as string) as T) : null;
  }

  async setValue(scope: string, id: string, value: unknown, expiresAt: string | null) {
    if (scope === 'recovery')
      throw new Error('The recovery scope is reserved; use beginRecovery, completeRecovery or cancelRecovery.');
    this.#run(
      'INSERT OR REPLACE INTO vals VALUES (?, ?, ?, ?)',
      scope,
      id,
      JSON.stringify(value),
      expiresAt === null ? null : ms(expiresAt),
    );
  }

  async releaseValue(scope: string, id: string, value: unknown) {
    if (scope === 'recovery')
      throw new Error('The recovery scope is reserved; use beginRecovery, completeRecovery or cancelRecovery.');
    const r = this.#run('DELETE FROM vals WHERE scope = ? AND id = ? AND value = ?', scope, id, JSON.stringify(value));
    return Number(r.changes) === 1;
  }

  async renewValue(scope: string, id: string, value: unknown, expiresAt: string) {
    if (scope === 'recovery')
      throw new Error('The recovery scope is reserved; use beginRecovery, completeRecovery or cancelRecovery.');
    const r = this.#run(
      'UPDATE vals SET expires = ? WHERE scope = ? AND id = ? AND value = ?',
      ms(expiresAt),
      scope,
      id,
      JSON.stringify(value),
    );
    return Number(r.changes) === 1;
  }

  async valueOnce<T>(scope: string, id: string, value: T, expiresAt: string | null, now: string) {
    if (scope === 'recovery')
      throw new Error('The recovery scope is reserved; use beginRecovery, completeRecovery or cancelRecovery.');
    return this.#tx(() => {
      const row = this.#get(
        'SELECT value FROM vals WHERE scope = ? AND id = ? AND (expires IS NULL OR expires > ?)',
        scope,
        id,
        ms(now),
      );
      if (row) return JSON.parse(row.value as string) as T;
      this.#run(
        'INSERT OR REPLACE INTO vals VALUES (?, ?, ?, ?)',
        scope,
        id,
        JSON.stringify(value),
        expiresAt === null ? null : ms(expiresAt),
      );
      return value;
    });
  }

  async sweep(now: string, uploadsBefore: string): Promise<SweepCounts> {
    this.#run('DELETE FROM fetches WHERE exhausted<=?', ms(now));

    return this.#tx(() => {
      const t = ms(now);
      const messages = this.#deleteMessages('expires <= ?', t);
      // Fetches no message names any more, from its carrier, given up or still waiting.
      this.#run(`DELETE FROM fetches WHERE NOT EXISTS (SELECT 1 FROM message_parts mp JOIN messages m ON m.id = mp.id
        WHERE mp.sha256 = fetches.sha256 AND m.carrier = fetches.carrier)`);
      const named = `SELECT 1 FROM message_parts mp JOIN messages m ON m.id = mp.id WHERE mp.sha256 = parts.sha256
        AND CASE parts.fetched WHEN 1 THEN m.carrier ELSE m.from_address END = parts.source`;
      const parts = Number(
        this.#run(`DELETE FROM parts WHERE (fetched = 1 OR created < ?) AND NOT EXISTS (${named})`, ms(uploadsBefore))
          .changes,
      );
      let marks = 0;
      for (const table of ['marks', 'counters'])
        marks += Number(this.#run(`DELETE FROM ${table} WHERE expires <= ?`, t).changes);
      // A recovery that lapsed ends as a cancelled or completed one does: its epoch advances.
      this.#run(
        "UPDATE agents SET recovery_epoch=recovery_epoch+1 WHERE address IN (SELECT id FROM vals WHERE scope='recovery' AND expires IS NOT NULL AND expires <= ?)",
        t,
      );
      marks += Number(this.#run('DELETE FROM vals WHERE expires IS NOT NULL AND expires <= ?', t).changes);
      const signals = Number(this.#run('DELETE FROM signals WHERE expires <= ?', t).changes);
      return { messages, parts, marks, signals };
    });
  }

  async close() {
    if (this.#db.isOpen) this.#db.close();
  }
}
