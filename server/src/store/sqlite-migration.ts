/**
 * Offline, copy-first schema-2 conversion. This module has no listener, worker, queue sender or
 * operational promotion operation. Its output is a private, structurally verified candidate cohort;
 * absent historical suppression/terminal evidence remains a blocking activation hold.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { backup, DatabaseSync, type SQLInputValue } from 'node:sqlite';
import {
  canonicalize,
  checkMessage,
  isAddress,
  isImplemented,
  isPrincipal,
  fromB64url,
  normalizeDomain,
  readKeys,
  serverOrigin,
  isPublicKey,
  MAX_DOCUMENT_BYTES,
  MAX_DOCUMENT_KEYS,
  messageId,
  namedFiles,
  parseJson,
  parseKeyToken,
  parseTimestamp,
  type AnyMessage,
  type Limits,
  type Message,
} from '@agnt-sdk/simon-protocol';
import { listedKeys } from '../public.ts';
import { SqliteStore } from './sqlite.ts';
import { resolveRetractionCapacity, type Agent, type RetractionCapacity } from './store.ts';

/** Exact schema from standalone6672513's vendor pin2fa256d; not a relabelled current schema. */
const LEGACY_SCHEMA = `
CREATE TABLE agents (address TEXT PRIMARY KEY, kind TEXT NOT NULL, principal TEXT, mailbox INTEGER NOT NULL,
  created_at TEXT NOT NULL, retired_at TEXT);
CREATE TABLE agent_keys (key TEXT PRIMARY KEY, address TEXT NOT NULL, added TEXT NOT NULL, revoked TEXT,
  seq INTEGER NOT NULL);
CREATE INDEX agent_keys_address ON agent_keys (address);
CREATE TABLE messages (id TEXT PRIMARY KEY, json TEXT NOT NULL, from_address TEXT NOT NULL, public INTEGER NOT NULL,
  carrier TEXT NOT NULL, claims TEXT NOT NULL, received_at TEXT NOT NULL, expires INTEGER NOT NULL,
  kept INTEGER NOT NULL);
CREATE INDEX messages_expires ON messages (expires);
CREATE TABLE message_parts (id TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, PRIMARY KEY (id, sha256));
CREATE INDEX message_parts_sha ON message_parts (sha256);
CREATE TABLE arrivals (id TEXT NOT NULL, recipient TEXT NOT NULL, hints TEXT NOT NULL, attempts INTEGER NOT NULL,
  due INTEGER NOT NULL, PRIMARY KEY (id, recipient));
CREATE INDEX arrivals_due ON arrivals (due);
CREATE TABLE inbox (cursor INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL, id TEXT NOT NULL,
  received_at TEXT NOT NULL, event INTEGER NOT NULL, UNIQUE (address, id));
CREATE INDEX inbox_id ON inbox (id);
CREATE INDEX inbox_events ON inbox (cursor) WHERE event = 1;
CREATE TABLE deliveries (id TEXT NOT NULL, domain TEXT NOT NULL, recipients TEXT NOT NULL, hints TEXT NOT NULL,
  server TEXT, status TEXT NOT NULL, reason TEXT, attempts INTEGER NOT NULL, next_attempt INTEGER NOT NULL,
  created_at TEXT NOT NULL, deadline TEXT NOT NULL, lease TEXT, PRIMARY KEY (id, domain));
CREATE INDEX deliveries_due ON deliveries (status, next_attempt);
CREATE TABLE parts (sha256 TEXT NOT NULL, source TEXT NOT NULL, fetched INTEGER NOT NULL, size INTEGER NOT NULL,
  bytes BLOB NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (sha256, source));
CREATE TABLE fetches (sha256 TEXT NOT NULL, carrier TEXT NOT NULL, size INTEGER NOT NULL, attempts INTEGER NOT NULL,
  due INTEGER NOT NULL, PRIMARY KEY (sha256, carrier));
CREATE INDEX fetches_due ON fetches (due);
CREATE TABLE marks (scope TEXT NOT NULL, id TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY (scope, id));
CREATE TABLE counters (scope TEXT NOT NULL, id TEXT NOT NULL, n INTEGER NOT NULL, expires INTEGER NOT NULL,
  PRIMARY KEY (scope, id));
CREATE TABLE vals (scope TEXT NOT NULL, id TEXT NOT NULL, value TEXT NOT NULL, expires INTEGER,
  PRIMARY KEY (scope, id));
PRAGMA user_version = 2;
`;
const OUTBOX_SCHEMA = `
CREATE TABLE arrivals(key TEXT PRIMARY KEY,domain TEXT NOT NULL,body TEXT NOT NULL,since INTEGER NOT NULL);
CREATE INDEX arrivals_by_domain ON arrivals(domain);
PRAGMA user_version=1;
`;
const TABLES = [
  'agents',
  'agent_keys',
  'messages',
  'message_parts',
  'arrivals',
  'inbox',
  'deliveries',
  'parts',
  'fetches',
  'marks',
  'counters',
  'vals',
] as const;
type Table = (typeof TABLES)[number];
type Row = Record<string, SQLInputValue>;
type Rows = Record<Table, Row[]>;
type Stage = 'SNAPSHOTTED' | 'PREFLIGHT_OK' | 'COPIED' | 'VERIFIED';
const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;
const MAX_FILE_BYTES = 256 * 1024 * 1024;
const MAX_ROWS = 250_000;

export class SqliteMigrationRefusal extends Error {
  readonly code: string;
  constructor(code: string) {
    // No raw values, addresses, keys, code material or native SQLite error text in diagnostics.
    super(`Offline conversion refused: ${code}.`);
    this.name = 'SqliteMigrationRefusal';
    this.code = code;
  }
}
function refuse(code: string): never {
  throw new SqliteMigrationRefusal(code);
}
/**
 * The bundle's `004-VERIFIED.json` is durable, but releasing the source handles/writer exclusions failed
 * afterwards. Not a refusal: the bundle keeps its single VERIFIED meaning and carries no REFUSED marker.
 */
export class SqliteV2CleanupFailure extends Error {
  readonly code = 'cleanup_failed';
  readonly candidate: SqliteV2Candidate;
  constructor(candidate: SqliteV2Candidate) {
    super('Offline conversion verified, but releasing the source handles failed: cleanup_failed.');
    this.name = 'SqliteV2CleanupFailure';
    this.candidate = candidate;
  }
}
const hash = (value: string | Uint8Array) => crypto.createHash('sha256').update(value).digest('hex');
const fileHash = (file: string) => hash(fs.readFileSync(file));
const text = (value: SQLInputValue, code: string): string => (typeof value === 'string' ? value : refuse(code));
const integer = (value: SQLInputValue, code: string, minimum = 0): number => {
  const n = typeof value === 'bigint' ? Number(value) : value;
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < minimum) refuse(code);
  return n;
};
const time = (value: SQLInputValue, code: string): number => {
  const s = text(value, code);
  const n = parseTimestamp(s);
  if (n === null) refuse(code);
  return n;
};
const json = (value: SQLInputValue, code: string): unknown => {
  try {
    return parseJson(Buffer.from(text(value, code)));
  } catch {
    return refuse(code);
  }
};
const object = (value: unknown, code: string): Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : refuse(code);
const isoField = (value: unknown, code: string) => time(typeof value === 'string' ? value : null, code);
const q = (identifier: string) => `"${identifier.replaceAll('"', '""')}"`;

function all(db: DatabaseSync, sql: string, ...params: SQLInputValue[]): Row[] {
  const statement = db.prepare(sql);
  statement.setReadBigInts(true);
  return statement.all(...params) as Row[];
}
function rows(db: DatabaseSync, table: string): Row[] {
  const result = all(db, `SELECT rowid AS __rowid,* FROM ${q(table)} ORDER BY rowid LIMIT ?`, MAX_ROWS + 1);
  if (result.length > MAX_ROWS) refuse('row_capacity');
  for (const row of result)
    for (const value of Object.values(row)) {
      if (typeof value === 'bigint') integer(value, 'unsafe_integer', -Number.MAX_SAFE_INTEGER);
      if (typeof value === 'number' && !Number.isSafeInteger(value)) refuse('non_integer_numeric_state');
    }
  return result;
}
function rowHash(row: Row) {
  const typed = Object.entries(row).map(([key, value]) => [
    key,
    typeof value === 'bigint'
      ? ['integer', String(value)]
      : value instanceof Uint8Array
        ? ['blob', hash(value), value.byteLength]
        : [value === null ? 'null' : typeof value, value],
  ]);
  return hash(JSON.stringify(typed));
}
function ledger(db: DatabaseSync, tables: readonly string[]) {
  return Object.fromEntries(
    tables.map(table => {
      const hashes = rows(db, table).map(rowHash);
      return [table, { count: hashes.length, orderedRowHashes: hashes, digest: hash(JSON.stringify(hashes)) }];
    }),
  );
}
function schema(db: DatabaseSync) {
  // Ignore whitespace/case only; unknown tables, indexes, views and triggers remain incompatible.
  return all(db, 'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name').map(row => [
    row.type,
    row.name,
    row.tbl_name,
    row.sql === null ? null : text(row.sql, 'schema_sql').replace(/\s+/g, '').toLowerCase(),
  ]);
}
function verifySchema(db: DatabaseSync, expected: string, version: number) {
  if (integer(all(db, 'PRAGMA user_version')[0].user_version, 'schema_version') !== version) refuse('schema_version');
  const model = new DatabaseSync(':memory:');
  try {
    model.exec(expected);
    if (JSON.stringify(schema(db)) !== JSON.stringify(schema(model))) refuse('schema_fingerprint');
  } finally {
    model.close();
  }
  const integrity = all(db, 'PRAGMA integrity_check');
  if (integrity.length !== 1 || integrity[0].integrity_check !== 'ok') refuse('integrity_check');
}

interface Maintenance {
  v: 1;
  id: string;
  origin: string;
  serverKeyFingerprint: string;
  serverKey: string;
  configDigest: string;
  toolCommit: string;
  observedAt: string;
  clockProvenance: string;
  previousObservedAt?: string;
  hostStopped: true;
  callbacksDrained: true;
  appOutboxStopped: true;
  fenceFile: string;
  fenceToken: string;
  limits: Limits;
}

export interface SqliteV2CandidateOptions {
  /** Existing actual schema2 file; its app-arrivals.sqlite cohort is required beside it. */
  source: string;
  /** Fresh private bundle directory; no existing unrelated directory or target is overwritten. */
  directory: string;
  /** Private external maintenance/drain attestation, including the still-held host fence. */
  maintenanceFile: string;
  retractions?: Partial<RetractionCapacity>;
  /** Synthetic fault injection only; never a CLI argument or a promotion hook. */
  afterStage?: (stage: Stage) => void;
  /** Synthetic failure points inside conversion (`cleanup`: releasing the source handles), absent from the CLI. */
  faultAt?: 'copy-row' | 'bootstrap' | 'verify' | 'cleanup';
}
export interface SqliteV2Candidate {
  status: 'VERIFIED_COPY_HELD';
  activationBlocked: true;
  holds: string[];
  bundleId: string;
  maintenanceDigest: string;
  origin: string;
  serverKeyFingerprint: string;
  configDigest: string;
  toolCommit: string;
  retractionLimits: RetractionCapacity;
  observation: { at: string; provenance: string; previous?: string };
  sourcePaths: { core: string; outbox: string };
  source: { core: ReturnType<typeof ledger>; outbox: ReturnType<typeof ledger> };
  snapshots: { core: string; outbox: string };
  candidate: { core: string; outbox: string };
  hashes: Record<string, string>;
  highWatermark: number;
  usableHeadroom: number;
  archivedTombstones: string[];
  generations: Record<string, string>;
  noOperationalPromotion: true;
}

function privateFile(file: string, secret = false): string {
  const absolute = path.resolve(file);
  const stat = fs.lstatSync(absolute);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) refuse('unsafe_file_type');
  if (process.getuid === undefined || stat.uid !== process.getuid() || (stat.mode & 0o022) !== 0)
    refuse('unsafe_file_owner_or_mode');
  if (secret && (stat.mode & 0o077) !== 0) refuse('private_file_permissions');
  if (fs.realpathSync(absolute) !== absolute) refuse('symlink_path');
  if (stat.size > MAX_FILE_BYTES) refuse('file_capacity');
  return absolute;
}
function maintenance(file: string): { value: Maintenance; digest: string } {
  const bytes = fs.readFileSync(privateFile(file, true));
  if (bytes.length > 32 * 1024) refuse('maintenance_capacity');
  const m = object(json(bytes.toString(), 'maintenance_json'), 'maintenance_json');
  if (
    m.v !== 1 ||
    typeof m.id !== 'string' ||
    !/^[a-zA-Z0-9_-]{16,128}$/.test(m.id) ||
    m.hostStopped !== true ||
    m.callbacksDrained !== true ||
    m.appOutboxStopped !== true
  )
    refuse('maintenance_drain_attestation');
  for (const field of ['serverKeyFingerprint', 'configDigest'])
    if (typeof m[field] !== 'string' || !HEX64.test(m[field])) refuse('maintenance_digest');
  if (typeof m.toolCommit !== 'string' || !HEX40.test(m.toolCommit)) refuse('maintenance_tool_commit');
  if (typeof m.origin !== 'string' || serverOrigin(m.origin, true) !== m.origin) refuse('maintenance_origin');
  if (
    typeof m.serverKey !== 'string' ||
    !parseKeyToken(m.serverKey) ||
    !isImplemented(m.serverKey) ||
    !isPublicKey(m.serverKey) ||
    hash(m.serverKey) !== m.serverKeyFingerprint
  )
    refuse('maintenance_public_key');
  const at = isoField(m.observedAt, 'maintenance_observation');
  if (m.previousObservedAt !== undefined && isoField(m.previousObservedAt, 'maintenance_previous') > at)
    refuse('maintenance_clock_rollback');
  if (typeof m.clockProvenance !== 'string' || !m.clockProvenance.trim() || m.clockProvenance.length > 256)
    refuse('maintenance_clock_provenance');
  const limits = object(m.limits, 'maintenance_limits');
  for (const field of ['messageBytes', 'requestBodyBytes', 'recipients', 'partBytes'])
    integer(typeof limits[field] === 'number' ? limits[field] : null, 'maintenance_limits', 1);
  if (typeof m.fenceFile !== 'string' || typeof m.fenceToken !== 'string') refuse('maintenance_fence');
  const fence = fs.readFileSync(privateFile(m.fenceFile, true), 'utf8');
  if (!/^[a-zA-Z0-9_-]{22,128}$/.test(m.fenceToken) || fence !== m.fenceToken) refuse('maintenance_fence');
  return { value: m as unknown as Maintenance, digest: hash(bytes) };
}

function validateRows(data: Rows, m: Maintenance) {
  const at = Date.parse(m.observedAt);
  const agents = new Map(data.agents.map(row => [text(row.address, 'agent_address'), row]));
  for (const row of data.agents) {
    if (!isAddress(row.address) || !['solo', 'paired'].includes(text(row.kind, 'agent_kind'))) refuse('agent_identity');
    if (row.kind === 'paired' ? !isPrincipal(row.principal) : row.principal !== null) refuse('agent_principal');
    if (![0, 1].includes(integer(row.mailbox, 'agent_mailbox'))) refuse('agent_mailbox');
    if (time(row.created_at, 'agent_created') > at) refuse('future_host_state');
    if (row.retired_at !== null && time(row.retired_at, 'agent_retired') > at) refuse('future_host_state');
    const keys = data.agent_keys.filter(key => key.address === row.address);
    const seqs = new Set<number>();
    for (const key of keys) {
      if (!parseKeyToken(key.key) || (isImplemented(key.key) && !isPublicKey(key.key))) refuse('agent_key');
      const seq = integer(key.seq, 'agent_key_sequence');
      if (seqs.has(seq)) refuse('agent_key_sequence');
      seqs.add(seq);
      if (time(key.added, 'agent_key_added') > at) refuse('future_host_state');
      if (key.revoked !== null) time(key.revoked, 'agent_key_revoked');
      if (row.retired_at !== null && key.revoked === null) refuse('retired_active_key');
    }
    const agent: Agent = {
      address: row.address as string,
      kind: row.kind as Agent['kind'],
      principal: row.principal as string | null,
      keys: keys
        .sort((a, b) => Number(a.seq) - Number(b.seq))
        .map(key => ({
          key: key.key as string,
          added: key.added as string,
          revoked: key.revoked as string | null,
        })),
      mailbox: row.mailbox === 1n,
      createdAt: row.created_at as string,
      retiredAt: row.retired_at as string | null,
    };
    if (!agent.keys.length) refuse('agent_without_keys');
    let projected;
    try {
      projected = listedKeys(agent, at);
    } catch {
      refuse('active_key_capacity');
    }
    if (projected.length > MAX_DOCUMENT_KEYS) refuse('active_key_capacity');
    if (
      !readKeys(
        projected.map(({ key, added, revoked }) => ({ key, added, revoked })),
        new Date(at),
      )
    )
      refuse('key_document_time');
    // Upper bound for either supported server signature, without fabricating signed evidence.
    const bytes = Buffer.byteLength(JSON.stringify({ address: agent.address, keys: projected })) + 4600;
    if (bytes > MAX_DOCUMENT_BYTES) refuse('key_document_byte_capacity');
  }
  for (const key of data.agent_keys) if (!agents.has(text(key.address, 'agent_key_parent'))) refuse('agent_key_parent');
  const messages = new Map<string, AnyMessage>();
  for (const row of data.messages) {
    if (integer(row.__rowid, 'message_rowid', 1) >= Number.MAX_SAFE_INTEGER) refuse('message_rowid_sentinel');
    let message: AnyMessage;
    try {
      message = checkMessage(json(row.json, 'message_json'), m.limits);
      if (messageId(message) !== row.id || message.from !== row.from_address) refuse('message_id_binding');
    } catch {
      refuse('message_structure_or_binding');
    }
    if (integer(row.public, 'message_public') !== (message.to.length === 0 ? 1 : 0)) refuse('message_public');
    if (![0, 1].includes(integer(row.kept, 'message_kept'))) refuse('message_kept');
    const carrier = text(row.carrier, 'message_carrier');
    if (serverOrigin(carrier, true) !== carrier) refuse('message_carrier');
    if (!Array.isArray(json(row.claims, 'message_claims'))) refuse('message_claims');
    if (time(row.received_at, 'message_received') > at) refuse('future_host_state');
    integer(row.expires, 'message_expiry');
    messages.set(row.id as string, message);
    const declared = new Map(namedFiles(message).map(part => [part.sha256, part.size]));
    const indexed = new Map(
      data.message_parts.filter(part => part.id === row.id).map(part => [part.sha256, integer(part.size, 'part_size')]),
    );
    const expected = [...declared].sort(([a], [b]) => a.localeCompare(b));
    const held = [...indexed].sort(([a], [b]) => String(a).localeCompare(String(b)));
    if (JSON.stringify(expected) !== JSON.stringify(held)) refuse('message_part_projection');
  }
  for (const row of data.message_parts)
    if (!messages.has(text(row.id, 'message_part_parent'))) refuse('message_part_parent');
  for (const row of data.inbox) {
    if (!agents.has(text(row.address, 'inbox_agent')) || !messages.has(text(row.id, 'inbox_message')))
      refuse('inbox_parent');
    integer(row.cursor, 'inbox_cursor', 1);
    if (time(row.received_at, 'inbox_received') > at) refuse('future_host_state');
    if (![0, 1].includes(integer(row.event, 'inbox_event'))) refuse('inbox_event');
  }
  for (const table of ['arrivals', 'deliveries'] as const)
    for (const row of data[table]) {
      if (!messages.has(text(row.id, 'job_parent'))) refuse('job_parent');
      integer(row.attempts, 'job_attempts');
      object(json(row.hints, 'job_hints'), 'job_hints');
      if (table === 'arrivals') {
        integer(row.__rowid, 'arrival_rowid', 1);
        if (!isAddress(row.recipient)) refuse('arrival_recipient');
        integer(row.due, 'arrival_due');
      } else {
        if (!['pending', 'delivered', 'failed'].includes(text(row.status, 'delivery_status')))
          refuse('delivery_status');
        const recipients = json(row.recipients, 'delivery_recipients');
        if (!Array.isArray(recipients) || !recipients.length || !recipients.every(isAddress))
          refuse('delivery_recipients');
        integer(row.next_attempt, 'delivery_due');
        time(row.created_at, 'delivery_created');
        time(row.deadline, 'delivery_deadline');
      }
    }
  for (const row of data.parts) {
    if (typeof row.sha256 !== 'string' || !HEX64.test(row.sha256)) refuse('blob_hash');
    if (!(row.bytes instanceof Uint8Array) || row.bytes.byteLength !== integer(row.size, 'blob_size'))
      refuse('blob_size');
    if (hash(row.bytes) !== row.sha256) refuse('blob_hash');
    const source = text(row.source, 'blob_source');
    if (!isAddress(source) && serverOrigin(source, true) !== source) refuse('blob_source');
    if (![0, 1].includes(integer(row.fetched, 'blob_fetched'))) refuse('blob_fetched');
    if (integer(row.created, 'blob_created') > at) refuse('future_host_state');
  }
  for (const row of data.fetches) {
    integer(row.__rowid, 'fetch_rowid', 1);
    if (typeof row.sha256 !== 'string' || !HEX64.test(row.sha256)) refuse('fetch_hash');
    const carrier = text(row.carrier, 'fetch_carrier');
    if (serverOrigin(carrier, true) !== carrier) refuse('fetch_carrier');
    integer(row.size, 'fetch_size');
    integer(row.attempts, 'fetch_attempts');
    integer(row.due, 'fetch_due');
  }
  const sizes = new Map<string, number>();
  for (const table of ['message_parts', 'parts', 'fetches'] as const)
    for (const row of data[table]) {
      const sha = text(row.sha256, 'part_hash');
      const size = integer(row.size, 'part_size');
      if (sizes.has(sha) && sizes.get(sha) !== size) refuse('hash_size_conflict');
      sizes.set(sha, size);
    }
  const archived: string[] = [];
  for (const row of data.vals) {
    const scope = text(row.scope, 'value_scope');
    const value = json(row.value, 'value_json');
    if (row.expires !== null) integer(row.expires, 'value_expiry');
    if (scope === 'code' || scope === 'recovery') {
      if (value !== null || row.value !== 'null') refuse('legacy_challenge_or_recovery');
      archived.push(rowHash(row));
    } else if (
      scope.startsWith('sync-') ||
      scope.includes('recovery') ||
      scope.startsWith('fetch-') ||
      scope === 'part-fetch-slot'
    ) {
      refuse('reserved_value_scope');
    } else if (scope === 'continuity') {
      if (normalizeDomain(row.id) !== row.id) refuse('consumed_value_shape');
      const state = object(value, 'consumed_value_shape');
      const keys = (value: unknown) => {
        if (
          !Array.isArray(value) ||
          !value.length ||
          value.length > MAX_DOCUMENT_KEYS ||
          new Set(value).size !== value.length ||
          !value.every(key => parseKeyToken(key) && (!isImplemented(key) || isPublicKey(key)))
        )
          refuse('consumed_value_shape');
      };
      keys(state.listed);
      keys(state.signers);
      if (state.held !== undefined) {
        const held = object(state.held, 'consumed_value_shape');
        if (typeof held.server !== 'string' || serverOrigin(held.server, true) !== held.server)
          refuse('consumed_value_shape');
        keys(held.keys);
        isoField(held.until, 'consumed_value_shape');
      }
    } else if (scope === 'serving-since') {
      if (normalizeDomain(row.id) !== row.id) refuse('consumed_value_shape');
      if (value === null) {
        // send.ts explicitly writes an expired null tombstone when a domain leaves this server.
        if (row.value !== 'null' || row.expires === null || integer(row.expires, 'value_expiry') > at)
          refuse('consumed_value_shape');
      } else if (typeof value === 'string') {
        if (isoField(value, 'consumed_value_shape') > at) refuse('future_host_state');
      } else {
        const noted = object(value, 'consumed_value_shape');
        const since = isoField(noted.since, 'consumed_value_shape');
        const checked = isoField(noted.checked, 'consumed_value_shape');
        if (since > checked || checked > at) refuse('consumed_value_shape');
      }
    } else if (scope === 'postmaster-key') {
      const seed = typeof value === 'string' ? fromB64url(value) : null;
      if (!isAddress(row.id) || !row.id.startsWith('postmaster@') || !seed || seed.length !== 32)
        refuse('consumed_value_shape');
    } else if (['server-key-added', 'recipients-refused'].includes(scope)) {
      if (isoField(value, 'consumed_value_shape') > at) refuse('future_host_state');
    } else if (scope === 'delivery-move-cutoff') {
      const cutoff = object(value, 'consumed_value_shape');
      isoField(cutoff.until, 'consumed_value_shape');
      if (!['invalid', 'bad_signature'].includes(String(cutoff.reason)) || typeof cutoff.fresh !== 'boolean')
        refuse('consumed_value_shape');
    } else if (scope === 'reresolve') {
      refuse('legacy_inflight_lease');
    }
  }
  for (const table of ['marks', 'counters'] as const)
    for (const row of data[table]) {
      text(row.scope, 'state_scope');
      text(row.id, 'state_id');
      integer(row.expires, 'state_expiry');
      if (table === 'counters') integer(row.n, 'counter_value');
    }
  return { messages, archived };
}

function outboxRows(db: DatabaseSync) {
  const result = rows(db, 'arrivals');
  for (const row of result) {
    integer(row.__rowid, 'outbox_rowid', 1);
    integer(row.since, 'outbox_since');
    const body = object(json(row.body, 'outbox_body'), 'outbox_body');
    if (body.v !== 1 && body.v !== 2) refuse('outbox_body_version');
    if (!isAddress(body.address) || typeof body.id !== 'string' || !HEX64.test(body.id)) refuse('outbox_identity');
    isoField(body.receivedAt, 'outbox_received');
    if (
      row.key !== `${body.address}\n${body.id}` ||
      row.domain !== body.address.slice(body.address.lastIndexOf('@') + 1)
    )
      refuse('outbox_identity');
    if (body.v === 2 && (!isAddress(body.from) || (body.inReplyTo !== null && !HEX64.test(String(body.inReplyTo)))))
      refuse('outbox_body_shape');
  }
  return result;
}

function precomputedReceipts(data: Rows, messages: Map<string, AnyMessage>, limits: RetractionCapacity) {
  const receipts: Record<string, Record<string, unknown>> = Object.create(null);
  for (const row of data.messages) {
    const message = messages.get(row.id as string)!;
    if (message.v !== 1) continue;
    const v1 = message as Message;
    if (v1.headers.rel !== 'retract' || v1.inReplyTo === null) continue;
    receipts[row.id as string] = {
      record: {
        id: row.id,
        message,
        carrier: row.carrier,
        claims: json(row.claims, 'message_claims'),
        signedClaims: null,
        receivedAt: row.received_at,
        expiresAt: new Date(Number(row.expires)).toISOString(),
      },
      author: message.from,
      markers: (message.to.length ? message.to : ['*']).map(owner => ({
        owner,
        target: v1.inReplyTo,
        author: message.from,
        retraction: row.id,
      })),
      generation: '00000000-0000-0000-0000-000000000000',
      active: true,
      materialized: true,
      knownDeliveries: data.deliveries
        .filter(job => job.id === row.id)
        .map(job => job.domain)
        .sort(),
      knownArrivals: data.arrivals
        .filter(job => job.id === row.id)
        .map(job => job.recipient)
        .sort(),
      pendingDeliveries: {},
      pendingArrivals: {},
    };
  }
  const values = Object.values(receipts);
  const authors = new Map<unknown, number>();
  for (const receipt of values) authors.set(receipt.author, (authors.get(receipt.author) ?? 0) + 1);
  if (
    values.length > limits.maxRecords ||
    [...authors.values()].some(n => n > limits.maxPerAuthor) ||
    Buffer.byteLength(canonicalize(receipts)) + 16 * values.length > limits.maxBytes
  )
    refuse('retraction_capacity');
  return receipts;
}

function durableJson(directory: string, name: string, value: unknown) {
  const file = path.join(directory, name);
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
  try {
    fs.writeFileSync(fd, JSON.stringify(value, null, 2) + '\n');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  const parent = fs.openSync(directory, fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(parent);
  } finally {
    fs.closeSync(parent);
  }
}
function syncFile(file: string) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}
function openRead(file: string) {
  const db = new DatabaseSync(file, { readOnly: true, timeout: 0 });
  db.exec('PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;');
  return db;
}
function insert(db: DatabaseSync, table: string, row: Row) {
  const columns = Object.keys(row);
  const statement = db.prepare(
    `INSERT INTO ${q(table)}(${columns.map(q).join(',')}) VALUES(${columns.map(() => '?').join(',')})`,
  );
  statement.run(...columns.map(column => row[column]));
}
function preserveRow(db: DatabaseSync, table: string, row: Row, extra: Row = {}, omit: string[] = []) {
  const { __rowid, ...fields } = row;
  const preserved = Object.fromEntries(Object.entries(fields).filter(([column]) => !omit.includes(column)));
  insert(db, table, { rowid: __rowid, ...preserved, ...extra });
}
function checkpoint(file: string) {
  const db = new DatabaseSync(file);
  try {
    db.exec('PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;');
  } finally {
    db.close();
  }
  fs.chmodSync(file, 0o600);
  syncFile(file);
}
function sourceState(core: DatabaseSync, outbox: DatabaseSync) {
  return { core: ledger(core, [...TABLES, 'sqlite_sequence']), outbox: ledger(outbox, ['arrivals']) };
}

function verifyPreservation(candidate: DatabaseSync, data: Rows, high: number, archived: string[]) {
  for (const table of TABLES) {
    const expected = data[table].filter(row => table !== 'vals' || !archived.includes(rowHash(row)));
    const actual = rows(candidate, table);
    // New reserved sync state is verified separately; legacy rows retain their own original rowids.
    const old = table === 'vals' ? actual.filter(row => !String(row.scope).startsWith('sync-')) : actual;
    if (old.length !== expected.length) refuse('candidate_row_count');
    for (let i = 0; i < expected.length; i++) {
      const original = expected[i];
      const fields = Object.keys(original).filter(column => !(table === 'inbox' && column === 'received_at'));
      const projected = Object.fromEntries(fields.map(column => [column, old[i][column]]));
      const source = Object.fromEntries(fields.map(column => [column, original[column]]));
      if (rowHash(projected) !== rowHash(source)) refuse('candidate_raw_preservation');
      if (
        table === 'inbox' &&
        integer(old[i].taken, 'candidate_inbox_time') !== time(original.received_at, 'inbox_time')
      )
        refuse('candidate_inbox_time');
      if (table === 'messages' && (old[i].signed_claims !== null || old[i].cursor !== null || old[i].taken !== null))
        refuse('invented_sent_or_signed_claims');
      if (table === 'fetches' && (old[i].revision !== 0n || old[i].token !== null || old[i].exhausted !== null))
        refuse('candidate_fetch_fence');
    }
  }
  const positions = all(candidate, 'SELECT n FROM positions');
  if (positions.length !== 1 || integer(positions[0].n, 'candidate_highwater') !== high) refuse('candidate_highwater');
  for (const agent of data.agents) {
    const gap = all(candidate, "SELECT value,expires FROM vals WHERE scope='sync-history-gap' AND id=?", agent.address);
    if (gap.length !== 1 || gap[0].value !== 'true' || gap[0].expires !== null) refuse('candidate_history_gap');
  }
  if (all(candidate, 'SELECT 1 FROM signals UNION ALL SELECT 1 FROM webhooks').length) refuse('invented_events');
}

/**
 * The maintenance attestation is an operator prerequisite, not proof that arbitrary external processes
 * stopped. Both actual SQLite writer locks are acquired before either snapshot; the host fence must
 * remain owned/respected outside this command. Output never selects an operational database path.
 */
export async function createSqliteV2Candidate(options: SqliteV2CandidateOptions): Promise<SqliteV2Candidate> {
  const locks: DatabaseSync[] = [];
  const readers: DatabaseSync[] = [];
  let directory: string | null = null;
  let created = false;
  // Set once 004-VERIFIED.json is durable (or a matching one is reused): from then on, nothing marks it REFUSED.
  let verified: SqliteV2Candidate | null = null;
  try {
    const source = privateFile(options.source);
    const outbox = privateFile(path.join(path.dirname(source), 'app-arrivals.sqlite'));
    const sourceParent = fs.statSync(path.dirname(source));
    if (process.getuid === undefined || sourceParent.uid !== process.getuid() || (sourceParent.mode & 0o022) !== 0)
      refuse('unsafe_source_parent');
    for (const file of [source, outbox]) {
      let size = fs.statSync(file).size;
      for (const suffix of ['-wal', '-shm']) {
        const sidecar = file + suffix;
        if (fs.existsSync(sidecar)) size += fs.statSync(privateFile(sidecar)).size;
      }
      if (size > MAX_FILE_BYTES) refuse('cohort_file_capacity');
    }
    const attestation = maintenance(options.maintenanceFile);
    const m = attestation.value;
    const limits = resolveRetractionCapacity(options.retractions);
    const identities = [source, outbox, privateFile(options.maintenanceFile), privateFile(m.fenceFile)].map(file => {
      const stat = fs.statSync(file);
      return `${stat.dev}:${stat.ino}`;
    });
    if (new Set(identities).size !== identities.length) refuse('aliased_input');
    directory = path.resolve(options.directory);
    const parent = fs.lstatSync(path.dirname(directory));
    if (
      !parent.isDirectory() ||
      parent.isSymbolicLink() ||
      process.getuid === undefined ||
      parent.uid !== process.getuid() ||
      (parent.mode & 0o022) !== 0 ||
      fs.realpathSync(path.dirname(directory)) !== path.dirname(directory)
    )
      refuse('unsafe_candidate_parent');
    // IMMEDIATE excludes writers in WAL and rollback modes without treating readers as drained.
    for (const file of [source, outbox]) {
      const db = new DatabaseSync(file, { timeout: 0 });
      try {
        db.exec('PRAGMA trusted_schema=OFF; BEGIN IMMEDIATE;');
        locks.push(db);
      } catch {
        db.close();
        refuse('writer_exclusion_failed');
      }
    }
    for (const file of [source, outbox]) readers.push(openRead(file));
    const [core, app] = readers;
    verifySchema(core, LEGACY_SCHEMA, 2);
    verifySchema(app, OUTBOX_SCHEMA, 1);
    outboxRows(app);
    const current = sourceState(core, app);
    const existing = path.join(directory, '004-VERIFIED.json');
    if (fs.existsSync(directory)) {
      const stat = fs.lstatSync(directory);
      if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0)
        refuse('unsafe_existing_candidate');
      // A bundle that recorded a refusal is never reused, whatever else it holds.
      if (fs.existsSync(path.join(directory, 'REFUSED.json'))) refuse('refused_candidate_choose_new_directory');
      if (!fs.existsSync(existing)) refuse('incomplete_candidate_choose_new_directory');
      const prior = object(
        json(fs.readFileSync(privateFile(existing), 'utf8'), 'candidate_manifest'),
        'candidate_manifest',
      );
      const candidate = object(prior.candidate, 'candidate_manifest') as unknown as SqliteV2Candidate;
      if (
        candidate.status !== 'VERIFIED_COPY_HELD' ||
        candidate.activationBlocked !== true ||
        candidate.noOperationalPromotion !== true ||
        !Array.isArray(candidate.holds) ||
        !candidate.holds.includes('historical_suppression_not_proven') ||
        candidate.origin !== m.origin ||
        candidate.configDigest !== m.configDigest ||
        candidate.serverKeyFingerprint !== m.serverKeyFingerprint ||
        candidate.toolCommit !== m.toolCommit ||
        JSON.stringify(candidate.retractionLimits) !== JSON.stringify(limits) ||
        candidate.maintenanceDigest !== attestation.digest ||
        JSON.stringify(candidate.sourcePaths) !== JSON.stringify({ core: source, outbox }) ||
        JSON.stringify(candidate.source) !== JSON.stringify(current)
      )
        refuse('candidate_input_mismatch');
      const expectedFiles = [
        'source-core.sqlite',
        'source-app-arrivals.sqlite',
        path.join('candidate', path.basename(source)),
        path.join('candidate', 'app-arrivals.sqlite'),
      ].sort();
      if (JSON.stringify(Object.keys(candidate.hashes).sort()) !== JSON.stringify(expectedFiles))
        refuse('candidate_artifact_set');
      for (const [file, digest] of Object.entries(candidate.hashes)) {
        const absolute = path.resolve(directory, file);
        if (
          !HEX64.test(digest) ||
          !absolute.startsWith(directory + path.sep) ||
          fileHash(privateFile(absolute)) !== digest
        )
          refuse('candidate_artifact_mismatch');
      }
      verified = candidate;
      return candidate;
    }
    fs.mkdirSync(directory, { mode: 0o700 });
    created = true;
    syncFile(path.dirname(directory));
    const bundleId = crypto.randomUUID();
    const snapshots = { core: 'source-core.sqlite', outbox: 'source-app-arrivals.sqlite' };
    await backup(core, path.join(directory, snapshots.core));
    await backup(app, path.join(directory, snapshots.outbox));
    for (const file of Object.values(snapshots)) checkpoint(path.join(directory, file));
    // A fence replaced/lost during snapshot invalidates the cut rather than granting a mixed cohort.
    if (maintenance(options.maintenanceFile).digest !== attestation.digest) refuse('maintenance_changed');
    const journal = (stage: Stage, number: string, detail: unknown) => {
      durableJson(directory!, `${number}-${stage}.json`, { bundleId, stage, detail });
      options.afterStage?.(stage);
    };
    journal('SNAPSHOTTED', '001', { source: current, snapshots, maintenanceDigest: attestation.digest });
    const sourceCore = openRead(path.join(directory, snapshots.core));
    const sourceApp = openRead(path.join(directory, snapshots.outbox));
    readers.push(sourceCore, sourceApp);
    verifySchema(sourceCore, LEGACY_SCHEMA, 2);
    verifySchema(sourceApp, OUTBOX_SCHEMA, 1);
    if (JSON.stringify(sourceState(sourceCore, sourceApp)) !== JSON.stringify(current))
      refuse('snapshot_cohort_mismatch');
    const data = Object.fromEntries(TABLES.map(table => [table, rows(sourceCore, table)])) as Rows;
    const { messages, archived } = validateRows(data, m);
    const sequence = all(sourceCore, 'SELECT name,seq FROM sqlite_sequence');
    if (sequence.some(row => row.name !== 'inbox')) refuse('sequence_layout');
    let high = 0;
    for (const row of sequence) high = Math.max(high, integer(row.seq, 'inbox_highwater'));
    for (const row of data.inbox) high = Math.max(high, integer(row.cursor, 'inbox_cursor', 1));
    const headroom = Number.MAX_SAFE_INTEGER - 1 - high;
    if (headroom <= 0) refuse('stream_headroom');
    const receipts = precomputedReceipts(data, messages, limits);
    const appRows = outboxRows(sourceApp);
    // No inference that absence of a schema2 row proves no deleted suppression or exhausted job.
    const holds = ['historical_suppression_not_proven', 'host_runtime_bom_and_backend_adoption_unverified'];
    if (
      data.fetches.length ||
      data.parts.length ||
      data.message_parts.length ||
      data.counters.some(row => row.scope === 'files:give-up-rounds')
    )
      holds.push('terminal_policy_history_and_host_adapter_unverified');
    journal('PREFLIGHT_OK', '002', {
      highWatermark: high,
      usableHeadroom: headroom,
      archivedTombstones: archived,
      holds,
    });
    const converted = path.join(directory, 'candidate');
    fs.mkdirSync(converted, { mode: 0o700 });
    const candidate = {
      core: path.join('candidate', path.basename(source)),
      outbox: path.join('candidate', 'app-arrivals.sqlite'),
    };
    if (candidate.core === candidate.outbox) refuse('core_outbox_name_collision');
    const coreFile = path.join(directory, candidate.core);
    const appFile = path.join(directory, candidate.outbox);
    const fresh = new SqliteStore(coreFile, { retractions: limits });
    await fresh.close();
    const destination = new DatabaseSync(coreFile);
    const generations: Record<string, string> = Object.create(null);
    try {
      destination.exec('BEGIN IMMEDIATE;');
      destination.exec('DELETE FROM positions;');
      insert(destination, 'positions', { n: high });
      for (const table of TABLES)
        for (const row of data[table]) {
          if (table === 'vals' && archived.includes(rowHash(row))) continue;
          let extra: Row = {};
          if (table === 'agents')
            extra = { unpairing: null, authority_version: 0, recovery_key_cancelled_at: null, authorized_keys: null };
          if (table === 'agent_keys') extra = { label: null };
          if (table === 'messages' || table === 'fetches') {
            const generation = crypto.randomUUID();
            generations[`${table}:${rowHash(row)}`] = generation;
            extra = { generation };
          }
          if (table === 'messages') {
            const message = messages.get(row.id as string)!;
            extra = {
              ...extra,
              in_reply_to: message.v === 1 ? (message as Message).inReplyTo : null,
              signed_claims: null,
              cursor: null,
              taken: null,
            };
          }
          if (table === 'fetches') extra = { ...extra, revision: 0, token: null, exhausted: null };
          if (table === 'inbox') extra = { taken: time(row.received_at, 'inbox_received') };
          preserveRow(destination, table, row, extra, table === 'inbox' ? ['received_at'] : []);
          if (options.faultAt === 'copy-row') refuse('synthetic_copy_failure');
        }
      for (const agent of data.agents)
        insert(destination, 'vals', { scope: 'sync-history-gap', id: agent.address, value: 'true', expires: null });
      insert(destination, 'vals', {
        scope: 'sync-secret',
        id: m.origin,
        value: JSON.stringify(crypto.randomBytes(32).toString('base64url')),
        expires: null,
      });
      verifyPreservation(destination, data, high, archived);
      destination.exec('COMMIT;');
    } catch (error) {
      destination.exec('ROLLBACK;');
      throw error;
    } finally {
      destination.close();
    }
    const out = new DatabaseSync(appFile);
    try {
      out.exec(OUTBOX_SCHEMA);
      out.exec('BEGIN IMMEDIATE;');
      for (const row of appRows) preserveRow(out, 'arrivals', row);
      out.exec('COMMIT;');
      if (JSON.stringify(ledger(out, ['arrivals'])) !== JSON.stringify(current.outbox)) refuse('outbox_preservation');
    } finally {
      out.close();
    }
    journal('COPIED', '003', { candidate, generations });
    // Only the private candidate is opened for the real bounded current-schema retraction bootstrap.
    if (options.faultAt === 'bootstrap') refuse('synthetic_bootstrap_failure');
    const validating = new SqliteStore(coreFile, { retractions: limits });
    await validating.close();
    const verification = openRead(coreFile);
    try {
      if (options.faultAt === 'verify') refuse('synthetic_verification_failure');
      verifyPreservation(verification, data, high, archived);
      const actual = object(
        json(all(verification, 'SELECT body FROM retraction_admission')[0].body, 'receipts'),
        'receipts',
      );
      if (Object.keys(actual).length !== Object.keys(receipts).length) refuse('retraction_marker_completeness');
      for (const [id, expected] of Object.entries(receipts)) {
        const receipt = object(actual[id], 'retraction_marker_completeness');
        if (typeof receipt.generation !== 'string' || !/^[0-9a-f-]{36}$/.test(receipt.generation))
          refuse('retraction_fence');
        generations[`retraction:${hash(id)}`] = receipt.generation;
        const normalized = {
          ...receipt,
          generation: expected.generation,
          knownDeliveries: [...(receipt.knownDeliveries as string[])].sort(),
          knownArrivals: [...(receipt.knownArrivals as string[])].sort(),
        };
        if (canonicalize(normalized) !== canonicalize(expected)) refuse('retraction_marker_completeness');
      }
    } finally {
      verification.close();
    }
    for (const file of [coreFile, appFile]) checkpoint(file);
    // Persist the nested file entries before the outer VERIFIED record can become durable.
    syncFile(converted);
    const hashes = Object.fromEntries(
      [...Object.values(snapshots), ...Object.values(candidate)].map(file => [
        file,
        fileHash(path.join(directory!, file)),
      ]),
    );
    const result: SqliteV2Candidate = {
      status: 'VERIFIED_COPY_HELD',
      activationBlocked: true,
      holds,
      bundleId,
      maintenanceDigest: attestation.digest,
      origin: m.origin,
      serverKeyFingerprint: m.serverKeyFingerprint,
      configDigest: m.configDigest,
      toolCommit: m.toolCommit,
      retractionLimits: limits,
      observation: {
        at: m.observedAt,
        provenance: m.clockProvenance,
        ...(m.previousObservedAt && { previous: m.previousObservedAt }),
      },
      sourcePaths: { core: source, outbox },
      source: current,
      snapshots,
      candidate,
      hashes,
      highWatermark: high,
      usableHeadroom: headroom,
      archivedTombstones: archived,
      generations: { ...generations },
      noOperationalPromotion: true,
    };
    durableJson(directory, '004-VERIFIED.json', { bundleId, stage: 'VERIFIED', candidate: result });
    verified = result;
    options.afterStage?.('VERIFIED');
    return result;
  } catch (error) {
    const refusal = error instanceof SqliteMigrationRefusal ? error : new SqliteMigrationRefusal('conversion_failed');
    // Once VERIFIED is durable, a later failure (a crash) must not give the bundle a second, refused meaning.
    if (created && directory && !verified) {
      try {
        durableJson(directory, 'REFUSED.json', { status: 'REFUSED', code: refusal.code, noOperationalPromotion: true });
      } catch {
        // A crash/full disk may prevent the final refusal journal. Existing stages/backups remain untouched.
      }
    }
    throw refusal;
  } finally {
    let cleanupFailed = false;
    for (const reader of readers.reverse()) {
      try {
        reader.close();
      } catch {
        cleanupFailed = true;
      }
    }
    for (const lock of locks.reverse()) {
      try {
        lock.exec('ROLLBACK;');
      } catch {
        cleanupFailed = true;
      }
      try {
        lock.close();
      } catch {
        cleanupFailed = true;
      }
    }
    if (options.faultAt === 'cleanup') cleanupFailed = true;
    if (cleanupFailed) {
      if (verified) throw new SqliteV2CleanupFailure(verified);
      refuse('cleanup_failed');
    }
  }
}
