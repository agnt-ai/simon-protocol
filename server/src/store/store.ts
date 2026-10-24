/**
 * Everything the server keeps, behind one interface. The sqlite store implements it; any other store (an
 * application may write one for its own database) proves itself with the contract suite in `contract.ts`.
 *
 * Rules every implementation keeps:
 *   - **No clock.** Every time is passed in, as an ISO timestamp or a Date, so tests move time freely.
 *   - **Uniqueness is part of the contract,** stated on each method that depends on it, and atomic: two
 *     calls racing on the same key never both win. A database index is one way to keep it; it is not the
 *     contract.
 *   - **A method is one change.** What a method writes is all there or none of it, so a crash between two
 *     calls never leaves half of one behind.
 *   - **Queues are claimed, not read.** Work the server does later (deliveries, arrivals, inbox events, part
 *     fetches, webhook posts) is a row it settles explicitly; nothing is lost by a crash, and a crash at worst
 *     repeats work.
 *   - **Retention is explicit.** Nothing expires except through `sweep`, which says what it removes.
 *   - Methods return copies; mutating a returned record changes nothing stored.
 */
import type { AnyMessage, Claim, Hints, KeyEntry, SignedClaims } from '@agnt-protocol/protocol';

/** Reference-host admission limits, separate from protocol limits. Accepted retractions are never evicted. */
export interface RetractionCapacity {
  maxRecords: number;
  maxPerAuthor: number;
  maxBytes: number;
}
export class StoreCapacityError extends Error {
  readonly code = 'store_capacity';
  constructor() {
    super('The server is temporarily at capacity.');
    this.name = 'StoreCapacityError';
  }
}
export function resolveRetractionCapacity(input: Partial<RetractionCapacity> = {}): RetractionCapacity {
  const limits = { maxRecords: 4096, maxPerAuthor: 256, maxBytes: 4 * 1024 * 1024, ...input };
  for (const n of Object.values(limits))
    if (!Number.isSafeInteger(n) || n < 1) throw new TypeError('Retraction limits are positive safe integers.');
  if (limits.maxBytes > 8 * 1024 * 1024) throw new TypeError('Retraction admission is limited to 8 MiB.');
  return limits;
}

/**
 * The most keys, revoked ones included, that adding a key may leave an agent with: four published
 * documents' worth (PROTOCOL.md section 4 lists at most 32). A revoked key is kept so it never returns, which
 * leaves history unbounded without a cap, and a Mongo agent document is limited to 16 MiB. Recovery is never
 * refused for it: a recovery replaces every key with one, and refusing it would let a key holder block it.
 */
export const MAX_STORED_KEYS = 128;

/** A key of an agent here: its entry in the agent's document, and a label for its own clients, never published. */
export interface AgentKey extends KeyEntry {
  label?: string;
}

/** An agent registered here. Its address and kind are fixed for the life of the address. */
export interface Agent {
  /** Private current authorization after recovery; absent for legacy temporal-key authorization. */
  authorizedKeys?: string[];
  /** Private Store authority epoch; never part of agent documents or account wire responses. */
  authorityVersion?: number;
  /**
   * Private recovery epoch, advanced only when a recovery ends or authority over the address is reset:
   * a recovery cancelled, completed or lapsed, a principal recovery, a retirement. Adding or revoking a key
   * never advances it, so a key holder cannot void a mailbox code (register.ts). Absent means zero.
   */
  recoveryEpoch?: number;
  /** Private last key cancellation, used by the host's recovery cooldown. */
  recoveryKeyCancelledAt?: string;
  address: string;
  kind: 'solo' | 'paired';
  /** The principal's identifier (the `for` header) of a paired agent; null for a solo one. */
  principal: string | null;
  /** Every key ever added, revoked ones included, oldest first. */
  keys: AgentKey[];
  /** Whether the address was bound by a code sent to it, so a code can recover it. */
  mailbox: boolean;
  createdAt: string;
  /**
   * When the address retired: it never serves anyone again and every key is revoked. Publishing optional
   * retirement evidence is host policy; private hosting may withhold it.
   */
  retiredAt: string | null;
  /** The key principal's unpairing that retired it, when one did, served in its retired document. */
  unpairing?: string | null;
}

/** A message held here: written by an agent here, or accepted from another server. */
export interface StoredMessage {
  id: string;
  message: AnyMessage;
  /** The origin of the server that carried it; this server's own for a message written here. */
  carrier: string;
  /** Claims about the author: made by this server, or accepted from the carrier, as judged here. */
  claims: Claim[];
  /** The carrier's claims exactly as it signed them for this message (spec section 6.2), or null with none. */
  signedClaims: SignedClaims | null;
  receivedAt: string;
  /** When `sweep` removes it, with everything tied to it. */
  expiresAt: string;
}

/** A message in an agent's sync stream: one it received, or one it wrote here. */
export interface SyncEntry {
  /** Its position in the stream. */
  cursor: number;
  address: string;
  id: string;
  message: AnyMessage;
  carrier: string;
  claims: Claim[];
  signedClaims: SignedClaims | null;
  /** When it entered the stream. */
  receivedAt: string;
}

/** A signal held for an agent here (CLIENT.md Signals), in its place in the agent's sync stream. */
export interface HeldSignal {
  cursor: number;
  type: string;
  from: string;
  about: string;
  at: string;
}

/** A page of an agent's sync stream. */
export interface SyncPage {
  messages: SyncEntry[];
  signals: HeldSignal[];
  /** The last position the page covers: the next page starts after it. */
  cursor: number;
  more: boolean;
}

/** A URL that wakes an agent here when something new reaches it (CLIENT.md sync, "Webhooks"). */
export interface Webhook {
  id: string;
  address: string;
  url: string;
  /** The hash of the code posted to the URL, which the agent hands back to verify it. */
  codeHash: string;
  verified: boolean;
  createdAt: string;
  /** When posts to it began failing, without an answer since; null while it answers. */
  failingSince: string | null;
}

/** A page of a listing, newest first: each record with its cursor, the message's id, which continues after it. */
export interface Page {
  records: { cursor: string; message: StoredMessage }[];
  more: boolean;
}

/** Delivery of one message to the recipients on one domain. */
export interface Delivery {
  id: string;
  domain: string;
  recipients: string[];
  /** The hints for these recipients, held only until the delivery ends. */
  hints: Hints;
  /** The server the domain last resolved to; null until it resolved. */
  server: string | null;
  status: 'pending' | 'delivered' | 'failed';
  /** Why it failed, or why the last attempt did not succeed: a resolution outcome or an error code. */
  reason: string | null;
  attempts: number;
  nextAttemptAt: string;
  createdAt: string;
  /** No attempt starts after this (spec section 6.3); the delivery then fails as `expired`. */
  deadline: string;
}

/** A message from another server (or written here), waiting to be offered to one recipient here. */
export interface QueuedArrival {
  id: string;
  recipient: string;
  /** This recipient's hints. */
  hints: Record<string, string>;
  attempts: number;
  dueAt: string;
}

/** Bytes of a part to fetch from the server that carried a message naming them. */
export interface PartFetch {
  /** Changes on every row mutation; absent only on an initial caller-created enqueue record. */
  revision?: number;
  /** A newly queued row has a fresh incarnation, so a stale pre-completion read never claims its successor. */
  generation?: string;
  sha256: string;
  carrier: string;
  size: number;
  attempts: number;
  dueAt: string;
}

/** Where bytes came from: the agent here that uploaded them, or the carrier they were fetched from. */
export type PartSource = { uploader: string } | { carrier: string };

export interface SweepCounts {
  messages: number;
  parts: number;
  marks: number;
  signals: number;
}

/** Synchronous final public-document capacity check, evaluated inside the mutation lock/CAS. */
export type AgentAdmission = (candidate: Agent) => boolean;

export interface Store {
  // Agents. An address and a key token each belong to at most one agent, forever: a retired address is
  // never registered again, and a key, revoked or not, never moves to another agent.

  /** Insert, unless the address or any of its keys is already taken. */
  createAgent(
    agent: Agent,
    admit?: AgentAdmission,
  ): Promise<'created' | 'address_taken' | 'key_in_use' | 'too_many_keys'>;
  agentByAddress(address: string): Promise<Agent | null>;
  /** The agent holding this key, whether the key is active or revoked. */
  agentByKey(key: string): Promise<Agent | null>;
  /**
   * Add a key, atomically, unless the agent already holds `maxActive` unrevoked keys or `MAX_STORED_KEYS`
   * keys in all, revoked ones included.
   */
  addKey(
    address: string,
    entry: AgentKey,
    maxActive: number,
    admit?: AgentAdmission,
  ): Promise<'added' | 'too_many_keys' | 'key_in_use'>;
  /** Revoke one active key unless it is the last; compare-and-change protects racing revocations. */
  revokeKey(
    address: string,
    key: string,
    at: string,
    admit?: AgentAdmission,
  ): Promise<'revoked' | 'last_key' | 'not_found'>;
  /** Recovery is atomic with retirement, uniqueness and final signed-document admission. */
  replaceKeys(
    address: string,
    entry: AgentKey,
    admit?: AgentAdmission,
  ): Promise<'replaced' | 'key_in_use' | 'retired' | 'too_many_keys'>;
  keepOnlyKey(address: string, key: string, at: string): Promise<'kept' | 'not_held'>;
  /** Only the first retirement counts, including its unpairing evidence. */
  retireAgent(address: string, at: string, unpairing?: string): Promise<void>;

  /** Begin only against the current admitted authority; return its existing live pending proof or the new one. */
  beginRecovery(
    address: string,
    value: unknown,
    expiresAt: string | null,
    now: string,
    admit?: AgentAdmission,
  ): Promise<unknown | null>;
  /** Activate exactly one live undefended proof after its mandatory defense completes; preserve all proof fields. */
  activateRecovery(address: string, expectedRecovery: unknown, now: string): Promise<boolean>;
  /** Compare pending proof and mutate keys in one change; explicit defended:false cannot complete. Rejection preserves proof. */
  completeRecovery(
    address: string,
    entry: AgentKey,
    expectedRecovery: unknown,
    admit?: AgentAdmission,
  ): Promise<'replaced' | 'not_pending' | 'key_in_use' | 'retired' | 'too_many_keys'>;
  /** Exact pending plus admitted actor, cancellation and optional private cooldown are one change. */
  cancelRecovery(
    address: string,
    expectedRecovery: unknown,
    now: string,
    admit?: AgentAdmission,
    keyCancelledAt?: string,
  ): Promise<boolean>;

  // Messages. One record per id, stored with the rows that carry it on, as one change.

  /**
   * Store a message once by id, with its delivery rows (a message sent here) or its arrivals (a message
   * taken for recipients here), all or nothing. Rows already there, by (id, domain) or (id, recipient), are
   * left as they are; the rest are added, even when the message was stored before, so repeating a call
   * completes it. Returns the stored record, the earlier one on a repeat. Accepted retractions retain
   * permanent bounded suppression receipts, including after envelope deletion; their repeats never
   * reactivate completed work. StoreCapacityError rejects new records or row grants before acceptance.
   *
   * A message first stored with arrivals is a received one: it stays only while an arrival waits for it,
   * or once an arrival kept it (`arrivalDone`). Any other message was written here: it takes a position in
   * its author's sync stream, and stays until it expires.
   */
  putMessage(m: StoredMessage, rows?: { deliveries?: Delivery[]; arrivals?: QueuedArrival[] }): Promise<StoredMessage>;
  message(id: string): Promise<StoredMessage | null>;
  /** Remove live message state, stream positions, deliveries, arrivals and parts; preserve accepted suppression receipts. */
  deleteMessage(id: string): Promise<void>;
  /**
   * The messages an agent here published (empty `to`), newest first, after the one whose id is `before` (null
   * for the newest; an id that is not one of them matches nothing). A record's cursor is its message id.
   */
  published(author: string, before: string | null, limit: number): Promise<Page>;
  /**
   * The messages in `address`'s inbox whose `inReplyTo` is `id`, newest first, after the one whose id is
   * `before` (null for the newest): the relations to a published message its author may show (spec section
   * 7.4). A record's cursor is its message id.
   */
  repliesTo(address: string, id: string, before: string | null, limit: number): Promise<Page>;

  /** Durable same-author rel:retract suppression for a live listing, scoped to its owner's accepted inbox. */
  listingRetracted(ownerAddress: string, id: string, replyAuthor: string): Promise<boolean>;

  // Arrivals: one per (id, recipient), each settled on its own, so one that fails holds up no other.

  /** Arrivals due at `now`, oldest first, with their messages. */
  arrivals(
    now: string,
    limit: number,
  ): Promise<{ arrival: QueuedArrival; message: StoredMessage; generation: string }[]>;
  /** Try an arrival again at `at`, one attempt more. Queued workers pass the snapshot generation to fence recreation. */
  arrivalRetry(id: string, recipient: string, at: string, generation?: string): Promise<void>;
  /**
   * An arrival is over; `kept` says whether its recipient took or holds the message. Answers `kept` when
   * this kept a received message for the first time, `dropped` when it removed a received message that
   * nothing waits for and nothing kept, and null otherwise.
   */
  arrivalDone(id: string, recipient: string, kept: boolean, generation?: string): Promise<'kept' | 'dropped' | null>;

  // Sync. An agent's stream holds the messages in its inbox, the messages it wrote here (`putMessage`) and
  // the signals held for it, each at a position taken from one sequence across the store, increasing in the
  // order the store takes them. An inbox entry is unique per (address, id).

  /** Add a message to an inbox, with its inbox event waiting to be told; false when it is already there. */
  addToInbox(address: string, id: string, at: string, generation?: string, minExpiresAt?: string): Promise<boolean>;
  /**
   * A page of an agent's stream after position `after`: up to `limit` messages in position order, only
   * those that entered it at or after `from` when given; and the signals held for it, unexpired at `now`,
   * among the positions the page covers. With `more`, the page ends at its last message. Without, it covers
   * every position taken so far, and never one taken before a position not yet written, so a reader
   * following `cursor` never skips a position written late.
   */
  sync(address: string, after: number, limit: number, now: string, from?: string): Promise<SyncPage>;
  /**
   * Hold a signal for an agent at the next position of its stream until `expiresAt`, and no longer; and
   * forget every signal expired at `now`.
   */
  holdSignal(address: string, signal: Omit<HeldSignal, 'cursor'>, expiresAt: string, now: string): Promise<void>;
  /** Inbound-only stream page for host unread views; uses the same safe watermark as sync. */
  inbox(address: string, after: number, limit: number): Promise<SyncEntry[]>;
  /** Whether a message is in an agent's inbox. */
  inInbox(address: string, id: string): Promise<boolean>;
  /** Whether an agent here has sent `recipient` a message this store still holds. */
  wroteTo(author: string, recipient: string, self: string): Promise<boolean>;
  /** Inbox entries whose inbox event is not yet told, in position order. */
  inboxEvents(limit: number): Promise<SyncEntry[]>;
  inboxEventDone(cursor: number): Promise<void>;

  // Webhooks: each wakes its agent when something new enters its stream, at most once in its quiet time.

  /** Add a webhook unless its agent holds `max` already: false then. Atomic, even when adds race. */
  addWebhook(webhook: Webhook, max: number): Promise<boolean>;
  webhook(id: string): Promise<Webhook | null>;
  verifyWebhook(id: string): Promise<void>;
  deleteWebhook(id: string): Promise<void>;
  /**
   * Something entered an agent's stream: each of its verified webhooks with no post due falls due at `at`,
   * or when its quiet time ends, if that is later.
   */
  wakeWebhooks(address: string, at: string): Promise<void>;
  /**
   * Claim up to `limit` webhooks due at `now`, earliest first: each is due no longer, and quiet until
   * `quietUntil`. Atomic: two claims never take the same webhook.
   */
  claimWebhooks(
    now: string,
    limit: number,
    quietUntil: string,
    lease: { token: string; until: string },
  ): Promise<Webhook[]>;
  /** A post's outcome: `failingSince` as it now stands, and after a failure, a retry due at `retryAt` unless one is. */
  settleWebhook(
    id: string,
    failingSince: string | null,
    retryAt: string | null,
    token: string,
    disable?: boolean,
  ): Promise<boolean>;

  // Deliveries. One row per (id, domain).

  /**
   * Claim up to `limit` pending rows due at `now`, earliest first, except those whose `server` is in `skip`:
   * each is leased to `lease.token` and not due again before `lease.until`. Atomic: two claims never take
   * the same row.
   */
  claimDeliveries(
    now: string,
    limit: number,
    skip: string[],
    lease: { token: string; until: string },
  ): Promise<Delivery[]>;
  /**
   * Write an attempt's outcome to the row (id, domain): its server, status, reason, attempts and next attempt.
   * Only while the row is pending and leased to `token`, and the lease ends; false when nothing was written.
   */
  settleDelivery(row: Delivery, token: string): Promise<boolean>;
  deliveries(id: string): Promise<Delivery[]>;

  // Parts: bytes kept per (sha256, source), never shared between sources.

  putPart(sha256: string, bytes: Buffer, source: PartSource, at: string): Promise<void>;
  part(sha256: string, source: PartSource): Promise<Buffer | null>;
  /**
   * The sources of the bytes held for an agent (spec section 7.2), held yet or not, with the size the
   * naming message gives: its own upload, and for a message in its inbox naming the part, the carrier's
   * bytes, or the sources held for the author when the carrier is `self`, through any number of local forwards.
   * Follow only inbox grants for this hash, with cycle detection; never search globally for matching bytes.
   */
  heldFor(sha256: string, address: string, self: string): Promise<(PartSource & { size: number })[]>;
  /**
   * The agents here, not retired, whose messages naming the part a reader may see: for `published`, their
   * published messages (the caller judges each audience); for a `server`, their messages delivered to that
   * server (status `delivered`). Each with the naming message.
   */
  partNamers(
    sha256: string,
    viewer: { published: true } | { server: string },
    self: string,
  ): Promise<{ author: string; message: AnyMessage }[]>;

  // Part fetches: one per (sha256, carrier).

  /**
   * Queue a fetch unless one is queued, and return the one now queued. With `max`, a fetch not yet queued is
   * not queued (null) while `max` fetches of its carrier are waiting (not given up); racing callers may pass
   * it by a few.
   */
  queueFetch(f: PartFetch, now?: string): Promise<PartFetch>;
  queueFetch(f: PartFetch, now: string | undefined, max: number): Promise<PartFetch | null>;
  /**
   * Fetches due at `now`, taken in turn across carriers: every carrier's earliest, earliest first, then
   * every carrier's second, and so on, so no carrier's backlog hides another's.
   */
  fetches(now: string, limit: number): Promise<PartFetch[]>;
  /**
   * Claim a fetch read from `fetches`: move it to `until`, only if it is still due at `now` and still has the
   * attempts and due time it was read with. Atomic: of callers racing with the same row, one wins, and a row
   * read before another caller settled it (done, retried or deferred) is never claimed. True for the winner.
   * Each worker supplies a unique token. Only that token can renew or settle; renewal also requires a live lease.
   */
  claimFetch(f: PartFetch, now: string, lease: { token: string; until: string }): Promise<boolean>;
  renewFetch(sha256: string, carrier: string, token: string, now: string, until: string): Promise<boolean>;
  /** Try a fetch again at `at`, one attempt more. */
  fetchRetry(sha256: string, carrier: string, at: string, token: string): Promise<boolean>;
  /** Move a fetch to `at` without counting an attempt: it waited its turn, and was not tried. */
  fetchDefer(sha256: string, carrier: string, at: string, token: string): Promise<boolean>;
  fetchDone(sha256: string, carrier: string, token: string): Promise<boolean>;
  /** Terminal failure and its ownership fence are one atomic row change; stale attempts cannot mark it. */
  fetchGiveUp(sha256: string, carrier: string, token: string, expiresAt: string): Promise<boolean>;
  fetchExhausted(sha256: string, carrier: string, now: string): Promise<boolean>;

  // Marks and small values, scoped by name. Each lives until its expiry and no longer.
  // `recovery` is reserved: value() reads it; generic mutations reject it. Use the atomic recovery methods.

  /** Set a mark unless an unexpired one exists: true for the one caller that set it. */
  mark(scope: string, id: string, expiresAt: string, now: string): Promise<boolean>;
  marked(scope: string, id: string, now: string): Promise<boolean>;
  /**
   * Add `by` (one unless given; it may be negative, to take back what was added) to a counter, atomically,
   * and return the new count; the first count fixes its expiry.
   */
  count(scope: string, id: string, expiresAt: string, now: string, by?: number): Promise<number>;
  /** A value, or null once it expired. */
  value<T>(scope: string, id: string, now: string): Promise<T | null>;
  setValue(scope: string, id: string, value: unknown, expiresAt: string | null): Promise<void>;
  /** Remove a value only while it is still `value`, atomically: true when this removed it. */
  releaseValue(scope: string, id: string, value: unknown): Promise<boolean>;
  /** Move a value's expiry to `expiresAt` only while it is still `value`, atomically: true when this did. */
  renewValue(scope: string, id: string, value: unknown, expiresAt: string): Promise<boolean>;
  /** Set a value unless an unexpired one exists, and return the value now stored. */
  valueOnce<T>(scope: string, id: string, value: T, expiresAt: string | null, now: string): Promise<T>;

  /**
   * Remove what expired at `now`: messages past `expiresAt` (with their stream positions, deliveries,
   * arrivals and part names); fetches no message from their carrier names any more, waiting or given up; then
   * bytes no message names any more, fetched bytes at once and uploads made before `uploadsBefore`; then
   * expired marks, counters, values and signals. A store may take the unnamed fetches, and rows a crash left
   * behind a removed message, a bounded slice per sweep, so each sweep's work stays bounded.
   */
  sweep(now: string, uploadsBefore: string): Promise<SweepCounts>;
  close(): Promise<void>;
}
