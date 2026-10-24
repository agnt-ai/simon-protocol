/**
 * The extension seam: how an application adds a directory, recipient policy, an owner window or a bridge
 * without editing the core. An extension is a plain object; the server takes an array of them, and every
 * hook is the list of all extensions' hooks, in the order given. No hook is a single slot.
 *
 *   routes           more HTTP routes (they may not replace the core's)
 *   admit            the admit chain: whether a recipient here takes a message
 *   claimsFor        claims this server makes about the author of a message sent here
 *   allowAddress     who may take a new name on a hosted domain, or a lease
 *   verifyPrincipal  pairing with a principal the core cannot verify itself (mailto:, tel:)
 *   upload           whether an agent's upload is kept (a malware scan, a volume limit)
 *   admitsReader     whether a published message's audience label admits a reader
 *   on               events: stored, inbox, delivered, deliveryFailed, unroutable, recovered, signal
 */
import type { AnyMessage, Claim, Hints, Json, Signal } from '@agnt-protocol/protocol';
import type { Config } from './config.ts';
import type { Request, Route } from './http.ts';
import type { Agent, Store, StoredMessage } from './store/store.ts';

export type Log = (
  level: 'debug' | 'info' | 'warn' | 'error',
  message: string,
  fields?: Record<string, unknown>,
) => void;

/** What extensions may use of the server. */
export interface ServerApi {
  readonly config: Config;
  readonly store: Store;
  now(): Date;
  log: Log;
  /** The agent here that signed this request (spec section 8), or a 401 in the protocol's shape. */
  authenticate(req: Request): Promise<Agent>;
  /** Take a message an admit hook answered `later` into a recipient's inbox; false if it already was. */
  admit(address: string, id: string): Promise<boolean>;
  /** Offer a stored message to an agent here through the admit chain, as delivery does; true when it took or holds it. */
  offer(address: string, id: string): Promise<boolean>;
  /**
   * Send a message written by an agent here (an application's own agents: notices, a bridge), checked and
   * delivered exactly as `POST /simon/send` would; `hints` as its `simon-hints` header carries them.
   */
  send(message: AnyMessage, hints?: Hints): Promise<{ id: string; receivedAt: string }>;
  /** Retire an address (spec section 2.2): its keys revoked, its document gone, never registered again. */
  retire(address: string): Promise<void>;
}

/** A message offered to one recipient here. */
export interface Arrival {
  id: string;
  message: AnyMessage;
  recipient: string;
  /** The origin of the server that carried it; this server's own for a message written here. */
  carrier: string;
  /**
   * The claims agents here are shown (spec section 6.2): authoritative ones always, the rest only from a
   * carrier this server trusts. Each acts-for and identifier claim carries `authoritative`.
   */
  claims: Claim[];
  /** This recipient's hints from the envelope or from `simon-hints`. */
  hints: Record<string, string>;
}

/**
 * One link of the admit chain, read like Postfix's restrictions: `accept` takes the message and ends the
 * chain, `refuse` drops it and ends the chain, `later` holds it (the extension calls `api.admit` when it
 * decides) and ends the chain, and `undefined` has no opinion. When no link decides, the message is taken.
 * The sender learns none of this: the answer was 202 either way.
 */
export type Decision = 'accept' | 'refuse' | 'later' | undefined;

/** A registration of a new address, by the key that would hold it. */
export interface AddressRequest {
  /**
   * The address being registered: the one named, or the one leased. The core asks only about an address
   * no agent holds and none ever retired, so an extension never decides, or sends a code, for one it
   * cannot have.
   */
  address: string;
  key: string;
  /** The whole register body, for members of the extension's own, such as a code or a proof. */
  body: Record<string, Json>;
}

/**
 * Whether a key may take a new address on a hosted domain or the lease domain, whose names are this
 * server's to give: `allow` or `refuse` ends the chain, `undefined` has no opinion. When no extension
 * decides, the key takes it, first come, first served. A refusal is `409 address_taken`, the answer a held
 * name gets; a thrown WireError is answered as itself. The hook only decides: it is asked on every call
 * that would create the address, each round trip of a pairing included, and an `allow` may still end in
 * no address (a pairing that fails, another key first), so it uses nothing up.
 */
export type AddressDecision = 'allow' | 'refuse' | undefined;

/** A registration naming a principal of a kind the core does not verify. */
export interface PrincipalRequest extends AddressRequest {
  principal: string;
}

/**
 * `verified`: pair the agent with the principal. `pending`: answer 202 with `body` and wait for another
 * call. `undefined`: not this extension's kind of principal. A refusal throws a WireError.
 */
export type PrincipalAnswer = { status: 'verified' } | { status: 'pending'; body: Record<string, Json> } | undefined;

/** Bytes an agent here uploaded, before they are kept. */
export interface Upload {
  address: string;
  sha256: string;
  bytes: Buffer;
}

/**
 * A reader asking for a published message whose `audience` header is `audience` (spec section 7.1). `reader`
 * is the address that signed the request with a key of its own agent document, or null when nobody in
 * particular asks.
 */
export interface ReaderRequest {
  message: AnyMessage;
  audience: string;
  reader: string | null;
}

/** `admit` or `refuse` ends the chain; `undefined` has no opinion. With no decision, only the author reads it. */
export type ReaderDecision = 'admit' | 'refuse' | undefined;

export interface Events {
  /**
   * A message was kept: sent by an agent here, or accepted from another server and taken or held by a
   * recipient here. A message nobody here took is never kept, and never reported.
   */
  stored: { message: StoredMessage };
  /**
   * A message entered an agent's inbox. Told at least once: the event is written with the entry and told
   * afterwards, so a crash between the two repeats it rather than losing it. A listener dedupes by
   * (address, message id) if it must.
   */
  inbox: { address: string; message: StoredMessage };
  /** A server answered 202 for these recipients (this server, for its own agents). */
  delivered: { id: string; server: string; recipients: string[] };
  /** Delivery to these recipients ended without a 202; `reason` is a resolution outcome or an error code. */
  deliveryFailed: { id: string; server: string | null; recipients: string[]; reason: string };
  /**
   * These recipients' domain names no SIMON server (`not_found`). A bridge may reach them another way: a
   * listener that answers `true` took them, and their delivery counts as delivered rather than failed.
   */
  unroutable: { id: string; domain: string; recipients: string[]; message: AnyMessage };
  /**
   * An agent's keys were replaced by `key`: `by` its address's mailbox, a code sent there, so whoever holds
   * the mailbox now holds the agent; or `by` its key principal, the agent's root of trust.
   */
  recovered: { address: string; key: string; by: 'mailbox' | 'principal' };
  /**
   * A signal passed for an agent here, about a message it holds, from a party to that message (spec section
   * 6.4; this server's policy). Nothing keeps it: a listener shows it now or never.
   */
  signal: { recipient: string; signal: Signal };
}

/** What a listener answers: only an `unroutable` listener may answer, `true` when it took the recipients. */
type Answer<E extends keyof Events> = E extends 'unroutable' ? boolean | void : void;

export type Listeners = {
  [E in keyof Events]?: (event: Events[E], api: ServerApi) => Answer<E> | Promise<Answer<E>>;
};

export interface Extension {
  name: string;
  routes?: Route<ServerApi>[];
  admit?(arrival: Arrival, api: ServerApi): Decision | Promise<Decision>;
  claimsFor?(message: AnyMessage, agent: Agent, api: ServerApi): Claim[] | Promise<Claim[]>;
  allowAddress?(request: AddressRequest, api: ServerApi): AddressDecision | Promise<AddressDecision>;
  verifyPrincipal?(request: PrincipalRequest, api: ServerApi): PrincipalAnswer | Promise<PrincipalAnswer>;
  /** Refuse an upload by throwing a WireError; return to let it be kept. */
  upload?(upload: Upload, api: ServerApi): void | Promise<void>;
  admitsReader?(request: ReaderRequest, api: ServerApi): ReaderDecision | Promise<ReaderDecision>;
  on?: Listeners;
}

/** All extensions' hooks, run as one. */
export class Hooks {
  readonly #extensions: Extension[];
  readonly #api: () => ServerApi;

  constructor(extensions: Extension[], api: () => ServerApi) {
    this.#extensions = extensions;
    this.#api = api;
  }

  get routes(): Route<ServerApi>[] {
    return this.#extensions.flatMap(e => e.routes ?? []);
  }

  /** The first decision in the chain, or `accept` when none decides. */
  async admit(arrival: Arrival): Promise<'accept' | 'refuse' | 'later'> {
    for (const e of this.#extensions) {
      const decision = await e.admit?.(arrival, this.#api());
      if (decision !== undefined) return decision;
    }
    return 'accept';
  }

  async claimsFor(message: AnyMessage, agent: Agent): Promise<Claim[]> {
    const all = await Promise.all(this.#extensions.map(e => e.claimsFor?.(message, agent, this.#api()) ?? []));
    return all.flat();
  }

  /** The first decision on a new hosted or leased address, or `allow` when none decides. */
  async allowAddress(request: AddressRequest): Promise<'allow' | 'refuse'> {
    for (const e of this.#extensions) {
      const decision = await e.allowAddress?.(request, this.#api());
      if (decision !== undefined) return decision;
    }
    return 'allow';
  }

  /** The first extension's answer for this principal, or undefined when none verifies its kind. */
  async verifyPrincipal(request: PrincipalRequest): Promise<PrincipalAnswer> {
    for (const e of this.#extensions) {
      const answer = await e.verifyPrincipal?.(request, this.#api());
      if (answer !== undefined) return answer;
    }
    return undefined;
  }

  /** The first decision on a reader of a message with an audience, or `refuse` when none decides. */
  async admitsReader(request: ReaderRequest): Promise<'admit' | 'refuse'> {
    for (const e of this.#extensions) {
      const decision = await e.admitsReader?.(request, this.#api());
      if (decision !== undefined) return decision;
    }
    return 'refuse';
  }

  /** Every extension's check of an upload, in order; the first refusal throws. */
  async upload(upload: Upload): Promise<void> {
    for (const e of this.#extensions) await e.upload?.(upload, this.#api());
  }

  /**
   * Tell every listener, in order. A listener that fails is logged; it never fails the core's work. For
   * `unroutable`, the first listener that answers `true` takes the recipients, and the rest are not told.
   * Answers whether one did.
   */
  async emit<E extends keyof Events>(event: E, payload: Events[E]): Promise<boolean> {
    for (const e of this.#extensions) {
      const listener = e.on?.[event] as ((p: Events[E], api: ServerApi) => unknown) | undefined;
      try {
        if ((await listener?.(payload, this.#api())) === true && event === 'unroutable') return true;
      } catch (err) {
        this.#api().log('error', `extension ${e.name} failed on ${event}`, { error: String(err) });
      }
    }
    return false;
  }
}
