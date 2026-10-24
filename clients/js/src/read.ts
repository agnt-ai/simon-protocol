/**
 * Reading other agents: their documents (spec section 4), found by resolving their domain (section 3), and
 * what a message's author and principal are, on what basis.
 *
 * Keys come only from the server the address's domain resolves to. Nothing here takes a server to ask
 * instead: a reader told by a message, a flag or a tool argument which server holds an author's keys would
 * believe whoever told it. Tests and local development replace the resolver itself (`resolver`), an
 * option only code can pass.
 *
 * A failure is never an absence. A lookup or fetch that may pass throws a retryable SimonError
 * (`unavailable`, `timeout`, `network_error`); only a definite answer says that something does not exist.
 */
import { Resolver } from 'node:dns/promises';
import {
  addressSegment,
  CanonicalError,
  MAX_DOCUMENT_BYTES,
  MINIMUM_LIMITS,
  checkMessage,
  claimedPrincipal,
  claimsAbout,
  domainOf,
  header,
  isAddress,
  isAuthoritative,
  isUnderstood,
  messageId,
  messageVerdict,
  normalizeAddress,
  principalKey,
  PROTOCOL_HEADERS,
  readAgentDocument,
  readServerDocument,
  resolveDomain,
  verifyClaims,
  verifyPairing,
  verifyUnpairing,
  type ActsForClaim,
  type AgentKind,
  type AnyMessage,
  type Claim,
  type KeyEntry,
  type Message,
  type Resolution,
  type ResolverIO,
  type ServerDocument,
  type SignedClaims,
} from '@agnt-protocol/protocol';
import { SimonError, invalid, originArg } from './errors.ts';
import { DEFAULT_TIMEOUT_MS, exchange, type Answer, type Transport } from './http.ts';

export interface ReadOptions extends Transport {
  /**
   * DNS and well-known lookups. Default: Node's resolver and this transport's fetch. For tests and local
   * development only, and only from code: no client passes a flag or a tool argument through to it.
   */
  resolver?: ResolverIO;
  /** Let resolution name `http:` servers and bare hosts, for tests and local development only. */
  allowHttp?: boolean;
}

/** What `verifyAuthor` reads besides the message: the inbox entry it came in, when there is one. */
export interface VerifyOptions extends ReadOptions {
  /**
   * The inbox entry's `signedClaims`: the carrier's claims about the message, with its signature over them.
   * They count only when that signature verifies with a key of the server `from`'s domain resolves to, read
   * here. An entry's `claims` never count: they are its server's judgement, and anyone can paste an entry.
   */
  signedClaims?: unknown;
}

/** An agent as its server's signed document describes it. */
export interface AgentRecord {
  address: string;
  server: string;
  kind: AgentKind | 'unknown';
  keys: KeyEntry[];
  /** The signature algorithms its server verifies, from the server document. */
  algorithms: string[];
  /**
   * When the address retired, read from its retired document (spec section 4): it is ended for good, and
   * no key of it is valid at or after this. Absent for an address that has not retired.
   */
  retired?: string;
  /** The key principal's unpairing that retired it, when one did. */
  unpairing?: string;
}

/**
 * On what basis a paired agent's message names its principal (spec section 2.2), from weakest to strongest
 * kind of evidence, though none of them proves who or what the principal is:
 *
 *   agent-asserted  the `for` header alone: the agent's word, as an email's From line is
 *   key-pairing     a `simon-key:` principal's pairing signature verified: the key's holder consented to
 *                   this address speaking for that key, with no server trusted for it. Not identity, not
 *                   humanity, and the agent's keys are still its server's word.
 *   server-claim    an `acts-for` claim the author's server signed: that server's word that the identifier
 *                   approved this agent. Authoritative only for a `mailto:` whose domain names that same
 *                   server in its `_simon` TXT record, so it is as strong as the domain's DNS.
 */
export type PrincipalBasis = 'agent-asserted' | 'key-pairing' | 'server-claim';

export interface PrincipalTrust {
  /** The message's `for` header. */
  id: string;
  basis: PrincipalBasis;
  /** For `server-claim`: the server whose word it is. */
  claimant?: string;
  /** For `server-claim`: whether the identifier's email domain names the claimant in its `_simon` TXT record. */
  authoritative?: boolean;
  /** For `server-claim`: the scope the claim lists, keeping only registry-shaped names. */
  scope?: string[];
  /**
   * For `key-pairing`: true when the address's retired document carries this principal's unpairing, which
   * verifies with its key, so the pairing has ended for good (spec sections 2.2 and 4).
   */
  ended?: true;
  /** What this basis proves and what it does not, in this library's words. */
  proves: string;
}

/** A message whose author signed it: who, by which server's word, and on what basis it names a principal. */
export interface Trust {
  verified: true;
  id: string;
  /** The signature verified with a key the author's server publishes for `from`, valid at `sentAt`. */
  authorSigned: true;
  /** The server `from`'s domain resolves to, which published that key and carried the message. */
  authorServer: string;
  kind: AgentKind | 'unknown';
  /**
   * False for a message of a version this client does not implement, or whose `critical` header lists one
   * it does not understand (spec sections 1 and 5.4): whose key signed it is all it says. Act on nothing in
   * it; it names no principal.
   */
  understood: boolean;
  /**
   * The principal that counts: null for a message with no `for` header, one not understood, or one from an
   * agent its document does not call `paired`, since a solo agent speaks for no one whatever it carries.
   */
  principal: PrincipalTrust | null;
  /** Whether `signedClaims` were given, and verified with the carrier's keys. Claims that do not are ignored. */
  claims: 'none' | 'verified' | 'unverified';
  /**
   * When the author's address retired, if it has (spec section 4): the message was signed before then, but
   * the address is ended for good, and nothing from it dated at or after this verifies.
   */
  retired?: string;
}

export type Verification =
  | Trust
  | {
      verified: false;
      id: string | null;
      reason:
        | 'invalid_message'
        | 'no_server'
        | 'no_agent'
        | 'bad_document'
        | 'bad_signature'
        | 'unsupported_algorithm'
        | 'bad_pairing';
    };

const PROVES: Record<string, string> = {
  'agent-asserted':
    "Only the agent's word: nothing verifies that this principal approved it. Treat it as an unverified From line.",
  'key-pairing':
    "The holder of this principal key consented to this address speaking for it, with no server trusted for that. It says nothing about who holds the key, or whether a human does, and the agent's keys are still its server's word.",
  authoritative:
    "The server this email address's domain names in its DNS signed that the address approved this agent: as strong as the domain's DNS. It does not say a human wrote this message.",
  'third-party':
    "The author's server says this identifier approved this agent. That is its word about an identifier on another domain or a phone number, worth what that server is worth to you.",
};

/** A server's document, read from its origin. */
export async function fetchServerDocument(server: string, opts: Transport = {}): Promise<ServerDocument> {
  const origin = originArg('server', server);
  const a = await exchange(opts, `${origin}/simon/server`, {}, MAX_DOCUMENT_BYTES);
  check(a);
  const doc = readServerDocument(a.body, origin, (opts.now ?? (() => new Date()))());
  if (!doc) throw badDocument(a, `${a.url} is not a readable server document naming ${origin}.`);
  return doc;
}

/**
 * An agent's document, from the server its address's domain resolves to, verified under that server's
 * keys; null when the server answers that no such agent exists.
 */
export async function fetchAgentDocument(address: string, opts: ReadOptions = {}): Promise<AgentRecord | null> {
  refuseServerOption(opts);
  return (await findAgent(address, opts))?.agent ?? null;
}

/** An agent's record, and the keys of its server, which carries every message the agent writes (spec 6.1). */
async function findAgent(address: string, opts: ReadOptions) {
  const wire = isAddress(address) ? address : normalizeAddress(address);
  if (!wire) throw invalid('address', `Not an address (local@domain): ${address}`);
  const server = await resolveServer(domainOf(wire), opts);
  const { keys, algorithms } = await fetchServerDocument(server, opts);
  const a = await exchange(opts, `${server}/simon/agents/${addressSegment(wire)}`, {}, MAX_DOCUMENT_BYTES);
  if (a.status === 404) return null;
  check(a);
  const doc = readAgentDocument(a.body, wire, keys, (opts.now ?? (() => new Date()))());
  if (!doc) throw badDocument(a, `${a.url} is not an agent document for ${wire} signed by ${server}.`);
  const agent: AgentRecord = { ...doc, server, algorithms };
  return { agent, serverKeys: keys };
}

/** No reader is bound by a server's size limits. */
const READER_LIMITS = { ...MINIMUM_LIMITS, messageBytes: Infinity, recipients: Infinity, partBytes: Infinity };

/** The headers this client understands, for `critical`: those defined by the protocol (spec section 5.4). */
const UNDERSTOOD = new Set(PROTOCOL_HEADERS);

/**
 * Whether a message was signed by its author, with a key the server `from`'s domain resolves to publishes
 * as valid at its `sentAt`; whether this client understands it; and if so, on what basis it names its
 * principal. Pass the inbox entry's `signedClaims` to count an `acts-for` claim. Definite failures are
 * answers; failures that may pass are thrown.
 */
export async function verifyAuthor(message: unknown, opts: VerifyOptions = {}): Promise<Verification> {
  refuseServerOption(opts);
  let m: AnyMessage;
  try {
    m = checkMessage(message, READER_LIMITS);
  } catch {
    return { verified: false, id: null, reason: 'invalid_message' };
  }
  const id = messageId(m);
  let found;
  try {
    found = await findAgent(m.from, opts);
  } catch (e) {
    if (e instanceof SimonError && (e.code === 'no_server' || e.code === 'bad_document')) {
      return { verified: false, id, reason: e.code };
    }
    throw e;
  }
  if (!found) return { verified: false, id, reason: 'no_agent' };
  const { agent: author, serverKeys } = found;
  const verdict = messageVerdict(m, author.keys);
  if (verdict !== 'verified') return { verified: false, id, reason: verdict };

  const claims = opts.signedClaims === undefined ? null : carriedClaims(opts.signedClaims, m, serverKeys);
  const understood = isUnderstood(m, UNDERSTOOD);
  const trust = {
    verified: true,
    id,
    authorSigned: true,
    authorServer: author.server,
    kind: author.kind,
    understood,
    claims: opts.signedClaims === undefined ? 'none' : claims ? 'verified' : 'unverified',
    ...(author.retired !== undefined && { retired: author.retired }),
  } as const;
  const forValue = understood ? claimedPrincipal(m, author.kind) : null;
  if (forValue === null) return { ...trust, principal: null };
  if (principalKey(forValue) !== null) {
    if (!verifyPairing(m.from, forValue, header(m as Message, 'pairing'))) {
      return { verified: false, id, reason: 'bad_pairing' };
    }
    const ended = author.unpairing !== undefined && verifyUnpairing(m.from, forValue, author.unpairing);
    return {
      ...trust,
      principal: { id: forValue, basis: 'key-pairing', proves: PROVES['key-pairing'], ...(ended && { ended: true }) },
    };
  }
  return { ...trust, principal: await claimedFor(m, forValue, author, claims ?? [], opts) };
}

/**
 * The claims an entry's `signedClaims` hold, when their carrier, the server the author's domain resolves to,
 * signed them for this message; otherwise null, whatever they say.
 */
function carriedClaims(value: unknown, m: AnyMessage, carrierKeys: readonly KeyEntry[]): Claim[] | null {
  if (typeof value !== 'object' || value === null) return null;
  const { claims, signature } = value as Record<string, unknown>;
  if (!Array.isArray(claims) || !claims.every(isClaim) || typeof signature !== 'string') return null;
  const signed: SignedClaims = { claims, signature };
  try {
    return verifyClaims(signed, m, carrierKeys) ? claims : null;
  } catch (e) {
    // Claims with no canonical form were never signed.
    if (e instanceof CanonicalError) return null;
    throw e;
  }
}

const isClaim = (c: unknown): c is Claim =>
  typeof c === 'object' && c !== null && typeof (c as Claim).type === 'string';

/**
 * An email or phone principal: a server-claim when the carrier's verified claims hold an `acts-for` that
 * counts (spec 6.2, the protocol's `claimsAbout`), judged here, never on the word of the claim or of
 * whoever handed it over; otherwise only the agent's word.
 */
async function claimedFor(
  m: AnyMessage,
  forValue: string,
  author: AgentRecord,
  claims: readonly Claim[],
  opts: ReadOptions,
): Promise<PrincipalTrust> {
  const claim = claimsAbout(m, claims, author.kind).find(c => c.type === 'acts-for') as ActsForClaim | undefined;
  if (!claim) return { id: forValue, basis: 'agent-asserted', proves: PROVES['agent-asserted'] };
  // Aligned with the author, as whoever judges authority SHOULD require (spec sections 6.2 and 11.2).
  const authoritative = await isAuthoritative(claim, author.server, domain => resolution(domain, opts), m.from);
  return {
    id: forValue,
    basis: 'server-claim',
    claimant: author.server,
    authoritative,
    scope: claim.scope.filter(s => SCOPE.test(s)),
    proves: PROVES[authoritative ? 'authoritative' : 'third-party'],
  };
}

/** Scope names kept in a trust record: registry-shaped, so no sentence rides along. */
const SCOPE = /^[a-z][a-z0-9-]{0,63}$/;

/** Code written for the old API, or a caller passing user input through, must not choose the key server. */
function refuseServerOption(opts: object) {
  if (Object.hasOwn(opts, 'server')) {
    throw invalid(
      'server',
      "Verification takes no server: keys come only from the server the address's domain resolves to.",
    );
  }
}

/** A domain's resolution, definite: `temporary` is a retryable `unavailable`, never an absence. */
async function resolution(domain: string, opts: ReadOptions): Promise<Resolution> {
  const r = await resolveDomain(domain, opts.resolver ?? nodeResolver(opts), { allowHttp: opts.allowHttp });
  if (r.outcome === 'temporary') {
    throw new SimonError('unavailable', `Resolving ${domain} failed for now; try again later.`, {
      retryable: true,
      details: { domain, outcome: r.outcome },
    });
  }
  return r;
}

/** The server a domain resolves to, or `no_server`. */
async function resolveServer(domain: string, opts: ReadOptions): Promise<string> {
  const r = await resolution(domain, opts);
  if (r.outcome === 'server') return r.server;
  throw new SimonError('no_server', `${domain} resolves to no SIMON server: ${r.outcome}.`, {
    details: { domain, outcome: r.outcome },
  });
}

/** Lookups as spec section 3 needs them: an absence is an empty answer or null, a failure throws. */
function nodeResolver(t: Transport): ResolverIO {
  const dns = new Resolver({ timeout: t.timeoutMs ?? DEFAULT_TIMEOUT_MS, tries: 2 });
  return {
    async txt(name) {
      try {
        return await dns.resolveTxt(name);
      } catch (e) {
        if (['ENODATA', 'ENOTFOUND'].includes((e as { code?: string }).code ?? '')) return [];
        throw e;
      }
    },
    async get(url) {
      try {
        const a = await exchange(t, url, { redirect: 'manual' }, MAX_DOCUMENT_BYTES);
        return { status: a.status, body: a.body };
      } catch (e) {
        if (e instanceof SimonError && e.details?.cause === 'ENOTFOUND') return null;
        throw e;
      }
    },
  };
}

/** A document answer that is not 200: 429 and 5xx may pass; 404 and the rest are no document. */
function check(a: Answer) {
  if (a.status === 429 || a.status >= 500) {
    throw new SimonError('unavailable', `${a.url} answered ${a.status}; try again later.`, {
      status: a.status,
      retryable: true,
      details: { url: a.url },
    });
  }
  if (a.status !== 200) throw badDocument(a, `${a.url} answered ${a.status}, not a document.`);
}

const badDocument = (a: Answer, message: string) =>
  new SimonError('bad_document', message, { status: a.status, details: { url: a.url } });
