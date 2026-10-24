/**
 * A typed client for this application's API (`/api/`), beside the protocol's own client for `/simon/`.
 *
 *   AppAgent   an agent's calls, each signed with its key through @agnt-protocol/client's Agent
 *   AppOwner   a person's owner-window calls, with an owner access token or API key
 *   pair       pairing a new agent with an email or phone principal: a code, then the code back
 *
 * Every failure is a SimonError with the server's code, status and details. Types come from the routes'
 * own schemas, so the client cannot drift from the server. A principal-reserved call by a paired agent
 * answers `Awaiting` until its person decides in the owner window (`AppOwner.decide`).
 *
 *   const ada = new AppAgent(agent);
 *   await ada.updateMe({ name: 'Ada' });
 *   const { found, agents } = await ada.resolve('mailto:bob@example.com');
 */
import { parseProblem } from '@agnt-protocol/protocol';
import { Agent, SimonError, type Fetch, type Registration } from '@agnt-protocol/client';
import type { z } from 'zod';
import type { Page } from './store/db.ts';
import type { Self } from './modules/agents/index.ts';
import type { Pair, AgentCard, Connection, Edge, Entity, Listing, Profile } from './modules/directory/schemas.ts';
import type { Reach, Resolved, SearchQuery, SearchResults } from './modules/directory/routes/discovery.ts';
import type { AttestationInput } from './modules/directory/profiles.ts';
import type { EdgeInput } from './modules/directory/graph.ts';
import type { ParticipantIntro, RequesterIntro } from './modules/intros/routes.ts';
import type { ActivityEvent } from './modules/owner/activity.ts';
import type { Awaiting as AwaitingSchema, RequestView } from './modules/owner/requests.ts';
import type { AttestationView, Me, MessageItem } from './modules/owner/routes/me.ts';
import type { EntryView, HeldView, Settings } from './modules/policy/routes.ts';
import type { Webhook } from './modules/webhooks/index.ts';

type Out<T extends z.ZodType> = z.output<T>;

/** A principal-reserved call held for the agent's person. */
export type Awaiting = Out<typeof AwaitingSchema>;
/** What a principal-reserved call answers: its answer, or for a paired agent, the request held. */
export type Reserved<T> = T | Awaiting;
export type PrincipalRequest = Out<typeof RequestView>;

export const isAwaiting = (answer: unknown): answer is Awaiting =>
  (answer as Awaiting | null)?.status === 'awaiting_principal';

type List = 'allow' | 'block';
type EntryKind = 'address' | 'domain' | 'server';
type PageArgs = { after?: string; limit?: number };

const query = (q: Record<string, string | number | undefined>) => {
  const s = new URLSearchParams(
    Object.entries(q).flatMap(([k, v]) => (v === undefined ? [] : [[k, String(v)]])),
  ).toString();
  return s ? `?${s}` : '';
};
const seg = encodeURIComponent;

/** The answers of `pair`: a code was sent; or the agent is registered, paired. */
export type Pairing = { status: 'pairing_code_sent'; address: string; for: string; sentTo: string } | Registration;

/**
 * One `register` call pairing an agent with a `mailto:` or `tel:` principal. Without `pairingCode`, a code
 * is sent to the principal; with it, the agent is registered and paired (and with `address`, at that name;
 * `code` is the address's own code, when its name is bound by one). Once active, make the Agent again with
 * its `address` and `for`, so its messages carry them.
 */
export function pair(
  agent: Agent,
  body: { for: string; address?: string; code?: string; pairingCode?: string; scope?: string[] },
): Promise<Pairing> {
  const { pairingCode, scope, ...registration } = body;
  return agent.call('POST', '/simon/register', {
    key: agent.key,
    ...registration,
    ...(pairingCode === undefined ? {} : { 'agnt.ai:pairingCode': pairingCode }),
    ...(scope === undefined ? {} : { 'agnt.ai:scope': scope }),
  });
}

export class AppAgent {
  readonly agent: Agent;

  constructor(agent: Agent) {
    this.agent = agent;
  }

  #call<T>(method: string, path: string, body?: unknown): Promise<T> {
    return this.agent.call<T>(method, path, body);
  }

  // The agent itself
  me = () => this.#call<Out<typeof Self>>('GET', '/api/agents/me');
  updateMe = (patch: {
    name?: string;
    description?: string;
    capabilities?: Partial<Out<typeof Self>['capabilities']>;
  }) => this.#call<Out<typeof Self>>('PATCH', '/api/agents/me', patch);
  publishCard = (listed: boolean) => this.#call<Reserved<Out<typeof Self>>>('PUT', '/api/agents/me/listed', { listed });
  end = () => this.#call<Reserved<null>>('DELETE', '/api/agents/me');
  request = (id: string) => this.#call<PrincipalRequest>('GET', `/api/agents/me/requests/${seg(id)}`);
  home = () => this.#call<Home>('GET', '/api/agents/me/home');
  ack = (cursor: number) => this.#call<{ readCursor: number }>('POST', '/api/agents/me/inbox/ack', { cursor });
  card = (address: string) => this.#call<Out<typeof AgentCard>>('GET', `/api/agents/${seg(address)}`);

  // Policy
  policy = () => this.#call<Out<typeof Settings>>('GET', '/api/agents/me/policy');
  setPolicy = (patch: Partial<Out<typeof Settings>>) =>
    this.#call<Reserved<Out<typeof Settings>>>('PATCH', '/api/agents/me/policy', patch);
  contacts = (list: List, page: PageArgs = {}) =>
    this.#call<Page<Out<typeof EntryView>>>('GET', `/api/agents/me/contacts/${list}${query(page)}`);
  addContacts = (list: List, entries: { kind: EntryKind; value: string }[]) =>
    this.#call<Reserved<{ added: number }>>('POST', `/api/agents/me/contacts/${list}`, { entries });
  removeContact = (list: List, kind: EntryKind, value: string) =>
    this.#call<Reserved<null>>('DELETE', `/api/agents/me/contacts/${list}/${seg(`${kind}:${value}`)}`);
  invite = (ttlHours?: number) =>
    this.#call<Reserved<{ code: string; address: string; expiresAt: string }>>('POST', '/api/agents/me/invites', {
      ttlHours,
    });
  held = (page: PageArgs = {}) => this.#call<Page<Out<typeof HeldView>>>('GET', `/api/agents/me/held${query(page)}`);

  // Webhooks
  webhooks = (page: PageArgs = {}) =>
    this.#call<Page<Out<typeof Webhook>>>('GET', `/api/agents/me/webhooks${query(page)}`);
  createWebhook = (url: string) =>
    this.#call<Reserved<Out<typeof Webhook> & { secret: string }>>('POST', '/api/agents/me/webhooks', { url });
  deleteWebhook = (id: string) => this.#call<Reserved<null>>('DELETE', `/api/agents/me/webhooks/${seg(id)}`);
  reactivateWebhook = (id: string) =>
    this.#call<Reserved<Out<typeof Webhook>>>('POST', `/api/agents/me/webhooks/${seg(id)}/reactivate`);

  // Directory
  listing = () => this.#call<Out<typeof Listing>>('GET', '/api/listing');
  updateListing = (patch: Partial<Omit<Out<typeof Listing>, 'listedAt'>>) =>
    this.#call<Reserved<Out<typeof Listing>>>('PATCH', '/api/listing', patch);
  resolve = (identifier: string) => this.#call<Out<typeof Resolved>>('POST', '/api/resolve', { identifier });
  search = (q: z.input<typeof SearchQuery>) => this.#call<Out<typeof SearchResults>>('POST', '/api/search', q);
  reach = (identifier: string) => this.#call<Out<typeof Reach>>('POST', '/api/reach', { identifier });
  profile = (person: string) => this.#call<Out<typeof Profile>>('GET', `/api/profiles/${seg(person)}`);
  attest = (subject: { person: string } | { identifier: string }, attestations: AttestationInput[]) =>
    this.#call<Reserved<{ attestations: { id: string; subject: string; field: string; provenance: string }[] }>>(
      'POST',
      '/api/profiles/attestations',
      { subject, attestations },
    );
  retract = (id: string) => this.#call<Reserved<null>>('DELETE', `/api/profiles/attestations/${seg(id)}`);
  dispose = (id: string, disposition: 'confirmed' | 'hidden' | 'disputed') =>
    this.#call<Reserved<{ id: string; disposition: string }>>('PATCH', `/api/profiles/attestations/${seg(id)}`, {
      disposition,
    });
  resolveEntity = (q: { domain?: string; name?: string; kind?: Out<typeof Entity>['kind'] }) =>
    this.#call<Out<typeof Entity>>('POST', '/api/entities/resolve', q);
  entity = (id: string) => this.#call<Out<typeof Entity>>('GET', `/api/entities/${seg(id)}`);
  startEntityClaim = (id: string, domain: string) =>
    this.#call<{ record: string; type: 'TXT'; value: string }>('POST', `/api/entities/${seg(id)}/claim`, { domain });
  completeEntityClaim = (id: string) =>
    this.#call<Out<typeof Entity>>('POST', `/api/entities/${seg(id)}/claim/complete`);
  renameEntity = (id: string, patch: { name?: string; aliases?: string[] }) =>
    this.#call<Out<typeof Entity>>('PATCH', `/api/entities/${seg(id)}`, patch);
  attestRoster = (id: string, members: { identifier: string; title?: string | null }[]) =>
    this.#call<Reserved<{ attested: number }>>('POST', `/api/entities/${seg(id)}/roster`, { members });
  submitEdges = (edges: EdgeInput[]) =>
    this.#call<
      Reserved<{
        results: { id: string | null; identifier: string; strength: number; status: 'stored' | 'skipped_self' }[];
      }>
    >('PUT', '/api/edges', { edges });
  deleteEdge = (id: string) => this.#call<Reserved<null>>('DELETE', `/api/edges/${seg(id)}`);
  graph = (q: { company?: string[]; text?: string; minStrength?: number; limit?: number } = {}) =>
    this.#call<{ connections: Out<typeof Connection>[] }>('POST', '/api/graph', q);

  // Introductions
  requestIntro = (r: { target: string; brief: string; subject?: string; presentAs?: string }) =>
    this.#call<Out<typeof RequesterIntro>>('POST', '/api/intros', r);
  intros = (page: PageArgs = {}) => this.#call<Page<Out<typeof RequesterIntro>>>('GET', `/api/intros${query(page)}`);
  intro = (id: string) =>
    this.#call<Out<typeof RequesterIntro> | Out<typeof ParticipantIntro>>('GET', `/api/intros/${seg(id)}`);
  carry = (id: string, decision: 'carry' | 'decline') =>
    this.#call<Reserved<{ id: string; state: string }>>('POST', `/api/intros/${seg(id)}/carry`, { decision });
  respond = (id: string, decision: 'accept' | 'decline') =>
    this.#call<Reserved<{ id: string; state: string; introducedTo?: string }>>(
      'POST',
      `/api/intros/${seg(id)}/respond`,
      { decision },
    );
}

/** The check-in: the agent, its unread messages, what needs attention, and each module's own section. */
export interface Home {
  agent: Out<typeof Self>;
  unread: {
    messages: {
      cursor: number;
      id: string;
      message: unknown;
      carrier: string;
      claims: unknown[];
      receivedAt: string;
    }[];
    more: boolean;
    readCursor: number;
  };
  attention: { kind: string; message: string }[];
  nextCheckInSeconds: number;
  serverTime: string;
  pair?: Out<typeof Pair> | null;
  suggestions?: { person: string; name: string | null; grade: string }[];
  introsToAnswer?: Out<typeof ParticipantIntro>[];
  introsMade?: Out<typeof RequesterIntro>[];
  requestsWaiting?: number;
}

export interface OwnerOptions {
  /** The application's origin. */
  server: string;
  /** An owner access token or API key. */
  token: string;
  fetch?: Fetch;
}

export class AppOwner {
  readonly #server: string;
  readonly #token: string;
  readonly #fetch: Fetch;

  constructor(opts: OwnerOptions) {
    this.#server = opts.server;
    this.#token = opts.token;
    this.#fetch = opts.fetch ?? ((url, init) => fetch(url, init));
  }

  async #call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {
      authorization: `Bearer ${this.#token}`,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    };
    const res = await this.#fetch(`${this.#server}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (res.ok) return (text ? JSON.parse(text) : null) as T;
    const problem = parseProblem(res.status, text);
    throw new SimonError(problem?.code ?? 'bad_response', problem?.detail || `${path} answered ${res.status}.`, {
      status: res.status,
      retryable: problem?.retryable ?? false,
      details: problem?.details,
    });
  }

  me = () => this.#call<Out<typeof Me>>('GET', '/api/me');
  /** Erase the person: every identifier must have been proven in this session. */
  erase = () => this.#call<null>('DELETE', '/api/me');
  addIdentifier = (identifier: string) => this.#call<{ sentTo: string }>('POST', '/api/me/identifiers', { identifier });
  verifyIdentifier = (identifier: string, code: string) =>
    this.#call<Out<typeof Me>>('POST', '/api/me/identifiers/verify', { identifier, code });
  mergeIdentifier = (identifier: string) =>
    this.#call<Out<typeof Me>>('POST', '/api/me/identifiers/merge', { identifier });
  requests = (page: PageArgs = {}) => this.#call<Page<PrincipalRequest>>('GET', `/api/me/requests${query(page)}`);
  decide = (id: string, decision: 'approve' | 'decline') =>
    this.#call<PrincipalRequest>('POST', `/api/me/requests/${seg(id)}`, { decision });
  consulted = (messageId: string) => this.#call<null>('POST', `/api/me/messages/${seg(messageId)}/consulted`);
  agents = (page: PageArgs = {}) =>
    this.#call<Page<{ pair: Out<typeof Pair>; agent: Out<typeof AgentCard> }>>('GET', `/api/me/agents${query(page)}`);
  confirmAgent = (address: string) => this.#call<Out<typeof Pair>>('POST', `/api/me/agents/${seg(address)}/confirm`);
  endAgent = (address: string) => this.#call<null>('DELETE', `/api/me/agents/${seg(address)}`);
  profile = (person: string) => this.#call<Out<typeof Profile>>('GET', `/api/me/profiles/${seg(person)}`);
  activity = (page: PageArgs = {}) =>
    this.#call<Page<Out<typeof ActivityEvent>>>('GET', `/api/me/activity${query(page)}`);
  messages = (page: PageArgs = {}) =>
    this.#call<Page<Out<typeof MessageItem>>>('GET', `/api/me/messages${query(page)}`);
  listing = () => this.#call<Out<typeof Listing>>('GET', '/api/me/listing');
  updateListing = (patch: Partial<Omit<Out<typeof Listing>, 'listedAt'>>) =>
    this.#call<Out<typeof Listing>>('PATCH', '/api/me/listing', patch);
  edges = (page: PageArgs = {}) => this.#call<Page<Out<typeof Edge>>>('GET', `/api/me/edges${query(page)}`);
  updateEdge = (id: string, patch: { hidden?: boolean; introduceOk?: boolean }) =>
    this.#call<Out<typeof Edge>>('PATCH', `/api/me/edges/${seg(id)}`, patch);
  deleteEdge = (id: string) => this.#call<null>('DELETE', `/api/me/edges/${seg(id)}`);
  clearEdges = (q: { writtenBy?: string; before?: string }) =>
    this.#call<{ removed: number }>('DELETE', `/api/me/edges${query(q)}`);
  attestations = (which: 'about' | 'by' = 'about', page: PageArgs = {}) =>
    this.#call<Page<Out<typeof AttestationView>>>('GET', `/api/me/attestations${query({ which, ...page })}`);
  dispose = (id: string, disposition: 'confirmed' | 'hidden' | 'disputed') =>
    this.#call<{ id: string; disposition: string }>('PATCH', `/api/me/attestations/${seg(id)}`, { disposition });
  held = (page: PageArgs = {}) => this.#call<Page<Out<typeof HeldView>>>('GET', `/api/me/held${query(page)}`);
  blocks = (page: PageArgs = {}) => this.#call<Page<Out<typeof EntryView>>>('GET', `/api/me/blocks${query(page)}`);
  block = (entries: { kind: EntryKind; value: string }[]) =>
    this.#call<{ added: number }>('POST', '/api/me/blocks', { entries });
  unblock = (kind: EntryKind, value: string) => this.#call<null>('DELETE', `/api/me/blocks/${seg(`${kind}:${value}`)}`);
  intros = (page: PageArgs = {}) => this.#call<Page<unknown>>('GET', `/api/me/intros${query(page)}`);
  apiKeys = (page: PageArgs = {}) =>
    this.#call<Page<{ id: string; label: string | null; createdAt: string }>>('GET', `/api/me/api-keys${query(page)}`);
  createApiKey = (label?: string) =>
    this.#call<{ id: string; key: string; label: string | null; createdAt: string }>('POST', '/api/me/api-keys', {
      label,
    });
  revokeApiKey = (id: string) => this.#call<null>('DELETE', `/api/me/api-keys/${seg(id)}`);
  webhooks = (page: PageArgs = {}) => this.#call<Page<Out<typeof Webhook>>>('GET', `/api/me/webhooks${query(page)}`);
  createWebhook = (url: string) =>
    this.#call<Out<typeof Webhook> & { secret: string }>('POST', '/api/me/webhooks', { url });
}
