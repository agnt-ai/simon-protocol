/**
 * People and the pairs that speak for them. A person is found by their identifiers (principals), and is
 * claimed once one is proven theirs. Each paired agent here speaks for exactly one identifier for life, so
 * the person an agent acts as is a lookup, never an inference; a person's several pairs are shown together
 * because their identifiers are one person's, which the person proves in the owner window. Two people
 * become one only when a person signed in by an identifier of their own proves another person's, and
 * confirms.
 *
 * Who an agent acts as in a directory call (its "actor"):
 *   - a paired agent whose pair this server verified: its person, unless a key recovery is unconfirmed;
 *   - a solo agent, or one waiting on that confirmation: itself, written `agent:<address>`, so its own
 *     edges and attestations still have an owner and nothing private to a person is shown.
 */
import type { Agent } from 'simon-server';
import type { Activity, Ctx } from '../../context.ts';
import { forbidden, notFound } from '../../lib/errors.ts';
import { newId } from '../../lib/ids.ts';
import { emailDomain, kindOf } from '../../lib/principals.ts';
import { isFreemail } from './entities.ts';
import type { EdgeOwner } from './graph-store.ts';
import { pairingId, type Listing, type Pairing, type PeopleStore, type Person } from './store.ts';
import { SCOPE_ACTIONS } from './vocab.ts';

/** Until a person lists, only their connections may write to them; the first listing opens it to anyone. */
export const DEFAULT_LISTING: Listing = {
  listed: false,
  listedAt: null,
  discoverability: 'everyone',
  contact: 'connections',
  secondDegreeOptIn: false,
  introCarrying: 'ask',
  introAutoMinGrade: 'strong',
};

/** A listing as the API shows it. */
export const listingView = (listing: Listing) => ({
  ...listing,
  listedAt: listing.listedAt?.toISOString() ?? null,
});

/** An identifier last proven longer ago than this grants nothing in the owner window until proven again. */
export const FRESH_MS = 365 * 86_400_000;

export interface Actor {
  /** A person id, or `agent:<address>` for an agent acting as itself. */
  principal: string;
  /** The identifier the agent speaks for, or `agent:<address>`: what it writes is filed under it. */
  identifier: string;
  person: Person | null;
  pairing: Pairing | null;
}

/** What an actor reads of its person's graph: the edges its own identifier's agents wrote. */
export const edgeOwner = (actor: Actor): EdgeOwner => ({ from: actor.principal, principals: [actor.identifier] });

/** Called when one person's records become another's. */
export type MergeListener = (from: string, to: string) => Promise<void>;
/** Called when a person is claimed for the first time. */
export type ClaimListener = (person: Person) => Promise<void>;

export class People {
  readonly store: PeopleStore;
  readonly #ctx: Ctx;
  readonly #activity: Activity;
  readonly #merges: MergeListener[] = [];
  readonly #claims: ClaimListener[] = [];

  constructor(ctx: Ctx, store: PeopleStore, activity: Activity) {
    this.#ctx = ctx;
    this.store = store;
    this.#activity = activity;
  }

  /** Re-key this module's records too when two people merge. */
  onMerge(listener: MergeListener) {
    this.#merges.push(listener);
  }

  /** Be told when someone first claims a person. */
  onClaim(listener: ClaimListener) {
    this.#claims.push(listener);
  }

  /** A person, following merges to the one they are now. */
  async live(id: string): Promise<Person | null> {
    let p = await this.store.person(id);
    for (let hops = 0; p?.mergedInto && hops < 8; hops++) p = await this.store.person(p.mergedInto);
    return p && !p.mergedInto ? p : null;
  }

  /** The person an identifier is, or null; with `create`, a new unclaimed person when it is nobody's. */
  async forPrincipal(principal: string, create = false): Promise<Person | null> {
    const found = await this.store.identifier(principal);
    if (found) return this.live(found.person);
    if (!create) return null;
    const now = this.#ctx.now();
    const person: Person = {
      _id: newId('person'),
      claimed: false,
      mergedInto: null,
      listing: { ...DEFAULT_LISTING },
      createdAt: now,
    };
    await this.store.insertPerson(person);
    if (await this.store.insertIdentifier({ _id: principal, person: person._id, verifiedAt: null, createdAt: now })) {
      return person;
    }
    // Another writer made it first: theirs stands.
    await this.store.deletePeople([person._id]);
    return this.forPrincipal(principal);
  }

  /** An identifier proven now by whoever holds it: its person, claimed. */
  async claim(principal: string): Promise<Person> {
    await this.#releaseIfRecycled(principal);
    const person = (await this.forPrincipal(principal, true))!;
    await this.store.verifyIdentifier(principal, this.#ctx.now());
    if (person.claimed) return person;
    const claimed = (await this.store.updatePerson(person._id, { claimed: true }))!;
    await this.#activity.record(person._id, 'person_claimed', { identifier: principal });
    for (const listener of this.#claims) await listener(claimed);
    return claimed;
  }

  /**
   * An email address or phone number proven again after it went stale may have changed hands: inboxes and
   * numbers are recycled. When its person has other proven identifiers, it no longer speaks for them: it
   * moves to a person of its own, and whoever holds it now starts there. The person it left gets it back
   * the way any two people join, by proving it in a session of theirs and confirming (`prove`, `merge`).
   * A person with no other identifier keeps it, since nothing tells a returning owner from a new holder.
   */
  async #releaseIfRecycled(principal: string, keepFor?: string): Promise<void> {
    const found = await this.store.identifier(principal);
    if (!found?.verifiedAt || kindOf(principal) === 'key') return;
    if (found.verifiedAt.getTime() > this.#ctx.now().getTime() - FRESH_MS) return;
    const owner = await this.live(found.person);
    // Proven again in a session of its own person, by someone already signed in as them: still theirs.
    if (!owner || owner._id === keepFor) return;
    const others = (await this.store.identifiersOf([owner._id])).filter(i => i._id !== principal && i.verifiedAt);
    if (!others.length) return;
    const now = this.#ctx.now();
    const fresh: Person = {
      _id: newId('person'),
      claimed: false,
      mergedInto: null,
      listing: { ...DEFAULT_LISTING },
      createdAt: now,
    };
    await this.store.insertPerson(fresh);
    await this.store.moveIdentifier(principal, fresh._id);
    // Told to every session of the person it left, whichever identifiers they proved.
    await this.#activity.record(owner._id, 'identifier_released', { released: principal });
  }

  /**
   * An identifier the signed-in `person` proved now: theirs, unless it is another person's here. Then the
   * same proof would sign in as that person too, so the two may be merged, but only on confirmation.
   */
  async prove(person: Person, principal: string): Promise<'added' | 'merge_required'> {
    // A recycled identifier proven by someone else leaves its old person first, so confirming the merge
    // joins only the person of its own it starts, never the whole person it left.
    await this.#releaseIfRecycled(principal, person._id);
    const other = await this.forPrincipal(principal);
    if (other && other._id !== person._id) return 'merge_required';
    const now = this.#ctx.now();
    if (!other)
      await this.store.insertIdentifier({ _id: principal, person: person._id, verifiedAt: now, createdAt: now });
    await this.store.verifyIdentifier(principal, now);
    await this.#activity.record(person._id, 'identifier_added', { identifier: principal });
    return 'added';
  }

  /** The person an identifier proved in the same session is, merged into `person`: confirmed by them. */
  async merge(person: Person, principal: string): Promise<Person> {
    const other = await this.forPrincipal(principal);
    if (other && other._id !== person._id) {
      await this.store.reassign(other._id, person._id);
      for (const listener of this.#merges) await listener(other._id, person._id);
      await this.store.updatePerson(other._id, { mergedInto: person._id });
    }
    await this.store.verifyIdentifier(principal, this.#ctx.now());
    await this.#activity.record(person._id, 'identifier_merged', { identifier: principal });
    return (await this.live(person._id))!;
  }

  /** A person's identifiers proven within FRESH_MS: the ones that still grant access to the owner window. */
  async fresh(person: string): Promise<string[]> {
    const since = this.#ctx.now().getTime() - FRESH_MS;
    return (await this.store.identifiersOf([person]))
      .filter(i => i.verifiedAt && i.verifiedAt.getTime() > since)
      .map(i => i._id);
  }

  /**
   * The domains each person holds a verified email address at, leaving out consumer mail: an address at a
   * domain anyone can sign up to vouches for nothing.
   */
  async verifiedDomains(persons: string[]): Promise<Map<string, Set<string>>> {
    const out = new Map<string, Set<string>>(persons.map(p => [p, new Set()]));
    for (const i of await this.store.identifiersOf(persons)) {
      const domain = i.verifiedAt && emailDomain(i._id);
      if (domain && !isFreemail(domain)) out.get(i.person)?.add(domain);
    }
    return out;
  }

  /** Who an agent acts as. */
  async actor(agent: Agent): Promise<Actor> {
    const self: Actor = {
      principal: `agent:${agent.address}`,
      identifier: `agent:${agent.address}`,
      person: null,
      pairing: null,
    };
    const pairing = await this.pairingOf(agent);
    if (!pairing || pairing.recoveredAt) return self;
    const person = await this.live(pairing.person);
    return person ? { principal: person._id, identifier: pairing.principal, person, pairing } : self;
  }

  /** The person an agent acts for, for a call in their name; refused for a solo agent or an unconfirmed recovery. */
  async personOf(agent: Agent): Promise<{ person: Person; pairing: Pairing }> {
    const pairing = await this.pairingOf(agent);
    if (pairing?.recoveredAt) {
      throw forbidden(
        'recovery_pending',
        'This agent replaced its keys; until its person confirms, it may only converse for them.',
      );
    }
    const person = pairing && (await this.live(pairing.person));
    if (!pairing || !person) throw forbidden('not_paired', 'This agent speaks for no person this server verified.');
    return { person, pairing };
  }

  /** Whether a person proved an email address or a phone number here: someone mail can be traced to. */
  async reachable(person: string): Promise<boolean> {
    return (await this.store.identifiersOf([person])).some(i => i.verifiedAt && kindOf(i._id) !== 'key');
  }

  /**
   * The pair a live agent here is, as this server verified it. A key principal's pairing the core verified
   * by its signature, so its pair is recorded the first time it is needed.
   */
  async pairingOf(agent: Agent): Promise<Pairing | null> {
    if (agent.kind !== 'paired' || !agent.principal || agent.retiredAt) return null;
    const pairing = await this.store.pairing(agent.address, agent.principal);
    if (pairing || kindOf(agent.principal) !== 'key') return pairing;
    const person = await this.claim(agent.principal);
    const record: Pairing = {
      _id: pairingId(agent.address, agent.principal),
      address: agent.address,
      principal: agent.principal,
      person: person._id,
      scope: [...SCOPE_ACTIONS],
      verifiedAt: new Date(agent.createdAt),
      recoveredAt: null,
      reconfirm: null,
    };
    await this.store.putPairing(record);
    return record;
  }

  /** A person's pairs whose agents are live here, of some identifiers only when given. */
  async pairsOf(person: string, identifiers?: string[]): Promise<Pairing[]> {
    const pairs = (await this.store.pairingsOf(person)).filter(p => !identifiers || identifiers.includes(p.principal));
    const live = await Promise.all(
      pairs.map(async p => {
        const agent = await this.#ctx.api.store.agentByAddress(p.address);
        return agent && !agent.retiredAt && agent.principal === p.principal;
      }),
    );
    return pairs.filter((_, i) => live[i]);
  }

  /** One of a person's live pairs, by its agent's address, among some identifiers' when given. */
  async pairOf(person: string, address: string, identifiers?: string[]): Promise<Pairing> {
    const pair = (await this.pairsOf(person, identifiers)).find(p => p.address === address);
    if (!pair) throw notFound('agent', 'No agent speaks for you at that address.');
    return pair;
  }

  async updateListing(
    person: Person,
    patch: Partial<Omit<Listing, 'listedAt'>>,
    by: { agent?: string },
  ): Promise<Person> {
    const listing = { ...person.listing };
    // Listing is the person's choice; the first time, who may find and write to them opens up with it.
    // Carrying second-degree relationships stays off until they turn it on themselves.
    if (patch.listed && !listing.listedAt) {
      Object.assign(listing, { listedAt: this.#ctx.now(), discoverability: 'everyone', contact: 'anyone' });
    }
    Object.assign(listing, Object.fromEntries(Object.entries(patch).filter(([, v]) => v !== undefined)));
    await this.#activity.record(person._id, 'listing_changed', { ...by, listing: listingView(listing) });
    return (await this.store.updatePerson(person._id, { listing }))!;
  }
}
