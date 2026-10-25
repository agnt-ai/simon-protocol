/**
 * Recipient policy: whether an agent here takes a message offered to it. The protocol says only that a
 * server may refuse, and answers 202 either way; these rules are this application's. They run per message
 * and per recipient, and the first that decides wins:
 *
 *   0. this application's own agents, and an agent writing to itself      taken
 *   1. block list (the agent's, or its person's): the sender's address,
 *      its domain or a parent of it, or the server that carried it          refused
 *   2. invite: a one-time code the recipient issued, as the `invite` hint  taken, for that message
 *   3. allow list, or a correspondent (the recipient wrote to the sender)   taken, within the limits
 *   4. verified human, when the agent asks for it: a verified principal
 *      behind the sender (a trusted acts-for claim, or a key's pairing)     else refused
 *   5. accept `known`                                                      everyone else refused
 *   6. the contact tier of the recipient's person, by graph relation        refused when it excludes
 *   7. inbound limits, per recipient per day                               held until the window reopens
 *
 * A held message is offered again through every rule, so a block made while it waited still refuses it.
 * A refused message is counted for the recipient (who, and how often), and kept nowhere.
 */
import {
  domainOf,
  header,
  verifyPairing,
  normalizeAddress,
  normalizeDomain,
  serverOrigin,
  type Message,
  VERSION,
} from '@agnt-sdk/simon-protocol';
import type { Arrival, Decision } from '@agnt-sdk/simon-server';
import type { Ctx } from '../../context.ts';
import { invalid, notFound } from '../../lib/errors.ts';
import { newId } from '../../lib/ids.ts';
import { hashSecret, randomToken } from '../../lib/secrets.ts';
import type { Directory } from '../directory/index.ts';
import { entryId, type Entry, type EntryKind, type PolicyStore } from './store.ts';

const DAY_MS = 86_400_000;

export class Policy {
  readonly store: PolicyStore;
  readonly #ctx: Ctx;
  readonly #directory: Directory | null;

  constructor(ctx: Ctx, store: PolicyStore, directory: Directory | null) {
    this.#ctx = ctx;
    this.store = store;
    this.#directory = directory;
  }

  /** The admit hook. */
  async admit(a: Arrival): Promise<Decision> {
    const { from } = a.message;
    if (this.#ctx.system.isSystem(from) || from === a.recipient) return 'accept';
    const owners = [a.recipient, ...(await this.#personOf(a.recipient))];
    const keys = matchKeys(from, a.carrier);
    if (await this.blocks(owners, from, a.carrier)) return this.#refuse(a);
    if (a.hints.invite && (await this.store.redeem(a.recipient, hashSecret(a.hints.invite), a.id, this.#ctx.now())))
      return 'accept';

    const { wrote, heard } = await this.store.corresponded(a.recipient, from);
    if (wrote || (await this.store.listed([a.recipient], 'allow', keys))) return this.#limit(a, wrote || heard);
    const settings = await this.store.settings(a.recipient);
    if (settings.requireVerifiedHuman && !verifiedPrincipal(a)) return this.#refuse(a);
    if (settings.accept === 'known') return this.#refuse(a);
    if (this.#directory && !(await this.#directory.contactAllows(a))) return this.#refuse(a);
    return this.#limit(a, heard);
  }

  /** Whether any of `owners` (agents here, or people) blocks `from`, as carried by `carrier`. */
  blocks(owners: string[], from: string, carrier: string): Promise<boolean> {
    return this.store.listed(owners, 'block', matchKeys(from, carrier));
  }

  /** The people whose blocks apply to a recipient: the person it speaks for, if any. */
  async #personOf(address: string): Promise<string[]> {
    const agent = this.#directory && (await this.#ctx.api.store.agentByAddress(address));
    const pairing = agent && (await this.#directory!.people.pairingOf(agent));
    return pairing ? [pairing.person] : [];
  }

  async #refuse(a: Arrival): Promise<'refuse'> {
    const now = this.#ctx.now();
    // Counted once per recipient and message, however often it arrives.
    const expires = new Date(now.getTime() + 30 * DAY_MS).toISOString();
    if (await this.#ctx.api.store.mark('held', `${a.recipient}\n${a.id}`, expires, now.toISOString())) {
      const forValue = a.message.v === VERSION ? header(a.message as Message, 'for') : null;
      await this.store.bumpHeld({ agent: a.recipient, sender: a.message.from, for: forValue }, now);
    }
    return 'refuse';
  }

  /**
   * Inbound limits, counted per recipient so no sender spends what another will take: per sender and per
   * domain for senders on other servers (agents here are limited by their own sending rate), and for
   * first contacts from anyone. A spent limit holds the message; `release` offers it again later.
   */
  async #limit(a: Arrival, known: boolean): Promise<Decision> {
    const { perSender, perDomain, firstContacts } = this.#ctx.config.policy;
    const local = a.carrier === this.#ctx.config.server.origin;
    const over =
      (!local && (await this.#count(`sender:${a.recipient}\n${a.message.from}`)) > perSender) ||
      (!local && (await this.#count(`domain:${a.recipient}\n${domainOf(a.message.from)}`)) > perDomain) ||
      (!known && (await this.#count(`first:${a.recipient}`)) > firstContacts);
    if (!over) return 'accept';
    await this.store.wait({ _id: `${a.recipient} ${a.id}`, agent: a.recipient, id: a.id, at: this.#ctx.now() });
    return 'later';
  }

  async #count(key: string): Promise<number> {
    const now = this.#ctx.now().getTime();
    const start = now - (now % DAY_MS);
    return this.#ctx.api.store.count(
      'inbound',
      `${key}\n${start}`,
      new Date(start + DAY_MS).toISOString(),
      new Date(now).toISOString(),
    );
  }

  /**
   * Background work: offer held messages again through every rule, once a day has turned, so a block made
   * meanwhile refuses them and a limit spent again holds them again. Answers how many it offered.
   */
  async release(): Promise<number> {
    const day = this.#ctx.now().getTime() - (this.#ctx.now().getTime() % DAY_MS);
    let released = 0;
    for (const w of await this.store.waiting(100)) {
      if (w.at.getTime() >= day) break;
      await this.#ctx.api.offer(w.agent, w.id);
      await this.store.doneWaiting(w._id, w.at);
      released++;
    }
    return released;
  }

  /** Remember who wrote to whom: replies and correspondents get through. Never for an agent that retired. */
  async correspond(from: string, to: string[], how: 'wrote' | 'heard'): Promise<void> {
    if (await this.#retired(from)) return;
    for (const peer of to) if (!(await this.#retired(peer))) await this.store.correspond(from, peer, how);
  }

  async #retired(address: string): Promise<boolean> {
    return !!(await this.#ctx.api.store.agentByAddress(address))?.retiredAt;
  }

  async addEntries(owner: string, list: Entry['list'], entries: { kind: EntryKind; value: string }[], source: string) {
    let added = 0;
    for (const e of entries) {
      const value = normalizeEntry(e.kind, e.value);
      const entry = {
        _id: entryId(owner, list, e.kind, value),
        owner,
        list,
        kind: e.kind,
        value,
        source,
        createdAt: this.#ctx.now(),
      };
      if (await this.store.addEntry(entry)) added++;
    }
    return added;
  }

  async removeEntry(owner: string, list: Entry['list'], kind: EntryKind, value: string): Promise<void> {
    if (!(await this.store.removeEntry(entryId(owner, list, kind, normalizeEntry(kind, value)))))
      throw notFound('entry');
  }

  /** A one-time code for someone the agent wants to hear from: good for one message, until it expires. */
  async invite(agent: string, ttlHours: number) {
    const code = randomToken(18);
    const expiresAt = new Date(this.#ctx.now().getTime() + ttlHours * 3_600_000);
    await this.store.insertInvite({
      _id: newId('invite'),
      agent,
      codeHash: hashSecret(code),
      expiresAt,
      usedFor: null,
    });
    return { code, address: agent, expiresAt: expiresAt.toISOString() };
  }
}

/** What a list entry may match: the sender's address, its domain and each parent domain, and the server. */
function matchKeys(from: string, carrier: string): { kind: EntryKind; value: string }[] {
  const labels = domainOf(from).split('.');
  const domains = labels.slice(0, -1).map((_, i) => labels.slice(i).join('.'));
  return [
    { kind: 'address', value: from },
    ...domains.map(value => ({ kind: 'domain' as const, value })),
    { kind: 'server', value: carrier },
  ];
}

/** A principal stands verified behind the sender: a trusted server's acts-for claim, or a key's own pairing. */
function verifiedPrincipal(a: Arrival): boolean {
  if (a.claims.some(c => c.type === 'acts-for')) return true;
  if (a.message.v !== VERSION) return false;
  const m = a.message as Message;
  const forValue = header(m, 'for');
  return forValue !== null && verifyPairing(m.from, forValue, header(m, 'pairing'));
}

function normalizeEntry(kind: EntryKind, value: string): string {
  const normal =
    kind === 'address'
      ? normalizeAddress(value)
      : kind === 'domain'
        ? normalizeDomain(value)
        : serverOrigin(value, true);
  if (!normal) throw invalid(`${value} is not ${kind === 'address' ? 'an address' : `a ${kind}`}.`, { field: 'value' });
  return normal;
}
