/**
 * Introductions, double-blind and opt-in on both sides:
 *
 *   1. A paired agent asks to meet someone, by identifier, with a brief written for them. Only someone who
 *      joined and listed themselves is ever introduced to; for anyone else nothing happens at all.
 *   2. Later, out of band, the request is routed sealed to carriers: people whose own edge says they
 *      know the requester and whose own edge to the target is strong enough, who opted in and allow
 *      carrying. The target's blocks are checked before any carrier is asked and again before the
 *      target's agents are, so a blocked requester reaches nobody this way either. They are asked strongest
 *      first, in waves of three; a wave opens when the one before all declined or after a set time. The
 *      first yes carries it and withdraws every other; carriers in waves never opened never hear of it. A
 *      carrier whose person chose `auto` for edges this strong carries it at once.
 *   3. The target's agents get it with the requester's chosen identifier, the brief and who vouched.
 *   4. Only when both said yes does the requester hear anything: each agent goes on the other's allow
 *      list, and both get a notice. The carrier is not told the outcome.
 *
 * A decline at either step, no path, and a carrier who carries nothing all look the same to the
 * requester: its view is `submitted` until the introduction arrives or the request expires.
 */
import crypto from 'node:crypto';
import type { Agent } from '@agnt-sdk/simon-server';
import type { Activity, Ctx } from '../../context.ts';
import type { Quoted } from '../../system.ts';
import { conflict, invalid, notFound } from '../../lib/errors.ts';
import { newId } from '../../lib/ids.ts';
import type { Directory } from '../directory/index.ts';
import { selfName } from '../directory/profiles.ts';
import { rankOf } from '../directory/vocab.ts';
import type { Policy } from '../policy/policy.ts';
import type { Intro, IntroStore, Seat } from './store.ts';

const OPEN: Intro['state'][] = ['submitted', 'routed', 'carried'];
/** How long a request is kept once it expired, so each side can still read how it ended. */
const KEEP_MS = 30 * 86_400_000;

/** Whether a carrier was ever told of the request. */
const told = (s: Seat) => !!s.notifiedAt || (s.auto && s.state === 'carried');

export const requesterView = (i: Intro, now: Date) => {
  const introduced = i.state === 'accepted' ? i.introduced : null;
  return {
    id: i._id,
    target: i.target,
    subject: i.subject,
    state: introduced ? ('introduced' as const) : now >= i.expiresAt ? ('expired' as const) : ('submitted' as const),
    introducedTo: introduced?.target ?? null,
    expiresAt: i.expiresAt.toISOString(),
    createdAt: i.createdAt.toISOString(),
  };
};

export class Intros {
  readonly store: IntroStore;
  readonly #ctx: Ctx;
  readonly #d: Directory;
  readonly #policy: Policy;
  readonly #activity: Activity;

  constructor(ctx: Ctx, store: IntroStore, d: Directory, policy: Policy, activity: Activity) {
    this.#ctx = ctx;
    this.store = store;
    this.#d = d;
    this.#policy = policy;
    this.#activity = activity;
  }

  async request(agent: Agent, input: { target: string; brief: string; subject?: string; presentAs?: string }) {
    const { person } = await this.#d.people.personOf(agent);
    const { intros } = this.#ctx.config;
    const now = this.#ctx.now();
    const delay = intros.routeDelaySec * 1000;
    const intro: Intro = {
      _id: newId('intro'),
      requesterAgent: agent.address,
      requesterPerson: person._id,
      target: input.target,
      targetPerson: null,
      brief: input.brief.trim(),
      subject: input.subject?.trim() || 'Introduction',
      state: 'submitted',
      carriers: [],
      carriedBy: null,
      targetAgents: [],
      targetDecision: null,
      presentAs: await this.#presentAs(person._id, input.presentAs),
      introduced: null,
      // Routed after a delay that varies, so the answer and its timing say nothing about what follows.
      routeAfter: new Date(now.getTime() + delay + crypto.randomInt(0, Math.max(1, delay))),
      nextWaveAt: null,
      expiresAt: new Date(now.getTime() + intros.ttlDays * 86_400_000),
      closedReason: null,
      createdAt: now,
      rev: 0,
    };
    await this.store.insert(intro);
    await this.#activity.record(person._id, 'intro_requested', { intro: intro._id, agent: agent.address });
    return requesterView(intro, now);
  }

  /** The one verified identifier the requester is known by: the one asked for, or their first email. */
  async #presentAs(person: string, asked?: string): Promise<string | null> {
    const verified = (await this.#d.people.store.identifiersOf([person])).filter(i => i.verifiedAt).map(i => i._id);
    if (asked && !verified.includes(asked))
      throw invalid("presentAs is one of your person's verified identifiers.", { field: 'presentAs' });
    return asked ?? verified.find(i => i.startsWith('mailto:')) ?? null;
  }

  /** Background work: route due requests, open due waves, close expired ones, drop long-expired ones. */
  async work(): Promise<number> {
    const now = this.#ctx.now();
    const routing = await this.store.dueForRouting(now, 50);
    const waves = await this.store.dueWaves(now, 50);
    const expired = await this.store.expired(now, 100);
    for (const i of routing) await this.#route(i);
    for (const i of waves) await this.#openWave(i);
    for (const i of expired) {
      if (!(await this.#close(i, 'expired'))) continue;
      for (const s of i.carriers.filter(c => c.state === 'pending' && c.notifiedAt)) this.#withdrawn(s, i._id);
    }
    const dropped = await this.store.prune(new Date(now.getTime() - KEEP_MS));
    return routing.length + waves.length + expired.length + dropped;
  }

  #close(i: Intro, reason: string) {
    return this.store.transition(i._id, OPEN, { state: 'closed', closedReason: reason, nextWaveAt: null });
  }

  async #route(i: Intro) {
    // Only someone who claimed and listed themselves is introduced to: nobody is asked about anyone else.
    const target = await this.#d.people.forPrincipal(i.target);
    if (!target?.claimed || !target.listing.listed || target._id === i.requesterPerson)
      return this.#close(i, 'no_route');
    if (await this.#blocked(i, target._id)) return this.#close(i, 'no_route');
    const carriers = (await this.#d.discovery.carriers(i.requesterPerson, target._id)).slice(
      0,
      this.#ctx.config.intros.maxCarriers,
    );
    if (!carriers.length) return this.#close(i, 'no_route');
    const auto = carriers.find(
      c => c.person.listing.introCarrying === 'auto' && rankOf(c.grade) >= rankOf(c.person.listing.introAutoMinGrade),
    );
    const seats: Seat[] = carriers.map(c => ({
      agent: c.agent,
      person: c.person._id,
      state: 'queued',
      auto: c === auto,
      notifiedAt: null,
      decidedAt: null,
    }));
    const routed = await this.store.transition(i._id, ['submitted'], {
      state: 'routed',
      targetPerson: target._id,
      carriers: seats,
    });
    if (!routed) return;
    if (auto) await this.#carry(routed._id, auto.agent);
    else await this.#openWave(routed);
  }

  /** Ask the next wave of queued carriers; earlier waves stay open. False when nobody is left to ask. */
  async #openWave(i: Intro): Promise<boolean> {
    const now = this.#ctx.now();
    const { waveSize, waveHours } = this.#ctx.config.intros;
    const wave = i.carriers.filter(c => c.state === 'queued').slice(0, waveSize);
    if (!wave.length) return false;
    if (await this.#blocked(i, i.targetPerson!)) {
      await this.#close(i, 'no_route');
      return true;
    }
    const carriers = i.carriers.map(c => (wave.includes(c) ? { ...c, state: 'pending' as const, notifiedAt: now } : c));
    const more = carriers.some(c => c.state === 'queued');
    const nextWaveAt = more ? new Date(now.getTime() + waveHours * 3_600_000) : null;
    if (!(await this.store.transition(i._id, ['routed'], { carriers, nextWaveAt }, i.rev))) return true;
    for (const seat of wave) {
      const asked = await this.#ctx.api.store.agentByAddress(seat.agent);
      const own = { from: seat.person, principals: asked?.principal ? [asked.principal] : [] };
      const note = (await this.#d.graph.notes(own, [i.targetPerson!])).get(i.targetPerson!) ?? null;
      const { name, ...requester } = await this.#requester(i, seat.person);
      this.#tell(
        seat.agent,
        seat.person,
        'intro-carry-request',
        `Introduction request ${i._id}: a contact of your person asks them to carry it.`,
        { intro: i._id, requester, target: i.target, yourNote: note, quoted: this.#quoted(i, { requesterName: name }) },
      );
      await this.#activity.record(seat.person, 'intro_carry_requested', { intro: i._id, agent: seat.agent });
    }
    return true;
  }

  /** A carrier's answer. */
  async decideCarry(agent: Agent, id: string, decision: 'carry' | 'decline') {
    const i = await this.store.get(id);
    const seat = i?.carriers.find(c => c.agent === agent.address);
    if (!i || !seat || !told(seat)) throw notFound('intro');
    const decided = () => conflict('intro_decided', 'This request is no longer waiting on you.');
    if (decision === 'carry') {
      if (!(await this.#carry(id, agent.address))) throw decided();
      return { id, state: 'carried' };
    }
    const updated = await this.#revise(id, current => {
      const mine = current.carriers.find(c => c.agent === agent.address);
      if (current.state !== 'routed' || mine?.state !== 'pending') return null;
      return {
        carriers: current.carriers.map(c =>
          c === mine ? { ...c, state: 'declined' as const, decidedAt: this.#ctx.now() } : c,
        ),
      };
    });
    if (!updated) throw decided();
    await this.#activity.record(seat.person, 'intro_carry_declined', { intro: id, agent: agent.address });
    // Everyone asked so far said no: ask the next wave, or close when nobody is left.
    if (!updated.carriers.some(c => c.state === 'pending') && !(await this.#openWave(updated)))
      await this.#close(updated, 'carriers_declined');
    return { id, state: 'declined' };
  }

  /** A carrier's yes: every other carrier is withdrawn, and the target's agents now are asked. */
  async #carry(id: string, carrier: string): Promise<Intro | null> {
    const now = this.#ctx.now();
    const before = await this.store.get(id);
    const blocked = !!before?.targetPerson && (await this.#blocked(before, before.targetPerson));
    const targetAgents = before?.targetPerson && !blocked ? await this.#targetAgents(before.targetPerson) : [];
    const updated = await this.#revise(id, current => {
      const mine = current.carriers.find(c => c.agent === carrier);
      if (current.state !== 'routed' || !mine || !(mine.state === 'pending' || (mine.auto && mine.state === 'queued')))
        return null;
      const carriers = current.carriers.map(c =>
        c === mine
          ? { ...c, state: 'carried' as const, decidedAt: now }
          : c.state === 'pending' || c.state === 'queued'
            ? { ...c, state: 'withdrawn' as const, decidedAt: now }
            : c,
      );
      return { state: 'carried', carriedBy: mine.person, carriers, targetAgents, nextWaveAt: null };
    });
    if (!updated) return null;
    for (const c of updated.carriers.filter(
      c => c.state === 'withdrawn' && c.notifiedAt && c.decidedAt?.getTime() === now.getTime(),
    )) {
      this.#withdrawn(c, id);
    }
    await this.#activity.record(updated.carriedBy!, 'intro_carried', { intro: id });
    if (!targetAgents.length) {
      // A yes with nobody to ask on the other side: the same, to everyone, as any other dead end.
      await this.store.transition(id, ['carried'], { state: 'closed', closedReason: 'target_unreachable' });
      return updated;
    }
    const carrierPerson = await this.#d.people.live(updated.carriedBy!);
    const carrierName = carrierPerson
      ? selfName(await this.#d.profiles.facts(carrierPerson, updated.targetPerson))
      : null;
    const { name, ...requester } = await this.#requester(updated, updated.targetPerson!);
    for (const address of targetAgents) {
      this.#tell(
        address,
        updated.targetPerson!,
        'intro-request',
        `Introduction request ${id} was carried to your person.`,
        {
          intro: id,
          requester,
          introducedBy: updated.carriedBy,
          quoted: this.#quoted(updated, { requesterName: name, carrierName }),
        },
      );
    }
    await this.#activity.record(updated.targetPerson!, 'intro_received', { intro: id });
    return updated;
  }

  /** Whether the target, or any agent speaking for them, blocks the requester's agent. */
  async #blocked(i: Intro, targetPerson: string): Promise<boolean> {
    const owners = [targetPerson, ...(await this.#targetAgents(targetPerson))];
    return this.#policy.blocks(owners, i.requesterAgent, this.#ctx.config.server.origin);
  }

  /** The target's agents, as they are when the request is carried. */
  async #targetAgents(person: string): Promise<string[]> {
    const target = await this.#d.people.live(person);
    return target?.claimed ? (await this.#d.people.pairsOf(person)).map(p => p.address) : [];
  }

  /** The target's answer. Accepting introduces the two agents; declining is never reported back. */
  async decideTarget(agent: Agent, id: string, decision: 'accept' | 'decline') {
    const i = await this.store.get(id);
    if (!i?.targetPerson || !i.targetAgents.includes(agent.address)) throw notFound('intro');
    const { person } = await this.#d.people.personOf(agent);
    if (person._id !== i.targetPerson) throw notFound('intro');
    const decided = () => conflict('intro_decided', 'This request is no longer waiting on you.');
    const targetDecision = { agent: agent.address, decision, at: this.#ctx.now() };
    const requester = await this.#ctx.api.store.agentByAddress(i.requesterAgent);
    const live =
      requester && (await this.#d.people.pairsOf(i.requesterPerson)).some(p => p.address === requester.address);
    if (decision === 'decline' || !live) {
      const reason = decision === 'decline' ? 'target_declined' : 'requester_gone';
      if (!(await this.store.transition(id, ['carried'], { state: 'closed', closedReason: reason, targetDecision })))
        throw decided();
      if (decision === 'decline')
        await this.#activity.record(i.targetPerson, 'intro_declined', { intro: id, agent: agent.address });
      return { id, state: decision === 'decline' ? 'declined' : 'closed' };
    }
    const introduced = { requester: requester!.address, target: agent.address, at: this.#ctx.now() };
    if (!(await this.store.transition(id, ['carried'], { state: 'accepted', targetDecision, introduced })))
      throw decided();
    // Each may write to the other now, whatever its policy says otherwise; the requester writes first.
    await this.#policy.addEntries(agent.address, 'allow', [{ kind: 'address', value: requester!.address }], 'intros');
    await this.#policy.addEntries(requester!.address, 'allow', [{ kind: 'address', value: agent.address }], 'intros');
    const about = { intro: id, introducedBy: i.carriedBy, quoted: this.#quoted(i, {}) };
    const made = `Introduction ${id} was made.`;
    this.#tell(requester!.address, i.requesterPerson, 'intro-made', made, { ...about, to: agent.address });
    this.#tell(agent.address, i.targetPerson, 'intro-made', made, { ...about, from: requester!.address });
    for (const p of [i.requesterPerson, i.targetPerson]) await this.#activity.record(p, 'intro_made', { intro: id });
    return { id, state: 'accepted', introducedTo: requester!.address };
  }

  /** What a carrier or the target may see of a request, as some of a person's agents, or null. */
  async participantView(i: Intro, as: { person: string; agents: string[] }) {
    const seat = i.carriers.find(c => c.person === as.person && as.agents.includes(c.agent) && told(c));
    if (seat) {
      return {
        id: i._id,
        role: 'carrier' as const,
        state: seat.state,
        subject: i.subject,
        brief: i.brief,
        target: i.target,
        requester: await this.#requester(i, as.person),
      };
    }
    const target =
      i.targetPerson === as.person &&
      i.carriedBy &&
      i.state !== 'routed' &&
      i.targetAgents.some(a => as.agents.includes(a));
    if (!target) return null;
    const state =
      i.state === 'carried'
        ? 'pending'
        : i.targetDecision?.decision === 'accept'
          ? 'accepted'
          : i.targetDecision
            ? 'declined'
            : 'closed';
    return {
      id: i._id,
      role: 'target' as const,
      state,
      subject: i.subject,
      brief: i.brief,
      introducedBy: i.carriedBy!,
      introducedTo: i.introduced?.requester ?? null,
      requester: await this.#requester(i, as.person),
    };
  }

  /** Who asked, as `reader` may see them: only the identifier they chose, never any other. */
  async #requester(i: Intro, reader: string) {
    const person = await this.#d.people.live(i.requesterPerson);
    return {
      person: i.requesterPerson,
      agent: i.requesterAgent,
      identifier: i.presentAs,
      /** The name the requester gives themselves, and no one else's word for it. */
      name: person ? selfName(await this.#d.profiles.facts(person, reader)) : null,
    };
  }

  /**
   * What others wrote, as a notice quotes it: the requester's subject and brief, and the names the
   * requester and the carrier give themselves, each with its author.
   */
  #quoted(i: Intro, names: { requesterName?: string | null; carrierName?: string | null }) {
    const quoted: Record<string, Quoted> = {
      subject: { author: i.requesterAgent, text: i.subject },
      brief: { author: i.requesterAgent, text: i.brief },
    };
    if (names.requesterName) quoted.requesterName = { author: i.requesterPerson, text: names.requesterName };
    if (names.carrierName && i.carriedBy) quoted.carrierName = { author: i.carriedBy, text: names.carrierName };
    return quoted;
  }

  #withdrawn(seat: Seat, intro: string) {
    this.#tell(
      seat.agent,
      seat.person,
      'intro-withdrawn',
      `Introduction request ${intro} no longer needs your person.`,
      {
        intro,
      },
    );
  }

  /**
   * A notice about an introduction, sent after the answer so its timing says nothing, and only while the
   * agent still speaks for that person. Its text line states a fact; what others wrote travels in `quoted`.
   */
  #tell(agent: string, person: string, notice: string, text: string, data: Record<string, unknown>) {
    this.#ctx.defer(async () => {
      if (!(await this.#d.people.pairsOf(person)).some(p => p.address === agent)) return;
      await this.#ctx.system.notify([agent], notice, text, data);
    });
  }

  /** Apply `change` to the request as it is now, written only if nothing changed it meanwhile; retried. */
  async #revise(id: string, change: (current: Intro) => Partial<Intro> | null): Promise<Intro | null> {
    for (let attempt = 0; attempt < 5; attempt++) {
      const current = await this.store.get(id);
      const patch = current && change(current);
      if (!patch) return null;
      const updated = await this.store.transition(id, [current.state], patch, current.rev);
      if (updated) return updated;
    }
    return null;
  }
}
