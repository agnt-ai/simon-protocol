/**
 * Pairing an agent with an email or phone principal, and what the pair means afterwards.
 *
 *   register { for: "mailto:..." }                 a code goes to the address (verifyPrincipal: pending)
 *   register { for, "agnt.ai:pairingCode" }                  the code binds: the pair is recorded, the person claimed
 *   every message the agent sends                  carries an acts-for claim (claimsFor)
 *   the agent's keys replaced by a code            the pair only converses until its person confirms (recovered)
 *   the person or the agent ends the pair          its address retires
 *
 * The register call's `agnt.ai:scope` member names what the agent asks to do for its person (default converse
 * and schedule); the code message names the agent, its key and that scope, so a person who never asked
 * can see it and ignore it. Key principals pair by their own signature, which the core checks.
 */
import type { Claim, Json } from '@agnt-protocol/protocol';
import type { Agent, PrincipalAnswer, PrincipalRequest } from '@agnt-protocol/server';
import type { Activity, Ctx } from '../../context.ts';
import type { Codes } from '../../lib/codes.ts';
import { gone, invalid } from '../../lib/errors.ts';
import { kindOf, masked } from '../../lib/principals.ts';
import { fingerprint, hashSecret, randomToken } from '../../lib/secrets.ts';
import type { People } from './people.ts';
import { pairingId, type Pairing } from './store.ts';
import { SCOPE_ACTIONS, type ScopeAction } from './vocab.ts';

const DEFAULT_SCOPE: ScopeAction[] = ['converse', 'schedule'];
const ASKED_MS = 15 * 60_000;
const RECONFIRM_MS = 30 * 86_400_000;

function readScope(value: Json | undefined): ScopeAction[] {
  if (value === undefined) return DEFAULT_SCOPE;
  const actions = Array.isArray(value) ? [...new Set(value)] : [];
  if (!actions.length || !actions.every(a => SCOPE_ACTIONS.includes(a as ScopeAction))) {
    throw invalid(`agnt.ai:scope is a list of ${SCOPE_ACTIONS.join(', ')}.`, { field: 'agnt.ai:scope' });
  }
  return actions as ScopeAction[];
}

export class Pairings {
  readonly #ctx: Ctx;
  readonly #people: People;
  readonly #codes: Codes;
  readonly #activity: Activity;

  constructor(ctx: Ctx, people: People, codes: Codes, activity: Activity) {
    this.#ctx = ctx;
    this.#people = people;
    this.#codes = codes;
    this.#activity = activity;
  }

  /** The verifyPrincipal hook: a code exchange for `mailto:` and `tel:` principals. */
  async verify({ principal, address, key, body }: PrincipalRequest): Promise<PrincipalAnswer> {
    if (kindOf(principal) === 'key') return undefined;
    const { api } = this.#ctx;
    const holder = `${address}\n${key}`;
    if (body['agnt.ai:pairingCode'] === undefined) {
      const scope = readScope(body['agnt.ai:scope']);
      await this.#codes.send(principal, 'pairing', holder, code => codeMessage(address, key, scope, code));
      const asked = new Date(api.now().getTime() + ASKED_MS).toISOString();
      await api.store.setValue('pairing-scope', `${holder}\n${principal}`, scope, asked);
      return {
        status: 'pending',
        body: { status: 'pairing_code_sent', address, for: principal, sentTo: masked(principal) },
      };
    }
    if (typeof body['agnt.ai:pairingCode'] !== 'string')
      throw invalid('agnt.ai:pairingCode is a string.', { field: 'agnt.ai:pairingCode' });
    await this.#codes.check(principal, 'pairing', holder, body['agnt.ai:pairingCode']);
    const scope =
      (await api.store.value<ScopeAction[]>('pairing-scope', `${holder}\n${principal}`, api.now().toISOString())) ??
      DEFAULT_SCOPE;
    const person = await this.#people.claim(principal);
    await this.#people.store.putPairing({
      _id: pairingId(address, principal),
      address,
      principal,
      person: person._id,
      scope,
      verifiedAt: api.now(),
      recoveredAt: null,
      reconfirm: null,
    });
    await this.#activity.record(person._id, 'agent_paired', { agent: address, identifier: principal, scope });
    return { status: 'verified' };
  }

  /** The claimsFor hook: the acts-for claim of a pair this server verified. Key principals need none. */
  async claims(agent: Agent): Promise<Claim[]> {
    if (!agent.principal || kindOf(agent.principal) === 'key') return [];
    const p = await this.#people.store.pairing(agent.address, agent.principal);
    if (!p) return [];
    const claim: Claim = {
      type: 'acts-for',
      agent: agent.address,
      for: agent.principal,
      scope: p.recoveredAt ? ['converse'] : p.scope,
      verifiedAt: p.verifiedAt.toISOString(),
      ...(p.recoveredAt ? { recoveredAt: p.recoveredAt.toISOString() } : {}),
    };
    return [claim];
  }

  /**
   * The recovered event: whoever holds the agent's mailbox now holds the agent, and its person never
   * approved them. The pair converses only, and the person is asked, at the very identifier it speaks for.
   */
  async recovered(address: string, key: string): Promise<void> {
    const agent = await this.#ctx.api.store.agentByAddress(address);
    const pairing = agent && (await this.#people.pairingOf(agent));
    if (!pairing) return;
    const token = randomToken();
    const now = this.#ctx.now();
    await this.#people.store.updatePairing(pairing._id, {
      recoveredAt: now,
      reconfirm: { tokenHash: hashSecret(token), expiresAt: new Date(now.getTime() + RECONFIRM_MS) },
    });
    await this.#activity.record(pairing.person, 'agent_recovered', { agent: address, fingerprint: fingerprint(key) });
    if (!this.#codes.canReach(pairing.principal)) return;
    const link = `${this.#ctx.config.server.origin}/api/recovery/${token}`;
    const to = pairing.principal.slice(pairing.principal.indexOf(':') + 1);
    const text = `The agent ${address}, which speaks for you on SIMON, replaced its keys by proving control of its own address (new key ${fingerprint(key)}). Until you confirm, it may only converse for you. Confirm or end it: ${link}`;
    if (kindOf(pairing.principal) === 'email')
      await this.#ctx.mail!.send({ to, subject: 'An agent speaking for you replaced its keys', text });
    else await this.#ctx.sms!.send({ to, text });
  }

  /** The person says yes to a recovered agent: its scope comes back. */
  async confirm(pairing: Pairing): Promise<Pairing> {
    await this.#activity.record(pairing.person, 'agent_confirmed', { agent: pairing.address });
    return (await this.#people.store.updatePairing(pairing._id, { recoveredAt: null, reconfirm: null }))!;
  }

  /** End a pair: the agent's address retires, and never speaks for anyone again. */
  async end(pairing: Pairing, by: 'owner' | 'agent'): Promise<void> {
    await this.#activity.record(pairing.person, 'agent_ended', { agent: pairing.address, by });
    await this.#ctx.retire(pairing.address);
  }

  /** The pair behind a recovery link, while the link is good. */
  async byLink(token: string): Promise<Pairing> {
    const p = await this.#people.store.pairingByToken(hashSecret(token));
    if (!p?.reconfirm || p.reconfirm.expiresAt <= this.#ctx.now()) {
      throw gone('link_expired', 'This link has expired or was used. Open the owner window instead.');
    }
    return p;
  }
}

function codeMessage(address: string, key: string, scope: ScopeAction[], code: string) {
  const asks = scope.join(', ');
  return {
    subject: `Your SIMON code: ${code}`,
    text: [
      'An agent asked to speak for you on SIMON.',
      '',
      `Agent: ${address}`,
      `Key fingerprint: ${fingerprint(key)}`,
      `It asks to: ${asks}`,
      '',
      `Your code is ${code}. It expires in 15 minutes.`,
      '',
      'Give it only to the agent you are setting up. If you did not ask for this, ignore this message: nothing happens without the code.',
    ].join('\n'),
    sms: `SIMON code ${code} for agent ${address} (${fingerprint(key).slice(0, 9)}), to ${asks}. Ignore it if you did not ask.`,
  };
}
