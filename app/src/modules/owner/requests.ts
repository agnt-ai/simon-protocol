/**
 * Principal-reserved routes. An agent's key authorises the protocol's client calls, and a server may reserve
 * its other operations to the agent's principal (spec/CLIENT.md). This one reserves what decides who may
 * reach an agent, what is published about it and its person, where it is woken, whether it lives, which
 * introductions its person joins, and what it writes into the graph:
 *
 *   the person's listing, the agent card's publication     policy settings, allow and block lists, invites
 *   webhooks                                               retiring the agent
 *   carrying and answering introductions                   writing edges and attestations
 *
 * A paired agent's call to one of these is held as a request, answered `202 {status: "awaiting_principal",
 * request}`, and runs only when its person approves it in the owner window, exactly as the agent made it:
 * an agent may ask, and only its person decides. A solo agent speaks for no one, so its key is all the
 * authority there is, and its calls run at once.
 */
import type { Agent, Reply, Request, ServerApi } from 'simon-server';
import { z } from 'zod';
import type { Ctx } from '../../context.ts';
import { agent, run, type ApiRoute, type Call, type Caller, type RouteSpec } from '../../http/route.ts';
import { conflict, forbidden, notFound, WireError } from '../../lib/errors.ts';
import { newId } from '../../lib/ids.ts';
import { spend } from '../../lib/rate.ts';
import { seal, unseal } from '../../lib/secrets.ts';

const TTL_MS = 7 * 86_400_000;
/** How long a decided or expired request is kept, so its agent can read the answer. */
const KEEP_MS = 30 * 86_400_000;

interface Held {
  _id: string;
  agent: string;
  /** The agent's principal: the identifier whose owner sessions see the request. */
  principal: string;
  operation: string;
  summary: string;
  /** The checked input, as JSON text. */
  call: string;
  state: 'pending' | 'approved' | 'declined' | 'failed';
  /** The call's answer, sealed: it may hold a secret shown once, such as a webhook's or an invite code. */
  answer: string | null;
  error: { code: string; detail: string } | null;
  createdAt: Date;
  expiresAt: Date;
  decidedAt: Date | null;
}

export const RequestView = z
  .object({
    id: z.string(),
    agent: z.string(),
    operation: z.string().meta({ description: 'The operationId of the route the agent called.' }),
    summary: z.string(),
    call: z.object({ params: z.unknown(), query: z.unknown(), body: z.unknown() }),
    state: z.enum(['pending', 'approved', 'declined', 'failed', 'expired']),
    answer: z.unknown().meta({ description: "The call's answer, once approved." }),
    error: z.object({ code: z.string(), detail: z.string() }).nullable(),
    createdAt: z.string(),
    expiresAt: z.string(),
    decidedAt: z.string().nullable(),
  })
  .meta({ id: 'PrincipalRequest', description: 'A principal-reserved call an agent made, held for its person.' });

export const Awaiting = z
  .object({ status: z.literal('awaiting_principal'), request: RequestView })
  .meta({ id: 'AwaitingPrincipal', description: "Held until the agent's person approves it in the owner window." });

export class Requests {
  /** The caller of every principal-reserved route: an agent here, whose paired calls wait for its person. */
  readonly caller: Caller<Agent>;
  readonly #ctx: Ctx;
  readonly #ownerWindow: boolean;
  readonly #requests;
  readonly #specs = new Map<string, RouteSpec>();
  readonly #held: ((request: Held) => Promise<void>)[] = [];

  constructor(ctx: Ctx, ownerWindow: boolean) {
    this.#ctx = ctx;
    this.#ownerWindow = ownerWindow;
    this.#requests = ctx.db.collection<Held>('owner.requests');
    this.caller = {
      ...agent,
      hold: (caller, call, spec) => this.#hold(caller, call, spec),
      held: {
        status: 202,
        description:
          "Principal-reserved: a paired agent's call waits for its person to approve it in the owner window.",
        response: Awaiting,
      },
    };
  }

  async init() {
    await this.#requests.createIndex({ principal: 1, _id: -1 });
    await this.#requests.createIndex({ agent: 1, state: 1 });
    await this.#requests.createIndex({ createdAt: 1 });
  }

  /** Learn the reserved routes among all of them, so an approved call can run. */
  adopt(routes: ApiRoute[]) {
    for (const { spec } of routes) if (spec.caller === this.caller) this.#specs.set(spec.operationId, spec);
  }

  /** Be told of every request held, to tell the person. */
  onHeld(listener: (request: Held) => Promise<void>) {
    this.#held.push(listener);
  }

  async #hold(caller: Agent, call: Call, spec: RouteSpec): Promise<Reply | null> {
    if (caller.kind !== 'paired' || !caller.principal) return null;
    if (!this.#ownerWindow) {
      throw forbidden(
        'principal_required',
        "Only this agent's principal may do this, and this server has no owner window.",
      );
    }
    await spend(this.#ctx.api, 'requests', this.#ctx.config.rates.requests, caller.address);
    const now = this.#ctx.now();
    const request: Held = {
      _id: newId('request'),
      agent: caller.address,
      principal: caller.principal,
      operation: spec.operationId,
      summary: spec.summary,
      call: JSON.stringify(call),
      state: 'pending',
      answer: null,
      error: null,
      createdAt: now,
      expiresAt: new Date(now.getTime() + TTL_MS),
      decidedAt: null,
    };
    await this.#requests.insertOne(request);
    for (const listener of this.#held) await listener(request);
    return { status: 202, json: { status: 'awaiting_principal', request: this.view(request) } };
  }

  /** Requests from the agents of these identifiers, newest first. */
  list(principals: string[], page: { after?: string; limit: number }) {
    return this.#requests
      .find({ principal: { $in: principals }, ...(page.after ? { _id: { $lt: page.after } } : {}) })
      .sort({ _id: -1 })
      .limit(page.limit + 1)
      .toArray();
  }

  /** One request, as its agent asked it. */
  async ofAgent(address: string, id: string): Promise<Held> {
    const request = await this.#requests.findOne({ _id: id, agent: address });
    if (!request) throw notFound('request');
    return request;
  }

  /** How many of an agent's requests wait on its person. */
  waiting(address: string): Promise<number> {
    return this.#requests.countDocuments({ agent: address, state: 'pending', expiresAt: { $gt: this.#ctx.now() } });
  }

  /** The person's decision on a request from one of the session's agents: approved, it runs as it was made. */
  async decide(id: string, principals: string[], decision: 'approve' | 'decline', req: Request, api: ServerApi) {
    const now = this.#ctx.now();
    const decided = await this.#requests.findOneAndUpdate(
      { _id: id, principal: { $in: principals }, state: 'pending', expiresAt: { $gt: now } },
      { $set: { state: decision === 'approve' ? 'approved' : 'declined', decidedAt: now } },
      { returnDocument: 'after' },
    );
    if (!decided) {
      if (await this.#requests.countDocuments({ _id: id, principal: { $in: principals } }, { limit: 1 }))
        throw conflict('request_decided', 'This request was decided already, or expired.');
      throw notFound('request');
    }
    const settled = decision === 'approve' ? await this.#run(decided, req, api) : decided;
    const state = this.view(settled).state;
    this.#ctx.defer(() =>
      this.#ctx.system.notify([settled.agent], 'request-decided', `Request ${settled._id} was ${state}.`, {
        request: settled._id,
        operation: settled.operation,
        state,
      }),
    );
    return settled;
  }

  async #run(request: Held, req: Request, api: ServerApi): Promise<Held> {
    const spec = this.#specs.get(request.operation);
    const caller = await api.store.agentByAddress(request.agent);
    let patch: Partial<Held>;
    try {
      if (!spec || !caller || caller.retiredAt || caller.principal !== request.principal)
        throw notFound('agent', 'The agent that asked no longer speaks for you.');
      const reply = await run(spec, { caller, ...(JSON.parse(request.call) as Call), req, api });
      patch = { answer: reply.json === undefined ? null : seal(this.#ctx.config.dataKey, JSON.stringify(reply.json)) };
    } catch (e) {
      if (!(e instanceof WireError)) throw e;
      patch = { state: 'failed', error: { code: e.code, detail: e.message } };
    }
    // Retiring the agent forgets its requests, this one too: it ends here as it ran.
    const settled = await this.#requests.findOneAndUpdate(
      { _id: request._id },
      { $set: patch },
      { returnDocument: 'after' },
    );
    return settled ?? { ...request, ...patch };
  }

  view(r: Held): z.output<typeof RequestView> {
    const expired = r.state === 'pending' && r.expiresAt <= this.#ctx.now();
    return {
      id: r._id,
      agent: r.agent,
      operation: r.operation,
      summary: r.summary,
      call: JSON.parse(r.call),
      state: expired ? 'expired' : r.state,
      answer: r.answer === null ? null : JSON.parse(unseal(this.#ctx.config.dataKey, r.answer)),
      error: r.error,
      createdAt: r.createdAt.toISOString(),
      expiresAt: r.expiresAt.toISOString(),
      decidedAt: r.decidedAt?.toISOString() ?? null,
    };
  }

  /** Background work: drop requests decided or expired long enough ago. */
  async work(): Promise<number> {
    const before = new Date(this.#ctx.now().getTime() - KEEP_MS);
    return (await this.#requests.deleteMany({ createdAt: { $lt: before } })).deletedCount;
  }

  async forgetAgent(address: string) {
    await this.#requests.deleteMany({ agent: address });
  }
}
