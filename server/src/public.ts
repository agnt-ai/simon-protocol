/**
 * What anyone may read, unsigned:
 *
 *   GET /agnt/server             this server's document (spec section 4)
 *   GET /agnt/agents/<address>   an agent's document, signed by this server: for a retired address its
 *                                retired document (spec section 4), its keys all revoked, `retired`, and
 *                                the `unpairing` that retired it when one did; 404 for an unknown address,
 *                                and 429 for any address once a client has asked for too many of those
 *   GET /agnt/messages/...       published messages, feeds and relations: published.ts
 *   GET /.well-known/agnt        {"server": <origin>}, served only when the origin's host is itself a domain
 *                                this server hosts or leases on, so that domain resolves here by the
 *                                well-known method (section 3) with no TXT record
 *   GET /health                  {"status":"ok"} while this server and its store answer, 503 when the store
 *                                does not: for a load balancer's checks. No part of the protocol, so outside
 *                                /agnt/, and it says nothing else
 */
import {
  canonicalize,
  keyToken,
  MAX_DOCUMENT_BYTES,
  MAX_DOCUMENT_KEYS,
  serverDocument,
  signAgentDocument,
  type AgentDocument,
  type KeyEntry,
  type ServerDocument,
} from '@agnt-protocol/protocol';
import { iso, type Context } from './context.ts';
import { notFound, unavailable } from './errors.ts';
import { json, type Route } from './http.ts';
import type { Agent } from './store/store.ts';

/**
 * This server's document: the signing key, and the next key when one is announced. A key's `added` is
 * when this server first published it, kept in the store, so it never moves.
 */
export async function ownDocument(ctx: Context): Promise<ServerDocument & { syncDays: number; history: false }> {
  const now = iso(ctx.now());
  const keys: KeyEntry[] = [];
  for (const k of [ctx.config.serverKey, ctx.config.nextServerKey]) {
    if (!k) continue;
    const key = keyToken(k);
    keys.push({ key, added: await ctx.store.valueOnce('server-key-added', key, now, null, now), revoked: null });
  }
  return {
    ...serverDocument(ctx.config.origin, keys, ctx.config.limits),
    syncDays: ctx.config.syncDays,
    history: false,
  };
}

/**
 * Every active key, then the newest retained revoked keys, within the total-entry bound. A
 * key whose revocation is ahead of this clock remains active. An invalid legacy account with too many
 * active keys fails closed; publication never silently drops an active key.
 * The signed document's final byte bound is applied by agentDocument, independently of this count.
 */
export function listedKeys(agent: Agent, now: number): KeyEntry[] {
  const active = agent.keys.filter(k => k.revoked === null || Date.parse(k.revoked) > now);
  if (active.length > MAX_DOCUMENT_KEYS) throw unavailable('This identity exceeds the key-document limit.');
  const room = MAX_DOCUMENT_KEYS - active.length;
  const retained =
    room > 0 ? agent.keys.filter(k => k.revoked !== null && Date.parse(k.revoked) <= now).slice(-room) : [];
  const chosen = new Set([...active, ...retained]);
  return agent.keys.filter(k => chosen.has(k)).map(({ key, added, revoked }) => ({ key, added, revoked }));
}

/**
 * An agent's document, signed with this server's key; a retired address's is its retired document (spec
 * section 4), whose keys were all revoked when it retired, at or before `retired`.
 */
export function agentDocument(ctx: Context, agent: Agent): AgentDocument {
  const now = ctx.now().getTime();
  let keys = listedKeys(agent, now);
  for (;;) {
    const doc = signAgentDocument(
      {
        address: agent.address,
        kind: agent.kind,
        keys,
        ...(agent.retiredAt && {
          retired: retiredAt(agent.retiredAt, keys),
          ...(agent.unpairing && { unpairing: agent.unpairing }),
        }),
      },
      ctx.config.serverKey,
    );
    if (Buffer.byteLength(canonicalize(doc)) <= MAX_DOCUMENT_BYTES) return doc;
    const oldest = keys.find(k => k.revoked !== null && Date.parse(k.revoked) <= now);
    if (!oldest) throw unavailable('This identity exceeds the signed-document byte limit.');
    keys = keys.filter(k => k !== oldest);
  }
}

/**
 * The `retired` a retired document states: when the address retired, or its latest revocation if later, so
 * a key a process whose clock ran ahead revoked still falls at or before it and the document stays readable.
 */
function retiredAt(retired: string, keys: readonly KeyEntry[]): string {
  const latest = Math.max(Date.parse(retired), ...keys.map(k => (k.revoked === null ? 0 : Date.parse(k.revoked))));
  return latest === Date.parse(retired) ? retired : new Date(latest).toISOString();
}

/** Whether this server's own host is a domain it gives addresses on, so it answers that domain's well-known. */
export function answersWellKnown(config: Context['config']): boolean {
  const host = new URL(config.origin).hostname;
  return config.hostedDomains.includes(host) || config.leaseDomain === host;
}

export function publicRoutes(ctx: Context, retiredAgentDocuments: 'public' | 'private'): Route[] {
  const wellKnown: Route[] = answersWellKnown(ctx.config)
    ? [{ method: 'GET', path: '/.well-known/agnt', handle: async () => json({ server: ctx.config.origin }) }]
    : [];
  return [
    ...wellKnown,
    {
      method: 'GET',
      path: '/health',
      async handle() {
        try {
          await ctx.store.marked('health', 'probe', iso(ctx.now()));
        } catch (e) {
          ctx.log('error', 'health: the store does not answer', { error: String(e) });
          throw unavailable('This server cannot reach its store.');
        }
        return json({ status: 'ok' });
      },
    },
    {
      method: 'GET',
      path: '/agnt/server',
      handle: async () => json(await ownDocument(ctx)),
    },
    {
      method: 'GET',
      path: '/agnt/agents/:address',
      async handle(req) {
        // Counted and refused before the lookup, so a client past its budget learns nothing of any address,
        // and lookups in flight together cannot exceed it; an agent served is not a miss, and is given back.
        ctx.rate.hitClient('agentMiss', req.ip);
        const agent = await ctx.store.agentByAddress(req.params.address);
        // Refuse private retirement evidence before projecting keys or unpairing, exactly like an absent row.
        if (!agent || (retiredAgentDocuments === 'private' && agent.retiredAt))
          throw notFound('No agent has this address here.');
        ctx.rate.refundClient('agentMiss', req.ip);
        return json(agentDocument(ctx, agent));
      },
    },
  ];
}
