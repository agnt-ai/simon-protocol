/**
 * Signed requests (spec section 8): agents sign their calls here, and servers sign their part fetches. The
 * protocol library checks the headers, the clock, the key and the signature, and asks for the nonce last;
 * the nonce is recorded here only once the signature verified, so a request nobody could sign never uses
 * one up. Recording is a store mark, which only one of two racing requests can set.
 */
import {
  actorOf,
  checkSignedRequest,
  domainOf,
  nonceExpiry,
  readSignedHeaders,
  unauthorized,
  type KeyEntry,
  type SignedHeaders,
} from '@agnt-sdk/simon-protocol';
import { iso, type Context } from './context.ts';
import type { Request } from './http.ts';
import { clientKey } from './net/ip.ts';
import type { Agent, AgentKey } from './store/store.ts';

const nonceId = (h: SignedHeaders) => `${h['simon-key']}\n${h['simon-nonce']}`;

/** Check a request's signature by `entry` (null: an unknown key), then record its nonce. */
export async function verifySigned(
  ctx: Context,
  req: Request,
  headers: SignedHeaders,
  entry: KeyEntry | null,
  now = ctx.now(),
) {
  await checkSignedRequest(
    { method: req.method, origin: ctx.config.origin, actor: actorOf(req.headers), target: req.target, body: req.body },
    headers,
    { now, entry, nonceSeen: () => ctx.store.marked('nonce', nonceId(headers), iso(now)) },
  );
  // Kept until the request's own timestamp leaves the window, so no replay inside it ever finds it gone.
  const expires = new Date(nonceExpiry(headers['simon-timestamp'])).toISOString();
  if (!(await ctx.store.mark('nonce', nonceId(headers), expires, iso(now)))) {
    throw unauthorized('replayed_request', 'This key already used this nonce inside the window.', now);
  }
}

/** The agent here that signed this request, named by its `simon-agent`, and the key it signed with; or a 401. */
export async function authenticateAgentKey(ctx: Context, req: Request): Promise<{ agent: Agent; key: AgentKey }> {
  const headers = readSignedHeaders(req.headers, ctx.now(), { agent: true });
  const agent = await ctx.store.agentByAddress(headers['simon-agent']!);
  const now = ctx.now();
  const held = agent?.keys.find(k => k.key === headers['simon-key']) ?? null;
  const authorized =
    agent && !agent.retiredAt && (!agent.authorizedKeys || agent.authorizedKeys.includes(headers['simon-key']));
  // Preserve a recorded revocation's diagnostic only when it must reject at this same verification time.
  // A retired or privately excluded key whose historical interval is still open remains unknown here.
  const revoked = held?.revoked != null && Date.parse(held.revoked) <= now.getTime();
  const key = authorized || revoked ? held : null;
  await verifySigned(ctx, req, headers, key, now);
  return { agent: agent!, key: key! };
}

/** The agent here that signed this request, named by its `simon-agent`, or a 401. */
export const authenticateAgent = async (ctx: Context, req: Request): Promise<Agent> =>
  (await authenticateAgentKey(ctx, req)).agent;

/**
 * A call authorised by what it carries rather than by its key (spec section 8, "Exceptions": register,
 * unpair, a cancel by code) may name no agent. When it names one, that must be `address`, the address the
 * call acts on, so the signature covers it.
 */
export function checkActor(headers: SignedHeaders, address: string | null, now: Date): void {
  if (headers['simon-agent'] !== undefined && headers['simon-agent'] !== address) {
    throw unauthorized('signature_required', 'simon-agent names another address than the one this call acts on.', now, {
      header: 'simon-agent',
    });
  }
}

/** Check the signature of such a call: any key may sign it, known here or not, and it is verified with that key. */
export const verifyAnyKey = (ctx: Context, req: Request, headers: SignedHeaders) =>
  verifySigned(ctx, req, headers, { key: headers['simon-key'], added: iso(ctx.now()), revoked: null });

/**
 * The agent, here or elsewhere, that signed this request, or a 401 (spec section 8, an agent request to
 * another server): `simon-key` must be a key of the `simon-agent` address's agent document valid now, read
 * from the server the address's domain resolves to. An agent here is read from the store. Looking up a
 * stranger's domain is charged to the client, as every lookup an unauthenticated caller causes is.
 */
export async function authenticateReader(ctx: Context, req: Request): Promise<string> {
  const now = ctx.now();
  const headers = readSignedHeaders(req.headers, now, { agent: true });
  const address = headers['simon-agent']!;
  const charge = () => ctx.rate.hit('lookup', clientKey(req.ip));
  const r = await ctx.resolver.resolve(domainOf(address), { charge });
  let keys: KeyEntry[] = [];
  if (r.outcome === 'server') {
    if (r.server === ctx.config.origin) {
      // This host's current authorization can end before a preserved historical revocation timestamp.
      const agent = await ctx.store.agentByAddress(address);
      if (agent && !agent.retiredAt)
        keys = agent.keys.filter(k => !agent.authorizedKeys || agent.authorizedKeys.includes(k.key));
    } else {
      const find = async (refresh: boolean) =>
        (await ctx.resolver.agentKeys(address, r.server, refresh, charge))?.keys ?? [];
      keys = await find(false);
      if (!keys.some(k => k.key === headers['simon-key'])) keys = await find(true);
    }
  }
  await verifySigned(ctx, req, headers, keys.find(k => k.key === headers['simon-key']) ?? null);
  return address;
}

/**
 * The origin of the server that signed this request, or a 401: `simon-key` must be a key of the
 * `simon-server` origin's server document valid now, a document this server reads itself. Anyone can name
 * any origin, so fetching it is charged to the client, as every lookup an unauthenticated caller causes is.
 */
export async function authenticateServer(ctx: Context, req: Request): Promise<string> {
  const now = ctx.now();
  const headers = readSignedHeaders(req.headers, now, { server: true, allowHttp: ctx.config.dev });
  const origin = headers['simon-server']!;
  const charge = () => ctx.rate.hit('lookup', clientKey(req.ip));
  const find = async (opts = {}) =>
    (await ctx.resolver.serverDocument(origin, { ...opts, charge }))?.keys.find(k => k.key === headers['simon-key']) ??
    null;
  await verifySigned(ctx, req, headers, (await find()) ?? (await find({ refresh: true })));
  return origin;
}

export const isServerSigned = (req: Request) => req.headers['simon-server'] !== undefined;
export const isAgentSigned = (req: Request) => req.headers['simon-agent'] !== undefined;
