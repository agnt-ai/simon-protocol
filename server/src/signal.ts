/**
 * `POST /simon/signal` (spec section 6.4): a short-lived note from another server about a message, checked in
 * the section's order, answering the first failure:
 *
 *   1-3  body size and parse, shape, and the signal for this server, with no lookup     (parseSignal)
 *   4    the `from` domain resolves to another server                                  (403 otherwise)
 *   5    the signal verifies with that server's keys valid now
 *   6    every recipient on a domain served here
 *   7    `at` within 300 seconds
 *   8    202, whatever happens next
 *
 * After the answer, which signals reach whom is this server's own policy (any server may drop any signal):
 * this one passes a signal to a recipient here who holds the message it is about, from that message's author
 * or one of its recipients, and drops the rest (docs/REFERENCE-SERVER.md). Nothing
 * keeps it beyond five minutes: it enters the recipient's sync stream and is told to the extensions' `signal` listeners, which show it now or never, and is then gone.
 */
import {
  canonicalBytes,
  checkServed,
  checkSignalFreshness,
  domainOf,
  forbidden,
  invalid,
  isAddress,
  isHeaderName,
  isJsonObject,
  parseJson,
  signSignal,
  parseSignal,
  signedByAny,
  signingBytes,
  type ServerDocument,
  type Signal,
} from '@agnt-sdk/simon-protocol';
import { authenticateAgent } from './auth.ts';
import { conflict } from './errors.ts';
import { iso, later, type Context } from './context.ts';
import { servedDomains } from './deliver.ts';
import { json, type Reply, type Request } from './http.ts';
import { clientKey, networkKey } from './net/ip.ts';
import type { Charge } from './resolver.ts';
import { changed } from './sync.ts';

const ACCEPTED = { accepted: true };

export async function signal(ctx: Context, req: Request): Promise<Reply> {
  const client = clientKey(req.ip);
  const charge: Charge = () => ctx.rate.hit('lookup', client);
  const { origin, dev: allowHttp, limits } = ctx.config;
  const s = parseSignal(req.body, { origin, allowHttp }, limits);

  const domain = domainOf(s.from);
  const peer = await ctx.resolver.peer(domain, charge);
  if (peer.outcome !== 'server' || peer.server === origin) {
    throw forbidden('bad_signature', `${domain} names no other SIMON server, so no signal from it verifies.`);
  }
  const failures = `${client} ${peer.server}`;
  ctx.rate.check('badSignature', failures);
  const bytes = signingBytes('SIMON-SIGNAL', s);
  const signs = (doc: ServerDocument | null) => !!doc && signedByAny(doc.keys, ctx.now(), bytes, s.signature);
  if (!signs(peer.document) && !signs(await ctx.resolver.serverDocument(peer.server, { refresh: true, charge }))) {
    ctx.rate.hit('badSignature', failures);
    throw forbidden('bad_signature', `The signal is not signed by a key of ${peer.server} valid now.`);
  }
  ctx.rate.hit('deliver', peer.server);

  const carrier = {
    carrier: peer.server,
    network: networkKey(req.ip),
    charge: () => ctx.rate.hit('carrierLookup', peer.server),
  };
  checkServed(s.to, await servedDomains(ctx, s.to, carrier), 'to');
  checkSignalFreshness(s, ctx.now());
  ctx.defer(() => pass(ctx, s));
  return json(ACCEPTED, 202);
}

/** Tell the listeners of each recipient here who holds the message the signal is about, from a party to it. */
async function pass(ctx: Context, s: Signal): Promise<void> {
  const record = await ctx.store.message(s.about);
  if (!record || !(record.message.from === s.from || record.message.to.includes(s.from))) return;
  for (const recipient of s.to) {
    const agent = await ctx.store.agentByAddress(recipient);
    if (!agent || agent.retiredAt) continue;
    if (record.message.from === recipient || (await ctx.store.inInbox(recipient, record.id))) {
      await ctx.store.holdSignal(
        recipient,
        { type: s.type, from: s.from, about: s.about, at: s.at },
        later(ctx.now(), 300_000),
        iso(ctx.now()),
      );
      await changed(ctx, recipient);
      await ctx.hooks.emit('signal', { recipient, signal: s });
    }
  }
}

/** A signed-in client asks its server to carry a transient signal to parties of a held message. */
export async function sendSignal(ctx: Context, req: Request): Promise<Reply> {
  const agent = await authenticateAgent(ctx, req);
  const body = parseJson(req.body);
  if (
    !isJsonObject(body) ||
    !isHeaderName(body.type) ||
    typeof body.about !== 'string' ||
    !/^[0-9a-f]{64}$/.test(body.about) ||
    !Array.isArray(body.to) ||
    !body.to.length ||
    body.to.length > ctx.config.limits.recipients ||
    !body.to.every(isAddress) ||
    new Set(body.to).size !== body.to.length
  )
    throw invalid('A signal names a type, message id and distinct recipient addresses.');
  const type = body.type as string,
    about = body.about,
    to = body.to as string[];
  ctx.rate.hit('send', agent.address);
  const record = await ctx.store.message(about);
  if (!record || !(record.message.from === agent.address || (await ctx.store.inInbox(agent.address, about)))) {
    return json(ACCEPTED, 202);
  }
  const parties = new Set([record.message.from, ...record.message.to]);
  const recipients = to.filter(address => parties.has(address) && address !== agent.address);
  if (!(await ctx.resolver.servesHere(domainOf(agent.address)))) {
    throw conflict('address_not_served', 'This address is no longer served here.');
  }
  const at = iso(ctx.now());
  // Validate the complete signed shape and canonical size before accepting, without a recipient lookup.
  const sample = signSignal(
    { type, from: agent.address, to, about, at, server: ctx.config.origin },
    ctx.config.serverKey,
  );
  parseSignal(canonicalBytes(sample), { origin: ctx.config.origin, allowHttp: ctx.config.dev }, ctx.config.limits);
  ctx.defer(async () => {
    const groups = new Map<string, string[]>();
    const charge = () => ctx.rate.hit('lookup', clientKey(req.ip));
    for (const recipient of recipients) {
      try {
        const resolved = await ctx.resolver.resolve(domainOf(recipient), { charge });
        if (resolved.outcome !== 'server') continue;
        const group = groups.get(resolved.server) ?? [];
        group.push(recipient);
        groups.set(resolved.server, group);
      } catch {
        /* Transient signals may be dropped. */
      }
    }
    for (const [server, to] of groups) {
      try {
        const s = signSignal({ type, from: agent.address, to, about, at, server }, ctx.config.serverKey);
        if (server === ctx.config.origin) await pass(ctx, s);
        else
          await ctx.http.request({
            method: 'POST',
            url: `${server}/simon/signal`,
            headers: { 'content-type': 'application/json' },
            body: canonicalBytes(s),
            maxBytes: 16_384,
            timeoutMs: 10_000,
          });
      } catch {
        /* No retries: a signal is useful only now. */
      }
    }
  });
  return json(ACCEPTED, 202);
}
