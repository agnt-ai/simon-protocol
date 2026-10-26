/**
 * `POST /simon/register` (CLIENT.md): creation/pairing for a key; recovery uses its own resource. The call is signed by the key it
 * registers, which it carries as `key`.
 *
 *   with no address                        an address leased on the lease domain
 *   with an address on a hosted domain     that name, at once
 *   with an address resolving here         a code sent to it; the same call with `code` binds the key
 *   POST /simon/recovery for a held address  the code exchange recovers it: the new key replaces all,
 *                                          after a wait while the agent still holds a valid key, which
 *                                          the agent is told of and the address may cancel (account.ts)
 *   recovery with `recover` and `at`       a key principal recovers its agent at once, whatever the
 *                                          agent's keys and any pending recovery say
 *
 * Names on hosted domains and leases are this server's to give, so an extension's `allowAddress` may
 * refuse one to a key. The call that creates an address may pair it with a principal (`for`): a key
 * principal by its `pairing` signature, any other kind through an extension's `verifyPrincipal`. Every path
 * repeats safely: once a key is registered, the same call returns the same agent. Success answers the
 * account (account.ts).
 */
import crypto from 'node:crypto';
import {
  b64url,
  domainOf,
  invalid,
  isPrincipal,
  isPublicKey,
  normalizeAddress,
  pairingBytes,
  parsePairing,
  parseTimestamp,
  principalKey,
  readSignedHeaders,
  SEND_WINDOW_MS,
  SENT_AT_FUTURE_MS,
  unauthorized,
  verifyPairing,
  verifyRecovery,
  WireError,
  type Json,
} from '@agnt-sdk/simon-protocol';
import {
  account,
  canPublishAgent,
  CANCEL_CODE,
  keysMayCancel,
  matches,
  readBody,
  RECOVERY,
  sha256,
  type Body,
  type Recovery,
} from './account.ts';
import { checkActor, verifyAnyKey } from './auth.ts';
import { iso, later, type Context } from './context.ts';
import { badRequest, conflict, notFound, unavailable } from './errors.ts';
import { json, type Reply, type Request } from './http.ts';
import { clientKey } from './net/ip.ts';
import { notify, POSTMASTER } from './notice.ts';
import type { Agent } from './store/store.ts';

export const CODE_TTL_MS = 15 * 60_000;
const CODE_ATTEMPTS = 5;
/** Role mailboxes of RFC 2142, kept by the server on every domain it serves; it writes notices as postmaster. */
const RESERVED = new Set([POSTMASTER, 'hostmaster', 'webmaster', 'abuse', 'security', 'noc']);
/** A waiting recovery can be completed this long after it may complete, then it lapses. */
const RECOVERY_KEPT_MS = 7 * 86_400_000;

const MEMBERS = ['key', 'address', 'code', 'for', 'pairing', 'recover', 'at'] as const;
type RegisterBody = Body<(typeof MEMBERS)[number]>;

/**
 * A mailbox challenge is bound to the account's recovery epoch when it was issued (Agent.recoveryEpoch).
 * Only a recovery ending or authority being reset advances it, never a key added or revoked, so a thief
 * holding a key cannot void the owner's code (CLIENT.md: "delay the mailbox's holder once, never for good").
 */
interface CodeChallenge {
  hash: string;
  nonce: string;
  /** Null means no account existed; an existing account starts at epoch zero. */
  recoveryEpoch: number | null;
}

export const register = (ctx: Context, req: Request) => lifecycle(ctx, req, false);
export const recover = (ctx: Context, req: Request) => lifecycle(ctx, req, true);

/** Creation and recovery share proofs/codes, but never silently select one another's authority. */
async function lifecycle(ctx: Context, req: Request, recovering: boolean): Promise<Reply> {
  const now = ctx.now();
  const headers = readSignedHeaders(req.headers, now, { agent: true, optionalAgent: true });
  const body = readBody(req.body, MEMBERS);
  const key = headers['simon-key'];
  if (body.key !== key) throw invalid('key is the key signing this call.', { field: 'key' });
  if (!isPublicKey(key)) throw invalid('key is not a supported public key.', { field: 'key' });
  // Prove possession before any lookup-dependent diagnostic or actor comparison.
  await verifyAnyKey(ctx, req, headers);
  const named = body.address === undefined ? null : normalizeAddress(body.address);
  const holder = await ctx.store.agentByKey(key);
  checkActor(headers, named ?? holder?.address ?? null, now);
  if (recovering) {
    if (!named) throw invalid('address names the account to recover.', { field: 'address' });
    if (body.recover !== undefined) return principalRecovery(ctx, key, body);
  } else if (body.recover !== undefined || body.at !== undefined) {
    throw invalid('Recovery uses POST /simon/recovery.', { field: 'recover' });
  }
  if (holder) {
    const held = holder.keys.find(k => k.key === key)!;
    if (holder.retiredAt || held.revoked !== null) throw conflict('key_in_use', 'That key cannot be registered again.');
    if (named !== null && holder.address !== named) throw conflict('key_in_use', 'That key is already bound.');
    if (!recovering || body.code !== undefined) return repeat(ctx, holder, key, body);
  }
  if (body.code === undefined) ctx.rate.hitClient('register', req.ip);
  if (body.address === undefined) return lease(ctx, key, body);
  if (!named) throw invalid('address is local@domain.', { field: 'address' });
  const domain = domainOf(named);
  if (RESERVED.has(named.slice(0, named.lastIndexOf('@'))))
    throw conflict('address_taken', 'That address is unavailable.');
  if (!recovering && ctx.config.hostedDomains.includes(domain))
    return create(ctx, { address: named, key, mailbox: false }, body);
  if (!recovering && domain === ctx.config.leaseDomain) {
    if (named !== leasedAddress(ctx, key)) throw conflict('address_taken', 'Names on this domain are leased.');
    return create(ctx, { address: named, key, mailbox: false }, body);
  }
  const r = await ctx.resolver.resolve(domain, {
    fresh: true,
    charge: () => ctx.rate.hit('lookup', clientKey(req.ip)),
  });
  if (r.outcome === 'temporary') throw unavailable('Could not resolve the address domain just now.');
  if (r.outcome !== 'server' || r.server !== ctx.config.origin) {
    throw conflict('address_homed_elsewhere', 'This server does not host that address.', {
      server: r.outcome === 'server' ? r.server : null,
    });
  }
  return codeExchange(ctx, req.ip, named, key, body, recovering);
}

/** A registration that succeeded, asked again. */
function repeat(ctx: Context, agent: Agent, key: string, body: RegisterBody): Promise<Reply> {
  if (body.address !== undefined && normalizeAddress(body.address) !== agent.address) {
    throw conflict('key_in_use', 'That key is already bound.');
  }
  return account(ctx, agent, key);
}

/**
 * A key principal recovers its paired agent: its signature over SIMON-RECOVER gives the address `key` at
 * once, ending every old key and any pending recovery. `at` has the window `send` gives `sentAt`, so a
 * signed recovery never used is never a standing key to the agent.
 */
async function principalRecovery(ctx: Context, key: string, body: RegisterBody): Promise<Reply> {
  const now = ctx.now();
  const at = parseTimestamp(body.at);
  if (at === null || at < now.getTime() - SEND_WINDOW_MS || at > now.getTime() + SENT_AT_FUTURE_MS) {
    throw invalid('at is a timestamp at most 24 hours old and at most 5 minutes ahead.', { field: 'at' });
  }
  const address = normalizeAddress(body.address);
  const agent = address === null ? null : await ctx.store.agentByAddress(address);
  // One answer for every refusal, as for an unpairing: a principal is shown only to its agent's recipients.
  if (
    !agent?.principal ||
    agent.retiredAt ||
    !verifyRecovery(agent.address, agent.principal, key, body.at!, body.recover)
  ) {
    throw unauthorized(
      'bad_proof',
      "recover is the key principal's signature over SIMON-RECOVER, the address, the new key and at.",
      now,
    );
  }
  const held = agent.keys.find(k => k.key === key);
  if (held?.revoked !== undefined && held.revoked !== null)
    throw conflict('key_in_use', 'That key was revoked and cannot return.');
  let recovered: Agent;
  if (held) {
    if ((await ctx.store.keepOnlyKey(agent.address, key, iso(now))) === 'not_held')
      throw conflict('key_in_use', 'That key cannot return.');
    recovered = (await ctx.store.agentByAddress(agent.address))!;
  } else recovered = await replaceKeys(ctx, agent.address, key);
  ctx.log('info', 'agent recovered by its principal', { address: agent.address });
  await ctx.hooks.emit('recovered', { address: agent.address, key, by: 'principal' });
  return account(ctx, recovered, key);
}

/** 16 base32 characters of the key's SHA-256: the same key always leases the same name. */
function leasedAddress(ctx: Context, key: string): string {
  const hash = crypto.createHash('sha256').update(key).digest();
  let bits = '';
  for (const byte of hash.subarray(0, 10)) bits += byte.toString(2).padStart(8, '0');
  const name = bits
    .match(/.{5}/g)!
    .map(b => 'abcdefghijklmnopqrstuvwxyz234567'[parseInt(b, 2)])
    .join('');
  return `${name}@${ctx.config.leaseDomain}`;
}

function lease(ctx: Context, key: string, body: RegisterBody): Promise<Reply> {
  if (!ctx.config.leaseDomain) {
    throw badRequest('address_required', 'This server leases no addresses; name one on a domain it serves.');
  }
  return create(ctx, { address: leasedAddress(ctx, key), key, mailbox: false }, body);
}

/**
 * The principal a new address pairs with: null for a solo agent, the identifier once verified, or the
 * 202 the agent answers by calling again (a key principal's signature, or an extension's own exchange).
 */
async function pairing(ctx: Context, address: string, key: string, body: RegisterBody): Promise<string | null | Reply> {
  const principal = body.for;
  if (principal === undefined) return null;
  if (!isPrincipal(principal)) throw invalid('for is a mailto:, tel: or simon-key: identifier.', { field: 'for' });
  if (principalKey(principal) !== null) {
    if (body.pairing === undefined) return json({ status: 'pairing_required', address }, 202);
    if (!verifyPairing(address, principal, body.pairing, ctx.now())) {
      const until = parsePairing(body.pairing)?.until ?? '<until>';
      throw unauthorized(
        'bad_proof',
        "pairing is <until> <signature>: the principal key's signature over the pairing string, lapsing within 366 days from now.",
        ctx.now(),
        { pairingString: pairingBytes(address, principal, until) },
      );
    }
    return principal;
  }
  const answer = await ctx.hooks.verifyPrincipal({ principal, address, key, body: body as Record<string, Json> });
  if (answer === undefined) {
    throw invalid('This server pairs agents with key principals only.', { field: 'for' });
  }
  return answer.status === 'verified' ? principal : json(answer.body, 202);
}

async function create(
  ctx: Context,
  a: { address: string; key: string; mailbox: boolean },
  body: RegisterBody,
  beforeInsert?: () => Promise<void>,
): Promise<Reply> {
  // Before any pairing step, so no principal is asked to approve, and no code is sent, for an address
  // that is held or retired.
  // One answer whether the address is held, retired or refused, so a refusal tells nothing more.
  const unavailable = () => conflict('address_taken', 'That address is held, retired, or not given to this key.');
  if (await ctx.store.agentByAddress(a.address)) throw unavailable();
  // An address with no mailbox behind it, a hosted name or a lease, is this server's to give.
  if (
    !a.mailbox &&
    (await ctx.hooks.allowAddress({ address: a.address, key: a.key, body: body as Record<string, Json> })) === 'refuse'
  ) {
    throw unavailable();
  }
  const principal = await pairing(ctx, a.address, a.key, body);
  if (principal !== null && typeof principal === 'object') return principal;
  await beforeInsert?.();
  const now = iso(ctx.now());
  const agent: Agent = {
    address: a.address,
    kind: principal === null ? 'solo' : 'paired',
    principal,
    keys: [{ key: a.key, added: now, revoked: null }],
    mailbox: a.mailbox,
    createdAt: now,
    retiredAt: null,
  };
  if (!canPublishAgent(ctx, agent))
    throw badRequest('too_many_keys', "The agent document exceeds this server\'s bounds.");
  const result = await ctx.store.createAgent(agent, candidate => canPublishAgent(ctx, candidate));
  if (result === 'address_taken') throw conflict('address_taken', 'That address belongs to another agent.');
  if (result === 'key_in_use') throw conflict('key_in_use', 'That key belongs to another agent.');
  if (result === 'too_many_keys') throw badRequest('too_many_keys', 'The agent document exceeds this server’s bounds.');
  return account(ctx, agent, a.key);
}

/**
 * The code exchange for creation or dedicated recovery on a domain resolving here. While a recovery
 * waits, asking for another challenge returns the ordinary code_sent response without sending another
 * code or reminder. Existing completion/cancel authority is unchanged; valid polling spends no attempts.
 */
async function codeExchange(
  ctx: Context,
  ip: string,
  address: string,
  key: string,
  body: RegisterBody,
  recovering: boolean,
) {
  const holder = await ctx.store.agentByAddress(address);
  if (holder && (!recovering || !holder.mailbox || holder.retiredAt)) {
    throw conflict('address_taken', 'That address belongs to another agent and cannot be recovered by code.');
  }
  if (!ctx.mailbox) throw invalid('This server binds no addresses by code.', { field: 'address' });
  const now = ctx.now();
  const id = [recovering ? 'recovery' : 'register', address, key].join('\n');
  const recoveryEpoch = holder ? (holder.recoveryEpoch ?? 0) : null;
  const recovery = holder && (await ctx.store.value<Recovery>(RECOVERY, address, iso(now)));
  if (body.code === undefined) {
    // Counted per client first, so a client past its own limit spends no address's allowance.
    ctx.rate.hitClient('codeClient', ip);
    ctx.rate.hit('code', address);
    const code = String(crypto.randomInt(100_000_000)).padStart(8, '0');
    const expires = later(now, CODE_TTL_MS);
    await ctx.store.setValue('code', id, { hash: sha256(code), nonce: crypto.randomUUID(), recoveryEpoch }, expires);
    // While recovery waits, keep an unsent challenge with identical wrong/locked/expiry behavior.
    if (!recovery) ctx.defer(() => ctx.mailbox!(address, { type: 'code', code }));
    return json({ status: 'code_sent', address }, 202);
  }
  if (recovery?.key === key) {
    await checkCode(ctx, `${id}\n${recovery.nonce ?? `legacy:${recovery.completesAt}`}`, recovery.hash, body.code, now);
    if (recovery.defended === false) {
      // A failed preparation never becomes a takeover merely because its clock ran out.
      try {
        await ctx.store.cancelRecovery(address, recovery, iso(now));
      } catch (error) {
        ctx.log('error', 'inert recovery preparation cleanup failed', { address, error: String(error) });
      }
      throw unavailable('Recovery defenses were not confirmed; request a new code to start again.');
    }
    if (now < new Date(recovery.completesAt)) return recoveryPending(address, recovery);
    return recoverByCode(ctx, address, key, recovery);
  }
  const pending = await ctx.store.value<CodeChallenge>('code', id, iso(now));
  if (!pending) throw new WireError(410, 'code_expired', 'No code is waiting for this address and key; ask for one.');
  await checkCode(ctx, `${id}\n${pending.nonce}`, pending.hash, body.code, now);
  // Cancellation, completion, lapse and retirement atomically advance the recovery epoch. Old challenges
  // stay invalid after the pending recovery disappears, and missing/legacy bindings never inherit it.
  const binding = pending.recoveryEpoch;
  const malformed = binding !== null && (!Number.isSafeInteger(binding) || binding < 0);
  if (recovery || malformed || binding !== recoveryEpoch) throw wrongCode();
  const spend = () => ctx.store.setValue('code', id, null, iso(now));
  if (!holder) {
    if (recovering) throw notFound('No recoverable account is held at this address.');
    return create(ctx, { address, key, mailbox: true }, body, spend);
  }
  const wait = holder.keys.some(k => k.revoked === null || Date.parse(k.revoked) > now.getTime())
    ? ctx.config.recoveryWaitSeconds * 1000
    : 0;
  const proof = { hash: pending.hash, nonce: pending.nonce };
  const answer = await startRecovery(ctx, holder, key, proof, wait);
  await spend();
  return answer;
}

const wrongCode = () => new WireError(422, 'wrong_code', 'That is not the code sent.');

/**
 * The agent still holds a key, so whoever reads the mailbox waits: the agent is told at once, and the
 * address is sent a cancel code with the news, which stops the recovery whoever holds the mailbox later.
 */
async function startRecovery(
  ctx: Context,
  holder: Agent,
  key: string,
  code: { hash: string; nonce: string },
  wait: number,
): Promise<Reply> {
  const now = ctx.now(),
    address = holder.address;
  const recovery: Recovery = {
    key,
    ...code,
    startedAt: iso(now),
    completesAt: later(now, wait),
    byKey: await keysMayCancel(ctx, address),
    defended: !wait,
  };
  // Another recovery started first: the code was sent before it, so it binds no key.
  const pending = (await ctx.store.beginRecovery(
    address,
    recovery,
    keptUntil(recovery),
    iso(now),
    current =>
      (current.recoveryEpoch ?? 0) === (holder.recoveryEpoch ?? 0) &&
      current.kind === holder.kind &&
      current.principal === holder.principal &&
      !current.retiredAt,
  )) as Recovery | null;
  if (pending?.nonce !== code.nonce) {
    throw wrongCode();
  }
  if (!wait) return recoverByCode(ctx, address, key, pending);
  ctx.log('info', 'recovery by code waiting', { address, completesAt: recovery.completesAt });
  const cancel = recovery.byKey
    ? 'by POST /simon/recovery/cancel signed by a key this agent holds now, or by the cancel code sent to the address'
    : 'by the cancel code sent to the address: a key cancelled a recovery of it within 30 days, so no key can';
  let stage = 'notice';
  try {
    const notified = await notify(
      ctx,
      address,
      `A code sent to ${address} was used to replace this agent's keys with ${key}. That happens at ` +
        `${recovery.completesAt} unless it is cancelled before then, ${cancel}.`,
    );
    if (!notified) throw new Error('The owner notice could not be confirmed.');
    stage = 'cancel-code persistence';
    const cancelCode = await newCancelCode(ctx, address, recovery);
    stage = 'mailbox';
    await ctx.mailbox!(address, { type: 'recovery', key, completesAt: recovery.completesAt, cancelCode });
    stage = 'activation';
    if (!(await ctx.store.activateRecovery(address, recovery, iso(ctx.now())))) {
      throw new Error('Recovery preparation lost its exact pending authority.');
    }
  } catch (error) {
    // The Store itself also rejects defended:false completion. A rollback outage therefore leaves an
    // inert preparation, never a takeover that can complete without the promised owner defences.
    try {
      if (await ctx.store.cancelRecovery(address, recovery, iso(ctx.now()))) {
        const reason =
          stage === 'mailbox' ? 'the cancel code could not be sent' : 'the recovery defences could not be confirmed';
        await notify(ctx, address, `The recovery was dropped: ${reason}.`);
      }
    } catch (rollbackError) {
      ctx.log('error', 'recovery preparation rollback failed; completion remains disabled', {
        address,
        error: String(rollbackError),
      });
    }
    ctx.log('warn', 'recovery preparation failed', { address, stage, error: String(error) });
    throw unavailable('Recovery defences could not be confirmed; request a new code to start again.');
  }
  return recoveryPending(address, recovery);
}

const keptUntil = (r: Recovery) => later(new Date(r.completesAt), RECOVERY_KEPT_MS);

/** A cancel code of 128 random bits for a pending recovery, good while it is pending; only its hash is kept. */
async function newCancelCode(ctx: Context, address: string, recovery: Recovery): Promise<string> {
  const cancelCode = b64url(crypto.randomBytes(16));
  await ctx.store.setValue(CANCEL_CODE, `${address}\n${sha256(cancelCode)}`, recovery.nonce, keptUntil(recovery));
  return cancelCode;
}

const recoveryPending = (address: string, r: Recovery) =>
  json({ status: 'recovery_pending', address, completesAt: r.completesAt }, 202);

/** A code handed back: the one sent, within its attempts, or 410 or 422. */
export async function checkCode(ctx: Context, attempt: string, hash: string, code: string, now: Date): Promise<void> {
  // Counted before comparing, so concurrent guesses all count against the same allowance: the fifth wrong
  // guess still reports wrong_code, and every attempt after it is locked, the right code included.
  const expiry = later(now, CODE_TTL_MS);
  if ((await ctx.store.count('code-attempt', attempt, expiry, iso(now))) > CODE_ATTEMPTS)
    throw new WireError(410, 'code_locked', 'Too many wrong codes; ask for a new one.');
  if (!matches(code, hash)) throw wrongCode();
  // Only a matching attempt is given back, so valid polling of an already-proved recovery spends nothing.
  await ctx.store.count('code-attempt', attempt, expiry, iso(now), -1);
}

/** Whoever holds the mailbox now holds the agent. */
async function recoverByCode(ctx: Context, address: string, key: string, expected: Recovery): Promise<Reply> {
  const result = await ctx.store.completeRecovery(
    address,
    { key, added: iso(ctx.now()), revoked: null },
    expected,
    candidate => canPublishAgent(ctx, candidate),
  );
  if (result === 'not_pending') throw wrongCode();
  if (result === 'retired') throw conflict('address_taken', 'That address is unavailable.');
  if (result === 'too_many_keys') throw badRequest('too_many_keys', 'The agent document cannot hold another key.');
  if (result === 'key_in_use') throw conflict('key_in_use', 'That key belongs to another agent.');
  const recovered = (await ctx.store.agentByAddress(address))!;
  ctx.log('info', 'agent recovered by code', { address });
  await ctx.hooks.emit('recovered', { address, key, by: 'mailbox' });
  return account(ctx, recovered, key);
}

/** Replace an agent's keys with `key`, every old one revoked now. */
async function replaceKeys(ctx: Context, address: string, key: string): Promise<Agent> {
  const result = await ctx.store.replaceKeys(address, { key, added: iso(ctx.now()), revoked: null }, candidate =>
    canPublishAgent(ctx, candidate),
  );
  if (result === 'retired') throw conflict('address_taken', 'That address is unavailable.');
  if (result === 'too_many_keys') throw badRequest('too_many_keys', 'The agent document cannot hold another key.');
  if (result === 'key_in_use') {
    throw conflict('key_in_use', 'That key belongs to another agent.');
  }
  return (await ctx.store.agentByAddress(address))!;
}
