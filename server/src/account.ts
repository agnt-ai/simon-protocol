/**
 * The agent's address and keys (CLIENT.md), beside `register` (register.ts):
 *
 *   GET    /agnt/account           the agent's address, keys, grants and pending recovery
 *   POST   /agnt/keys              a key added, by the new key's proof
 *   DELETE /agnt/keys/<key>        a key revoked: by itself or a key added before it, never the agent's last
 *   DELETE /agnt/grants/<id>       none: this server keeps no key to sign for an agent, so it offers no grants
 *   POST   /agnt/recovery/cancel   a pending recovery cancelled: by a key the agent held before it started,
 *                                  once in 30 days, or by the cancel code sent to the address
 *   POST   /agnt/unpair            a key principal's unpairing: the address retires, whatever its keys say
 *
 * A cancel by code and an unpairing are authorised by what they carry, so any key may sign them (spec
 * section 8, "Exceptions"); every other call is signed by a key the agent holds. Ranking keys by age and
 * letting a key cancel once in 30 days are this server's practice, CLIENT.md's "Recommended host practice".
 */
import crypto from 'node:crypto';
import {
  addKeyProofString,
  canonicalBytes,
  invalid,
  isJsonObject,
  isPublicKey,
  normalizeAddress,
  parseJson,
  readSignedHeaders,
  unauthorized,
  verify,
  verifyUnpairing,
  WireError,
  type Json,
} from '@agnt-protocol/protocol';
import { authenticateAgent, authenticateAgentKey, checkActor, verifyAnyKey } from './auth.ts';
import { iso, type Context } from './context.ts';
import { badRequest, conflict, notFound } from './errors.ts';
import { json, type Reply, type Request } from './http.ts';
import { agentDocument } from './public.ts';
import type { Agent, AgentKey } from './store/store.ts';

/** The value scope of an address's pending recovery. */
export const RECOVERY = 'recovery';
/**
 * The value scope of a cancel code, by the address and the code's hash: the nonce of the recovery it
 * cancels. A recovery may have several, one for each time the address was told of it.
 */
export const CANCEL_CODE = 'recovery-cancel-code';
/** The mark scope of an address whose recovery a key cancelled, kept 30 days. */
const KEY_CANCELLED = 'recovery-cancelled-by-key';
const KEY_CANCEL_MS = 30 * 86_400_000;
const LABEL_CHARACTERS = 64;

/** A recovery by the address's mailbox, waiting until `completesAt` (register.ts). */
export interface Recovery {
  /** The key that proved the code, which repeats the call to complete it, and that code's hash and nonce. */
  key: string;
  hash: string;
  nonce?: string;
  startedAt?: string;
  completesAt: string;
  /** Whether a key may cancel it: not when it started within 30 days after a recovery a key cancelled. */
  byKey?: boolean;
  cancelHash?: string;
  keyCancelBlocked?: true;
  /** Private preparation gate: explicit false cannot replace keys even if rollback is unavailable. */
  defended?: boolean;
}

export type Body<Member extends string> = Partial<Record<Member, string>> & Record<string, Json | undefined>;

/**
 * A body of these calls: a JSON object whose members named in `members` are strings when present. Other
 * members are ignored, unless an extension defines them.
 */
export function readBody<Member extends string>(bytes: Buffer, members: readonly Member[]): Body<Member> {
  const body = parseJson(bytes);
  if (!isJsonObject(body)) throw invalid('The body is a JSON object.', { field: 'body' });
  for (const name of members) {
    if (body[name] !== undefined && typeof body[name] !== 'string') {
      throw invalid(`${name} is a string when present.`, { field: name });
    }
  }
  return body as Body<Member>;
}

export const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');

/** Whether `code` is the one whose SHA-256 is `hash`, compared in constant time. */
export const matches = (code: string, hash: string) =>
  crypto.timingSafeEqual(Buffer.from(sha256(code), 'hex'), Buffer.from(hash, 'hex'));

/** Whether a key may cancel a recovery starting now: not within 30 days after a key cancelled one. */
export const keysMayCancel = async (ctx: Context, address: string) => {
  const now = iso(ctx.now());
  const cancelled = await ctx.store.value<string>('recovery-key-cancelled-at', address, now);
  const agent = await ctx.store.agentByAddress(address);
  const recent = agent?.recoveryKeyCancelledAt;
  return (
    !(await ctx.store.marked(KEY_CANCELLED, address, now)) &&
    !(await ctx.store.marked('recovery-key-cancelled', address, now)) &&
    !(cancelled && Date.parse(cancelled) > ctx.now().getTime() - KEY_CANCEL_MS) &&
    !(recent && Date.parse(recent) > ctx.now().getTime() - KEY_CANCEL_MS)
  );
};

/** Evaluate the exact final signed projection inside the Store's atomic key admission. */
export function canPublishAgent(ctx: Context, agent: Agent): boolean {
  try {
    const doc = agentDocument(ctx, agent);
    const allActive = agent.keys.filter(k => k.revoked === null || Date.parse(k.revoked) > ctx.now().getTime());
    return (
      doc.keys.length <= 32 &&
      canonicalBytes(doc).length <= 131072 &&
      allActive.every(k => doc.keys.some(listed => listed.key === k.key))
    );
  } catch {
    return false;
  }
}

/** Whether `signer` may cancel a recovery: a key the agent held when it started and holds still. */
function mayCancel(recovery: Recovery, agent: Agent, signer: string, now: Date): boolean {
  const key = agent.keys.find(k => k.key === signer);
  return (
    !recovery.keyCancelBlocked &&
    recovery.byKey === true &&
    typeof recovery.startedAt === 'string' &&
    key !== undefined &&
    (!agent.authorizedKeys || agent.authorizedKeys.includes(signer)) &&
    (key.revoked === null || Date.parse(key.revoked) > now.getTime()) &&
    Date.parse(key.added) <= Date.parse(recovery.startedAt)
  );
}

/** The account as it stands, for the key that asked: `cancellable` says whether it may cancel the recovery. */
export async function account(ctx: Context, agent: Agent, signer: string): Promise<Reply> {
  const recovery = await ctx.store.value<Recovery>(RECOVERY, agent.address, iso(ctx.now()));
  return json({
    address: agent.address,
    keys: agent.keys,
    grants: [],
    recovery: recovery && {
      completesAt: recovery.completesAt,
      cancellable: mayCancel(recovery, agent, signer, ctx.now()),
    },
  });
}

/** The agent's state as it stands after a call that changed it. */
const accountNow = async (ctx: Context, address: string, signer: string) =>
  account(ctx, (await ctx.store.agentByAddress(address))!, signer);

export async function getAccount(ctx: Context, req: Request): Promise<Reply> {
  const { agent, key } = await authenticateAgentKey(ctx, req);
  return account(ctx, agent, key.key);
}

/** A device's key added with its own proof, so no agent lists a key it does not hold. */
export async function addKey(ctx: Context, req: Request): Promise<Reply> {
  const { agent, key: signer } = await authenticateAgentKey(ctx, req);
  const body = readBody(req.body, ['key', 'proof', 'label']);
  const key = body.key;
  if (!isPublicKey(key)) throw invalid('key is a key of an algorithm this server implements.', { field: 'key' });
  if (body.label !== undefined && [...body.label].length > LABEL_CHARACTERS) {
    throw invalid(`label is at most ${LABEL_CHARACTERS} characters.`, { field: 'label' });
  }
  if (!verify(key, addKeyProofString(agent.address, key), body.proof)) {
    throw unauthorized('bad_proof', "proof is the new key's signature over the add-key string.", ctx.now(), {
      proofString: addKeyProofString(agent.address, key),
    });
  }
  const held = agent.keys.find(k => k.key === key);
  if (held) {
    if (held.revoked !== null) throw conflict('key_in_use', 'That key was revoked, and a revoked key never returns.');
    return account(ctx, agent, signer.key);
  }
  const entry: AgentKey = { key, added: iso(ctx.now()), revoked: null };
  if (body.label !== undefined) entry.label = body.label;
  const result = await ctx.store.addKey(
    agent.address,
    entry,
    ctx.config.maxAgentKeys,
    candidate =>
      (!candidate.authorizedKeys || candidate.authorizedKeys.includes(signer.key)) &&
      candidate.keys.some(
        k => k.key === signer.key && (k.revoked === null || Date.parse(k.revoked) > ctx.now().getTime()),
      ) &&
      candidate.keys.filter(k => k.revoked === null || Date.parse(k.revoked) > ctx.now().getTime()).length <=
        ctx.config.maxAgentKeys &&
      canPublishAgent(ctx, candidate),
  );
  if (result === 'too_many_keys') {
    throw badRequest(
      'too_many_keys',
      'The key addition exceeds active-key, stored-history or published-document bounds.',
    );
  }
  // This server's policy: a key serves one address, forever, so no reader can link two addresses by it.
  if (result === 'key_in_use') throw conflict('key_in_use', 'That key belongs to another agent.');
  return accountNow(ctx, agent.address, signer.key);
}

/**
 * A key revoked at once. Keys rank by age: a key may revoke itself and any key added after it, never one
 * added before it, so a thief who copies a newer device's key cannot evict the older ones.
 */
export async function revokeKey(ctx: Context, req: Request): Promise<Reply> {
  const { agent, key: signer } = await authenticateAgentKey(ctx, req);
  const rank = (key: string) => agent.keys.findIndex(k => k.key === key);
  const target = agent.keys.find(k => k.key === req.params.key);
  if (!target || target.revoked !== null) throw notFound('This agent holds no such active key.');
  if (rank(target.key) < rank(signer.key)) {
    throw conflict('key_senior', 'A key may revoke itself and keys added after it, never one added before it.');
  }
  const result = await ctx.store.revokeKey(
    agent.address,
    target.key,
    iso(ctx.now()),
    candidate =>
      (!candidate.authorizedKeys || candidate.authorizedKeys.includes(signer.key)) &&
      candidate.keys.some(
        k => k.key === signer.key && (k.revoked === null || Date.parse(k.revoked) > ctx.now().getTime()),
      ),
  );
  if (result === 'not_found') throw notFound('This agent holds no such active key.');
  if (result === 'last_key') throw conflict('last_key', "That is the agent's last active key.");
  ctx.log('info', 'key revoked', { address: agent.address });
  return accountNow(ctx, agent.address, signer.key);
}

export async function endGrant(ctx: Context, req: Request): Promise<Reply> {
  await authenticateAgent(ctx, req);
  throw notFound('This server offers no grants.');
}

/** A pending recovery cancelled by a key of the agent (`{}`), or by its cancel code (`{"address","cancelCode"}`). */
export async function cancelRecovery(ctx: Context, req: Request): Promise<Reply> {
  const body = readBody(req.body, ['address', 'cancelCode']);
  if (body.cancelCode !== undefined) return cancelByCode(ctx, req, body.address, body.cancelCode);
  const { agent, key } = await authenticateAgentKey(ctx, req);
  const now = ctx.now();
  const recovery = await ctx.store.value<Recovery>(RECOVERY, agent.address, iso(now));
  if (!recovery) throw notFound('No recovery of this address is pending.');
  if (!mayCancel(recovery, agent, key.key, now)) {
    throw conflict(
      'recovery_not_cancellable',
      'A key may cancel a recovery only if the agent held it when the recovery started, and once in 30 days; ' +
        'the cancel code sent to the address cancels any.',
    );
  }
  if (
    !(await ctx.store.cancelRecovery(
      agent.address,
      recovery,
      iso(now),
      candidate => mayCancel(recovery, candidate, key.key, now),
      iso(now),
    ))
  ) {
    throw notFound('No cancellable recovery of this address is pending.');
  }
  ctx.log('info', 'recovery cancelled by a key', { address: agent.address });
  // Whoever holds the mailbox learns of it: a thief with a stolen key delays them once, never for good.
  await ctx.mailbox?.(agent.address, { type: 'recoveryCancelled' });
  return json({ status: 'cancelled', address: agent.address });
}

/**
 * A cancel code sent with the news of a recovery cancels that recovery while it is pending. It is never
 * locked by wrong tries, which would let anyone disarm it, and every refusal is the same 422, so no
 * stranger learns whether an address is being recovered.
 */
async function cancelByCode(ctx: Context, req: Request, address: string | undefined, cancelCode: string) {
  const now = ctx.now();
  const headers = readSignedHeaders(req.headers, now, { agent: true, optionalAgent: true });
  const named = normalizeAddress(address);
  if (named === null) throw invalid('address is the address whose recovery the code cancels.', { field: 'address' });
  checkActor(headers, named, now);
  await verifyAnyKey(ctx, req, headers);
  const recovery = await ctx.store.value<Recovery>(RECOVERY, named, iso(now));
  const cancels = await ctx.store.value<string>(CANCEL_CODE, `${named}\n${sha256(cancelCode)}`, iso(now));
  const legacyMatches = recovery?.cancelHash !== undefined && matches(cancelCode, recovery.cancelHash);
  if (!recovery || !(legacyMatches || (recovery.nonce !== undefined && cancels === recovery.nonce))) {
    throw new WireError(422, 'wrong_code', 'That cancel code cancels no pending recovery.');
  }
  if (!(await ctx.store.cancelRecovery(named, recovery, iso(now))))
    throw new WireError(422, 'wrong_code', 'That cancel code cancels no pending recovery.');
  ctx.log('info', 'recovery cancelled by its cancel code', { address: named });
  return json({ status: 'cancelled', address: named });
}

/**
 * A key principal ends its pairing: the address retires at once, its keys revoked, whatever they say. The
 * unpairing is the authority, so any key may sign the request; a repeat answers as the first call did.
 */
export async function unpair(ctx: Context, req: Request): Promise<Reply> {
  const now = ctx.now();
  const headers = readSignedHeaders(req.headers, now, { agent: true, optionalAgent: true });
  const body = readBody(req.body, ['address', 'unpairing']);
  const named = normalizeAddress(body.address);
  checkActor(headers, named, now);
  await verifyAnyKey(ctx, req, headers);
  const agent = named === null ? null : await ctx.store.agentByAddress(named);
  // One answer for every refusal, with nothing in it: a principal is shown only to its agent's recipients.
  if (!agent?.principal || !verifyUnpairing(agent.address, agent.principal, body.unpairing)) {
    throw unauthorized(
      'bad_proof',
      "unpairing is the key principal's signature over AGNT-UNPAIR, the address and the principal.",
      now,
    );
  }
  if (!agent.retiredAt) {
    await ctx.store.retireAgent(agent.address, iso(now), body.unpairing);
    ctx.log('info', 'unpaired by its principal', { address: agent.address });
  }
  return json({ status: 'retired', address: agent.address });
}

/** Recovery status is reserved to a currently authorized agent key. */
export async function getRecovery(ctx: Context, req: Request): Promise<Reply> {
  const { agent, key } = await authenticateAgentKey(ctx, req);
  const r = await ctx.store.value<Recovery>(RECOVERY, agent.address, iso(ctx.now()));
  return json({
    recovery: r ? { completesAt: r.completesAt, cancellable: mayCancel(r, agent, key.key, ctx.now()) } : null,
  });
}
