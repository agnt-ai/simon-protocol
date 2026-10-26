/**
 * Notices: a message from this server itself to an agent here (CLIENT.md register, recovery). It is an
 * ordinary signed message, from `postmaster@<the agent's domain>`, a solo agent this server keeps for
 * itself with a key held in its store, so a reader verifies it as it verifies any other. It goes straight
 * into the inbox: no policy stands between a server and its own agent.
 */
import crypto from 'node:crypto';
import {
  b64url,
  domainOf,
  fromB64url,
  keyToken,
  messageId,
  privateKeyFromSeed,
  signMessage,
  timestamp,
  type Message,
  VERSION,
} from '@agnt-sdk/simon-protocol';
import { iso, later, type Context } from './context.ts';
import { takeIntoInbox } from './fanout.ts';

/** The local part this server writes notices as, on every domain it serves; no agent may register it. */
export const POSTMASTER = 'postmaster';

const DAY_MS = 86_400_000;

/** Put a notice in the inbox. True confirms residence; false means the host identity is unavailable. Store failures throw. */
export async function notify(ctx: Context, address: string, text: string): Promise<boolean> {
  const { store, now: clock } = ctx;
  const now = clock();
  const from = `${POSTMASTER}@${domainOf(address)}`;
  const seed = await store.valueOnce('postmaster-key', from, b64url(crypto.randomBytes(32)), null, iso(now));
  const key = privateKeyFromSeed('ed25519', fromB64url(seed)!);
  const token = keyToken(key);
  await store.createAgent({
    address: from,
    kind: 'solo',
    principal: null,
    keys: [{ key: token, added: iso(now), revoked: null }],
    mailbox: false,
    createdAt: iso(now),
    retiredAt: null,
  });
  const author = await store.agentByAddress(from);
  if (
    !author ||
    author.kind !== 'solo' ||
    author.principal !== null ||
    author.retiredAt ||
    (author.authorizedKeys && !author.authorizedKeys.includes(token)) ||
    !author.keys.some(k => k.key === token && k.revoked === null)
  ) {
    ctx.log('warn', 'no notice: the postmaster identity is unavailable', { address, from });
    return false;
  }
  const message = signMessage<Message>(
    {
      v: VERSION,
      from,
      to: [address],
      inReplyTo: null,
      parts: [{ type: 'text/plain', data: text }],
      headers: {},
      sentAt: timestamp(now),
    },
    key,
  );
  const record = await store.putMessage({
    id: messageId(message),
    message,
    carrier: ctx.config.origin,
    claims: [],
    signedClaims: null,
    receivedAt: iso(now),
    expiresAt: later(now, ctx.config.retentionDays * DAY_MS),
  });
  const added = await takeIntoInbox(ctx, address, record);
  return added || (await store.inInbox(address, record.id));
}
