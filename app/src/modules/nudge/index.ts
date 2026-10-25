/**
 * The agent-only nudge. A run of messages down one reply chain with no person consulted earns the agents
 * here in the thread a notice from `notices@`, at every run of `SIMON_NUDGE_TURNS`: the author, if it is
 * here, and each agent here that took the message, each with a notice of its own naming nobody else.
 * Delivery never stops: whether to wrap up, ask a person, or carry on is the agents' call.
 *
 * A message's run is its parent's plus one, or zero when a person was consulted, so it is the same however
 * often or in whatever order it is counted. A `human-consulted` header is only its sender's word, so on its
 * own it resets nothing. It resets the run when evidence stands behind it that a person saw or approved it:
 *
 *   - the author's person marked the message it answers consulted in the owner window (for an author here);
 *     or
 *   - the header's value is the signature, by the author's key principal (its pairing carried and
 *     verifying), over `SIMON-HUMAN-CONSULTED\n<from>\n<id>`, where `<id>` is the id the message would have
 *     without the header (spec/registry.md), which any server can check.
 *
 * Hooks: on.stored (the author), on.inbox (each recipient).
 */
import {
  header,
  messageId,
  principalKey,
  verify,
  verifyPairing,
  type Message,
  VERSION,
} from '@agnt-sdk/simon-protocol';
import type { ServerApi, StoredMessage } from '@agnt-sdk/simon-server';
import type { Ctx, Module } from '../../context.ts';

/** The bytes a key principal signs to say they saw or approved `from`'s message `id` (its id without the header). */
export const consultedBytes = (from: string, id: string) => `SIMON-HUMAN-CONSULTED\n${from}\n${id}`;

/** The id a message would have without its `human-consulted` header: the one its principal signs. */
function unconsultedId(m: Message): string {
  const { 'human-consulted': _, ...headers } = m.headers;
  return messageId({ ...m, headers });
}

/** Whether `signature` is the author's key principal's, over the message, its pairing carried and counting now. */
function signedByPrincipal(m: Message, signature: string, now: Date): boolean {
  const principal = header(m, 'for');
  const key = principal && principalKey(principal);
  return (
    !!key &&
    verifyPairing(m.from, principal, header(m, 'pairing'), now) &&
    verify(key, consultedBytes(m.from, unconsultedId(m)), signature)
  );
}

/** The owner window's evidence: the person behind `address` saw the thread up to message `id`. */
export const markConsulted = (api: ServerApi, address: string, id: string, expiresAt: string) =>
  api.store.mark('consulted', `${address}\n${id}`, expiresAt, api.now().toISOString());

export function nudgeModule(ctx: Ctx): { module: Module } {
  /** Whether a person stands behind the message's `human-consulted` header. */
  async function consulted(record: StoredMessage): Promise<boolean> {
    const m = record.message as Message;
    const claim = header(m, 'human-consulted');
    if (!claim) return false;
    if (signedByPrincipal(m, claim, ctx.api.now())) return true;
    const { api } = ctx;
    return (
      !!m.inReplyTo &&
      record.carrier === ctx.config.server.origin &&
      api.store.marked('consulted', `${m.from}\n${m.inReplyTo}`, api.now().toISOString())
    );
  }

  async function runOf(record: StoredMessage): Promise<number> {
    const m = record.message as Message;
    if (m.v !== VERSION || (await consulted(record))) return 0;
    const { store } = ctx.api;
    const parent = m.inReplyTo ? await store.value<number>('nudge-run', m.inReplyTo, ctx.now().toISOString()) : null;
    return store.valueOnce('nudge-run', record.id, (parent ?? 0) + 1, record.expiresAt, ctx.now().toISOString());
  }

  async function nudge(address: string, record: StoredMessage) {
    if (ctx.system.isSystem(record.message.from) || ctx.system.isSystem(address)) return;
    const run = await runOf(record);
    if (run === 0 || run % ctx.config.nudge.turns !== 0) return;
    if (!(await ctx.api.store.mark('nudged', `${address}\n${record.id}`, record.expiresAt, ctx.now().toISOString())))
      return;
    await ctx.system.notify(
      [address],
      'agent-only-run',
      `This thread has run ${run} messages with no person consulted on any side.`,
      { turns: run },
      record.id,
    );
  }

  return {
    module: {
      name: 'nudge',
      hooks: {
        on: {
          stored: ({ message }) =>
            message.carrier === ctx.config.server.origin ? nudge(message.message.from, message) : undefined,
          inbox: ({ address, message }) => nudge(address, message),
        },
      },
    },
  };
}
