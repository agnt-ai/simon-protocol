/** Helpers the check files share. */
import { readAgentDocument, type KeyEntry } from '@agnt-protocol/protocol';
import { check, poll, type CheckSpec, type T } from '../harness.ts';
import type { Ctx } from '../context.ts';
import type { TargetAgent } from '../agent.ts';

/** Declare a check that gets the shared context. */
export const def = (spec: CheckSpec, run: (t: T, ctx: Ctx) => Promise<void>) => check<Ctx>(spec, run);

/** The agent document of `address` on the server, as section 4 reads it (null when unreadable). */
export async function agentDocument(t: T, ctx: Ctx, address: string, label = 'agent document') {
  const { doc } = await ctx.serverDoc();
  const res = await t.http({ method: 'GET', origin: ctx.origin, target: `/agnt/agents/${address}` }, { label });
  const read = res.status === 200 ? readAgentDocument(res.bytes, address, doc.keys, new Date(ctx.now())) : null;
  return { res, read };
}

export interface SyncEntry {
  id: string;
  message: Record<string, any>;
  carrier: string;
  claims: Record<string, any>[];
  signedClaims?: { claims: Record<string, any>[]; signature: string };
  receivedAt: string;
}

/** Read retained messages from sync (up to 2000 entries), following opaque tokens. */
export async function readSync(t: T, a: TargetAgent, label = 'sync'): Promise<SyncEntry[]> {
  const out: SyncEntry[] = [];
  let since: string | undefined;
  for (let page = 0; page < 10; page++) {
    const res = await a.sync(t, `limit=200${since === undefined ? '' : `&since=${encodeURIComponent(since)}`}`, label);
    t.status(res, 200, 'reading sync');
    const b = res.json;
    t.assert(Array.isArray(b?.messages), `the sync answer has no messages array: ${res.text.slice(0, 200)}`);
    t.assert(typeof b.token === 'string' && b.token.length > 0, 'sync has no opaque token');
    t.assert(typeof b.more === 'boolean', 'sync has no boolean more');
    out.push(...b.messages);
    if (!b.more) return out;
    t.assert(b.token !== since, 'sync reports more without moving its token');
    since = b.token;
  }
  t.fail('sync still reports more after 2000 entries; refusing to return a truncated stream');
}

/** Wait until a message with this id is in the agent's sync stream; the entry, or undefined. Shows the last read. */
export async function awaitSync(t: T, a: TargetAgent, id: string, ms: number) {
  const s = t.scratch();
  try {
    return await poll(
      async () => (await readSync(s, a, `sync, looking for ${id.slice(0, 12)}`)).find(e => e.id === id),
      ms,
      500,
    );
  } finally {
    t.adopt(s.exchanges.slice(-1));
  }
}

/** Whether a key entry lists this token. */
export const lists = (keys: readonly KeyEntry[] | undefined, token: string) => !!keys?.some(k => k.key === token);
