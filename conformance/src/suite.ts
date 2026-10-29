/**
 * The SIMON Protocol conformance suite: black-box checks of any server, over HTTP, with a simulated peer
 * server on localhost that delivers to it and receives from it.
 *
 *   const report = await runConformance({ server: 'http://127.0.0.1:8080' });
 *
 * The server under test must resolve the peer's domain (default `peer.test`) to the peer's origin
 * (default `http://127.0.0.1:47100`). Every check is declared in `checks/` with its id, spec section,
 * level and expectation; `catalog()` lists them, in the order they run.
 */
import './checks/documents.ts';
import './checks/requests.ts';
import './checks/deliver.ts';
import './checks/register.ts';
import './checks/account.ts';
import './checks/keys.ts';
import './checks/send.ts';
import './checks/sync.ts';
import './checks/webhooks.ts';
import './checks/signals.ts';
import './checks/outbound.ts';
import './checks/parts.ts';
import './checks/public.ts';
import './checks/discovery.ts';
import './checks/reading.ts';
import './checks/security.ts';
import './checks/errors.ts';
import { early, retried } from './checks/outbound.ts';
import { remoteParts } from './checks/parts.ts';
import { Ctx, DEFAULTS, type Options } from './context.ts';
import {
  catalog,
  CheckFailure,
  CheckSkip,
  registered,
  summarize,
  T,
  type CheckResult,
  type CheckSpec,
  type Report,
} from './harness.ts';
import { fetchServerKeys, type Peer } from './peer.ts';

export { catalog, DEFAULTS, type CheckResult, type CheckSpec, type Options, type Report };

export const SUITE = 'simon-conformance 0.3.0';
export const SPEC = 'SIMON Protocol version 1 (draft): spec/protocol.md, spec/client.md';

const selected = (id: string, only: string[]) =>
  only.length === 0 || only.some(o => id === o || id.startsWith(o.endsWith('.') ? o : `${o}.`));

/**
 * Scenarios that take minutes of the server's time (a retry after a 503, a message dated ahead, parts a
 * server may wait a few minutes to fetch): each starts early, when a check that needs it is selected, and
 * its checks read what it saw later in the run.
 */
const BACKGROUND: [(id: string) => boolean, (ctx: Ctx) => Promise<unknown>][] = [
  [id => id === 'outbound.retry' || id.startsWith('sent.'), retried],
  [id => id === 'outbound.not-before-sent-at', early],
  [
    id => ['parts.prefetch', 'parts.recipient-fetch', 'parts.server-request', 'parts.hash-checked'].includes(id),
    remoteParts,
  ],
];

export async function runConformance(
  input: Partial<Options> & { server: string },
  hooks: { onCheck?: (r: CheckResult) => void } = {},
): Promise<Report> {
  const opts: Options = { ...DEFAULTS, ...input };
  const ctx = new Ctx(opts);
  const startedAt = new Date().toISOString();
  for (const peer of [ctx.peer, ctx.secondPeer]) {
    try {
      await peer?.start();
    } catch (e) {
      await ctx.peer.stop();
      throw new Error(`The peer simulator could not listen on ${peer!.host}:${peer!.port}: ${(e as Error).message}`);
    }
  }
  // A server that tries a tunnel's name before it resolves may remember that it does not; so the suite first
  // reaches each simulator at its origin itself, as the server will.
  for (const peer of [ctx.peer, ctx.secondPeer]) {
    if (peer && !(await answersAtOrigin(peer))) {
      await Promise.all([ctx.peer.stop(), ctx.secondPeer?.stop()]);
      throw new Error(
        `The peer simulator does not answer at ${peer.origin}; is the tunnel to ${peer.host}:${peer.port} up?`,
      );
    }
  }
  const results: CheckResult[] = [];
  try {
    await ctx.calibrate().catch(e => ctx.notes.push(`Could not read the server's clock: ${(e as Error).message}`));
    const checks = registered().filter(c => selected(c.id, opts.only));
    // The background scenarios start early and are checked later; but only after the check that needs the
    // server not to have fetched the simulator's server document yet.
    const firstFetch = 'deliver.server-document-unavailable';
    let kickoff: Promise<unknown> | undefined;
    const start = () =>
      (kickoff ??= Promise.all(
        BACKGROUND.filter(([wanted]) => checks.some(c => wanted(c.id))).map(([, run]) =>
          run(ctx).catch(() => undefined),
        ),
      ));
    if (!checks.some(c => c.id === firstFetch)) start();
    for (const c of checks) {
      const { run: _, ...spec } = c;
      const t = new T(spec, e => e.direction === 'to-target' && ctx.allExchanges.push(e), opts.rateLimitWaitMs);
      const began = Date.now();
      let status: CheckResult['status'] = 'pass';
      let observed: string | undefined;
      try {
        await c.run(t, ctx);
      } catch (e) {
        if (e instanceof CheckSkip) status = 'skip';
        else status = 'fail';
        observed =
          e instanceof CheckFailure || e instanceof CheckSkip
            ? e.message
            : `the check could not complete: ${(e as Error)?.stack ?? e}`;
      }
      const r: CheckResult = {
        ...spec,
        status,
        ...(observed ? { observed } : {}),
        exchanges: t.exchanges,
        ms: Date.now() - began,
      };
      results.push(r);
      hooks.onCheck?.(r);
      if (c.id === firstFetch) start();
    }
    await kickoff;
  } finally {
    await ctx.peer.stop();
    await ctx.secondPeer?.stop();
    await ctx.close();
  }
  return {
    suite: SUITE,
    spec: SPEC,
    target: { server: opts.server, origin: ctx.origin },
    peer: { domain: opts.peerDomain, origin: ctx.peer.origin },
    startedAt,
    finishedAt: new Date().toISOString(),
    summary: summarize(results),
    setup: { notes: ctx.notes, exchanges: ctx.setupExchanges },
    checks: results,
  };
}

/** The areas checks are grouped in, by the first part of their id. */
export const AREAS: Record<string, string> = {
  documents: 'Documents (PROTOCOL 4)',
  requests: 'Signed requests (PROTOCOL 8)',
  deliver: 'Deliver, received from the simulator (PROTOCOL 6)',
  register: 'register (CLIENT)',
  send: 'send (CLIENT)',
  account: 'Account and recovery (CLIENT)',
  keys: 'Keys (CLIENT)',
  sync: 'sync (CLIENT)',
  webhooks: 'Webhooks (CLIENT)',
  signal: 'Signals, received from the simulator (PROTOCOL 6.4)',
  outbound: 'Deliver, sent to the simulator (PROTOCOL 6)',
  sent: 'sent (CLIENT)',
  parts: 'Parts (CLIENT parts, PROTOCOL 7.2)',
  public: 'Published messages, feeds and relations (publishing profile; must for a server that publishes)',
  discovery: 'Lookups (discovery profile; must for a server that answers them)',
  reading: 'Messages a server leaves to readers (PROTOCOL 5.4, reader profile)',
  security: 'Transport and security (PROTOCOL 9, 11.2)',
  errors: 'Errors (PROTOCOL 9, CLIENT errors)',
};

/** The check list as Markdown, grouped by area, in the order the checks run. */
export function catalogMarkdown(): string {
  const specs = catalog();
  const lines: string[] = [];
  const count = (f: (s: CheckSpec) => boolean) => specs.filter(f).length;
  lines.push(
    `${specs.length} checks: ${count(s => s.level === 'must')} must, ${count(s => s.level === 'should')} should.`,
    '',
  );
  for (const [area, title] of Object.entries(AREAS)) {
    const group = specs.filter(s => s.id.split('.')[0] === area);
    if (!group.length) continue;
    lines.push(`### ${title}`, '', '| Check | Level | Section | Expected |', '| --- | --- | --- | --- |');
    for (const s of group)
      lines.push(`| \`${s.id}\` | ${s.level} | ${s.section} | ${s.expected.replaceAll('|', '\\|')} |`);
    lines.push('');
  }
  return lines.join('\n');
}

/** Whether a simulator serves its own server document at its origin, within a minute. */
async function answersAtOrigin(peer: Peer): Promise<boolean> {
  for (const end = Date.now() + 60_000; Date.now() < end; await new Promise(r => setTimeout(r, 2000))) {
    if (await fetchServerKeys(peer.origin)) return true;
  }
  return false;
}
