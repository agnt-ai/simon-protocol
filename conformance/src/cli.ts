#!/usr/bin/env node
/**
 * Run the conformance suite against a server:
 *
 *   node conformance/src/cli.ts --server http://127.0.0.1:8080
 *
 * The JSON report goes to stdout (or a text report, with --format text); a short summary goes to stderr.
 * The exit code is 1 when any `must` check failed, 2 when the suite could not run, 0 otherwise.
 * `--help` lists every option.
 */
import { parseArgs } from 'node:util';
import { serverOrigin } from '@agnt-protocol/protocol';
import { AREAS, catalog, catalogMarkdown, DEFAULTS, runConformance, type CheckResult, type Report } from './suite.ts';

const HELP = `Usage: node conformance/src/cli.ts --server <origin> [options]

The server under test must resolve the peer domain to the peer origin, for example with the basic
server's development setting SIMON_DEV_RESOLVE="peer.test=http://127.0.0.1:47100". A server elsewhere
reaches the simulator through a tunnel to the peer port: give the tunnel's https origin as --peer-origin,
and its name becomes the peer domain, resolved by the well-known answer the simulator gives.

  --server <origin>             the server under test, e.g. http://127.0.0.1:8080
  --peer-domain <domain>        the domain the server resolves to the simulator   (${DEFAULTS.peerDomain})
  --peer-host <host>            where the simulator listens                        (${DEFAULTS.peerHost})
  --peer-port <port>            the simulator's port                               (${DEFAULTS.peerPort})
  --peer-origin <origin>        where the server reaches the simulator, when not at the host and port:
                                a tunnel's https://<name>, which is then the default peer domain
  --hosted-domain <domain>      a domain whose names agents take at once, for a server that leases
                                none, and for the hosted-name checks
  --unresolvable-domain <d>     a domain that names no SIMON server                 (${DEFAULTS.unresolvableDomain})
  --code-command <command>      a shell command printing the code the server sent to an address
                                (given as $1 and SIMON_ADDRESS); enables the code and recovery checks
  --code-address <address>      an address with a mailbox on a domain resolving to the server
  --cancel-code-command <cmd>   a shell command printing the cancel code the server sent to an address
                                with the news of a recovery; enables register.cancel-code
  --retire-command <command>    a shell command retiring the agent at an address (given as $1 and
                                SIMON_ADDRESS); enables public.retired
  --second-peer-domain <d>      a second domain the server resolves to a second simulator, for the
                                one-envelope-per-server check
  --second-peer-port <port>     the second simulator's port                        (${DEFAULTS.secondPeerPort})
  --second-peer-origin <origin> where the server reaches the second simulator, as --peer-origin
  --delivery-wait <seconds>     how long to wait for a delivery                    (${DEFAULTS.deliveryWaitMs / 1000})
  --retry-wait <seconds>        how long to wait for a retry after a 503           (${DEFAULTS.retryWaitMs / 1000})
  --prefetch-wait <seconds>     how long to wait for the server to fetch a part    (${DEFAULTS.prefetchWaitMs / 1000})
  --recovery-wait <seconds>     the longest wait for a recovery to complete        (${DEFAULTS.recoveryWaitMs / 1000})
  --clock-margin <seconds>      slack at time boundaries                           (${DEFAULTS.clockMarginSeconds})
  --rate-limit-wait <seconds>   the longest Retry-After to wait out                (${DEFAULTS.rateLimitWaitMs / 1000})
  --only <ids>                  comma-separated check ids or prefixes (deliver., requests.nonce)
  --format json|text            the report on stdout                               (json)
  --list                        print the checks instead of running them (json, or --format markdown)
  --help`;

function fail(message: string): never {
  process.stderr.write(`${message}\n\n${HELP}\n`);
  process.exit(2);
}

let args: ReturnType<typeof parse>;
function parse() {
  return parseArgs({
    allowPositionals: true,
    options: {
      server: { type: 'string' },
      'peer-domain': { type: 'string' },
      'peer-host': { type: 'string' },
      'peer-port': { type: 'string' },
      'peer-origin': { type: 'string' },
      'hosted-domain': { type: 'string' },
      'unresolvable-domain': { type: 'string' },
      'code-command': { type: 'string' },
      'cancel-code-command': { type: 'string' },
      'code-address': { type: 'string' },
      'retire-command': { type: 'string' },
      'second-peer-domain': { type: 'string' },
      'second-peer-port': { type: 'string' },
      'second-peer-origin': { type: 'string' },
      'prefetch-wait': { type: 'string' },
      'recovery-wait': { type: 'string' },
      'delivery-wait': { type: 'string' },
      'retry-wait': { type: 'string' },
      'clock-margin': { type: 'string' },
      'rate-limit-wait': { type: 'string' },
      only: { type: 'string' },
      format: { type: 'string' },
      list: { type: 'boolean' },
      help: { type: 'boolean' },
    },
  });
}
try {
  args = parse();
} catch (e) {
  fail((e as Error).message);
}
const v = args.values;
if (v.help) {
  process.stdout.write(`${HELP}\n`);
  process.exit(0);
}
if (v.list) {
  process.stdout.write(v.format === 'markdown' ? `${catalogMarkdown()}\n` : `${JSON.stringify(catalog(), null, 2)}\n`);
  process.exit(0);
}

const seconds = (name: string, value: string | undefined, fallbackMs: number) => {
  if (value === undefined) return fallbackMs;
  const n = Number(value);
  if (!(n >= 0)) fail(`--${name} takes a number of seconds`);
  return n * 1000;
};
const server = v.server ?? args.positionals[0];
if (!server) fail('Give the server under test with --server.');
try {
  if (!/^https?:$/.test(new URL(server).protocol)) throw new Error();
} catch {
  fail(`--server ${server} is not an http(s) origin`);
}
const portOf = (name: string, value: string | undefined, fallback: number) => {
  const n = value === undefined ? fallback : Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 65535) fail(`--${name} takes a port number`);
  return n;
};
const port = portOf('peer-port', v['peer-port'], DEFAULTS.peerPort);
const secondPort = portOf('second-peer-port', v['second-peer-port'], DEFAULTS.secondPeerPort);
const originOf = (name: string, value: string | undefined) =>
  value === undefined ? undefined : (serverOrigin(value, true) ?? fail(`--${name} ${value} is not an origin`));
const peerOrigin = originOf('peer-origin', v['peer-origin']);
const secondPeerOrigin = originOf('second-peer-origin', v['second-peer-origin']);
/** The peer domain a tunnel's origin gives: its name, which resolves by the well-known answer only on 443. */
const domainOf = (name: string, origin: string | undefined) => {
  if (!origin) return undefined;
  const url = new URL(origin);
  if (url.protocol !== 'https:' || url.port) fail(`--${name} ${origin} is not https on port 443; give its domain too`);
  return url.hostname;
};
if (v['second-peer-domain'] && peerOrigin && !secondPeerOrigin) {
  fail('A server elsewhere reaches the second simulator only through a tunnel too: give --second-peer-origin');
}

const mark = { pass: 'pass', fail: 'FAIL', skip: 'skip' } as const;
const line = (r: CheckResult) =>
  `${mark[r.status]} ${r.level.padEnd(6)} ${r.id}${r.observed ? `: ${r.observed.split('\n')[0]}` : ''}`;

let report: Report;
try {
  report = await runConformance(
    {
      server,
      peerDomain: v['peer-domain'] ?? domainOf('peer-origin', peerOrigin) ?? DEFAULTS.peerDomain,
      peerHost: v['peer-host'] ?? DEFAULTS.peerHost,
      peerPort: port,
      peerOrigin,
      hostedDomain: v['hosted-domain'],
      unresolvableDomain: v['unresolvable-domain'] ?? DEFAULTS.unresolvableDomain,
      codeCommand: v['code-command'],
      cancelCodeCommand: v['cancel-code-command'],
      codeAddress: v['code-address'],
      retireCommand: v['retire-command'],
      secondPeerDomain: v['second-peer-domain'] ?? domainOf('second-peer-origin', secondPeerOrigin),
      secondPeerPort: secondPort,
      secondPeerOrigin,
      deliveryWaitMs: seconds('delivery-wait', v['delivery-wait'], DEFAULTS.deliveryWaitMs),
      retryWaitMs: seconds('retry-wait', v['retry-wait'], DEFAULTS.retryWaitMs),
      prefetchWaitMs: seconds('prefetch-wait', v['prefetch-wait'], DEFAULTS.prefetchWaitMs),
      recoveryWaitMs: seconds('recovery-wait', v['recovery-wait'], DEFAULTS.recoveryWaitMs),
      clockMarginSeconds: seconds('clock-margin', v['clock-margin'], DEFAULTS.clockMarginSeconds * 1000) / 1000,
      rateLimitWaitMs: seconds('rate-limit-wait', v['rate-limit-wait'], DEFAULTS.rateLimitWaitMs),
      only: (v.only ?? '')
        .split(',')
        .map(s => s.trim())
        .filter(Boolean),
    },
    { onCheck: r => r.status !== 'pass' && process.stderr.write(`${line(r)}\n`) },
  );
} catch (e) {
  process.stderr.write(`The suite could not run: ${(e as Error).message}\n`);
  process.exit(2);
}

const s = report.summary;
const byArea = Object.entries(AREAS)
  .map(([area, title]) => {
    const group = report.checks.filter(c => c.id.split('.')[0] === area);
    if (!group.length) return '';
    const n = (st: string) => group.filter(c => c.status === st).length;
    return `  ${title.padEnd(52)} ${n('pass')} pass, ${n('fail')} fail, ${n('skip')} skip`;
  })
  .filter(Boolean);
process.stderr.write(
  [
    '',
    ...report.setup.notes.map(n => `note: ${n}`),
    ...byArea,
    `${s.pass} of ${s.total} passed, ${s.fail} failed (${s.mustFailed} must, ${s.shouldFailed} should), ${s.skip} skipped.`,
    '',
  ].join('\n'),
);
process.stdout.write(
  v.format === 'text' ? `${report.checks.map(line).join('\n')}\n` : `${JSON.stringify(report, null, 2)}\n`,
);
process.exitCode = s.mustFailed ? 1 : 0;
