/**
 * DNS through c-ares (node:dns Resolver), never getaddrinfo: every query has a timeout, and an absence
 * (NXDOMAIN, no records) is told apart from a failure that may pass (SERVFAIL, a timeout, a refusal), as
 * resolution requires (spec section 3).
 *
 * With two or more DNS-over-HTTPS resolvers configured, every TXT answer is confirmed: c-ares and each
 * resolver must return the same records, or the answer is a failure that may pass (spec section 11.1).
 * A validating resolver answers SERVFAIL for a DNSSEC failure, which is therefore temporary too.
 */
import { Resolver } from 'node:dns/promises';

export interface Dns {
  /** TXT records at a name, each as its character strings; [] when there are none. Throws on a failure. */
  txt(name: string): Promise<string[][]>;
  /** The A and AAAA addresses of a host; [] when it does not exist. Throws on a failure. */
  addresses(host: string): Promise<string[]>;
}

/** A DNS answer that may change: retried later, never read as "none". */
export class DnsFailure extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DnsFailure';
  }
}

const ABSENT = new Set(['ENOTFOUND', 'ENODATA']);

/** The c-ares calls used, so tests can stand in for them. */
export type Lookups = Pick<Resolver, 'resolveTxt' | 'resolve4' | 'resolve6'>;

export function systemDns(
  opts: { timeoutMs?: number; doh?: string[]; servers?: string[]; resolver?: Lookups; fetch?: typeof fetch } = {},
): Dns {
  const timeoutMs = opts.timeoutMs ?? 3000;
  const resolver = opts.resolver ?? cares(timeoutMs, opts.servers ?? []);
  const get = opts.fetch ?? fetch;

  async function query<T>(name: string, lookup: () => Promise<T[]>): Promise<T[]> {
    try {
      return await lookup();
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code ?? '';
      if (ABSENT.has(code)) return [];
      throw new DnsFailure(`${name}: ${code || (e as Error).message}`);
    }
  }

  return {
    async txt(name) {
      const [local, ...confirmations] = await Promise.all([
        query(name, () => resolver.resolveTxt(name)),
        ...(opts.doh ?? []).map(url => dohTxt(get, url, name, timeoutMs)),
      ]);
      const answer = recordSet(local);
      if (confirmations.some(c => recordSet(c) !== answer)) {
        throw new DnsFailure(`${name}: resolvers disagree`);
      }
      return local;
    },
    async addresses(host) {
      const results = await Promise.allSettled([resolver.resolve4(host), resolver.resolve6(host)]);
      const found = results.flatMap(r => (r.status === 'fulfilled' ? r.value : []));
      const failed = results.some(
        r => r.status === 'rejected' && !ABSENT.has((r.reason as NodeJS.ErrnoException).code ?? ''),
      );
      if (!found.length && failed) throw new DnsFailure(`${host}: address lookup failed`);
      return found;
    },
  };
}

/** Records compared as resolution reads them: each joined, sorted. */
const recordSet = (records: string[][]) => JSON.stringify(records.map(r => r.join('')).sort());

/**
 * TXT records from a DNS-over-HTTPS JSON endpoint (`?name=&type=TXT`, as Google and Cloudflare serve).
 * Status 0 is an answer, 3 (NXDOMAIN) is none, and anything else (2 is SERVFAIL, a DNSSEC failure at a
 * validating resolver among them) is a failure.
 */
async function dohTxt(get: typeof fetch, endpoint: string, name: string, timeoutMs: number): Promise<string[][]> {
  let body: { Status?: number; Answer?: { type: number; data: string }[] };
  try {
    const url = `${endpoint}?name=${encodeURIComponent(name)}&type=TXT&do=1`;
    const res = await get(url, {
      headers: { accept: 'application/dns-json' },
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    if (text.length > 65_536) throw new Error('answer too large');
    body = JSON.parse(text);
  } catch (e) {
    throw new DnsFailure(`${name} via ${endpoint}: ${(e as Error).message}`);
  }
  if (body.Status === 3) return [];
  if (body.Status !== 0) throw new DnsFailure(`${name} via ${endpoint}: status ${body.Status}`);
  return (body.Answer ?? []).filter(a => a.type === 16).map(a => txtStrings(a.data));
}

/** A TXT record's character strings from presentation form (`"a" "b\"c"`); unquoted text is one string. */
export function txtStrings(data: string): string[] {
  if (!data.startsWith('"')) return [data];
  return [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(m =>
    m[1].replace(/\\(\d{3}|.)/g, (_, c: string) => (c.length === 3 ? String.fromCharCode(Number(c)) : c)),
  );
}

/** A c-ares resolver with a timeout, asking `servers` when given and the system's DNS servers otherwise. */
function cares(timeoutMs: number, servers: string[]): Resolver {
  const resolver = new Resolver({ timeout: timeoutMs, tries: 2 });
  if (servers.length) resolver.setServers(servers);
  return resolver;
}
