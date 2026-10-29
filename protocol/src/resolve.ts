/**
 * Resolution: which server a domain's agents live on (spec section 3). Exactly two methods, in this order:
 *
 *   _simon.<domain>  TXT  "v=simon1; server=https://<host>"
 *   GET https://<domain>/.well-known/simon   {"server":"https://<host>"}
 *
 * A TXT record is the join of its character strings, read as fields separated by `;`, spaces around each
 * ignored; a field's name is the text before its first `=`, or the whole field. A record is a simon record
 * when its first field is exactly `v=simon1`; it must then have exactly one field named `server`, whose value
 * is a server origin; every other field is ignored. Records that are not simon records are ignored. A
 * malformed simon record fails resolution (`invalid_record`) whatever the others say; otherwise simon records
 * naming different servers fail it (`conflict`), and one or more naming the same server resolve to it. Only
 * when the TXT lookup answered and found no simon record is the well-known answer tried, never through a
 * redirect: a TXT lookup that fails for now ends resolution `temporary` (spec section 3), so whoever can make
 * TXT answers fail cannot send resolution to whoever runs the domain's website.
 *
 * The lookups are passed in, so any runtime (and any test) supplies its own. They tell an absence (a host
 * that does not exist, refuses the connection or has a certificate not valid for it) from a failure that may
 * pass (a thrown error), and so does resolution: `temporary` is never "no server".
 */
import { isJsonObject, parseStrict, type Json } from './canonical.ts';
import { normalizeDomain } from './address.ts';
import { NOT_FOUND_CACHE_MS, SERVER_CACHE_MAX_MS, TEMPORARY_CACHE_MS } from './limits.ts';

export interface ResolverIO {
  /**
   * TXT records at a name, each as its character strings; [] when there are none. Throws on a failure that
   * may pass: a DNS server error, a timeout, or a DNSSEC validation failure.
   */
  txt(name: string): Promise<string[][]>;
  /**
   * GET a URL without following redirects: the status and body, or null when there is no answer to be had:
   * the host does not exist (NXDOMAIN), refuses the connection, or presents a certificate not valid for it.
   * Throws on a failure that may pass: a DNS server error, a timeout or a dropped connection.
   */
  get(url: string): Promise<{ status: number; body: Uint8Array } | null>;
}

export type Resolution =
  | {
      outcome: 'server';
      server: string;
      via: 'dns' | 'well-known';
    }
  | { outcome: 'invalid_domain' | 'invalid_record' | 'conflict' | 'not_found' | 'temporary' };

/** How a caller resolves a domain: `resolveDomain` behind whatever cache it keeps. */
export type Resolve = (domain: string) => Promise<Resolution>;

/**
 * How long this library caches an outcome, within the bounds of spec section 3 (docs/host-notes.md), given the lifetime its source allows (the TXT
 * record's TTL, or the well-known answer's HTTP freshness, RFC 9111): a `server` for that, at most an hour;
 * `not_found` ten minutes; `temporary` a minute. The spec allows no caching of the other outcomes.
 */
export function resolutionCacheMs(r: Resolution, sourceTtlMs = 0): number {
  if (r.outcome === 'server') return Math.max(0, Math.min(sourceTtlMs, SERVER_CACHE_MAX_MS));
  if (r.outcome === 'not_found') return NOT_FOUND_CACHE_MS;
  return r.outcome === 'temporary' ? TEMPORARY_CACHE_MS : 0;
}

const ORIGIN = /^(https?):\/\/([^/:?#]+)(?::([0-9]{1,5}))?\/?$/i;
const DEFAULT_PORT: Record<string, number> = { https: 443, http: 80 };

/**
 * A server origin as the URL standard serialises it (lower-case scheme and host, the default port dropped,
 * no trailing `/`), or null. The input is `https://host[:port]` and an optional `/`: the scheme in any case,
 * the host a domain, the port 1 to 5 digits whose value is 1 to 65535. `allowHttp` admits `http:` and hosts
 * such as `localhost`, for local development only.
 */
export function serverOrigin(value: unknown, allowHttp = false): string | null {
  const m = typeof value === 'string' ? ORIGIN.exec(value) : null;
  if (!m) return null;
  const scheme = m[1].toLowerCase();
  const host = allowHttp && /^[a-z0-9.-]+$/i.test(m[2]) ? m[2].toLowerCase() : normalizeDomain(m[2]);
  const port = m[3] === undefined ? DEFAULT_PORT[scheme] : Number(m[3]);
  if ((scheme === 'http' && !allowHttp) || !host || port < 1 || port > 65535) return null;
  return `${scheme}://${host}${port === DEFAULT_PORT[scheme] ? '' : `:${port}`}`;
}

/** The fields of each simon record among these, as `[name, value]` pairs; records that are not simon records are left out. */
function simonRecords(records: string[][]): [string, string][][] {
  const found: [string, string][][] = [];
  for (const strings of records) {
    const [first, ...rest] = strings
      .join('')
      .split(';')
      .map(f => f.replace(/^ +| +$/g, ''));
    if (first !== 'v=simon1') continue;
    found.push(rest.map(f => (f.includes('=') ? [f.slice(0, f.indexOf('=')), f.slice(f.indexOf('=') + 1)] : [f, ''])));
  }
  return found;
}

/** The servers the simon records name, or 'invalid' when one of them is malformed. */
export function serversInTxt(records: string[][], allowHttp = false): string[] | 'invalid' {
  const servers = new Set<string>();
  for (const fields of simonRecords(records)) {
    const values = fields.filter(([name]) => name === 'server').map(([, value]) => value);
    const origin = values.length === 1 ? serverOrigin(values[0], allowHttp) : null;
    if (!origin) return 'invalid';
    servers.add(origin);
  }
  return [...servers];
}

/**
 * What a well-known answer resolves to: a `200` whose body is a JSON object under the canonical rules with a
 * `server` that is a server origin names that server; `429` and `5xx` are `temporary`; anything else, no
 * answer at all (null) included, is `not_found`.
 */
export function wellKnownOutcome(answer: { status: number; body: Uint8Array } | null, allowHttp = false): Resolution {
  if (answer && (answer.status === 429 || (answer.status >= 500 && answer.status <= 599))) {
    return { outcome: 'temporary' };
  }
  let value: Json = null;
  try {
    if (answer?.status === 200) value = parseStrict(answer.body);
  } catch {
    // Not JSON under the canonical rules: no server.
  }
  const server = isJsonObject(value) ? serverOrigin(value.server, allowHttp) : null;
  return server ? { outcome: 'server', server, via: 'well-known' } : { outcome: 'not_found' };
}

export async function resolveDomain(
  domainIn: string,
  io: ResolverIO,
  opts: { allowHttp?: boolean } = {},
): Promise<Resolution> {
  const domain = normalizeDomain(domainIn);
  if (!domain) return { outcome: 'invalid_domain' };
  let records: string[][];
  try {
    records = await io.txt(`_simon.${domain}`);
  } catch {
    return { outcome: 'temporary' };
  }
  const servers = serversInTxt(records, opts.allowHttp);
  if (servers === 'invalid') return { outcome: 'invalid_record' };
  if (servers.length > 1) return { outcome: 'conflict' };
  if (servers.length === 1) return { outcome: 'server', server: servers[0], via: 'dns' };
  try {
    return wellKnownOutcome(await io.get(`https://${domain}/.well-known/simon`), opts.allowHttp);
  } catch {
    return { outcome: 'temporary' };
  }
}
