/**
 * The machinery every check runs on: a registry of checks, the HTTP exchanges each one records, and the
 * report they add up to. A check is declared once, with its id, spec section, level and expectation, so
 * the list in README.md is generated from the same declarations that run.
 */
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';

export type Level = 'must' | 'should';
export type Status = 'pass' | 'fail' | 'skip';

export interface CheckSpec {
  /** Stable, dotted: `<area>.<what>`. */
  id: string;
  /** Where the rule is: `PROTOCOL 6.3 step 3`, `CLIENT send`. */
  section: string;
  /** `must` when the spec requires it (a failure fails the run); `should` otherwise. */
  level: Level;
  title: string;
  /** What a conforming server does, in one sentence. */
  expected: string;
}

/** One HTTP request and its answer, as the report shows them. */
export interface Exchange {
  label?: string;
  /** `to-target`: the suite (or its simulated peer) called the server under test. `from-target`: the reverse. */
  direction: 'to-target' | 'from-target';
  at: string;
  request: { method: string; url: string; headers: Record<string, string>; body?: Shown };
  response?: { status: number; headers: Record<string, string>; body?: Shown };
  error?: string;
}

/** A body in a report: its text when short, or its size, hash and first characters. */
export type Shown = string | { bytes: number; sha256: string; head: string };

export interface CheckResult extends CheckSpec {
  status: Status;
  /** What came back, when the check failed or was skipped, in one or two sentences. */
  observed?: string;
  exchanges: Exchange[];
  ms: number;
}

/** A raw request: the origin and the request target exactly as sent. */
export interface Req {
  method: string;
  origin: string;
  target: string;
  headers?: Record<string, string>;
  body?: string | Buffer;
}

export interface Res {
  status: number;
  headers: Record<string, string>;
  bytes: Buffer;
  text: string;
  /** The body as JSON, or undefined when it is not JSON. */
  json: any;
}

export class CheckFailure extends Error {}
export class CheckSkip extends Error {}

export interface Registered extends CheckSpec {
  run: (t: T, ctx: any) => Promise<void>;
}

const registry: Registered[] = [];

/** Declare a check. Checks run in the order they are declared. */
export function check<C>(spec: CheckSpec, run: (t: T, ctx: C) => Promise<void>) {
  if (registry.some(c => c.id === spec.id)) throw new Error(`Duplicate check id ${spec.id}`);
  registry.push({ ...spec, run });
}

export const catalog = (): CheckSpec[] => registry.map(({ run: _, ...spec }) => spec);
export const registered = (): readonly Registered[] => registry;

const SHOWN_HEADERS = /^(agnt-|content-type$|retry-after$|location$|www-authenticate$)/;
const MAX_SHOWN = 4096;

export function show(body: string | Buffer | undefined): Shown | undefined {
  if (body === undefined || body.length === 0) return undefined;
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
  const text = buf.toString('utf8');
  const printable = Buffer.from(text).equals(buf);
  if (buf.length <= MAX_SHOWN && printable) return text;
  return {
    bytes: buf.length,
    sha256: crypto.createHash('sha256').update(buf).digest('hex'),
    head: printable ? text.slice(0, 400) : buf.subarray(0, 200).toString('base64'),
  };
}

const pickHeaders = (h: Record<string, string>) =>
  Object.fromEntries(Object.entries(h).filter(([k]) => SHOWN_HEADERS.test(k.toLowerCase())));

/** Send one request with Node's own client, so the request target goes out byte for byte as given. */
export function transport(req: Req, timeoutMs = 30_000): Promise<Res> {
  const url = new URL(req.origin);
  const mod = url.protocol === 'https:' ? https : http;
  const body = req.body === undefined ? undefined : Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body);
  const headers: Record<string, string> = { ...req.headers };
  if (body !== undefined) {
    headers['content-length'] = String(body.length);
    headers['content-type'] ??= 'application/json';
  }
  const whole = new URL(req.target, req.origin);
  if (body !== undefined && body.length > 64 * 1024 && whole.pathname + whole.search === req.target) {
    return viaFetch(whole, req.method, headers, body, timeoutMs);
  }
  return new Promise((resolve, reject) => {
    let responded = false;
    const r = mod.request(
      {
        host: url.hostname.replace(/^\[|\]$/g, ''),
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        method: req.method,
        path: req.target,
        headers,
        timeout: timeoutMs,
        agent: false,
      },
      res => {
        responded = true;
        const chunks: Buffer[] = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          const bytes = Buffer.concat(chunks);
          const text = bytes.toString('utf8');
          let json: any;
          try {
            json = JSON.parse(text);
          } catch {
            json = undefined;
          }
          const hs: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) hs[k] = String(v);
          resolve({ status: res.statusCode ?? 0, headers: hs, bytes, text, json });
        });
        res.on('error', reject);
      },
    );
    r.on('timeout', () => r.destroy(new Error(`no answer within ${timeoutMs / 1000} s`)));
    r.on('error', err => responded || reject(err));
    r.end(body);
  });
}

/**
 * Large bodies go through fetch: a server may answer (413, say) before reading the whole body and close
 * the connection, and fetch still reads that answer where Node's http client reports only the broken pipe.
 */
async function viaFetch(
  url: URL,
  method: string,
  headers: Record<string, string>,
  body: Buffer,
  timeoutMs: number,
): Promise<Res> {
  const { 'content-length': _, ...rest } = headers;
  const res = await fetch(url, {
    method,
    headers: rest,
    body: new Uint8Array(body),
    redirect: 'manual',
    signal: AbortSignal.timeout(timeoutMs),
  });
  const bytes = Buffer.from(await res.arrayBuffer());
  const text = bytes.toString('utf8');
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { status: res.status, headers: Object.fromEntries(res.headers), bytes, text, json };
}

export interface HttpOptions {
  label?: string;
  /** Wait out a 429 with Retry-After at most this long, then send again. */
  rateLimitWaitMs?: number;
}

/** What a check gets: HTTP that records, assertions that say what was expected, and skips. */
export class T {
  readonly exchanges: Exchange[] = [];
  readonly spec: CheckSpec;
  readonly sink: (e: Exchange) => void;
  readonly rateLimitWaitMs: number;

  constructor(spec: CheckSpec, sink: (e: Exchange) => void, rateLimitWaitMs: number) {
    this.spec = spec;
    this.sink = sink;
    this.rateLimitWaitMs = rateLimitWaitMs;
  }

  /** Send a request (or a builder that makes a fresh one, so a signed request is signed again on retry). */
  async http(req: Req | (() => Req), opts: HttpOptions = {}): Promise<Res> {
    const build = typeof req === 'function' ? req : () => req;
    for (let attempt = 0; ; attempt++) {
      const r = build();
      const res = await this.exchange(r, opts.label);
      if (res.status !== 429) return res;
      const wait = Number(res.headers['retry-after'] ?? '1') * 1000;
      const cap = opts.rateLimitWaitMs ?? this.rateLimitWaitMs;
      if (attempt >= 3 || !(wait <= cap)) {
        throw new CheckSkip(
          `The server rate-limited the suite (429, Retry-After ${res.headers['retry-after'] ?? 'absent'}). ` +
            'Raise its limits for conformance runs and run again.',
        );
      }
      await sleep(Math.max(wait, 250));
    }
  }

  private async exchange(r: Req, label?: string): Promise<Res> {
    const e: Exchange = {
      label,
      direction: 'to-target',
      at: new Date().toISOString(),
      request: {
        method: r.method,
        url: r.origin + r.target,
        headers: pickHeaders(r.headers ?? {}),
        body: show(r.body),
      },
    };
    this.record(e);
    try {
      const res = await transport(r);
      e.response = { status: res.status, headers: pickHeaders(res.headers), body: show(res.bytes) };
      return res;
    } catch (err) {
      e.error = (err as Error).message;
      throw new CheckFailure(`${r.method} ${r.target}: the request failed: ${(err as Error).message}`);
    }
  }

  /** Add an exchange the suite observed rather than made, such as a delivery the server under test sent. */
  record(e: Exchange) {
    this.exchanges.push(e);
    this.sink(e);
  }

  /** A T whose exchanges stay apart, for polling: adopt the ones worth showing afterwards. */
  scratch(): T {
    return new T(this.spec, this.sink, this.rateLimitWaitMs);
  }

  adopt(es: Exchange[]) {
    this.exchanges.push(...es);
  }

  fail(observed: string): never {
    throw new CheckFailure(observed);
  }

  assert(cond: unknown, observed: string): asserts cond {
    if (!cond) this.fail(observed);
  }

  skip(reason: string): never {
    throw new CheckSkip(reason);
  }

  /** The answer has this status. */
  status(res: Res, status: number | number[], what = ''): void {
    const ok = Array.isArray(status) ? status.includes(res.status) : res.status === status;
    this.assert(ok, `${what ? `${what}: ` : ''}expected status ${[status].flat().join(' or ')}, got ${describe(res)}`);
  }

  /**
   * The answer is this error, as an RFC 9457 problem with the protocol's members (spec section 9). `field` is
   * details.field (a nested name such as `headers.for` counts for `headers`); `canonical` is details.canonical,
   * exactly. The rest of the problem's shape is judged once, over the whole run, by the errors checks.
   */
  error(
    res: Res,
    status: number,
    code: string,
    what = '',
    opts: { field?: string | string[]; canonical?: string; anyField?: boolean } = {},
  ) {
    const p = what ? `${what}: ` : '';
    const found = problem(res);
    this.assert(res.status === status && found?.code === code, `${p}expected ${status} ${code}, got ${describe(res)}`);
    const err = found!;
    this.assert(
      typeof err.retryable === 'boolean',
      `${p}the problem lacks a boolean retryable: ${res.text.slice(0, 300)}`,
    );
    const field = err.details?.field;
    if (opts.anyField)
      this.assert(typeof field === 'string', `${p}expected a details.field, got ${JSON.stringify(field)}`);
    if (opts.field !== undefined) {
      const wanted = [opts.field].flat();
      this.assert(
        typeof field === 'string' && wanted.some(w => fieldMatches(field, w)),
        `${p}expected details.field ${wanted.map(w => JSON.stringify(w)).join(' or ')}, got ${JSON.stringify(field)}`,
      );
    }
    if (opts.canonical !== undefined) {
      this.assert(
        err.details?.canonical === opts.canonical,
        `${p}expected details.canonical to be the canonical form ${JSON.stringify(opts.canonical).slice(0, 200)}, got ${JSON.stringify(err.details?.canonical)?.slice(0, 200)}`,
      );
    }
    return err;
  }
}

/** The protocol's members of a problem answer (spec section 9). */
export interface Problem {
  code: string;
  status?: unknown;
  retryable: boolean;
  detail?: unknown;
  details?: Record<string, any>;
  [member: string]: unknown;
}

/** An answer's problem details: the body when it is a JSON object with a string `code`, else undefined. */
export function problem(res: Pick<Res, 'json'>): Problem | undefined {
  const b = res.json;
  return b && typeof b === 'object' && !Array.isArray(b) && typeof b.code === 'string' ? (b as Problem) : undefined;
}

/** `headers.for` and `headers[for]` count as `headers`. */
export const fieldMatches = (field: string, wanted: string) =>
  field === wanted ||
  field.startsWith(`${wanted}.`) ||
  field.startsWith(`${wanted}[`) ||
  field.startsWith(`${wanted}/`);

/** A one-line account of an answer, for failure messages. */
export function describe(res: Res): string {
  const err = problem(res);
  if (err) {
    const field = err.details?.field ? ` (details.field ${JSON.stringify(err.details.field)})` : '';
    return `${res.status} ${err.code}${field}`;
  }
  const body = res.text.length > 160 ? `${res.text.slice(0, 160)}...` : res.text;
  return `${res.status}${body ? ` ${body}` : ''}`;
}

export const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

/** Poll `fn` until it returns something other than undefined, or the time runs out. */
export async function poll<X>(fn: () => Promise<X | undefined>, ms: number, every = 250): Promise<X | undefined> {
  const end = Date.now() + ms;
  for (;;) {
    const x = await fn();
    if (x !== undefined) return x;
    if (Date.now() >= end) return undefined;
    await sleep(every);
  }
}

export interface Report {
  suite: string;
  spec: string;
  target: { server: string; origin: string };
  peer: { domain: string; origin: string };
  startedAt: string;
  finishedAt: string;
  summary: { total: number; pass: number; fail: number; skip: number; mustFailed: number; shouldFailed: number };
  /** What the suite did to get agents on the server, and anything it noticed while setting up. */
  setup: { notes: string[]; exchanges: Exchange[] };
  checks: CheckResult[];
}

export function summarize(checks: CheckResult[]): Report['summary'] {
  const count = (f: (c: CheckResult) => boolean) => checks.filter(f).length;
  return {
    total: checks.length,
    pass: count(c => c.status === 'pass'),
    fail: count(c => c.status === 'fail'),
    skip: count(c => c.status === 'skip'),
    mustFailed: count(c => c.status === 'fail' && c.level === 'must'),
    shouldFailed: count(c => c.status === 'fail' && c.level === 'should'),
  };
}
