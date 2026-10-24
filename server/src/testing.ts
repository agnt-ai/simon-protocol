/**
 * A fake outside world, for tests of the server and of applications built on it: one movable clock, DNS
 * answered from a map, and HTTP answered in-process by the origins registered on it.
 *
 *   const clock = new Clock();
 *   const dns = new FakeDns();
 *   const net = new FakeNet();
 *   const server = createServer({ config, store, dns, http: net, now: clock.now, worker: false });
 *   net.hosts.set(config.origin, req => server.handle(req));
 *   dns.point('example.test', config.origin);
 */
import { canonicalize } from '@agnt-sdk/simon-protocol';
import type { Reply, Request } from './http.ts';
import { DnsFailure, type Dns } from './net/dns.ts';
import { Unreachable, type Http, type HttpRequest, type HttpResponse } from './net/fetch.ts';

export class Clock {
  t = Date.parse('2026-10-15T12:00:00.000Z');
  now = () => new Date(this.t);
  advance(ms: number) {
    this.t += ms;
  }
}

/** TXT records by name; a name in `failing` answers SERVFAIL. */
export class FakeDns implements Dns {
  readonly records = new Map<string, string[][]>();
  readonly failing = new Set<string>();
  async txt(name: string) {
    if (this.failing.has(name)) throw new DnsFailure(`${name}: SERVFAIL`);
    return this.records.get(name) ?? [];
  }
  async addresses() {
    return ['203.0.113.10'];
  }
  point(domain: string, origin: string) {
    this.records.set(`_simon.${domain}`, [[`v=simon1; server=${origin}`]]);
  }
}

type Host = ((req: Request) => Promise<Reply>) | 'down';

/** Every deadline on the fake network, at most: a tarpit costs a test this long. */
export const TARPIT_MS = 150;

/**
 * Origins answered in-process. A request reaches the host's handler as an HTTP request would. Each host has
 * one address, its own name unless `addresses` maps it to another, so several names can share one machine.
 */
export class FakeNet implements Http {
  readonly hosts = new Map<string, Host>();
  readonly addresses = new Map<string, string>();
  /** The client address every request appears to come from. */
  ip = '198.51.100.7';
  readonly sent: { method: string; url: string }[] = [];

  async request(r: HttpRequest): Promise<HttpResponse> {
    const url = new URL(r.url);
    this.sent.push({ method: r.method, url: r.url });
    const host = this.hosts.get(url.origin);
    if (!host) throw new Unreachable('absent', `no such host: ${url.host}`);
    const address = this.addresses.get(url.hostname) ?? url.hostname;
    if (r.avoid?.(address)) throw new Unreachable('refused', `${address} is avoided`, address);
    if (host === 'down') throw new Unreachable('refused', `${url.host} refuses connections`, address);
    // Deadlines are honoured, scaled down so a test never waits long for one.
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Unreachable('timeout', `${url.host}: no answer in time`, address)),
        Math.min(r.timeoutMs ?? TARPIT_MS, TARPIT_MS),
      );
    });
    const request = toRequest(r.method, url, r.headers ?? {}, Buffer.from(r.body ?? new Uint8Array()), this.ip);
    const reply = await Promise.race([host(request), deadline]).finally(() => clearTimeout(timer));
    const body = replyBody(reply);
    if (body.length > r.maxBytes) throw new Unreachable('too_large', 'answer too large');
    return { status: reply.status, headers: { ...reply.headers }, body };
  }
}

export function toRequest(
  method: string,
  url: URL,
  headers: Record<string, string>,
  body: Buffer,
  ip: string,
): Request {
  return {
    method,
    target: url.pathname + url.search,
    path: url.pathname,
    query: url.searchParams,
    params: {},
    headers: Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])),
    body,
    ip,
  };
}

/** A reply's body as the node:http adapter would send it. */
export const replyBody = (reply: Reply) =>
  reply.bytes ?? (reply.json === undefined ? Buffer.alloc(0) : Buffer.from(canonicalize(reply.json)));
