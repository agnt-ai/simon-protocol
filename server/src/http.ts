/**
 * Serving HTTP: a request and reply independent of node:http (so tests can drive a server in-process), a
 * small router, and the adapter to node:http. A body is read only up to its route's cap, so an oversized
 * one is refused without being held. Every error leaves as an RFC 9457 problem (spec section 9), with the
 * headers its WireError names: its content type, `WWW-Authenticate` on a 401, Retry-After.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { isIP } from 'node:net';
import { bodyTooLarge, canonicalize, WireError } from '@agnt-protocol/protocol';
import { inNetworks, parseNetwork, type Network } from './net/ip.ts';

export interface Request {
  method: string;
  /** The request target exactly as sent: the path and query a signature covers. */
  target: string;
  path: string;
  query: URLSearchParams;
  /** The route's `:name` segments, percent-decoded. */
  params: Record<string, string>;
  /** Lower-case names, as node:http gives them. */
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  /** The client's address, as the socket saw it. */
  ip: string;
}

export interface Reply {
  status: number;
  /** A JSON body, sent in canonical form, as application/json unless `headers` name another type. */
  json?: unknown;
  /** A byte body, sent as application/octet-stream. */
  bytes?: Buffer;
  headers?: Record<string, string>;
}

export interface Route<Api = unknown> {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** A path whose `:name` segments match any one segment, e.g. `/agnt/agents/:address`. */
  path: string;
  /** The largest body accepted; the server's `requestBodyBytes` when absent. */
  maxBody?: number;
  handle(req: Request, api: Api): Reply | Promise<Reply>;
}

export const json = (body: unknown, status = 200): Reply => ({ status, json: body });

export const errorReply = (e: WireError): Reply => ({ status: e.status, json: e.toProblem(), headers: e.headers });

export class Router<Api> {
  readonly #routes: { route: Route<Api>; segments: string[] }[] = [];

  add(route: Route<Api>): void {
    if (this.#routes.some(r => r.route.method === route.method && r.route.path === route.path)) {
      throw new Error(`Two routes for ${route.method} ${route.path}.`);
    }
    this.#routes.push({ route, segments: route.path.split('/') });
  }

  /** The route for a method and path, with its parameters; null when none matches. */
  match(method: string, path: string): { route: Route<Api>; params: Record<string, string> } | null {
    const parts = path.split('/');
    for (const { route, segments } of this.#routes) {
      if (route.method !== method || segments.length !== parts.length) continue;
      const params: Record<string, string> = {};
      const fits = segments.every((s, i) => {
        if (!s.startsWith(':')) return s === parts[i];
        try {
          params[s.slice(1)] = decodeURIComponent(parts[i]);
        } catch {
          return false;
        }
        return parts[i] !== '';
      });
      if (fits) return { route, params };
    }
    return null;
  }
}

/** What the node:http adapter serves: the body cap for a request, and the handling of a whole one. */
export interface App {
  bodyLimit(method: string, path: string): number;
  handle(req: Request): Promise<Reply>;
}

/** Where a client's address comes from behind proxies: the header they set, and the networks they connect from. */
export interface ProxySettings {
  clientIpHeader: string | null;
  trustedProxies: readonly Network[];
}

/** This machine, always a trusted proxy: a tunnel's connector runs here. */
const LOOPBACK = ['127.0.0.0/8', '::1/128'].map(cidr => parseNetwork(cidr) as Network);

/**
 * The client's address. With no `clientIpHeader`, the connection's. With one, the header is a list each proxy
 * appends the address it heard from to, so it is read from the right: while the address so far is a trusted
 * proxy, the entry before it names who that proxy heard from. A client can write anything at the left of the
 * list, but never past the last trusted hop, so no spoofed entry is reached; an entry that is not an address
 * stops the walk.
 */
export function clientIp(req: IncomingMessage, { clientIpHeader, trustedProxies }: ProxySettings): string {
  let ip = req.socket.remoteAddress ?? '';
  if (!clientIpHeader) return ip;
  const named = req.headers[clientIpHeader];
  const hops = typeof named === 'string' ? named.split(',').map(s => s.trim()) : [];
  while (hops.length && (inNetworks(ip, LOOPBACK) || inNetworks(ip, trustedProxies))) {
    const hop = hops.pop()!;
    if (!isIP(hop)) break;
    ip = hop;
  }
  return ip;
}

export function nodeListener(app: App, proxies: ProxySettings) {
  return (req: IncomingMessage, res: ServerResponse) => {
    const target = req.url ?? '/';
    const path = target.split('?')[0];
    const limit = app.bodyLimit(req.method ?? 'GET', path);
    readBody(req, limit)
      .then(body =>
        body === null
          ? errorReply(bodyTooLarge(limit))
          : app.handle({
              method: req.method ?? 'GET',
              target,
              path,
              query: new URLSearchParams(target.includes('?') ? target.slice(target.indexOf('?') + 1) : ''),
              params: {},
              headers: req.headers,
              body,
              ip: clientIp(req, proxies),
            }),
      )
      .then(reply => write(res, reply))
      .catch(() => res.destroy());
  };
}

/** The body, or null as soon as it passes `limit` bytes. */
function readBody(req: IncomingMessage, limit: number): Promise<Buffer | null> {
  if (Number(req.headers['content-length'] ?? 0) > limit) {
    req.resume();
    return Promise.resolve(null);
  }
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size <= limit) return void chunks.push(c);
      req.removeAllListeners('data');
      req.resume();
      resolve(null);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function write(res: ServerResponse, reply: Reply) {
  const body = reply.bytes ?? (reply.json === undefined ? Buffer.alloc(0) : Buffer.from(canonicalize(reply.json)));
  res.writeHead(reply.status, {
    'content-type': reply.bytes ? 'application/octet-stream' : 'application/json',
    'content-length': String(body.length),
    ...reply.headers,
  });
  res.end(body);
}
