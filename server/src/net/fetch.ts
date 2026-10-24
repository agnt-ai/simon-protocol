/**
 * Outbound HTTP with an SSRF guard. Every request this server makes to a URL it did not choose (another
 * server, a domain's well-known answer) goes through here:
 *
 *   - https only, TLS 1.3 or later; http and this machine's own addresses only in development;
 *   - no address outside the public internet, except in the networks the operator trusts
 *     (AGNT_TRUSTED_NETWORKS, for a private network such as a Tailscale tailnet);
 *   - no credentials in the URL, no redirects followed;
 *   - the host resolved through `Dns` (c-ares), every address checked, and the connection pinned to the
 *     checked address, so a second lookup cannot swap in another one;
 *   - a short connect timeout, a deadline for the whole exchange, and a cap on the answer's bytes;
 *   - an address the caller knows is dead (`avoid`) is not connected to at all, so many names for one
 *     tarpit cost one timeout, not one each.
 */
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import type { Dns } from './dns.ts';
import { inNetworks, isBlockedAddress, isLoopback, type Network } from './ip.ts';

export interface HttpRequest {
  method: 'GET' | 'POST';
  url: string;
  headers?: Record<string, string>;
  body?: Uint8Array;
  /** The largest answer body accepted; a larger one fails the request. */
  maxBytes: number;
  /** The deadline for the whole exchange. */
  timeoutMs?: number;
  /** Refuse to connect to an address this answers true for, as if it refused the connection. */
  avoid?: (address: string) => boolean;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
}

export interface Http {
  request(r: HttpRequest): Promise<HttpResponse>;
}

/**
 * Why a request got no answer:
 *   absent       the host does not exist
 *   forbidden    the URL or an address it resolves to is one this server must not call
 *   refused      the connection was refused, or the address is one the caller avoids
 *   certificate  the server's certificate is not valid for the host
 *   connect      no connection within the connect timeout
 *   timeout      connected, but no whole answer before the deadline
 *   too_large    the answer is larger than `maxBytes`
 *   failed       anything else that may pass: a DNS failure, a TLS failure, a reset
 *
 * `address` is the address a connection was tried to, when one was.
 */
export class Unreachable extends Error {
  readonly kind: 'absent' | 'forbidden' | 'refused' | 'certificate' | 'connect' | 'timeout' | 'too_large' | 'failed';
  readonly address?: string;
  constructor(kind: Unreachable['kind'], message: string, address?: string) {
    super(message);
    this.name = 'Unreachable';
    this.kind = kind;
    this.address = address;
  }
}

/** Node's codes for a certificate that does not authenticate the host (RFC 9525). */
const CERTIFICATE_ERRORS = new Set([
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'CERT_HAS_EXPIRED',
  'CERT_NOT_YET_VALID',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'CERT_REVOKED',
  'CERT_UNTRUSTED',
]);

export function guardedHttp(opts: {
  dns: Dns;
  dev?: boolean;
  /** Networks whose addresses may be called although they are not public (config.trustedNetworks). */
  trustedNetworks?: readonly Network[];
  connectTimeoutMs?: number;
  timeoutMs?: number;
}): Http {
  const connectTimeoutMs = opts.connectTimeoutMs ?? 3000;
  const allowLocal = opts.dev ?? false;
  const trusted = opts.trustedNetworks ?? [];

  async function target(raw: string): Promise<{ url: URL; address: string }> {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      throw new Unreachable('forbidden', `not a URL: ${raw}`);
    }
    if (url.username || url.password) throw new Unreachable('forbidden', 'credentials in a URL');
    if (!(url.protocol === 'https:' || (allowLocal && url.protocol === 'http:'))) {
      throw new Unreachable('forbidden', `${url.protocol} is not allowed`);
    }
    const host = url.hostname.replace(/^\[|\]$/g, '');
    let addresses: string[];
    if (net.isIP(host)) addresses = [host];
    else if (allowLocal && host === 'localhost') addresses = ['127.0.0.1'];
    else {
      try {
        addresses = await opts.dns.addresses(host);
      } catch (e) {
        throw new Unreachable('failed', (e as Error).message);
      }
    }
    if (!addresses.length) throw new Unreachable('absent', `no such host: ${host}`);
    const refused = addresses.find(
      a => isBlockedAddress(a) && !(allowLocal && isLoopback(a)) && !inNetworks(a, trusted),
    );
    if (refused) throw new Unreachable('forbidden', `${host} resolves to ${refused}, not a public address`);
    return { url, address: addresses[0] };
  }

  return {
    async request(r) {
      const deadline = r.timeoutMs ?? opts.timeoutMs ?? 10_000;
      const abort = new AbortController();
      const timer = setTimeout(
        () => abort.abort(new Unreachable('timeout', `no answer within ${deadline} ms`)),
        deadline,
      );
      try {
        const t = await Promise.race([target(r.url), aborted(abort.signal)]);
        if (r.avoid?.(t.address)) throw new Unreachable('refused', `${t.address} is avoided`, t.address);
        return await send(r, t, abort.signal, connectTimeoutMs);
      } catch (e) {
        if (abort.signal.aborted) throw abort.signal.reason;
        throw e instanceof Unreachable ? e : new Unreachable('failed', (e as Error).message);
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

const aborted = (signal: AbortSignal) =>
  new Promise<never>((_, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));

function send(
  r: HttpRequest,
  { url, address }: { url: URL; address: string },
  signal: AbortSignal,
  connectTimeoutMs: number,
): Promise<HttpResponse> {
  const secure = url.protocol === 'https:';
  return new Promise((resolve, reject) => {
    const req = (secure ? https : http).request({
      host: address,
      port: url.port || (secure ? 443 : 80),
      servername: net.isIP(url.hostname) ? undefined : url.hostname,
      path: url.pathname + url.search,
      method: r.method,
      minVersion: 'TLSv1.3',
      headers: { ...r.headers, host: url.host, ...(r.body ? { 'content-length': String(r.body.length) } : {}) },
      agent: false,
      signal,
    });
    req.on('socket', socket => {
      const timer = setTimeout(() => {
        req.destroy(new Unreachable('connect', `no connection to ${url.host} within ${connectTimeoutMs} ms`, address));
      }, connectTimeoutMs);
      socket.once(secure ? 'secureConnect' : 'connect', () => clearTimeout(timer));
      socket.once('close', () => clearTimeout(timer));
    });
    req.on('response', res => {
      const declared = Number(res.headers['content-length'] ?? 0);
      if (declared > r.maxBytes) {
        res.destroy();
        return reject(new Unreachable('too_large', `answer larger than ${r.maxBytes} bytes`));
      }
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (c: Buffer) => {
        size += c.length;
        if (size <= r.maxBytes) return void chunks.push(c);
        res.destroy();
        reject(new Unreachable('too_large', `answer larger than ${r.maxBytes} bytes`));
      });
      res.on('end', () => {
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers))
          headers[k] = Array.isArray(v) ? v.join(', ') : String(v ?? '');
        resolve({ status: res.statusCode ?? 0, headers, body: Buffer.concat(chunks) });
      });
      res.on('error', reject);
    });
    req.on('error', e => {
      if (e instanceof Unreachable) return reject(e);
      const code = (e as NodeJS.ErrnoException).code ?? '';
      const kind = ['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH'].includes(code)
        ? 'refused'
        : CERTIFICATE_ERRORS.has(code)
          ? 'certificate'
          : 'failed';
      reject(new Unreachable(kind, e.message, address));
    });
    req.end(r.body);
  });
}
