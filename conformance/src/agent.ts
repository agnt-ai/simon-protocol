/**
 * An agent of the server under test, as the suite drives it: a key, an address once registered, and
 * signed calls to the client API. Built on the protocol package alone, so nothing a product client adds
 * can hide a server's fault.
 */
import crypto, { type KeyObject } from 'node:crypto';
import {
  canonicalize,
  generateKey,
  keyToken,
  requestSigningString,
  sign,
  signMessage,
  timestamp,
  type AnyMessage,
  type Message,
  type Part,
} from '@agnt-protocol/protocol';
import type { Req, Res, T } from './harness.ts';

export interface SignOptions {
  /** Sign with this key instead of the agent's. */
  key?: KeyObject;
  /** The origin line, when it should not be the server's. */
  origin?: string;
  /** The request target that is signed, when it should not be the one sent. */
  signedTarget?: string;
  /** The body that is signed, when it should not be the one sent. */
  signedBody?: string | Buffer;
  /** Unix seconds as sent, or an offset in seconds from the server's clock. */
  timestamp?: string;
  skewSeconds?: number;
  nonce?: string;
  /** Act as this address (`simon-agent`) instead of the agent's own; null for no actor at all. */
  agent?: string | null;
  /** Replace or drop (undefined) headers after signing. */
  override?: Record<string, string | undefined>;
  headers?: Record<string, string>;
}

export const newNonce = () => crypto.randomBytes(16).toString('base64url');

/** The signature headers over an agent's request, as section 8 builds them: `simon-agent` when it acts as one. */
export function signatureHeaders(
  key: KeyObject,
  r: {
    method: string;
    origin: string;
    target: string;
    body: string | Buffer;
    timestamp: string;
    nonce: string;
    agent?: string;
  },
): Record<string, string> {
  const { agent, ...rest } = r;
  const signing = requestSigningString({ ...rest, actor: agent ?? '' });
  return {
    'simon-key': keyToken(key),
    'simon-timestamp': r.timestamp,
    'simon-nonce': r.nonce,
    'simon-signature': sign(key, signing),
    ...(agent ? { 'simon-agent': agent } : {}),
  };
}

export class TargetAgent {
  readonly key: KeyObject;
  readonly token: string;
  address: string;
  /** Other keys this agent holds, beyond `key`. */
  readonly extraKeys: KeyObject[] = [];

  readonly server: { origin: string; now: () => number };

  constructor(server: { origin: string; now: () => number }, key: KeyObject, address = '') {
    this.server = server;
    this.key = key;
    this.token = keyToken(key);
    this.address = address;
  }

  static fresh(server: { origin: string; now: () => number }, alg: 'ed25519' | 'ml-dsa-65' = 'ed25519') {
    return new TargetAgent(server, generateKey(alg).privateKey);
  }

  /** A signed request, made fresh each time it is called (a 429 retry signs again with a new nonce). */
  request(method: string, target: string, body?: string | Buffer, o: SignOptions = {}): () => Req {
    return () => {
      const ts = o.timestamp ?? String(Math.floor(this.server.now() / 1000) + (o.skewSeconds ?? 0));
      const headers: Record<string, string> = {
        ...o.headers,
        ...signatureHeaders(o.key ?? this.key, {
          method,
          origin: o.origin ?? this.server.origin,
          target: o.signedTarget ?? target,
          body: o.signedBody ?? body ?? '',
          timestamp: ts,
          nonce: o.nonce ?? newNonce(),
          agent: (o.agent === undefined ? this.address : o.agent) || undefined,
        }),
      };
      for (const [k, v] of Object.entries(o.override ?? {})) {
        if (v === undefined) delete headers[k];
        else headers[k] = v;
      }
      return { method, origin: this.server.origin, target, headers, body };
    };
  }

  call(
    t: T,
    method: string,
    target: string,
    body?: string | Buffer,
    o: SignOptions = {},
    label?: string,
  ): Promise<Res> {
    return t.http(this.request(method, target, body, o), { label });
  }

  register(t: T, body: Record<string, unknown>, o: SignOptions = {}, label = 'register') {
    return this.call(t, 'POST', '/simon/register', JSON.stringify({ key: this.token, ...body }), o, label);
  }

  recover(t: T, body: Record<string, unknown>, o: SignOptions = {}, label = 'recover') {
    return this.call(
      t,
      'POST',
      '/simon/recovery',
      JSON.stringify({ key: this.token, ...body }),
      { agent: typeof body.address === 'string' ? body.address : this.address, ...o },
      label,
    );
  }

  cancelRecovery(t: T, body: Record<string, unknown>, o: SignOptions = {}, label = 'cancel recovery') {
    return this.call(
      t,
      'POST',
      '/simon/recovery/cancel',
      JSON.stringify(body),
      { agent: typeof body.address === 'string' ? body.address : this.address, ...o },
      label,
    );
  }

  send(t: T, m: AnyMessage | string, o: SignOptions = {}, label = 'send') {
    return this.call(t, 'POST', '/simon/send', typeof m === 'string' ? m : canonicalize(m), o, label);
  }

  sync(t: T, query = 'limit=200', label = 'sync') {
    return this.call(t, 'GET', `/simon/sync${query ? `?${query}` : ''}`, undefined, {}, label);
  }

  /** A version 1 message from this agent, signed. */
  message(f: MessageFields = {}): Message {
    return buildMessage({ from: this.address, ...f }, f.signWith ?? this.key, this.server.now());
  }
}

export interface MessageFields {
  from?: string;
  to?: string[];
  text?: string;
  parts?: Part[];
  headers?: Record<string, string>;
  inReplyTo?: string | null;
  /** A wire timestamp, or an offset in seconds from the server's clock. */
  sentAt?: string;
  ageSeconds?: number;
  signWith?: KeyObject;
  /** Exactly the parts given, with no text added: a message need carry none (section 5.3). */
  bare?: boolean;
}

let counter = 0;

/** An inline text/plain or text/markdown part. */
const isTextBlock = (p: Part) => 'data' in p && /^text\/(plain|markdown)(;|$)/.test(p.type);

/**
 * A signed version 1 message. Each one differs, so no two are repeats of each other: a text of its own
 * comes first, unless the parts given carry one, or the message is `bare`.
 */
export function buildMessage(f: MessageFields & { from: string }, key: KeyObject, now: number): Message {
  const text = f.text ?? `conformance ${process.pid}-${Date.now()}-${++counter}`;
  return signMessage<Message>(
    {
      v: 1,
      from: f.from,
      to: f.to ?? [],
      inReplyTo: f.inReplyTo ?? null,
      parts:
        f.bare || f.parts?.some(isTextBlock)
          ? (f.parts ?? [])
          : [{ type: 'text/plain', data: text }, ...(f.parts ?? [])],
      headers: f.headers ?? {},
      sentAt: f.sentAt ?? timestamp(Math.floor((now - (f.ageSeconds ?? 0) * 1000) / 1000) * 1000),
    },
    key,
  );
}

/** Re-sign a message after changing it, as a malicious or careless author would. */
export function resign<M extends AnyMessage>(m: M, key: KeyObject): M {
  const { signature: _, ...unsigned } = m;
  return signMessage(unsigned as never, key) as M;
}
