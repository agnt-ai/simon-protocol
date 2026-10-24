/**
 * Errors are RFC 9457 problem details (spec section 9), sent as `application/problem+json`:
 *
 *   { type: "about:blank", title, status, code, retryable, detail, details? }
 *
 * `code` is stable and `detail` may change. `retryable` is true exactly for 429 and 5xx, so it follows from
 * the status rather than being chosen. Validation errors are honest and synchronous; policy is never an
 * error (a server answers 202 whether or not it delivers).
 */
import { isJsonObject, parseStrict } from './canonical.ts';

export const PROBLEM_CONTENT_TYPE = 'application/problem+json';

/** The scheme every request-signature 401 names in `WWW-Authenticate` (spec section 8). */
export const AUTH_SCHEME = 'AGNT';

export interface Problem {
  type: string;
  title: string;
  status: number;
  code: string;
  retryable: boolean;
  detail: string;
  details?: Record<string, unknown>;
}

/** Whether an answer of this status may succeed if repeated later: 429 and 5xx, and nothing else. */
export const isRetryable = (status: number) => status === 429 || (status >= 500 && status <= 599);

/** A code as a short human title, `bad_signature` as `Bad signature`, since `about:blank` has no title of its own. */
const titleOf = (code: string) => (code.charAt(0).toUpperCase() + code.slice(1)).replaceAll('_', ' ');

export class WireError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: Record<string, unknown>;

  constructor(status: number, code: string, detail: string, details?: Record<string, unknown>);
  /** @deprecated `retryable` follows from the status; pass `details` fourth. */
  constructor(status: number, code: string, detail: string, retryable: boolean, details?: Record<string, unknown>);
  constructor(
    status: number,
    code: string,
    detail: string,
    a?: boolean | Record<string, unknown>,
    b?: Record<string, unknown>,
  ) {
    super(detail);
    this.name = 'WireError';
    this.status = status;
    this.code = code;
    this.details = typeof a === 'boolean' ? b : a;
  }

  get retryable() {
    return isRetryable(this.status);
  }

  toProblem(): Problem {
    return {
      type: 'about:blank',
      title: titleOf(this.code),
      status: this.status,
      code: this.code,
      retryable: this.retryable,
      detail: this.message,
      ...(this.details ? { details: this.details } : {}),
    };
  }

  toJSON() {
    return this.toProblem();
  }

  /**
   * The headers this answer carries: its content type; on a 401 the challenge HTTP requires; and Retry-After
   * when `details.retryAfter` gives the seconds to wait.
   */
  get headers(): Record<string, string> {
    const retryAfter = this.details?.retryAfter;
    return {
      'content-type': PROBLEM_CONTENT_TYPE,
      ...(this.status === 401 ? { 'www-authenticate': AUTH_SCHEME } : {}),
      ...(typeof retryAfter === 'number' ? { 'retry-after': String(retryAfter) } : {}),
    };
  }
}

/**
 * A problem read from an error answer, for clients: its `code`, `detail` and `details` when they are the
 * right types, with `status` and `retryable` taken from the HTTP status, which is what a client acts on.
 * Null when the body is no problem detail (no string `code`), so the caller falls back on the status.
 */
export function parseProblem(status: number, body: Uint8Array | string): Problem | null {
  let value;
  try {
    value = parseStrict(body);
  } catch {
    return null;
  }
  if (!isJsonObject(value) || typeof value.code !== 'string') return null;
  const str = (v: unknown, fallback: string) => (typeof v === 'string' ? v : fallback);
  return {
    type: str(value.type, 'about:blank'),
    title: str(value.title, titleOf(value.code)),
    status,
    code: value.code,
    retryable: isRetryable(status),
    detail: str(value.detail, ''),
    ...(isJsonObject(value.details) ? { details: value.details } : {}),
  };
}

export const invalid = (detail: string, details?: Record<string, unknown>) =>
  new WireError(400, 'invalid', detail, details);

export const bodyTooLarge = (limit: number) =>
  new WireError(413, 'body_too_large', `The body is larger than this server's ${limit} bytes.`);

/** A refused request signature. Every 401 carries the server's clock in unix seconds, so a signer can see its skew. */
export const unauthorized = (code: string, detail: string, now: Date, details?: Record<string, unknown>) =>
  new WireError(401, code, detail, { serverTime: Math.floor(now.getTime() / 1000), ...details });

/** A refused envelope or message signature at deliver (spec section 6.3): 403, never 401, since no request failed. */
export const forbidden = (code: 'bad_signature' | 'unsupported_algorithm', detail: string) =>
  new WireError(403, code, detail);

/** `send` of a message whose version this server does not implement (CLIENT.md). */
export const unsupportedVersion = (v: number) =>
  new WireError(400, 'unsupported_version', `This server does not implement version ${v} messages.`, { field: 'v' });
