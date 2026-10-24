import { normalizeAddress, serverOrigin } from '@agnt-sdk/simon-protocol';

/**
 * Every failure this client reports is a SimonError. A server's refusal keeps the server's code, message,
 * status, retryable flag and details exactly as sent. Failures with no server answer behind them have
 * `status: null` and one of these codes:
 *
 *   invalid         an argument the client refused before sending; `details.field` names it
 *   not_registered  the call needs the agent's address, and the agent has none yet
 *   network_error   no answer: the connection failed (retryable; `details.url`, `details.cause`)
 *   timeout         no answer within the timeout (retryable; `details.url`)
 *   bad_response    an answer that is not what the protocol says it is (`details.url`)
 *   hash_mismatch   part bytes whose hash or size is not the part's
 *   unavailable     a document or resolution failed in a way that may pass (retryable)
 *   no_server       the author's domain resolves to no server (`details.outcome`)
 *   bad_document    a document that is not readable as the protocol says (`details.url`)
 */
export class SimonError extends Error {
  override readonly name = 'SimonError';
  readonly code: string;
  /** The HTTP status of the server's answer, or null when there was none. */
  readonly status: number | null;
  readonly retryable: boolean;
  readonly details: Record<string, unknown> | undefined;
  /** Seconds to wait before retrying, from a `Retry-After` header. */
  readonly retryAfter: number | undefined;

  constructor(
    code: string,
    message: string,
    opts: { status?: number | null; retryable?: boolean; details?: Record<string, unknown>; retryAfter?: number } = {},
  ) {
    super(message);
    this.code = code;
    this.status = opts.status ?? null;
    this.retryable = opts.retryable ?? false;
    this.details = opts.details;
    this.retryAfter = opts.retryAfter;
  }

  /** The protocol's error shape, plus `status` and `retryAfter`. */
  toJSON() {
    const { code, message, status, retryable, details, retryAfter } = this;
    return { error: { code, message, status, retryable, details, retryAfter } };
  }
}

/** A refused argument, named by its field. */
export const invalid = (field: string, message: string) => new SimonError('invalid', message, { details: { field } });

/** A server origin as the URL standard writes it, or `invalid`. `http:` is accepted, for local development. */
export function originArg(field: string, value: string): string {
  const origin = serverOrigin(value, true);
  if (!origin) throw invalid(field, `${field} is an origin such as https://simon.example.com, not ${value}.`);
  return origin;
}

/** An address in its wire form (lower case), or `invalid`. */
export function addressArg(field: string, value: string): string {
  const address = normalizeAddress(value);
  if (!address) throw invalid(field, `${field} is not an address (local@domain): ${value}`);
  return address;
}
