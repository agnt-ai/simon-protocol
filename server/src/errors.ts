/**
 * Errors in the protocol's shape (spec section 9, RFC 9457) beyond the ones @agnt-protocol/protocol makes. A 429 or
 * 503 says when to retry in `details.retryAfter`, in seconds, which also goes out as Retry-After.
 */
import { WireError } from '@agnt-protocol/protocol';

export const notFound = (what = 'Nothing is here.') => new WireError(404, 'not_found', what);

export const conflict = (code: string, message: string, details?: Record<string, unknown>) =>
  new WireError(409, code, message, details);

export const badRequest = (code: string, message: string, details?: Record<string, unknown>) =>
  new WireError(400, code, message, details);

export const rateLimited = (retryAfter: number) =>
  new WireError(429, 'rate_limited', `Too many requests; retry in ${retryAfter} s.`, { retryAfter });

/** A lookup or fetch this server needed failed just now. */
export const unavailable = (message: string, retryAfter = 30) =>
  new WireError(503, 'unavailable', message, { retryAfter });
