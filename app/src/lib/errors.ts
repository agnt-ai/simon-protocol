/**
 * Errors as this application's API answers them: RFC 9457 problem details, the protocol's shape
 * (`{type, title, status, code, retryable, detail, details?}`, spec/protocol.md section 9). `invalid`
 * (400, `details.field`) comes from @agnt-sdk/simon-protocol.
 */
import { WireError } from '@agnt-sdk/simon-protocol';

export { invalid, WireError } from '@agnt-sdk/simon-protocol';

/** A missing resource, always the same code, with `details.what` naming what was missing. */
export const notFound = (what: string, message = `No such ${what}.`) =>
  new WireError(404, 'not_found', message, { what });

const error = (status: number) => (code: string, message: string, details?: Record<string, unknown>) =>
  new WireError(status, code, message, details);

export const badRequest = error(400);
export const unauthorized = error(401);
export const forbidden = error(403);
export const conflict = error(409);
export const gone = error(410);
export const unprocessable = error(422);

/** A limit was reached: retry after `retryAfter` seconds (sent as Retry-After). */
export const rateLimited = (retryAfter: number) =>
  new WireError(429, 'rate_limited', `Too many requests; retry in ${retryAfter} s.`, { retryAfter });

/** Something this application needs failed for now. */
export const unavailable = (message: string, retryAfter = 30) =>
  new WireError(503, 'unavailable', message, { retryAfter });
