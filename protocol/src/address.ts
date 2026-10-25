/**
 * Addresses: `local@domain`, the only thing the protocol routes to (spec section 2.1).
 *
 *   - The domain is an ASCII DNS name of at most 253 bytes; an internationalised domain travels as A-labels.
 *   - The local part, in every version, is 1 to 64 bytes of UTF-8 with no `@`, no space (U+0020), no ASCII
 *     capital and no character of general category Cc: a set Unicode's stability policy fixes, so routers
 *     on any Unicode version agree. Normalisation is not checked here: whether a string is NFC depends on
 *     the runtime's Unicode tables, and a version that allows non-ASCII local parts judges them against
 *     Unicode 17.0 on agents' own servers and in readers. Version 2 narrows the local part to email's ASCII
 *     dot-atom, so a later version can widen it without touching routing.
 *   - Inside a message an address is written in lower case (ASCII lowercasing only), so one message has one
 *     form and one id. Elsewhere (an API, a command line) any case is accepted and lowered.
 */

const LOCAL_V1 = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
/** What no local part in any version holds: `@`, space, category Cc, and (on the wire) ASCII capitals. */
const NOT_IN_LOCAL = /[@ \p{Cc}A-Z]/u;

const lower = (s: string) => s.replace(/[A-Z]/g, c => c.toLowerCase());

/** A domain in its wire form (lower case), or null: at most 253 bytes, two or more labels, the last not all digits. */
export function normalizeDomain(input: unknown): string | null {
  if (typeof input !== 'string' || input.length > 253 || !/^[\x21-\x7e]+$/.test(input)) return null;
  const d = lower(input);
  const labels = d.split('.');
  if (labels.length < 2 || !labels.every(l => LABEL.test(l)) || /^\d+$/.test(labels.at(-1)!)) return null;
  return d;
}

/** A version 2 address in its wire form (ASCII, lower case), from any case, or null. */
export function normalizeAddress(input: unknown): string | null {
  if (typeof input !== 'string' || !/^[\x21-\x7e]+$/.test(input)) return null;
  const s = lower(input);
  const at = s.lastIndexOf('@');
  const local = s.slice(0, at);
  const domain = normalizeDomain(s.slice(at + 1));
  return at > 0 && domain && local.length <= 64 && LOCAL_V1.test(local) ? `${local}@${domain}` : null;
}

/** Whether a value is an address as a version 2 message writes it. */
export const isV1Address = (value: unknown): value is string =>
  typeof value === 'string' && normalizeAddress(value) === value;

/**
 * Whether a value is an address as any version's message may write it: the invariant local part, and a
 * domain in its wire form. This is all a server checks of a version it does not know.
 */
export function isAddress(value: unknown): value is string {
  if (typeof value !== 'string' || !value.isWellFormed()) return false;
  const at = value.lastIndexOf('@');
  const local = value.slice(0, at);
  const domain = value.slice(at + 1);
  return at > 0 && Buffer.byteLength(local) <= 64 && !NOT_IN_LOCAL.test(local) && normalizeDomain(domain) === domain;
}

export const domainOf = (address: string) => address.slice(address.lastIndexOf('@') + 1);

/** RFC 3986 `pchar` bytes, which an address in a path keeps as they are: unreserved, sub-delims, `:` and `@`. */
const PCHAR = /^[A-Za-z0-9\-._~!$&'()*+,;=:@]$/;

/**
 * An address as one path segment (spec section 8): every byte of its UTF-8 that is not an RFC 3986 `pchar`
 * percent-encoded with upper-case hex digits, and nothing else, so `@` stays literal and an address has one
 * form in a path. In a version 2 address those are the characters `# % / ? ^ \` { | }`.
 */
export function addressSegment(address: string): string {
  let out = '';
  for (const byte of Buffer.from(address, 'utf8')) {
    const c = String.fromCharCode(byte);
    out += byte < 0x80 && PCHAR.test(c) ? c : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return out;
}
