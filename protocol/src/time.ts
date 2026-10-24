/**
 * Timestamps on the wire (`sentAt`, a key's `added` and `revoked`): RFC 3339 in UTC, to the second or the
 * millisecond, `YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS.sssZ`, years 0000 to 9999, and a real calendar
 * moment (no 30 February, no hour 24, no leap second). One grammar, so every implementation reads the same
 * instant.
 */
const TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?Z$/;

/** The instant a wire timestamp names, in milliseconds, or null when it is not one. */
export function parseTimestamp(value: unknown): number | null {
  const m = typeof value === 'string' ? TIMESTAMP.exec(value) : null;
  if (!m) return null;
  const [year, month, day, hour, minute, second, ms] = m.slice(1).map(n => Number(n ?? 0));
  // Built field by field: Date.UTC would read years 0 to 99 as 1900 to 1999.
  const d = new Date(0);
  d.setUTCFullYear(year, month - 1, day);
  d.setUTCHours(hour, minute, second, ms);
  const exact =
    d.getUTCFullYear() === year &&
    d.getUTCMonth() === month - 1 &&
    d.getUTCDate() === day &&
    d.getUTCHours() === hour &&
    d.getUTCMinutes() === minute &&
    d.getUTCSeconds() === second;
  return exact ? d.getTime() : null;
}

/** A wire timestamp for a moment, to the millisecond. Throws outside years 0000 to 9999, which none can write. */
export function timestamp(at: Date | number): string {
  const s = new Date(at).toISOString();
  if (parseTimestamp(s) === null) throw new RangeError(`No wire timestamp names ${s}.`);
  return s;
}
