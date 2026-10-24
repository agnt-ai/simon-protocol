// The SIMON relationship-strength rubric, as runnable code. Every agent computes strength with this
// same function from its own person's mail, calendar and contacts, so the same history gives the same
// number everywhere. Only the number leaves the agent; the counts never do.
//
//   node grade.js '{"threads":"10-49","meetings":"3-9","lastTouch":"30d"}'      prints 4
//   import { grade } from './grade.js'
//
// Inputs are coarse buckets, counted locally:
//   threads    two-way email threads (both sides wrote):   "0" | "1-2" | "3-9" | "10-49" | "50+"
//   meetings   events both attended (not declined):        "0" | "1-2" | "3-9" | "10+"
//   recurring  active shared recurring series:             "0" | "1" | "2+"
//   lastTouch  most recent two-way contact:                "30d" | "90d" | "1y" | "older" | "never"
//   explicit   your person said something explicit and positive about them: true | false
//   sameOrg    you share an organisation:                  true | false
//   provenance "observed" (you counted it) | "imported" (a list your person gave you) | "self_reported"
//
// Output, 1..5 (0 means "do not submit"):
//   1 barely   a known connection with no two-way contact (the same school or company, an explicit word)
//   2 weak     any two-way contact
//   3 working  three or more threads, or any meeting
//   4 strong   ten or more threads, or three or more meetings, with contact in the last 90 days
//   5 close    a shared recurring series, or fifty or more threads, with contact in the last 90 days
// No contact in over a year caps strength at 2. Anything not observed caps at 3 (the network enforces
// this cap too).
//
// Examples: a former colleague you still email now and then -> 4; someone you went to school with and
// are not in touch with -> 1; someone you had coffee with last week and meet every month -> 5.

export const THREADS = ['0', '1-2', '3-9', '10-49', '50+'];
export const MEETINGS = ['0', '1-2', '3-9', '10+'];
export const RECURRING = ['0', '1', '2+'];
export const LAST_TOUCH = ['30d', '90d', '1y', 'older', 'never'];
export const NAMES = ['none', 'barely', 'weak', 'working', 'strong', 'close'];

const at = (list, v) => Math.max(0, list.indexOf(v ?? list[0]));

export function grade({
  threads = '0',
  meetings = '0',
  recurring = '0',
  lastTouch = 'never',
  explicit = false,
  sameOrg = false,
  provenance = 'observed',
} = {}) {
  const t = at(THREADS, threads);
  const m = at(MEETINGS, meetings);
  const r = at(RECURRING, recurring);
  const touch = LAST_TOUCH.indexOf(lastTouch);
  const within90 = touch === 0 || touch === 1;
  const withinYear = touch >= 0 && touch <= 2;

  const contact = t >= 1 || m >= 1 || r >= 1;
  let s = 0;
  if (!contact && (explicit || sameOrg)) s = 1;
  if (contact) s = 2;
  if (t >= 2 || m >= 1) s = 3;
  if ((t >= 3 || m >= 2) && within90) s = 4;
  if ((r >= 1 || t >= 4) && within90) s = 5;
  if (contact && !withinYear && s > 2) s = 2;
  if (provenance !== 'observed' && s > 3) s = 3;
  return s;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(grade(JSON.parse(process.argv[2] ?? '{}')));
}
