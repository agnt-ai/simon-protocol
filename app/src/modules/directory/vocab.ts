/** The directory's vocabulary: the enumerations its records, its rules and its API share. */

/** Who may find a person in the directory. */
export const DISCOVERABILITY = ['everyone', 'connections', 'second_degree', 'private'] as const;
export type Discoverability = (typeof DISCOVERABILITY)[number];

/** Who may write to a person's agents, by graph relation. */
export const CONTACT_TIERS = ['anyone', 'connections', 'second_degree', 'introduced_only'] as const;
export type ContactTier = (typeof CONTACT_TIERS)[number];

/** Whether a person's relationships carry introductions for others. */
export const INTRO_CARRYING = ['never', 'ask', 'auto'] as const;
export type IntroCarrying = (typeof INTRO_CARRYING)[number];

/** Where a fact came from, weakest first. The last two are computed on read, never written. */
export const PROVENANCE = ['self_reported', 'imported', 'observed', 'domain_verified', 'corroborated'] as const;
export type Provenance = (typeof PROVENANCE)[number];

export const EDGE_PROVENANCE = ['observed', 'imported', 'self_reported'] as const;
export type EdgeProvenance = (typeof EDGE_PROVENANCE)[number];

/** A relationship's strength by name: its place here. Agents rate 1 to 5 with skill/grade.js. */
export const GRADES = ['none', 'barely', 'weak', 'working', 'strong', 'close'] as const;
export type Grade = (typeof GRADES)[number];
export const gradeOf = (strength: number): Grade => GRADES[Math.max(0, Math.min(5, strength))];
export const rankOf = (grade: Grade) => GRADES.indexOf(grade);

/** Strength that counts as knowing someone at all. */
export const ANY_EDGE = 1;
/** What an agent did not observe itself never counts as more than this. */
export const UNOBSERVED_CAP = 3;
/** The least strength of a carrier's edge to an introduction's target. */
export const CARRY_MIN = 3;

/** What a paired agent may do in its person's name, as its acts-for claim says. Agents honour it. */
export const SCOPE_ACTIONS = ['converse', 'schedule', 'negotiate', 'commit'] as const;
export type ScopeAction = (typeof SCOPE_ACTIONS)[number];

export const PROFILE_FIELDS = [
  'name',
  'headline',
  'title',
  'location',
  'bio',
  'affiliation',
  'link',
  'skill',
  'interest',
] as const;
export type ProfileField = (typeof PROFILE_FIELDS)[number];

/** What others say about someone may be only these: nothing else about a person is anyone else's to say. */
export const ATTESTABLE_BY_OTHERS: readonly ProfileField[] = ['name', 'title', 'affiliation'];

/**
 * Where an attestation stands with its subject. Others' start `pending` and are shown only once the subject
 * confirms them; the subject's own are `confirmed` as written.
 */
export const DISPOSITIONS = ['pending', 'confirmed', 'hidden', 'disputed'] as const;
export type Disposition = (typeof DISPOSITIONS)[number];

/** What a subject may decide about an attestation. */
export const DECISIONS = ['confirmed', 'hidden', 'disputed'] as const;
export type Decision = (typeof DECISIONS)[number];

export const ENTITY_KINDS = ['company', 'school', 'organization'] as const;
export type EntityKind = (typeof ENTITY_KINDS)[number];
