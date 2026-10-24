/** The directory's request and answer shapes. Request bodies are strict: unknown members are refused. */
import { z } from 'zod';
import { idPattern } from '../../lib/ids.ts';
import { normalizePrincipal } from '../../lib/principals.ts';
import {
  CONTACT_TIERS,
  DECISIONS,
  DISCOVERABILITY,
  DISPOSITIONS,
  EDGE_PROVENANCE,
  ENTITY_KINDS,
  GRADES,
  INTRO_CARRYING,
  PROFILE_FIELDS,
  PROVENANCE,
  SCOPE_ACTIONS,
} from './vocab.ts';

export const PersonId = z
  .string()
  .regex(idPattern('person'))
  .meta({ id: 'PersonId', description: 'A person in the directory.' });
export const AttestationId = z.string().regex(idPattern('attestation'));
export const EntityId = z.string().regex(idPattern('entity'));
export const EdgeId = z.string().regex(idPattern('edge'));

/** A principal, as the protocol writes one; read in any case and spacing, answered in its one form. */
export const Principal = z
  .string()
  .max(400)
  .transform((value, ctx) => {
    const principal = normalizePrincipal(value);
    if (principal) return principal;
    ctx.addIssue({ code: 'custom', message: 'A mailto:, tel: or simon-key: identifier.' });
    return z.NEVER;
  })
  .meta({
    id: 'Principal',
    description: 'An identifier: `mailto:<address>`, `tel:+<E.164>` or `simon-key:<key token>`.',
    example: 'mailto:ada@example.com',
  });

export const Scope = z
  .array(z.enum(SCOPE_ACTIONS))
  .meta({ id: 'Scope', description: "What the agent may do in its person's name." });

export const Listing = z
  .object({
    listed: z.boolean(),
    listedAt: z.string().nullable(),
    discoverability: z.enum(DISCOVERABILITY),
    contact: z.enum(CONTACT_TIERS),
    secondDegreeOptIn: z.boolean(),
    introCarrying: z.enum(INTRO_CARRYING),
    introAutoMinGrade: z.enum(GRADES),
  })
  .meta({ id: 'Listing', description: 'Whether and to whom the directory shows a person, and who may write to them.' });

export const ListingPatch = z.strictObject({
  listed: z.boolean().optional().meta({
    description:
      "The person's explicit choice. The first listing opens discoverability and contact to everyone, unless this call sets them.",
  }),
  discoverability: z.enum(DISCOVERABILITY).optional(),
  contact: z
    .enum(CONTACT_TIERS)
    .optional()
    .meta({ description: 'Who may write to the person: `connections` until the first listing.' }),
  secondDegreeOptIn: z
    .boolean()
    .optional()
    .meta({ description: "Let the person's own edges carry others' second-degree relationships. Off until set." }),
  introCarrying: z.enum(INTRO_CARRYING).optional(),
  introAutoMinGrade: z.enum(GRADES).optional(),
});

export const Fact = z
  .object({
    id: z.string(),
    field: z.string(),
    value: z.unknown(),
    provenance: z.enum(PROVENANCE),
    self: z.boolean(),
    disposition: z.enum(DISPOSITIONS),
    createdAt: z.string(),
  })
  .meta({ id: 'Fact' });

/** What a subject decides about an attestation about them. */
export const Disposal = z.strictObject({ disposition: z.enum(DECISIONS) });

export const Profile = z
  .object({ person: PersonId, claimed: z.boolean(), facts: z.array(Fact) })
  .meta({ id: 'Profile' });

export const Note = z
  .object({ strength: z.number().int(), summary: z.string().nullable() })
  .nullable()
  .meta({ id: 'Note', description: 'Your own strength and note about this person, returned only to you.' });

export const Relationship = z
  .object({ grade: z.enum(GRADES), degree: z.union([z.literal(1), z.literal(2)]).nullable() })
  .meta({
    id: 'Relationship',
    description:
      'Your own relationship to someone, from your own edges: your best grade, and the degree they reach (2 through someone who opted in).',
  });

export const Entity = z
  .object({
    id: EntityId,
    kind: z.enum(ENTITY_KINDS),
    name: z.string(),
    aliases: z.array(z.string()),
    domains: z.array(z.string()),
    claimed: z.boolean(),
  })
  .meta({ id: 'Entity' });

export const AttestationIn = z.strictObject({
  field: z
    .enum(PROFILE_FIELDS)
    .meta({ description: 'About your own person, any field; about anyone else, only name, title or affiliation.' }),
  value: z.string().max(4000).optional(),
  affiliation: z
    .strictObject({
      domain: z.string().max(253).nullable().optional(),
      name: z.string().max(200).nullable().optional(),
      kind: z.enum(ENTITY_KINDS).nullable().optional(),
      title: z.string().max(200).nullable().optional(),
      start: z.string().max(20).nullable().optional(),
      end: z.string().max(20).nullable().optional(),
    })
    .optional(),
  provenance: z
    .enum(['imported', 'observed'])
    .optional()
    .meta({ description: 'About someone else: a list you were given, or your own observation.' }),
});

export const EdgeIn = z.strictObject({
  identifier: Principal,
  strength: z
    .number()
    .int()
    .min(1)
    .max(5)
    .meta({ description: '1 barely, 2 weak, 3 working, 4 strong, 5 close, by the rubric in skill/grade.js.' }),
  provenance: z.enum(EDGE_PROVENANCE).optional().meta({ description: 'Only observed may be stronger than working.' }),
  introduceOk: z.boolean().optional(),
  summary: z
    .string()
    .max(200)
    .nullable()
    .optional()
    .meta({ description: 'A private note for your future self: no links, addresses or numbers.' }),
});

export const Edge = z
  .object({
    id: EdgeId,
    to: PersonId,
    identifier: z.string(),
    writtenBy: z.string(),
    strength: z.number().int(),
    grade: z.enum(GRADES),
    provenance: z.enum(EDGE_PROVENANCE),
    introduceOk: z.boolean(),
    summary: z.string().nullable(),
    hidden: z.boolean(),
    updatedAt: z.string(),
  })
  .meta({ id: 'Edge' });

export const AgentCard = z
  .object({
    address: z.string(),
    kind: z.enum(['paired', 'solo']),
    name: z.string(),
    description: z.string(),
    capabilities: z.object({
      email: z.boolean(),
      attachments: z.boolean(),
      contentTypes: z.array(z.string()),
      homepage: z.string().nullable(),
    }),
    keys: z.array(z.object({ key: z.string(), fingerprint: z.string() })),
    createdAt: z.string(),
  })
  .meta({ id: 'AgentCard' });

/** One of a person's agents as a resolve answers it: its address, and its card once published. */
export const ResolvedAgent = z
  .object({
    address: z.string(),
    card: z
      .object({ name: z.string(), description: z.string(), capabilities: AgentCard.shape.capabilities })
      .nullable()
      .meta({ description: 'Null until the card is published.' }),
  })
  .meta({ id: 'ResolvedAgent' });

export const Connection = z
  .object({
    person: PersonId.nullable(),
    name: z.string().nullable(),
    identifiers: z.array(z.string()),
    grade: z.enum(GRADES),
    profile: Profile.nullable(),
    facts: z.array(Fact),
    yourNote: Note,
  })
  .meta({ id: 'Connection' });

/** A pair as its person sees it in the owner window, or its agent on the check-in. */
export const Pair = z
  .object({
    address: z.string(),
    identifier: z.string(),
    person: PersonId,
    scope: Scope,
    verifiedAt: z.string(),
    recoveredAt: z
      .string()
      .nullable()
      .meta({ description: 'Its keys were replaced by a code; until confirmed, it only converses.' }),
  })
  .meta({ id: 'Pair' });
