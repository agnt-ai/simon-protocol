/**
 * Entities: companies, schools and organisations, keyed by domain. Anyone's agent may name one; a person
 * proves an organisation is theirs with a DNS TXT record at `_simon-challenge.<domain>`, then names it and
 * attests who works there. A roster attestation by an address at the entity's own domain is the strongest
 * evidence of an affiliation here, so it is recorded as corroborated; like anything said about someone
 * else, it waits for its subject to confirm it.
 */
import { normalizeDomain } from '@agnt-sdk/simon-protocol';
import type { Ctx } from '../../context.ts';
import { badRequest, conflict, forbidden, invalid, notFound, unprocessable } from '../../lib/errors.ts';
import { newId } from '../../lib/ids.ts';
import { emailDomain } from '../../lib/principals.ts';
import { randomToken } from '../../lib/secrets.ts';
import { plainText } from '../../lib/text.ts';
import type { Attestation, Entity, GraphStore } from './graph-store.ts';
import type { People } from './people.ts';
import type { Person } from './store.ts';
import type { EntityKind } from './vocab.ts';

const CHALLENGE_MS = 48 * 3600_000;

/** Consumer mail providers: an address there says nothing about where a person works. */
const FREEMAIL = new Set(
  'gmail.com googlemail.com yahoo.com ymail.com outlook.com hotmail.com live.com msn.com aol.com icloud.com me.com mac.com proton.me protonmail.com pm.me gmx.com gmx.de gmx.net web.de mail.com zoho.com yandex.com yandex.ru mail.ru qq.com 163.com 126.com fastmail.com hey.com tutanota.com tuta.io comcast.net verizon.net att.net btinternet.com orange.fr free.fr t-online.de libero.it naver.com'.split(
    ' ',
  ),
);

/** A web domain from what a person may type (`https://www.Example.com/about`), or null. */
export function webDomain(raw: string): string | null {
  const host = raw
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split(/[/?#]/)[0]
    .replace(/\.$/, '');
  return normalizeDomain(host);
}

/** Consumer mail never becomes an entity; this also matches the providers' national domains. */
export const isFreemail = (domain: string) =>
  FREEMAIL.has(domain) || /^(yahoo|hotmail|outlook|live|gmx|aol|yandex)\.[a-z.]{2,6}$/.test(domain);

const isSchool = (domain: string) => /\.(edu|ac\.[a-z]{2}|edu\.[a-z]{2})$/.test(domain);

/** Named from the domain, so the first writer cannot call `example-evil.com` "Example". */
const nameOf = (domain: string) => {
  const label = domain.split('.').at(-2) ?? domain;
  return label[0].toUpperCase() + label.slice(1);
};

export const entityView = (e: Entity) => ({
  id: e._id,
  kind: e.kind,
  name: e.name,
  aliases: e.aliases,
  domains: e.domains,
  claimed: !!e.claimedBy,
});

export class Entities {
  readonly #ctx: Ctx;
  readonly #graph: GraphStore;
  readonly #people: People;

  constructor(ctx: Ctx, graph: GraphStore, people: People) {
    this.#ctx = ctx;
    this.#graph = graph;
    this.#people = people;
  }

  async get(id: string): Promise<Entity> {
    const entity = await this.#graph.entity(id);
    if (!entity) throw notFound('entity');
    return entity;
  }

  /** The entity at a domain, or one by exact name for an organisation with none; made when missing. */
  async findOrCreate(input: {
    domain?: string | null;
    name?: string | null;
    kind?: EntityKind | null;
  }): Promise<Entity> {
    const base = { aliases: [], claimedBy: null, challenges: [], createdAt: this.#ctx.now() };
    if (input.domain) {
      const domain = webDomain(input.domain);
      if (!domain) throw invalid('domain is not a domain.', { field: 'domain' });
      if (isFreemail(domain)) throw badRequest('freemail_domain', 'Consumer mail domains never become an entity.');
      return (
        (await this.#graph.entityByDomain(domain)) ??
        this.#graph.insertEntity({
          _id: newId('entity'),
          kind: input.kind ?? (isSchool(domain) ? 'school' : 'company'),
          name: nameOf(domain),
          domains: [domain],
          ...base,
        })
      );
    }
    const name = plainText('name', input.name?.trim() ?? '');
    if (!name) throw invalid('Give a domain, or a name for an organisation with none.', { field: 'domain' });
    // Matched only exactly, so lookalike names never merge.
    const same = (await this.#graph.entitiesNamed(name, 10)).find(
      e => !e.domains.length && e.name.toLowerCase() === name.toLowerCase(),
    );
    return (
      same ??
      this.#graph.insertEntity({ _id: newId('entity'), kind: input.kind ?? 'organization', name, domains: [], ...base })
    );
  }

  /** Entity ids a search names: ids, domains, or name prefixes (a school facet takes only schools). */
  async named(values: string[], facet: 'company' | 'school'): Promise<string[]> {
    const ids: string[] = [];
    for (const v of values.slice(0, 10)) {
      const domain = webDomain(v);
      const byDomain = (await this.#graph.entity(v)) ?? (domain && (await this.#graph.entityByDomain(domain)));
      if (byDomain) ids.push(byDomain._id);
      else
        for (const e of await this.#graph.entitiesNamed(v, 5))
          if ((e.kind === 'school') === (facet === 'school')) ids.push(e._id);
    }
    return ids;
  }

  /** A DNS challenge of this person's own for one of the entity's domains. */
  async startClaim(person: Person, entityId: string, domainIn: string) {
    const entity = await this.get(entityId);
    const domain = webDomain(domainIn);
    if (!domain || !entity.domains.includes(domain))
      throw invalid("domain is one of the entity's domains.", { field: 'domain' });
    if (entity.claimedBy && entity.claimedBy.person !== person._id)
      throw conflict('entity_claimed', 'This entity is already claimed.');
    const challenge = {
      token: `simon-verify=${randomToken(18)}`,
      person: person._id,
      domain,
      expiresAt: new Date(this.#ctx.now().getTime() + CHALLENGE_MS),
    };
    await this.#graph.setChallenge(entity._id, challenge, this.#ctx.now());
    return { record: `_simon-challenge.${domain}`, type: 'TXT' as const, value: challenge.token };
  }

  async completeClaim(person: Person, agent: string, entityId: string): Promise<Entity> {
    const entity = await this.get(entityId);
    if (entity.claimedBy?.person === person._id) return entity;
    if (entity.claimedBy) throw conflict('entity_claimed', 'This entity is already claimed.');
    const ch = entity.challenges.find(c => c.person === person._id);
    if (!ch) throw conflict('claim_not_started', 'Start a claim first.');
    if (ch.expiresAt <= this.#ctx.now()) throw conflict('challenge_expired', 'The challenge expired; start again.');
    const records = await this.#ctx.dns.txt(`_simon-challenge.${ch.domain}`).catch(() => []);
    if (!records.some(r => r.join('') === ch.token)) {
      throw unprocessable(
        'challenge_not_found',
        'The TXT record is not there yet; DNS can take a while, so try again.',
      );
    }
    const claimed = await this.#graph.claimEntity(entity._id, { agent, person: person._id, at: this.#ctx.now() });
    if (!claimed) throw conflict('entity_claimed', 'This entity is already claimed.');
    return claimed;
  }

  async rename(person: Person, entityId: string, input: { name?: string; aliases?: string[] }): Promise<Entity> {
    const entity = await this.#owned(person, entityId);
    const name = plainText('name', input.name?.trim() || entity.name);
    const aliases = [
      ...new Set((input.aliases ?? entity.aliases).map(a => plainText('aliases', a.trim())).filter(Boolean)),
    ];
    return (await this.#graph.updateEntity(entity._id, { name, aliases }))!;
  }

  /** The organisation attests who works there, through `identifier`'s agent: one affiliation each. */
  async attestRoster(
    person: Person,
    agent: string,
    identifier: string,
    entityId: string,
    members: { identifier: string; title?: string | null; start?: string | null; end?: string | null }[],
  ): Promise<number> {
    const entity = await this.#owned(person, entityId);
    const now = this.#ctx.now();
    const records: Attestation[] = [];
    for (const m of members) {
      const subject = (await this.#people.forPrincipal(m.identifier, true))!;
      const verified = !!(await this.#people.store.identifier(m.identifier))?.verifiedAt;
      // It vouches for its own domain only: anyone listed by an address elsewhere is an ordinary import.
      const atDomain = verified && entity.domains.includes(emailDomain(m.identifier) ?? '');
      const title = m.title?.trim() || null;
      records.push({
        _id: newId('attestation'),
        subject: subject._id,
        field: 'affiliation',
        value: { entity: entity._id, title, start: m.start ?? null, end: m.end ?? null },
        norm: `${entity._id}|${(title ?? '').toLowerCase()}`,
        authorAgent: agent,
        authorPrincipal: person._id,
        authorIdentifier: identifier,
        via: m.identifier,
        provenance: atDomain ? 'corroborated' : 'imported',
        disposition: subject._id === person._id ? 'confirmed' : 'pending',
        retractedAt: null,
        createdAt: now,
      });
    }
    await this.#graph.insertAttestations(records);
    return records.length;
  }

  async #owned(person: Person, entityId: string): Promise<Entity> {
    const entity = await this.get(entityId);
    if (entity.claimedBy?.person !== person._id)
      throw forbidden('not_entity_owner', 'Only the person who claimed this entity may do that.');
    return entity;
  }
}
