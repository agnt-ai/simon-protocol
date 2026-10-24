/**
 * The activity log: one entry for each thing any agent did as a person, in the order written, announced to
 * the person's webhooks. Kept in `owner.activity`; an entry's id is its cursor. Messages a person's agents
 * sent and received are entries too, so the owner window lists them from here. An entry about one of the
 * person's identifiers (what that identifier's agents did, its sign-ins) is shown only to sessions that
 * proved it; one about the whole person, to all of them.
 */
import type { StoredMessage } from 'simon-server';
import { z } from 'zod';
import type { Activity, ActivityFields, Ctx } from '../../context.ts';
import { newId } from '../../lib/ids.ts';
import type { People } from '../directory/people.ts';
import type { Webhooks } from '../webhooks/index.ts';

export interface Entry {
  _id: string;
  person: string;
  kind: string;
  /** The identifier it concerns; null for the whole person. */
  identifier: string | null;
  agent: string | null;
  message: string | null;
  intro: string | null;
  data: Record<string, unknown> | null;
  at: Date;
}

export const ActivityEvent = z
  .object({
    cursor: z.string(),
    kind: z.string(),
    identifier: z.string().nullable(),
    agent: z.string().nullable(),
    message: z.string().nullable(),
    intro: z.string().nullable(),
    data: z.record(z.string(), z.unknown()).nullable(),
    at: z.string(),
  })
  .meta({ id: 'ActivityEvent' });

export const eventView = (e: Entry) => ({
  cursor: e._id,
  kind: e.kind,
  identifier: e.identifier,
  agent: e.agent,
  message: e.message,
  intro: e.intro,
  data: e.data,
  at: e.at.toISOString(),
});

export class ActivityLog implements Activity {
  readonly #ctx: Ctx;
  readonly #entries;
  readonly #webhooks: Webhooks | null;

  constructor(ctx: Ctx, webhooks: Webhooks | null) {
    this.#ctx = ctx;
    this.#entries = ctx.db.collection<Entry>('owner.activity');
    this.#webhooks = webhooks;
  }

  async init() {
    await this.#entries.createIndex({ person: 1, _id: 1 });
    await this.#entries.createIndex({ person: 1, kind: 1, message: 1 });
  }

  async record(person: string, kind: string, fields: ActivityFields = {}) {
    const { agent, identifier, message, intro, ...data } = fields;
    // One entry per person, kind and message, however often the message's event repeats.
    if (message && (await this.#entries.countDocuments({ person, kind, message }, { limit: 1 }))) return;
    const entry: Entry = {
      _id: newId('activity'),
      person,
      kind,
      identifier: identifier ?? (agent ? ((await this.#ctx.api.store.agentByAddress(agent))?.principal ?? null) : null),
      agent: agent ?? null,
      message: message ?? null,
      intro: intro ?? null,
      data: Object.keys(data).length ? data : null,
      at: this.#ctx.now(),
    };
    await this.#entries.insertOne(entry);
    await this.#webhooks?.announce(person, { type: 'activity', ...eventView(entry) }, entry.identifier);
  }

  /**
   * A page of a person's log as a session proving `identifiers` sees it, oldest first, optionally of some
   * kinds only.
   */
  page(person: string, identifiers: string[], page: { after?: string; limit: number }, kinds?: string[]) {
    return this.#entries
      .find({
        person,
        identifier: { $in: [null, ...identifiers] },
        ...(kinds ? { kind: { $in: kinds } } : {}),
        ...(page.after ? { _id: { $gt: page.after } } : {}),
      })
      .sort({ _id: 1 })
      .limit(page.limit + 1)
      .toArray();
  }

  async reassign(from: string, to: string) {
    await this.#entries.updateMany({ person: from }, { $set: { person: to } });
  }

  async forget(person: string) {
    await this.#entries.deleteMany({ person });
  }

  /** Messages a paired agent here sent and received, entered for its person. */
  async messageEvent(
    people: People,
    address: string,
    record: StoredMessage,
    kind: 'message_sent' | 'message_received',
  ) {
    const agent = await this.#ctx.api.store.agentByAddress(address);
    const pairing = agent && (await people.pairingOf(agent));
    if (pairing) await this.record(pairing.person, kind, { agent: address, message: record.id });
  }
}
