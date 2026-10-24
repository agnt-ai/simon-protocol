/**
 * Published messages: messages written here with an empty `to` (spec section 7), served to whoever their
 * audience admits (readers.ts):
 *
 *   GET /agnt/messages/<id>                  the message and its author's keys valid at its `sentAt`
 *   GET /agnt/feeds/<address>/<feed>         the author's published messages in that feed, newest first
 *   GET /agnt/messages/<id>/related          the relations to it marked listed that this server shows, newest first
 *
 * A message a reader may not see, an unknown one and a retired author's are answered alike: `404` for a
 * message and its relations, an empty page for a feed. Listings page with an opaque cursor, `before`.
 */
import {
  header,
  invalid,
  MAX_CURSOR_LENGTH,
  MAX_LISTING_LIMIT,
  DEFAULT_LISTING_LIMIT,
  parseTimestamp,
  PUBLIC_RELATIONS,
  validAt,
  VERSION,
  type AnyMessage,
  type Message,
} from '@agnt-protocol/protocol';
import type { Context } from './context.ts';
import { notFound } from './errors.ts';
import { json, type Request, type Route } from './http.ts';
import { askerOf, mayRead, type Asker } from './readers.ts';
import type { Page, StoredMessage } from './store/store.ts';

/**
 * Records read from the store for one page at most, so a listing of hidden messages costs a bounded scan. A
 * scan that ends there ends the listing too: its next cursor would be a hidden message's.
 */
const MAX_SCANNED = 5000;
/** The feed of a published message that names none (spec section 7.3). */
const DEFAULT_FEED = 'posts';
const CURSOR = new RegExp(`^[\\x21-\\x7e]{1,${MAX_CURSOR_LENGTH}}$`);
const EMPTY = { messages: [], cursor: null, more: false };

const v1Header = (m: AnyMessage, name: string) => (m.v === VERSION ? header(m as Message, name) : null);

/** The published message written here by an agent not retired, or null. */
async function published(ctx: Context, id: string): Promise<StoredMessage | null> {
  const record = await ctx.store.message(id);
  if (!record || record.carrier !== ctx.config.origin || record.message.to.length !== 0) return null;
  const author = await ctx.store.agentByAddress(record.message.from);
  return author && !author.retiredAt ? record : null;
}

/** `before` and `limit` of a listing request. */
function paging(req: Request) {
  const before = req.query.get('before');
  if (before !== null && !CURSOR.test(before)) {
    throw invalid(`before is a cursor this server gave: 1 to ${MAX_CURSOR_LENGTH} printable ASCII characters.`, {
      field: 'before',
    });
  }
  const limitText = req.query.get('limit');
  const limit = limitText === null ? DEFAULT_LISTING_LIMIT : /^[0-9]{1,3}$/.test(limitText) ? Number(limitText) : 0;
  if (limit < 1 || limit > MAX_LISTING_LIMIT) {
    throw invalid(`limit is 1 to ${MAX_LISTING_LIMIT}.`, { field: 'limit' });
  }
  return { before, limit };
}

/**
 * One page of a listing: the records `next` pages through, newest first, that `shows` keeps, up to `limit`.
 * The cursor is the last record shown, never one the reader may not see, and is null at the end.
 */
async function listing(
  next: (before: string | null, limit: number) => Promise<Page>,
  shows: (record: StoredMessage) => Promise<boolean>,
  before: string | null,
  limit: number,
) {
  const shown: { cursor: string; message: AnyMessage }[] = [];
  let cursor = before;
  scan: for (let scanned = 0; scanned < MAX_SCANNED; ) {
    const page = await next(cursor, limit + 1);
    for (const r of page.records) {
      scanned++;
      cursor = r.cursor;
      if (await shows(r.message)) shown.push({ cursor: r.cursor, message: r.message.message });
      if (shown.length > limit) break scan;
    }
    if (!page.more) break;
  }
  const page = shown.slice(0, limit);
  const more = shown.length > limit;
  return { messages: page.map(s => s.message), cursor: more ? page.at(-1)!.cursor : null, more };
}

/**
 * Whether a relation to a published message is one its author's server lists (spec section 7.4): its writer
 * marked it `listed`, a plain reply never is; of those, the relations this server shows (PUBLIC_RELATIONS);
 * and not retracted by its writer since.
 */
async function listable(ctx: Context, author: string, record: StoredMessage): Promise<boolean> {
  const rel = v1Header(record.message, 'rel');
  if (v1Header(record.message, 'listed') !== 'yes') return false;
  if (rel === null || !PUBLIC_RELATIONS.includes(rel)) return false;
  return !(await ctx.store.listingRetracted(author, record.id, record.message.from));
}

export function publishedRoutes(ctx: Context): Route[] {
  const readable = async (id: string, asker: Asker) => {
    const record = await published(ctx, id);
    return record && (await mayRead(ctx, record.message, asker)) ? record : null;
  };

  return [
    {
      method: 'GET',
      path: '/agnt/messages/:id',
      async handle(req) {
        const record = await readable(req.params.id, await askerOf(ctx, req));
        if (!record) throw notFound('No published message has this id here.');
        const author = (await ctx.store.agentByAddress(record.message.from))!;
        const at = new Date(parseTimestamp(record.message.sentAt)!);
        const claims = record.signedClaims
          ? { claims: record.signedClaims.claims, claimsSignature: record.signedClaims.signature }
          : {};
        return json({
          message: record.message,
          keys: author.keys.filter(k => validAt(k, at)).map(({ key, added, revoked }) => ({ key, added, revoked })),
          ...claims,
        });
      },
    },
    {
      method: 'GET',
      path: '/agnt/feeds/:address/:feed',
      async handle(req) {
        const { before, limit } = paging(req);
        const { address, feed } = req.params;
        const asker = await askerOf(ctx, req);
        const author = await ctx.store.agentByAddress(address);
        if (!author || author.retiredAt) return json(EMPTY);
        const inFeed = (m: AnyMessage) => (v1Header(m, 'feed') ?? DEFAULT_FEED).split(',').includes(feed);
        const shows = async (r: StoredMessage) => inFeed(r.message) && (await mayRead(ctx, r.message, asker));
        return json(await listing((b, n) => ctx.store.published(address, b, n), shows, before, limit));
      },
    },
    {
      method: 'GET',
      path: '/agnt/messages/:id/related',
      async handle(req) {
        const { before, limit } = paging(req);
        const record = await readable(req.params.id, await askerOf(ctx, req));
        if (!record) throw notFound('No published message has this id here.');
        const author = record.message.from;
        const page = (b: string | null, n: number) => ctx.store.repliesTo(author, record.id, b, n);
        return json(await listing(page, r => listable(ctx, author, r), before, limit));
      },
    },
  ];
}
