/**
 * MongoDB, as this application uses it: the connection and duplicate-key reading of
 * @agnt-sdk/simon-store-mongo, whose MongoStore keeps the server's `core.*` collections, and one prefix of
 * collections per module, each paged by id.
 */
export { connect, insertOnce, isDuplicate, upsert } from '@agnt-sdk/simon-store-mongo';

/** A page of a list, by id: `after` is the last id of the page before. */
export interface Page<T> {
  items: T[];
  cursor: string | null;
  more: boolean;
}

/**
 * A page from up to `limit + 1` records read in `_id` order after `after`: `cursor` is the last id shown
 * (or `after` again when none is), and `more` says whether the extra record was there.
 */
export function pageOf<T extends { _id: string }, V>(
  records: T[],
  page: { after?: string; limit: number },
  view: (r: T) => V,
): Page<V> {
  const shown = records.slice(0, page.limit);
  return { items: shown.map(view), cursor: shown.at(-1)?._id ?? page.after ?? null, more: records.length > page.limit };
}
