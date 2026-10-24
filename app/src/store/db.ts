/**
 * MongoDB, as this application uses it: one database, collections named by their owner (`core.*` for the
 * server's Store, one prefix per module), and the duplicate-key error read as the uniqueness it enforces.
 * Every rule the stores keep is a single-document operation or a unique index, so no replica set is needed.
 */
import { MongoClient, MongoServerError, type Db } from 'mongodb';

export async function connect(uri: string, name: string): Promise<{ client: MongoClient; db: Db }> {
  // These stores read what they just wrote. Primary reads take precedence over a connection string's
  // secondary preference; recognizing another server's error format does not establish adapter support.
  const client = await MongoClient.connect(uri, { readPreference: 'primary' });
  return { client, db: client.db(name) };
}

/** Whether an error is a unique index refusing a write; with `field`, that index's. */
export function isDuplicate(e: unknown, field?: string): boolean {
  if (!(e instanceof MongoServerError) || e.code !== 11000) return false;
  if (field === undefined) return true;
  if (e.keyPattern) return Object.hasOwn(e.keyPattern as object, field);
  // When structured metadata is absent, recognize only a default index name in a duplicate-key error:
  // `<field>_<1|-1>_...` (`_id_` for _id). Unknown custom names fail closed for a field-specific check.
  const index = / index: (\S+)/.exec(e.message)?.[1];
  if (!index) return false;
  if (index === '_id_') return field === '_id';
  return index.split(/_(?:-?1)(?:_|$)/).includes(field);
}

/** Insert, answering false when a unique index says the record is already there. */
export async function insertOnce(write: () => Promise<unknown>, field?: string): Promise<boolean> {
  try {
    await write();
    return true;
  } catch (e) {
    if (isDuplicate(e, field)) return false;
    throw e;
  }
}

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

/** An upsert, run again if a concurrent one inserted first (MongoDB answers the loser a duplicate key). */
export async function upsert(write: () => Promise<unknown>): Promise<void> {
  try {
    await write();
  } catch (e) {
    if (!isDuplicate(e)) throw e;
    await write();
  }
}
