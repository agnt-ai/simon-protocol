/**
 * MongoDB, as these stores use it: one database, collections named by their owner (`core.*` for the
 * server's Store), and the duplicate-key error read as the uniqueness it enforces. Every rule the stores
 * keep is a single-document operation or a unique index, so no replica set, session or transaction is
 * needed, and Amazon DocumentDB serves as well as MongoDB.
 */
import { MongoClient, MongoServerError, type Db, type MongoClientOptions } from 'mongodb';

/**
 * How `connect` opens its client. The pool settings matter most where many processes share one database
 * (DocumentDB counts connections per instance): `maxPoolSize` bounds the connections one process opens,
 * `minPoolSize` keeps that many open while idle, and `maxIdleTimeMS` closes one idle longer than that.
 * `appName` is shown in the database's own logs and current-operation lists. Any other driver option may be
 * given too, but never a read preference: reads are always from the primary (`connect` refuses another).
 */
export interface ConnectOptions extends Omit<MongoClientOptions, 'readPreference'> {
  /** Connections this process opens at most (default 10). */
  maxPoolSize?: number;
  /** Connections kept open while idle (default 0). */
  minPoolSize?: number;
  /** Milliseconds a connection may sit idle before it is closed (default 60000). */
  maxIdleTimeMS?: number;
  /** The name the database shows for this client's connections. */
  appName?: string;
}

/** The pool `connect` opens unless told otherwise. */
export const DEFAULT_POOL = { maxPoolSize: 10, minPoolSize: 0, maxIdleTimeMS: 60_000 } as const;

/**
 * A client and its database. The stores read what they just wrote, so every read is from the primary: that
 * takes precedence over a connection string's secondary preference, and asking for another is refused.
 */
export async function connect(
  uri: string,
  name: string,
  options: ConnectOptions = {},
): Promise<{ client: MongoClient; db: Db }> {
  const asked = (options as { readPreference?: unknown }).readPreference;
  if (asked !== undefined && asked !== 'primary')
    throw new Error('connect: the stores read what they just wrote, so reads are from the primary only.');
  const given = Object.fromEntries(Object.entries(options).filter(([, v]) => v !== undefined));
  const client = await MongoClient.connect(uri, { ...DEFAULT_POOL, ...given, readPreference: 'primary' });
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

/** An upsert, run again if a concurrent one inserted first (MongoDB answers the loser a duplicate key). */
export async function upsert(write: () => Promise<unknown>): Promise<void> {
  try {
    await write();
  } catch (e) {
    if (!isDuplicate(e)) throw e;
    await write();
  }
}
