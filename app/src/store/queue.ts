/**
 * Work that waits and is retried (webhook posts, bridge mail), in one collection per queue. Any number of
 * workers may drain a queue: each job is leased to one at a time, and an outcome is recorded only by the
 * worker whose lease is current. A drain may try several jobs at once, never two that share a payload
 * field (one webhook, say) at the same time, so one slow destination holds up only itself. A job that keeps failing is retried on a schedule, then fails for good.
 * Finished jobs are pruned, and jobs for something forgotten are dropped, so no payload outlives its use.
 */
import type { Collection, Db } from 'mongodb';
import { insertOnce } from './db.ts';

export interface Job<T> {
  _id: string;
  payload: T;
  status: 'pending' | 'done' | 'failed';
  attempts: number;
  nextAttemptAt: Date;
  lockedUntil: Date | null;
  lastError: string | null;
}

/** What one try came to: done, worth another try, or never going to work. */
export type Outcome = 'done' | { retry: string } | { fail: string };

const LEASE_MS = 60_000;

export class Queue<T> {
  /** Jobs as stored: the payload is this queue's, read back as `T`. */
  readonly #jobs: Collection<Job<unknown>>;
  /** Seconds to wait before each retry; its length is how many retries a job gets. */
  readonly #retrySeconds: number[];

  constructor(db: Db, name: string, retrySeconds: number[]) {
    this.#jobs = db.collection<Job<unknown>>(name);
    this.#retrySeconds = retrySeconds;
  }

  async init(): Promise<void> {
    await this.#jobs.createIndex({ status: 1, nextAttemptAt: 1 });
  }

  /** Drop the jobs whose payload's `field` is one of `values`: work for something forgotten. */
  async drop<K extends keyof T & string>(field: K, values: T[K][]): Promise<void> {
    await this.#jobs.deleteMany({ [`payload.${field}`]: { $in: values } });
  }

  /** Drop finished jobs last tried before a time. Answers how many. */
  async prune(before: Date): Promise<number> {
    return (await this.#jobs.deleteMany({ status: { $ne: 'pending' }, nextAttemptAt: { $lt: before } })).deletedCount;
  }

  /** Queue a job once by id; false when it is already queued. */
  push(id: string, payload: T, at: Date): Promise<boolean> {
    const job: Job<T> = {
      _id: id,
      payload,
      status: 'pending',
      attempts: 0,
      nextAttemptAt: at,
      lockedUntil: null,
      lastError: null,
    };
    return insertOnce(() => this.#jobs.insertOne(job), '_id');
  }

  /**
   * Try up to `limit` due jobs, `concurrency` at a time, and never two at once whose payloads share the
   * value of `apart`. Answers how many it tried.
   */
  async drain(
    now: () => Date,
    limit: number,
    attempt: (payload: T) => Promise<Outcome>,
    { concurrency = 1, apart }: { concurrency?: number; apart?: keyof T & string } = {},
  ): Promise<number> {
    let tried = 0;
    const busy = new Set<unknown>();
    const lane = async () => {
      while (tried < limit) {
        // A slot is taken before the claim, so lanes claiming at once never try more than `limit` in all.
        tried++;
        const at = now();
        const lease = new Date(at.getTime() + LEASE_MS);
        const job = await this.#jobs.findOneAndUpdate(
          {
            status: 'pending',
            nextAttemptAt: { $lte: at },
            $or: [{ lockedUntil: null }, { lockedUntil: { $lte: at } }],
            ...(apart ? { [`payload.${apart}`]: { $nin: [...busy] } } : {}),
          },
          { $set: { lockedUntil: lease } },
          { sort: { nextAttemptAt: 1 }, returnDocument: 'after' },
        );
        if (!job) {
          tried--;
          return;
        }
        const key = apart && (job.payload as T)[apart];
        if (apart && busy.has(key)) {
          // Another lane took a job of the same key while this one was claiming: give it back.
          tried--;
          await this.#jobs.updateOne({ _id: job._id, lockedUntil: lease }, { $set: { lockedUntil: null } });
          continue;
        }
        if (apart) busy.add(key);
        let outcome: Outcome;
        try {
          outcome = await attempt(job.payload as T);
        } catch (e) {
          outcome = { retry: e instanceof Error ? e.message : String(e) };
        } finally {
          if (apart) busy.delete(key);
        }
        await this.#settle(job, lease, outcome, now());
      }
    };
    await Promise.all(Array.from({ length: concurrency }, lane));
    return tried;
  }

  async #settle(job: Job<unknown>, lease: Date, outcome: Outcome, at: Date) {
    const attempts = job.attempts + 1;
    const wait = typeof outcome === 'object' && 'retry' in outcome ? this.#retrySeconds[job.attempts] : undefined;
    const set =
      outcome === 'done'
        ? { status: 'done', attempts, lastError: null, lockedUntil: null }
        : wait === undefined
          ? { status: 'failed', attempts, lastError: errorOf(outcome), lockedUntil: null }
          : {
              attempts,
              lastError: errorOf(outcome),
              lockedUntil: null,
              nextAttemptAt: new Date(at.getTime() + wait * 1000),
            };
    await this.#jobs.updateOne({ _id: job._id, lockedUntil: lease }, { $set: set as Partial<Job<unknown>> });
  }
}

const errorOf = (o: Exclude<Outcome, 'done'>) => ('retry' in o ? o.retry : o.fail).slice(0, 300);
