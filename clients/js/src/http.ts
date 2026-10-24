/** One HTTP exchange with a timeout, and an answer read into JSON or into the AgntError it carries. */
import { isRetryable, parseProblem } from '@agnt-protocol/protocol';
import { AgntError } from './errors.ts';

export type Fetch = (url: string, init?: RequestInit) => Promise<Response>;

/** How a call reaches the network and tells the time. Every call has a timeout. */
export interface Transport {
  fetch?: Fetch;
  /** Milliseconds to wait for a whole answer, body included. Default 30000. */
  timeoutMs?: number;
  /** The clock, for timestamps, signatures and key validity. Default: the system clock. */
  now?: () => Date;
}

export const DEFAULT_TIMEOUT_MS = 30_000;
/** Client resource budget for a decoded error body, independent of a successful part's declared size. */
export const MAX_PROBLEM_BYTES = 128 * 1024;

export interface Answer {
  url: string;
  status: number;
  headers: Headers;
  body: Uint8Array;
}

/**
 * A request and its whole answer, or `timeout` or `network_error` naming the URL. With `maxBytes`, reading
 * stops once the body passes that many bytes, as fetch decodes them (a compressed answer is counted decoded,
 * spec section 9), and the body is its first `maxBytes + 1` bytes, which every reader of a bounded answer
 * refuses. Non-2xx answers instead have a separate finite problem-details budget, even for a tiny part.
 */
export async function exchange(t: Transport, url: string, init: RequestInit = {}, maxBytes?: number): Promise<Answer> {
  const timeoutMs = t.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const method = init.method ?? 'GET';
  const clock = new AbortController();
  const timer = setTimeout(
    () => clock.abort(new DOMException('The request deadline passed.', 'TimeoutError')),
    Math.max(1, Math.ceil(timeoutMs)),
  );
  const deadline = clock.signal;
  const caller = init.signal;
  const signal = caller ? AbortSignal.any([caller, deadline]) : deadline;
  let onAbort: (() => void) | undefined;
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => reject(signal.reason);
    if (signal.aborted) onAbort();
    else signal.addEventListener('abort', onAbort, { once: true });
  });
  try {
    const operation = async () => {
      if (signal.aborted) throw signal.reason;
      const res = await (t.fetch ?? fetch)(url, { ...init, signal });
      if (signal.aborted) {
        void res.body?.cancel(signal.reason).catch(() => {});
        throw signal.reason;
      }
      const budget = res.status >= 200 && res.status <= 299 ? maxBytes : MAX_PROBLEM_BYTES;
      return { url, status: res.status, headers: res.headers, body: await readBody(res, budget, signal) };
    };
    // Bound even custom fetch implementations and streams that ignore the supplied signal.
    return await Promise.race([operation(), aborted]);
  } catch (e) {
    if (caller?.aborted && signal.reason === caller.reason) throw caller.reason;
    if (deadline.aborted || (e instanceof Error && e.name === 'TimeoutError')) {
      throw new AgntError('timeout', `${method} ${url}: no answer within ${timeoutMs} ms.`, {
        retryable: true,
        details: { url, timeoutMs },
      });
    }
    const cause = (e as { cause?: { code?: string; message?: string } } | null)?.cause;
    const why = cause?.code ?? cause?.message ?? (e instanceof Error ? e.message : String(e));
    throw new AgntError('network_error', `${method} ${url} failed: ${why}.`, {
      retryable: true,
      details: { url, cause: why },
    });
  } finally {
    clearTimeout(timer);
    if (onAbort) signal.removeEventListener('abort', onAbort);
  }
}

/** Keep only maxBytes+1 decoded bytes; cancellation cleanup never extends the request deadline. */
async function readBody(res: Response, maxBytes: number | undefined, signal: AbortSignal): Promise<Uint8Array> {
  if (!res.body) return new Uint8Array();
  const reader = res.body.getReader();
  const cancel = () => {
    void reader.cancel(signal.reason).catch(() => {});
  };
  signal.addEventListener('abort', cancel, { once: true });
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      if (signal.aborted) throw signal.reason;
      const { done, value } = await reader.read();
      if (done) break;
      const keep = maxBytes === undefined ? value.length : Math.min(value.length, Math.max(0, maxBytes + 1 - size));
      // Copy a bounded slice so a huge decoded backing buffer is not retained by a subarray.
      chunks.push(value.slice(0, keep));
      size += keep;
      if (maxBytes !== undefined && size > maxBytes) {
        void reader.cancel().catch(() => {});
        break;
      }
    }
    if (signal.aborted) throw signal.reason;
    return new Uint8Array(Buffer.concat(chunks, size));
  } finally {
    signal.removeEventListener('abort', cancel);
    try {
      reader.releaseLock();
    } catch {
      /* A nonconforming stream may still hold a pending read. */
    }
  }
}

/** The JSON of a 2xx answer, or the error the answer carries. */
export function readJson<T>(a: Answer, now: Date): T {
  if (a.status < 200 || a.status > 299) throw failure(a, now);
  try {
    return (a.body.length ? JSON.parse(Buffer.from(a.body).toString('utf8')) : null) as T;
  } catch {
    throw new AgntError('bad_response', `${a.url} answered ${a.status} with a body that is not JSON.`, {
      status: a.status,
      details: { url: a.url },
    });
  }
}

/**
 * The error an answer that is not a success carries: the server's own problem details (spec section 9),
 * read by the protocol's `parseProblem`, or `bad_response` when it sent none. `status` and `retryable`
 * follow the HTTP status, which is what a client acts on; the code, detail and details are the server's.
 */
export function failure(a: Answer, now: Date): AgntError {
  const retryAfter = readRetryAfter(a.headers.get('retry-after'), now);
  // Never accept a parseable JSON prefix of an oversized error body.
  const problem = a.body.length <= MAX_PROBLEM_BYTES ? parseProblem(a.status, a.body) : null;
  if (problem) {
    return new AgntError(problem.code, problem.detail || problem.title, {
      status: a.status,
      retryable: problem.retryable,
      details: problem.details,
      retryAfter,
    });
  }
  return new AgntError('bad_response', `${a.url} answered ${a.status} without problem details.`, {
    status: a.status,
    retryable: isRetryable(a.status),
    details: { url: a.url },
    retryAfter,
  });
}

/** `Retry-After` in seconds: a whole number of seconds, or an HTTP date. */
function readRetryAfter(value: string | null, now: Date): number | undefined {
  if (value === null) return undefined;
  if (/^[0-9]+$/.test(value)) return Number(value);
  const at = Date.parse(value);
  return Number.isNaN(at) ? undefined : Math.max(0, Math.ceil((at - now.getTime()) / 1000));
}
