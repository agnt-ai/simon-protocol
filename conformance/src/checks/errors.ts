/**
 * PROTOCOL section 9 and CLIENT errors: every error the server answered during the whole run, checked
 * for its shape, its retryable flag and its status. These run last, over everything the run saw.
 */
import type { Ctx } from '../context.ts';
import type { Exchange, T } from '../harness.ts';
import { def } from './common.ts';

/** The statuses each code the spec defines comes with: `bad_signature` is a request's 401 or deliver's 403. */
export const CODE_STATUS: Record<string, number[]> = {
  invalid: [400],
  address_required: [400],
  too_many_keys: [400],
  part_not_uploaded: [400],
  unsupported_version: [400],
  signature_required: [401],
  stale_request: [401],
  replayed_request: [401],
  unknown_key: [401],
  key_revoked: [401],
  bad_signature: [401, 403],
  bad_proof: [401],
  unsupported_algorithm: [403],
  not_found: [404],
  address_taken: [409],
  address_homed_elsewhere: [409],
  key_in_use: [409],
  address_not_served: [409],
  code_expired: [410],
  code_locked: [410],
  body_too_large: [413],
  wrong_code: [422],
  rate_limited: [429],
  unavailable: [503],
};

/** The codes of a refused request signature (PROTOCOL 8), each a 401. */
export const REQUEST_CODES = [
  'signature_required',
  'stale_request',
  'unknown_key',
  'key_revoked',
  'bad_signature',
  'replayed_request',
];

interface Seen {
  e: Exchange;
  status: number;
  body: any;
}

/** Every error answer from the server under test during the run. */
function errors(ctx: Ctx): Seen[] {
  return ctx.allExchanges
    .filter(e => e.direction === 'to-target' && e.response && e.response.status >= 400)
    .map(e => {
      let body: any;
      try {
        body = typeof e.response!.body === 'string' ? JSON.parse(e.response!.body) : undefined;
      } catch {
        body = undefined;
      }
      return { e, status: e.response!.status, body };
    });
}

/** Fail with the offending exchanges (at most 10 shown), or pass saying how many were seen. */
function verdict(t: T, all: Seen[], bad: { s: Seen; why: string }[]) {
  for (const { s, why } of bad.slice(0, 10)) t.record({ ...s.e, label: why });
  if (all.length === 0) t.skip('the run saw no answers of this kind (run the whole suite)');
  t.assert(
    bad.length === 0,
    `${bad.length} of ${all.length} error answers: ${[...new Set(bad.map(b => b.why))].slice(0, 5).join('; ')}`,
  );
}

const isObject = (v: unknown) => typeof v === 'object' && v !== null && !Array.isArray(v);

/** A request-signature 401 (PROTOCOL 8), as opposed to a 401 the client API adds, such as bad_proof. */
const requestRefusals = (ctx: Ctx) => errors(ctx).filter(s => s.status === 401 && REQUEST_CODES.includes(s.body?.code));

def(
  {
    id: 'errors.shape',
    section: 'PROTOCOL 9',
    level: 'must',
    title: "Every error is an RFC 9457 problem with the protocol's members",
    expected:
      'every 4xx and 5xx answer of the run is a JSON object with a string code, status equal to the HTTP status, a boolean retryable, details an object when present, and type, title and detail strings when present',
  },
  async (t: T, ctx: Ctx) => {
    const all = errors(ctx);
    const bad = all.flatMap(s => {
      const p = s.body;
      if (!isObject(p)) return [{ s, why: `${s.status} whose body is not a JSON object` }];
      const faults = [
        typeof p.code !== 'string' && 'no string code',
        p.status !== s.status && `status ${JSON.stringify(p.status)}`,
        typeof p.retryable !== 'boolean' && 'no boolean retryable',
        p.details !== undefined && !isObject(p.details) && 'details not an object',
        ...['type', 'title', 'detail'].map(m => p[m] !== undefined && typeof p[m] !== 'string' && `${m} not a string`),
      ].filter(Boolean);
      return faults.length ? [{ s, why: `${s.status} ${p.code ?? ''}: ${faults.join(', ')}` }] : [];
    });
    verdict(t, all, bad);
  },
);

def(
  {
    id: 'errors.content-type',
    section: 'PROTOCOL 9',
    level: 'must',
    title: 'Errors are sent as application/problem+json',
    expected: 'every 4xx and 5xx answer of the run has Content-Type application/problem+json (parameters allowed)',
  },
  async (t: T, ctx: Ctx) => {
    const all = errors(ctx);
    const bad = all.flatMap(s => {
      const type = s.e.response!.headers['content-type'] ?? '';
      return type.split(';')[0].trim().toLowerCase() === 'application/problem+json'
        ? []
        : [{ s, why: `${s.status} sent as ${JSON.stringify(type)}` }];
    });
    verdict(t, all, bad);
  },
);

def(
  {
    id: 'errors.retryable',
    section: 'PROTOCOL 6.3 "Delivery", 9',
    level: 'must',
    title: 'retryable is true exactly for 429 and 5xx',
    expected: 'retryable: true on every 429 and 5xx answer; retryable: false on every other 4xx, which is permanent',
  },
  async (t: T, ctx: Ctx) => {
    const all = errors(ctx).filter(s => typeof s.body?.retryable === 'boolean');
    const bad = all.flatMap(s => {
      const want = s.status === 429 || s.status >= 500;
      return s.body.retryable === want
        ? []
        : [{ s, why: `${s.status} ${s.body.code} says retryable: ${s.body.retryable}` }];
    });
    verdict(t, all, bad);
  },
);

def(
  {
    id: 'errors.status',
    section: 'PROTOCOL 9, CLIENT errors',
    level: 'must',
    title: 'Each code comes with its status',
    expected: `every code the spec defines comes with the status its table gives (${Object.entries(CODE_STATUS)
      .map(([c, s]) => `${c} ${s.join(' or ')}`)
      .join(', ')})`,
  },
  async (t: T, ctx: Ctx) => {
    const all = errors(ctx).filter(s => typeof s.body?.code === 'string' && s.body.code in CODE_STATUS);
    const bad = all.flatMap(s =>
      CODE_STATUS[s.body.code].includes(s.status)
        ? []
        : [{ s, why: `${s.body.code} came with ${s.status}, not ${CODE_STATUS[s.body.code].join(' or ')}` }],
    );
    verdict(t, all, bad);
  },
);

def(
  {
    id: 'errors.server-time',
    section: 'PROTOCOL 8',
    level: 'must',
    title: 'Every request-signature 401 carries details.serverTime',
    expected: `every 401 answer of the run with a request-signature code (${REQUEST_CODES.join(', ')}) has details.serverTime, an integer number of unix seconds`,
  },
  async (t: T, ctx: Ctx) => {
    const all = requestRefusals(ctx);
    const bad = all.flatMap(s =>
      Number.isInteger(s.body?.details?.serverTime)
        ? []
        : [{ s, why: `a 401 ${s.body?.code} without details.serverTime` }],
    );
    verdict(t, all, bad);
  },
);

def(
  {
    id: 'errors.www-authenticate',
    section: 'PROTOCOL 8, 13',
    level: 'must',
    title: 'Every request-signature 401 names the SIMON authentication scheme',
    expected: `every 401 answer of the run with a request-signature code (${REQUEST_CODES.join(', ')}) carries the header WWW-Authenticate: SIMON`,
  },
  async (t: T, ctx: Ctx) => {
    const all = requestRefusals(ctx);
    const bad = all.flatMap(s => {
      const challenge = s.e.response!.headers['www-authenticate'];
      return /^SIMON(\s|,|$)/i.test(challenge ?? '')
        ? []
        : [{ s, why: `a 401 ${s.body?.code} with WWW-Authenticate ${JSON.stringify(challenge ?? null)}` }];
    });
    verdict(t, all, bad);
  },
);

def(
  {
    id: 'errors.rate-limited',
    section: 'PROTOCOL 6.3, 9',
    level: 'must',
    title: 'A 429 is rate_limited with Retry-After',
    expected:
      'every 429 answer of the run is rate_limited, retryable, with a Retry-After header (passes when the server never rate-limited the suite)',
  },
  async (t: T, ctx: Ctx) => {
    const all = errors(ctx).filter(s => s.status === 429);
    const bad = all.flatMap(s =>
      s.body?.code === 'rate_limited' && s.e.response!.headers['retry-after'] !== undefined
        ? []
        : [{ s, why: '429 without rate_limited or Retry-After' }],
    );
    for (const { s, why } of bad.slice(0, 10)) t.record({ ...s.e, label: why });
    t.assert(bad.length === 0, `${bad.length} of ${all.length} 429 answers lack rate_limited or Retry-After`);
  },
);
