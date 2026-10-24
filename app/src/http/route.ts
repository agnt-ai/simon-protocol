/**
 * How this application defines its API: one object per route, with the caller it needs, zod schemas for
 * its path, query and body, and its answer. `defineRoute` gives the basic server's Route, which validates
 * input and answers JSON, and the same object documents itself in the OpenAPI document (openapi.ts).
 *
 *   defineRoute({
 *     method: 'GET', path: '/api/agents/me/held', operationId: 'listHeld', tag: 'Policy',
 *     summary: "Senders this agent's policy held back", caller: agent,
 *     query: PageQuery, response: Paged(Held),
 *     handle: ({ caller, query }) => policy.held(caller.address, query),
 *   })
 */
import { parseJson, type Json } from '@agnt-protocol/protocol';
import type { Agent, Reply, Request, Route, ServerApi } from '@agnt-protocol/server';
import { z } from 'zod';
import { invalid } from '../lib/errors.ts';

/** Who may call a route, and how a request proves it. */
export interface Caller<T> {
  /** The OpenAPI security scheme; null for anyone. */
  scheme: 'agentSignature' | 'ownerBearer' | 'bridgeSecret' | null;
  /** Whether a request without the scheme's credentials is taken too. */
  optional?: boolean;
  resolve(req: Request, api: ServerApi): Promise<T>;
  /**
   * For a principal-reserved route (owner/requests.ts): the answer to give instead of running the call,
   * when the caller's principal must approve it first; null to run it now.
   */
  hold?(caller: T, call: Call, spec: RouteSpec): Promise<Reply | null>;
  /** What a held call answers, for the API document. */
  held?: { status: number; description: string; response: z.ZodType };
}

/** A call's input, read and checked: what a held call keeps, to run later as it was made. */
export interface Call {
  params: unknown;
  query: unknown;
  body: unknown;
}

export const anyone: Caller<null> = { scheme: null, resolve: async () => null };

/** An agent here, by its signed request (spec section 8). */
export const agent: Caller<Agent> = { scheme: 'agentSignature', resolve: (req, api) => api.authenticate(req) };

/** An agent here when the request is signed; anyone otherwise. */
export const agentOrAnyone: Caller<Agent | null> = {
  scheme: 'agentSignature',
  optional: true,
  resolve: (req, api) => (req.headers['simon-key'] === undefined ? Promise.resolve(null) : api.authenticate(req)),
};

export interface Input<C, P, Q, B> {
  caller: C;
  params: P;
  query: Q;
  body: B;
  req: Request;
  api: ServerApi;
}

interface Common<C, P, Q, B> {
  method: Route['method'];
  /** `:name` segments, as the server's router reads them. */
  path: string;
  operationId: string;
  tag: string;
  summary: string;
  description?: string;
  caller: Caller<C>;
  params?: z.ZodType<P>;
  query?: z.ZodType<Q>;
  body?: z.ZodType<B, unknown>;
  /** The largest body accepted; the server's own limit otherwise. */
  maxBody?: number;
}

/** A route that answers JSON: `response` at `status` (200 by default), or nothing at 204. */
export interface JsonRoute<C, P, Q, B, R> extends Common<C, P, Q, B> {
  status?: 200 | 201 | 202 | 204;
  response?: z.ZodType<R>;
  handle(input: Input<C, P, Q, B>): Promise<R>;
}

/** A route that answers otherwise: a page, a redirect, OAuth's own shapes. `produces` documents it. */
export interface RawRoute<C, P, Q, B> extends Common<C, P, Q, B> {
  produces: { status: number; type: string; description: string };
  handle(input: Input<C, P, Q, B>): Promise<Reply>;
}

export type RouteSpec = JsonRoute<any, any, any, any, any> | RawRoute<any, any, any, any>;

/** A defined route: the server's Route, and its spec for the API document. */
export interface ApiRoute {
  route: Route<ServerApi>;
  spec: RouteSpec;
}

export function defineRoute<C, P = unknown, Q = unknown, B = unknown, R = unknown>(
  spec: JsonRoute<C, P, Q, B, R> | RawRoute<C, P, Q, B>,
): ApiRoute {
  return {
    spec,
    route: {
      method: spec.method,
      path: spec.path,
      maxBody: spec.maxBody,
      async handle(req, api) {
        const caller = await spec.caller.resolve(req, api);
        const call = {
          params: read(spec.params, req.params, 'path'),
          query: read(spec.query, Object.fromEntries(req.query), 'query'),
          body: spec.body ? read(spec.body, bodyOf(req), 'body') : (undefined as B),
        };
        return (await spec.caller.hold?.(caller, call, spec)) ?? run(spec, { caller, ...call, req, api });
      },
    },
  };
}

/** Run a route's handler on its checked input, and shape the answer. */
export async function run<C, P, Q, B>(spec: RouteSpec, input: Input<C, P, Q, B>): Promise<Reply> {
  if ('produces' in spec) return spec.handle(input);
  const result = await spec.handle(input);
  return spec.status === 204 ? { status: 204 } : { status: spec.status ?? 200, json: result };
}

/** A body as JSON under the protocol's parsing rules, or `400 invalid`. A form post is read as an object. */
function bodyOf(req: Request): Json {
  const type = String(req.headers['content-type'] ?? '');
  if (type.startsWith('application/x-www-form-urlencoded')) {
    return Object.fromEntries(new URLSearchParams(req.body.toString('utf8')));
  }
  return req.body.length ? parseJson(req.body) : {};
}

function read<T>(schema: z.ZodType<T, unknown> | undefined, value: unknown, where: string): T {
  if (!schema) return undefined as T;
  const result = schema.safeParse(value);
  if (result.success) return result.data;
  const issue = result.error.issues[0];
  const field = issue.path.length ? issue.path.join('.') : where;
  throw invalid(`${field}: ${issue.message}`, {
    field,
    issues: result.error.issues.map(i => ({ path: i.path.join('.'), message: i.message })),
  });
}

/** A page of a list: `after` is the `cursor` the page before answered. */
export const PageQuery = z.object({
  after: z.string().max(100).optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});

/** The answer for a page of `item`. */
export const Paged = <T extends z.ZodType>(item: T) =>
  z.object({
    items: z.array(item),
    cursor: z.string().nullable().meta({ description: 'Pass back as `after` for the next page.' }),
    more: z.boolean(),
  });

export const json = (body: unknown, status = 200): Reply => ({ status, json: body });
