/**
 * The OpenAPI 3.1 document of this application's API, built from its route definitions: served at
 * `GET /api/openapi.json` (the routes this server runs) and committed as app/openapi.json (all of them).
 * Schemas with a meta `id` become components.
 */
import { z } from 'zod';
import { anyone, defineRoute, type ApiRoute, type RouteSpec } from './route.ts';

type JsonSchema = Record<string, unknown>;

const ERRORS = {
  400: 'Invalid: `details.field` names what',
  401: 'No valid signature or token',
  403: 'Not allowed',
  404: 'Not found: `details.what` names what',
  409: 'Conflict',
  429: 'Rate limited: retry after Retry-After',
};

const SCHEMES = {
  agentSignature: {
    type: 'apiKey',
    in: 'header',
    name: 'agnt-signature',
    description:
      'A signed request (spec/PROTOCOL.md section 8): agnt-key, agnt-timestamp, agnt-nonce and agnt-signature.',
  },
  ownerBearer: {
    type: 'http',
    scheme: 'bearer',
    description: 'An owner access token (OAuth 2.1 from this server) or an owner API key.',
  },
  bridgeSecret: {
    type: 'http',
    scheme: 'bearer',
    description: 'AGNT_BRIDGE_INBOUND_SECRET, presented by the inbound-mail provider.',
  },
};

export function openApiDocument(routes: ApiRoute[], origin: string) {
  const components: Record<string, JsonSchema> = {
    Problem: {
      type: 'object',
      description: "RFC 9457 problem details, the protocol's error shape (spec/PROTOCOL.md section 9).",
      properties: {
        type: { type: 'string' },
        title: { type: 'string' },
        status: { type: 'integer' },
        code: { type: 'string' },
        retryable: { type: 'boolean' },
        detail: { type: 'string' },
        details: { type: 'object' },
      },
      required: ['type', 'title', 'status', 'code', 'retryable', 'detail'],
    },
  };

  /** A schema as JSON Schema, its named parts moved into components (a request's variant renamed if it differs). */
  const schema = (s: z.ZodType, io: 'input' | 'output'): JsonSchema => {
    const json = z.toJSONSchema(s, { io, unrepresentable: 'any' }) as JsonSchema;
    const defs = (json.$defs ?? {}) as Record<string, JsonSchema>;
    delete json.$schema;
    delete json.$defs;
    const names = new Map<string, string>();
    for (const [name, def] of Object.entries(defs)) {
      const same = (n: string) => !components[n] || JSON.stringify(components[n]) === JSON.stringify(def);
      const target = same(name) ? name : `${name}Input`;
      components[target] = def;
      names.set(name, target);
    }
    return JSON.parse(
      JSON.stringify(json).replace(/"#\/\$defs\/([^"]+)"/g, (_, n) => `"#/components/schemas/${names.get(n) ?? n}"`),
    );
  };

  const parameters = (spec: RouteSpec) =>
    (['params', 'query'] as const).flatMap(where => {
      const s = spec[where] as z.ZodObject | undefined;
      return s
        ? Object.entries(s.shape).map(([name, field]) => ({
            name,
            in: where === 'params' ? 'path' : 'query',
            required: where === 'params' || !(field as z.ZodType).safeParse(undefined).success,
            schema: schema(field as z.ZodType, 'input'),
          }))
        : [];
    });

  const paths: Record<string, Record<string, unknown>> = {};
  for (const { spec } of routes) {
    const path = spec.path.replace(/:([A-Za-z]+)/g, '{$1}');
    const success =
      'produces' in spec
        ? { [spec.produces.status]: { description: spec.produces.description, content: { [spec.produces.type]: {} } } }
        : spec.status === 204
          ? { 204: { description: 'Done' } }
          : {
              [spec.status ?? 200]: {
                description: 'OK',
                content: { 'application/json': { schema: spec.response ? schema(spec.response, 'output') : {} } },
              },
            };
    const errors = Object.fromEntries(
      Object.entries(ERRORS).map(([status, description]) => [
        status,
        { description, content: { 'application/problem+json': { schema: { $ref: '#/components/schemas/Problem' } } } },
      ]),
    );
    const { scheme, optional, held } = spec.caller;
    const reserved = held && {
      [held.status]: {
        description: held.description,
        content: { 'application/json': { schema: schema(held.response, 'output') } },
      },
    };
    (paths[path] ??= {})[spec.method.toLowerCase()] = {
      operationId: spec.operationId,
      tags: [spec.tag],
      summary: spec.summary,
      ...(spec.description ? { description: spec.description } : {}),
      security: scheme ? [{ [scheme]: [] }, ...(optional ? [{}] : [])] : [],
      parameters: parameters(spec),
      ...(spec.body
        ? { requestBody: { required: true, content: { 'application/json': { schema: schema(spec.body, 'input') } } } }
        : {}),
      responses: { ...success, ...reserved, ...errors },
    };
  }
  return {
    openapi: '3.1.0',
    info: {
      title: 'AGNT application',
      version: '0.1.0',
      description:
        "The API of the AGNT application template, beside the protocol's own calls under /agnt/ (spec/CLIENT.md): a directory, recipient policy, introductions, an owner window, webhooks and an email bridge.",
    },
    servers: [{ url: origin }],
    paths: Object.fromEntries(Object.entries(paths).sort(([a], [b]) => a.localeCompare(b))),
    components: {
      schemas: Object.fromEntries(Object.entries(components).sort(([a], [b]) => a.localeCompare(b))),
      securitySchemes: SCHEMES,
    },
  };
}

export const openApiRoute = (document: ReturnType<typeof openApiDocument>) =>
  defineRoute({
    method: 'GET',
    path: '/api/openapi.json',
    operationId: 'openapi',
    tag: 'API',
    summary: 'This document, for the routes this server runs',
    caller: anyone,
    response: z.record(z.string(), z.unknown()),
    handle: async () => document,
  });
