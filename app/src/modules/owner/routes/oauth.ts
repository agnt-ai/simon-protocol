/**
 * The OAuth 2.1 sign-in that opens the owner window: metadata, client registration, the authorization
 * page (an identifier, then its code, or a key principal's signature over a challenge), and the token and
 * revocation endpoints, which answer as RFC 6749 says.
 */
import { z } from 'zod';
import type { Ctx } from '../../../context.ts';
import { WireError } from '../../../lib/errors.ts';
import { normalizePrincipal } from '../../../lib/principals.ts';
import { clientKey, spend } from '../../../lib/rate.ts';
import { htmlPage, redirect } from '../../../http/pages.ts';
import { anyone, defineRoute, json, type ApiRoute } from '../../../http/route.ts';
import { loginPage } from '../login-page.ts';
import { OAuthError, signInBytes, type OAuth } from '../oauth.ts';

const messageOf = (e: unknown) => (e instanceof WireError ? e.message : 'Something went wrong.');
const LoginId = z.object({ loginId: z.string().max(40) });
const page = (status: number) => ({ status, type: 'text/html', description: 'The sign-in page.' });

export function oauthRoutes(ctx: Ctx, oauth: OAuth): ApiRoute[] {
  const tag = 'Owner sign-in';
  const limit = (ip: string) => spend(ctx.api, 'pages', ctx.config.rates.pages, clientKey(ip));
  const appFor = (id: string) =>
    oauth.open(id).then(
      o => o.app,
      () => null,
    );
  return [
    defineRoute({
      method: 'GET',
      path: '/.well-known/oauth-authorization-server',
      operationId: 'oauthMetadata',
      tag,
      summary: 'OAuth authorization server metadata (RFC 8414)',
      caller: anyone,
      response: z.record(z.string(), z.unknown()),
      handle: async () => oauth.metadata(),
    }),
    defineRoute({
      method: 'POST',
      path: '/api/oauth/register',
      operationId: 'registerClient',
      tag,
      summary: 'Register a client (RFC 7591): public, PKCE only',
      caller: anyone,
      body: z.object({
        client_name: z.string().max(100).optional(),
        redirect_uris: z.array(z.string().max(2000)).min(1).max(10),
      }),
      status: 201,
      response: z.record(z.string(), z.unknown()),
      async handle({ body, req }) {
        await limit(req.ip);
        return oauth.register(body);
      },
    }),
    defineRoute({
      method: 'GET',
      path: '/api/oauth/authorize',
      operationId: 'authorize',
      tag,
      summary: 'Start signing in: redirects to the sign-in page',
      caller: anyone,
      query: z.object({
        response_type: z.string().optional(),
        client_id: z.string().optional(),
        redirect_uri: z.string().optional(),
        code_challenge: z.string().optional(),
        code_challenge_method: z.string().optional(),
        state: z.string().max(500).optional(),
      }),
      produces: { status: 302, type: 'text/html', description: 'To the sign-in page.' },
      async handle({ query, req }) {
        await limit(req.ip);
        return redirect(`/api/oauth/login/${(await oauth.authorize(query))._id}`);
      },
    }),
    defineRoute({
      method: 'GET',
      path: '/api/oauth/login/:loginId',
      operationId: 'loginPage',
      tag,
      summary: 'The sign-in page',
      caller: anyone,
      params: LoginId,
      produces: page(200),
      async handle({ params }) {
        try {
          const { login, app } = await oauth.open(params.loginId);
          if (login.challenge) {
            const challenge = signInBytes(ctx.config.server.origin, login.challenge);
            return htmlPage(loginPage({ loginId: login._id, app, step: 'sign', challenge }));
          }
          return htmlPage(loginPage({ loginId: login._id, app, step: login.identifier ? 'code' : 'identifier' }));
        } catch (e) {
          return htmlPage(loginPage({ loginId: '', app: null, step: 'error', error: messageOf(e) }), 400);
        }
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/api/oauth/login/:loginId/identifier',
      operationId: 'loginIdentifier',
      tag,
      summary: 'The sign-in page: a code to an email address or phone number, or a challenge for a key',
      caller: anyone,
      params: LoginId,
      body: z.object({ identifier: z.string().max(320) }),
      produces: page(200),
      async handle({ params, body, req }) {
        const typed = body.identifier.trim();
        const principal = normalizePrincipal(
          typed.startsWith('agnt-key:') ? typed : typed.includes('@') ? `mailto:${typed}` : `tel:${typed}`,
        );
        try {
          await limit(req.ip);
          const app = (await oauth.open(params.loginId)).app;
          if (!principal) {
            throw new WireError(
              400,
              'invalid',
              'That is not an email address, a phone number in +15551234567 form, or an agnt-key: identifier.',
            );
          }
          const next = await oauth.start(params.loginId, principal);
          return htmlPage(loginPage({ loginId: params.loginId, app, ...next }));
        } catch (e) {
          return htmlPage(
            loginPage({
              loginId: params.loginId,
              app: await appFor(params.loginId),
              step: 'identifier',
              error: messageOf(e),
            }),
            400,
          );
        }
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/api/oauth/login/:loginId/code',
      operationId: 'loginCode',
      tag,
      summary: 'The sign-in page: the code, then back to the app',
      caller: anyone,
      params: LoginId,
      body: z.object({ code: z.string().max(20) }),
      produces: {
        status: 302,
        type: 'text/html',
        description: "Back to the app's redirect URI, with the authorization code.",
      },
      async handle({ params, body }) {
        try {
          return redirect(await oauth.verifyCode(params.loginId, body.code.trim()));
        } catch (e) {
          const app = await appFor(params.loginId);
          return htmlPage(
            loginPage({ loginId: params.loginId, app, step: app ? 'code' : 'error', error: messageOf(e) }),
            400,
          );
        }
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/api/oauth/login/:loginId/signature',
      operationId: 'loginSignature',
      tag,
      summary: "The sign-in page: a key principal's signature over its challenge, then back to the app",
      caller: anyone,
      params: LoginId,
      body: z.object({ signature: z.string().max(8000) }),
      produces: {
        status: 302,
        type: 'text/html',
        description: "Back to the app's redirect URI, with the authorization code.",
      },
      async handle({ params, body }) {
        try {
          return redirect(await oauth.verifySignature(params.loginId, body.signature));
        } catch (e) {
          const login = await oauth.open(params.loginId).catch(() => null);
          const challenge = login?.login.challenge && signInBytes(ctx.config.server.origin, login.login.challenge);
          return htmlPage(
            loginPage({
              loginId: params.loginId,
              app: login?.app ?? null,
              ...(challenge ? { step: 'sign' as const, challenge } : { step: 'error' as const }),
              error: messageOf(e),
            }),
            400,
          );
        }
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/api/oauth/token',
      operationId: 'token',
      tag,
      summary: 'Exchange an authorization code or a refresh token for tokens',
      caller: anyone,
      body: z.record(z.string(), z.string()),
      produces: {
        status: 200,
        type: 'application/json',
        description: 'Tokens, or an error as RFC 6749 section 5.2 writes it.',
      },
      async handle({ body }) {
        try {
          return { ...json(await oauth.token(body)), headers: { 'cache-control': 'no-store' } };
        } catch (e) {
          if (e instanceof OAuthError) return json({ error: e.code, error_description: e.message }, 400);
          throw e;
        }
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/api/oauth/revoke',
      operationId: 'revokeToken',
      tag,
      summary: 'Revoke a token (RFC 7009)',
      caller: anyone,
      body: z.object({ token: z.string().max(200).optional() }),
      produces: { status: 200, type: 'application/json', description: 'Revoked, or never valid: the same answer.' },
      async handle({ body }) {
        if (body.token) await oauth.revokeToken(body.token);
        return json({});
      },
    }),
  ];
}
