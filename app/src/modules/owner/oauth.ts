/**
 * The owner credential. This application is its own OAuth 2.1 authorization server: dynamic client
 * registration, public clients, PKCE with S256 only. A person signs in by a code sent to an email address
 * or phone number of theirs, or, for a key principal, by signing a challenge with that key; any client (a
 * portal, a dashboard, a command line) then reads the owner window as that person. People may also make
 * long-lived API keys for scripts. Agent keys never work in the owner window, and owner tokens never work
 * as an agent.
 *
 * A session sees only what belongs to the identifiers proven in it: the one it signed in by, and any
 * proven since. An identifier last proven more than a year ago grants nothing until proven again, so an
 * inbox that changed hands, or a long-lived API key, does not stand in for the person for ever.
 */
import { principalKey, verify } from '@agnt-sdk/simon-protocol';
import type { Request } from '@agnt-sdk/simon-server';
import type { Activity, Ctx } from '../../context.ts';
import type { Codes } from '../../lib/codes.ts';
import { badRequest, conflict, gone, notFound, unauthorized, unprocessable } from '../../lib/errors.ts';
import { newId } from '../../lib/ids.ts';
import { kindOf, masked } from '../../lib/principals.ts';
import { spend } from '../../lib/rate.ts';
import { hashSecret, pkceS256, randomToken, sameSecret } from '../../lib/secrets.ts';
import { plainText } from '../../lib/text.ts';
import type { People } from '../directory/people.ts';
import type { Person } from '../directory/store.ts';
import type { Client, Login, OwnerStore, Token } from './store.ts';

const SCOPE = 'owner';
const LOGIN_MS = 15 * 60_000;
const ACCESS_MS = 3600_000;
const REFRESH_MS = 60 * 86_400_000;
const MAX_API_KEYS = 10;
const SIGNATURE_TRIES = 5;

/** What a key principal signs to sign in: this server, and the challenge it was given. */
export const signInBytes = (origin: string, challenge: string) => `SIMON-APP-SIGN-IN\n${origin}\n${challenge}`;

/** A signed-in person, and the identifiers proven in the session that are still fresh. */
export interface Session {
  /** The sign-in its tokens came from. */
  id: string;
  person: Person;
  identifiers: string[];
}

/** The next step of a sign-in: a code was sent, or a key principal signs a challenge. */
export type SignInStep = { step: 'code'; sentTo: string } | { step: 'sign'; challenge: string };

/** OAuth's own error shape (RFC 6749 section 5.2), as the token endpoint answers it. */
export class OAuthError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

function validRedirect(uri: string): boolean {
  try {
    const u = new URL(uri);
    // https, or a loopback address for native and command-line clients (RFC 8252).
    return (
      !u.hash &&
      (u.protocol === 'https:' || (u.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname)))
    );
  } catch {
    return false;
  }
}

export class OAuth {
  readonly store: OwnerStore;
  readonly #ctx: Ctx;
  readonly #people: People;
  readonly #codes: Codes;
  readonly #activity: Activity;

  constructor(ctx: Ctx, store: OwnerStore, people: People, codes: Codes, activity: Activity) {
    this.#ctx = ctx;
    this.store = store;
    this.#people = people;
    this.#codes = codes;
    this.#activity = activity;
  }

  metadata() {
    const issuer = this.#ctx.config.server.origin;
    return {
      issuer,
      authorization_endpoint: `${issuer}/api/oauth/authorize`,
      token_endpoint: `${issuer}/api/oauth/token`,
      registration_endpoint: `${issuer}/api/oauth/register`,
      revocation_endpoint: `${issuer}/api/oauth/revoke`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
      scopes_supported: [SCOPE],
    };
  }

  async register(input: { client_name?: string; redirect_uris: string[] }) {
    if (!input.redirect_uris.length || !input.redirect_uris.every(validRedirect)) {
      throw badRequest(
        'invalid_redirect_uri',
        'redirect_uris are https URLs, or loopback http URLs, without fragments.',
      );
    }
    // The name is repeated into sign-in mail, so it may not carry a link.
    const name = plainText('client_name', input.client_name?.trim() || 'An app');
    const client: Client = {
      _id: newId('oauthClient'),
      name,
      redirectUris: input.redirect_uris,
      createdAt: this.#ctx.now(),
    };
    await this.store.insertClient(client);
    return {
      client_id: client._id,
      client_name: name,
      redirect_uris: client.redirectUris,
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    };
  }

  /** The authorization request: checks the client and PKCE, and opens a sign-in for the page to drive. */
  async authorize(q: {
    response_type?: string;
    client_id?: string;
    redirect_uri?: string;
    code_challenge?: string;
    code_challenge_method?: string;
    state?: string;
  }) {
    if (q.response_type !== 'code') throw badRequest('unsupported_response_type', 'response_type is code.');
    const client = q.client_id ? await this.store.client(q.client_id) : null;
    if (!client) throw badRequest('invalid_client', 'Unknown client_id.');
    if (!q.redirect_uri || !client.redirectUris.includes(q.redirect_uri)) {
      throw badRequest('invalid_redirect_uri', 'redirect_uri is not registered for this client.');
    }
    if (q.code_challenge_method !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(q.code_challenge ?? '')) {
      throw badRequest('invalid_request', 'PKCE with S256 is required.');
    }
    const login: Login = {
      _id: newId('login'),
      client: client._id,
      redirectUri: q.redirect_uri,
      codeChallenge: q.code_challenge!,
      state: q.state ?? null,
      identifier: null,
      challenge: null,
      authCodeHash: null,
      person: null,
      expiresAt: new Date(this.#ctx.now().getTime() + LOGIN_MS),
    };
    await this.store.insertLogin(login);
    return login;
  }

  /** An open sign-in, and the app asking: its chosen name, and the host it will send the person back to. */
  async open(id: string) {
    const login = await this.store.login(id);
    if (!login) throw notFound('login', 'This sign-in link is not valid. Start again from the app.');
    if (login.person) throw gone('login_used', 'This sign-in was completed.');
    if (login.expiresAt <= this.#ctx.now())
      throw gone('login_expired', 'This sign-in expired. Start again from the app.');
    const client = (await this.store.client(login.client))!;
    return { login, app: { name: client.name, host: new URL(login.redirectUri).host } };
  }

  /** The identifier step: a code to an email address or phone number, or a challenge for a key principal. */
  async start(id: string, identifier: string): Promise<SignInStep> {
    const { login, app } = await this.open(id);
    if (kindOf(identifier) === 'key') {
      const challenge = randomToken();
      await this.store.updateLogin(login._id, { identifier, challenge });
      return { step: 'sign', challenge: signInBytes(this.#ctx.config.server.origin, challenge) };
    }
    await this.#codes.send(identifier, 'sign-in', login._id, code => ({
      subject: `Your SIMON sign-in code: ${code}`,
      text: `"${app.name}", an app at ${app.host}, asks to show you what your agents do on SIMON.\n\nYour code is ${code}. It expires in 15 minutes. Enter it only if you are signing in to ${app.host}.\n\nIf you did not ask for this, ignore this message.`,
      sms: `SIMON sign-in code ${code} for "${app.name}" at ${app.host}. Ignore it if you did not ask.`,
    }));
    await this.store.updateLogin(login._id, { identifier, challenge: null });
    return { step: 'code', sentTo: masked(identifier) };
  }

  /** The code is right: the person is who the identifier is, and the browser goes back with a code. */
  async verifyCode(id: string, code: string): Promise<string> {
    const { login } = await this.open(id);
    if (!login.identifier || login.challenge) throw badRequest('code_not_sent', 'Ask for a code first.');
    await this.#codes.check(login.identifier, 'sign-in', login._id, code);
    return this.#signedIn(login, login.identifier);
  }

  /** The key principal's signature over its challenge: the person is who the key is. */
  async verifySignature(id: string, signature: string): Promise<string> {
    const { login } = await this.open(id);
    const key = login.identifier && principalKey(login.identifier);
    if (!key || !login.challenge) throw badRequest('challenge_not_sent', 'Name your key first.');
    const { api } = this.#ctx;
    const until = login.expiresAt.toISOString();
    if ((await api.store.count('sign-in-signature', login._id, until, api.now().toISOString())) > SIGNATURE_TRIES)
      throw gone('login_locked', 'Too many signatures that do not verify. Start again from the app.');
    if (!verify(key, signInBytes(this.#ctx.config.server.origin, login.challenge), signature.trim()))
      throw unprocessable('bad_signature', 'That signature does not verify with the key over the challenge.');
    return this.#signedIn(login, login.identifier!);
  }

  async #signedIn(login: Login, identifier: string): Promise<string> {
    const person = await this.#people.claim(identifier);
    const authCode = randomToken();
    await this.store.updateLogin(login._id, {
      authCodeHash: hashSecret(authCode),
      person: person._id,
      expiresAt: new Date(this.#ctx.now().getTime() + 2 * 60_000),
    });
    await this.#activity.record(person._id, 'owner_signed_in', { client: login.client, identifier });
    const url = new URL(login.redirectUri);
    url.searchParams.set('code', authCode);
    if (login.state) url.searchParams.set('state', login.state);
    url.searchParams.set('iss', this.#ctx.config.server.origin);
    return url.toString();
  }

  async token(form: Record<string, string | undefined>) {
    if (form.grant_type === 'authorization_code') {
      if (!form.code || !form.code_verifier || !form.client_id) {
        throw new OAuthError('invalid_request', 'code, code_verifier and client_id are required.');
      }
      // Spent before anything else is checked, so a failed or concurrent try is never retried.
      const login = await this.store.spendAuthCode(hashSecret(form.code), this.#ctx.now());
      if (!login?.person || login.client !== form.client_id || login.redirectUri !== form.redirect_uri) {
        throw new OAuthError('invalid_grant', 'The authorization code is not valid.');
      }
      if (!sameSecret(pkceS256(form.code_verifier), login.codeChallenge))
        throw new OAuthError('invalid_grant', 'PKCE verification failed.');
      return this.#issue(
        { person: login.person, session: newId('session'), identifiers: [login.identifier!] },
        login.client,
      );
    }
    if (form.grant_type === 'refresh_token') {
      const t = form.refresh_token ? await this.store.token(hashSecret(form.refresh_token)) : null;
      const now = this.#ctx.now();
      const usable =
        t?.kind === 'refresh' && !t.revokedAt && t.expiresAt! > now && (!form.client_id || t.client === form.client_id);
      // Rotation: a refresh token is spent once, so a copy used concurrently or later fails.
      if (!usable || !(await this.store.revoke(t._id, now)))
        throw new OAuthError('invalid_grant', 'The refresh token is not valid.');
      return this.#issue(t, t.client!);
    }
    throw new OAuthError('unsupported_grant_type', 'grant_type is authorization_code or refresh_token.');
  }

  async #issue(session: Pick<Token, 'person' | 'session' | 'identifiers'>, client: string) {
    const now = this.#ctx.now();
    const access = `simono_${randomToken()}`;
    const refresh = `simonr_${randomToken()}`;
    const { person, identifiers } = session;
    const base = {
      person,
      session: session.session,
      identifiers,
      client,
      label: null,
      revokedAt: null,
      createdAt: now,
    };
    await this.store.insertToken({
      _id: newId('token'),
      tokenHash: hashSecret(access),
      kind: 'access',
      expiresAt: new Date(now.getTime() + ACCESS_MS),
      ...base,
    });
    await this.store.insertToken({
      _id: newId('token'),
      tokenHash: hashSecret(refresh),
      kind: 'refresh',
      expiresAt: new Date(now.getTime() + REFRESH_MS),
      ...base,
    });
    return {
      access_token: access,
      token_type: 'Bearer',
      expires_in: ACCESS_MS / 1000,
      refresh_token: refresh,
      scope: SCOPE,
    };
  }

  async revokeToken(value: string) {
    const t = await this.store.token(hashSecret(value));
    if (t) await this.store.revoke(t._id, this.#ctx.now());
  }

  /** The session behind an owner access token or API key, with its fresh identifiers; or a 401. */
  async authenticate(req: Request): Promise<Session> {
    const m = /^Bearer\s+(\S+)$/i.exec(String(req.headers.authorization ?? ''));
    if (!m) throw unauthorized('owner_token_required', 'Send an owner access token or API key as a Bearer token.');
    const t = await this.store.token(hashSecret(m[1]));
    const now = this.#ctx.now();
    const person =
      t && t.kind !== 'refresh' && !t.revokedAt && (!t.expiresAt || t.expiresAt > now)
        ? await this.#people.live(t.person)
        : null;
    if (!person) throw unauthorized('invalid_owner_token', 'The owner token is not valid.');
    await spend(this.#ctx.api, 'owner', this.#ctx.config.rates.owner, person._id);
    const fresh = await this.#people.fresh(person._id);
    const identifiers = t!.identifiers.filter(i => fresh.includes(i));
    if (!identifiers.length) {
      throw unauthorized('reverify_required', 'The identifiers this session proved are stale: sign in again.');
    }
    return { id: t!.session, person, identifiers };
  }

  /** A key for scripts, holding what the session proved now: a session of its own. */
  async createApiKey(session: Session, label: string | null) {
    const person = session.person._id;
    if ((await this.store.apiKeys(person, session.identifiers)).length >= MAX_API_KEYS) {
      throw conflict('too_many_api_keys', `A person holds at most ${MAX_API_KEYS} API keys; revoke one first.`);
    }
    const key = `simonk_${randomToken()}`;
    const t: Token = {
      _id: newId('token'),
      tokenHash: hashSecret(key),
      kind: 'api_key',
      person,
      session: newId('session'),
      identifiers: session.identifiers,
      client: null,
      label,
      expiresAt: null,
      revokedAt: null,
      createdAt: this.#ctx.now(),
    };
    await this.store.insertToken(t);
    await this.#activity.record(person, 'api_key_created', { key: t._id, identifier: session.identifiers[0] });
    return { ...apiKeyView(t), key };
  }

  /** The API keys a session may see: those that hold nothing it did not prove. */
  apiKeys(session: Session) {
    return this.store.apiKeys(session.person._id, session.identifiers);
  }

  async revokeApiKey(session: Session, id: string) {
    const t = (await this.apiKeys(session)).find(k => k._id === id);
    if (!t) throw notFound('api_key');
    await this.store.revoke(id, this.#ctx.now());
  }
}

export const apiKeyView = (t: Token) => ({ id: t._id, label: t.label, createdAt: t.createdAt.toISOString() });
