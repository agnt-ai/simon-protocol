/**
 * Discovery (discovery profile): lookups of the assistant an identifier's holder chose, and the directory
 * that lists them.
 *
 *   GET    /simon/lookup?identifier=<id>   signed by the asking agent: this server's record for the identifier, or 404
 *   POST   /simon/directory                signed by the agent to list: {"identifier"} sends a code to it;
 *                                          {"identifier","code"} lists the agent as its assistant
 *   DELETE /simon/directory                {"identifier"}: signed by the listed agent, unlists it; from anyone
 *                                          else, sends the identifier a code, and with it {"identifier","code"}
 *                                          unlists it, so a holder never needs its assistant to leave
 *
 * This server lists the email addresses of the domains it serves, as their authority, and, when configured
 * as a directory, those of any domain. Every identifier it has no record for answers the same 404.
 */
import crypto from 'node:crypto';
import {
  domainOf,
  invalid,
  isListableIdentifier,
  signDirectoryRecord,
  timestamp,
  unauthorized,
  WireError,
  type DirectoryRecord,
} from '@agnt-sdk/simon-protocol';
import { readBody, sha256 } from './account.ts';
import { authenticateReader, isAgentSigned } from './auth.ts';
import { iso, later, type Context, type MailboxNote } from './context.ts';
import { notFound } from './errors.ts';
import { json, type Request, type Route } from './http.ts';
import { clientKey } from './net/ip.ts';
import { checkCode, CODE_TTL_MS } from './register.ts';

const RECORDS = 'directory';
const CODES = 'directory-code';
/** Each identifier's last revision, kept for good so a later choice always takes a higher one. */
const REVISIONS = 'directory-revision';
const NEVER = '9999-12-31T23:59:59Z';
/** How long a record this server issues lasts: a year, within the profile's 366 days. */
const RECORD_MS = 365 * 24 * 60 * 60 * 1000;

/** The agent that signed the request, wherever it is hosted; `401` when none did. */
async function asker(ctx: Context, req: Request): Promise<string> {
  if (!isAgentSigned(req)) {
    throw unauthorized(
      'signature_required',
      'Sign the request with your agent key, naming yourself in simon-agent.',
      ctx.now(),
    );
  }
  return authenticateReader(ctx, req);
}

function identifierOf(value: unknown): string {
  if (!isListableIdentifier(value)) {
    throw invalid('identifier is a mailto: or tel: identifier.', { field: 'identifier' });
  }
  return value;
}

/** This server's record for an identifier while it lasts, or null. */
async function recordOf(ctx: Context, identifier: string): Promise<DirectoryRecord | null> {
  const record = await ctx.store.value<DirectoryRecord>(RECORDS, identifier, iso(ctx.now()));
  return record && Date.parse(record.expires) > ctx.now().getTime() ? record : null;
}

/**
 * Whether this server lists an identifier: an email address on a domain it serves, of which it is the
 * authority, or any email address when it keeps a directory. It reaches email addresses only.
 */
async function lists(ctx: Context, identifier: string): Promise<boolean> {
  if (!identifier.startsWith('mailto:') || !ctx.mailbox) return false;
  return ctx.config.directory || ctx.resolver.servesHere(domainOf(identifier.slice('mailto:'.length)));
}

/**
 * A code for `purpose` sent to the identifier: stored under a fresh nonce, so wrong guesses at one code never
 * lock the next (CLIENT.md's codes).
 */
async function sendCode(
  ctx: Context,
  req: Request,
  purpose: string,
  identifier: string,
  note: (code: string) => MailboxNote,
) {
  ctx.rate.hitClient('codeClient', req.ip);
  ctx.rate.hit('code', identifier);
  const code = String(crypto.randomInt(100_000_000)).padStart(8, '0');
  const now = ctx.now();
  await ctx.store.setValue(CODES, purpose, { hash: sha256(code), nonce: crypto.randomUUID() }, later(now, CODE_TTL_MS));
  const address = identifier.slice('mailto:'.length);
  ctx.defer(() => ctx.mailbox!(address, note(code)));
}

/** Spend the code sent for `purpose`, or `401 bad_proof`. */
async function spendCode(ctx: Context, purpose: string, code: string): Promise<void> {
  const now = ctx.now();
  const sent = await ctx.store.value<{ hash: string; nonce: string }>(CODES, purpose, iso(now));
  if (!sent) throw unauthorized('bad_proof', 'No code was sent for this, or it expired.', now);
  await checkCode(ctx, `${purpose}\n${sent.nonce}`, sent.hash, code, now).catch(e => {
    // Wrong or locked, the answer is the profile's one refusal of a code.
    throw e instanceof WireError ? unauthorized('bad_proof', 'That is not the code sent.', now) : e;
  });
  await ctx.store.setValue(CODES, purpose, null, iso(now));
}

export function directoryRoutes(ctx: Context): Route[] {
  return [
    {
      method: 'GET',
      path: '/simon/lookup',
      async handle(req) {
        const who = await asker(ctx, req);
        // Per agent, and per server for agents of one domain, so minting agents buys no more lookups.
        ctx.rate.hit('directoryLookup', who);
        ctx.rate.hit('directoryLookupServer', domainOf(who));
        const identifier = identifierOf(req.query.get('identifier'));
        const record = await recordOf(ctx, identifier);
        if (!record) throw notFound('No record for this identifier.');
        return json({ record });
      },
    },
    {
      method: 'POST',
      path: '/simon/directory',
      async handle(req) {
        const agent = await asker(ctx, req);
        const body = readBody(req.body, ['identifier', 'code']);
        const identifier = identifierOf(body.identifier);
        if (!(await lists(ctx, identifier))) {
          throw invalid('This server keeps no directory that reaches this identifier.', { field: 'identifier' });
        }
        const purpose = `list\n${identifier}\n${agent}`;
        if (body.code === undefined) {
          ctx.rate.hit('code', agent);
          await sendCode(ctx, req, purpose, identifier, code => ({ type: 'listing', assistant: agent, code }));
          return json({ status: 'code_sent' }, 202);
        }
        await spendCode(ctx, purpose, body.code);
        const now = ctx.now();
        const revision = await ctx.store.count(REVISIONS, identifier, NEVER, iso(now));
        const expires = later(now, RECORD_MS);
        const record = signDirectoryRecord(
          { identifier, address: agent, revision, issued: timestamp(now), expires, issuer: ctx.config.origin },
          ctx.config.serverKey,
        );
        await ctx.store.setValue(RECORDS, identifier, record, expires);
        ctx.log('info', 'directory listed', { identifier, address: agent, client: clientKey(req.ip) });
        return json({ record });
      },
    },
    {
      method: 'DELETE',
      path: '/simon/directory',
      async handle(req) {
        const body = readBody(req.body, ['identifier', 'code']);
        const identifier = identifierOf(body.identifier);
        const record = await recordOf(ctx, identifier);
        const unlist = () => ctx.store.setValue(RECORDS, identifier, null, iso(ctx.now()));
        const listed = isAgentSigned(req) ? await asker(ctx, req) : null;
        if (listed !== null && body.code === undefined) {
          // The same answer whether or not this agent was listed for it: unlisting tells nothing.
          if (record?.address === listed) await unlist();
          return json({ status: 'unlisted' });
        }
        // The holder, with or without an assistant, by a code sent to the identifier: sent only when there is
        // a record, answered alike either way.
        const purpose = `unlist\n${identifier}`;
        if (body.code === undefined) {
          if (record && (await lists(ctx, identifier))) {
            await sendCode(ctx, req, purpose, identifier, code => ({ type: 'unlisting', code }));
          }
          return json({ status: 'code_sent' }, 202);
        }
        await spendCode(ctx, purpose, body.code);
        await unlist();
        return json({ status: 'unlisted' });
      },
    },
  ];
}
