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
 * as a directory, those of any domain; its server document says `discovery`. Every identifier it has no
 * record for answers the same 404, and asking for an unlisting code answers and works alike whether or not
 * the identifier is listed.
 *
 * Codes. A code lasts CODE_TTL_MS. Each client may guess wrong CODE_ATTEMPTS times at one code, and every
 * client together CODE_GUESSES times, after which the code is dropped so a fresh one can be sent: no third
 * party can lock the holder out of the code it was sent. An unexpired unlisting code is never replaced, so a
 * request from anyone else cannot spoil the holder's, and an identifier is sent at most one unlisting code
 * at a time, which is what keeps unlisting requests from flooding it with no per-identifier limit a third
 * party could spend.
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
import { notFound, unavailable } from './errors.ts';
import { json, type Request, type Route } from './http.ts';
import { clientKey } from './net/ip.ts';
import { loadPublicSuffixes, registrableDomain, shippedPublicSuffixes } from './net/psl.ts';
import { checkCode, CODE_TTL_MS } from './register.ts';

const RECORDS = 'directory';
const CODES = 'directory-code';
/** Guesses at one code from every client together, after which it is dropped and a fresh one may be sent. */
const CODE_GUESSES = 50;
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

interface StoredCode {
  hash: string;
  nonce: string;
}

/** A fresh code, and what is stored of it: its hash, under a fresh nonce, so wrong guesses at one never lock the next. */
function freshCode(): { code: string; stored: StoredCode } {
  const code = String(crypto.randomInt(100_000_000)).padStart(8, '0');
  return { code, stored: { hash: sha256(code), nonce: crypto.randomUUID() } };
}

/** Send `note` to the identifier's mailbox, after the answer. */
function mail(ctx: Context, identifier: string, note: MailboxNote) {
  const address = identifier.slice('mailto:'.length);
  ctx.defer(() => ctx.mailbox!(address, note));
}

/**
 * Spend the code sent for `purpose`, or `401 bad_proof`. Every attempt counts against the client making it;
 * a client's wrong guesses lock only that client out of the code, and all clients' together, past
 * CODE_GUESSES, drop it.
 */
async function spendCode(ctx: Context, req: Request, purpose: string, code: string): Promise<void> {
  ctx.rate.hitClient('codeClient', req.ip);
  const now = ctx.now();
  const refuse = () => unauthorized('bad_proof', 'That is not the code sent, or it expired.', now);
  const sent = await ctx.store.value<StoredCode>(CODES, purpose, iso(now));
  if (!sent) throw refuse();
  const attempt = `${purpose}\n${sent.nonce}`;
  if ((await ctx.store.count('code-attempt', attempt, later(now, CODE_TTL_MS), iso(now))) > CODE_GUESSES) {
    await ctx.store.releaseValue(CODES, purpose, sent);
    throw refuse();
  }
  await checkCode(ctx, `${attempt}\n${clientKey(req.ip)}`, sent.hash, code, now).catch(e => {
    // Wrong or locked, the answer is the profile's one refusal of a code.
    throw e instanceof WireError ? refuse() : e;
  });
  // Spent once: of two spending it together, one wins.
  if (!(await ctx.store.releaseValue(CODES, purpose, sent))) throw refuse();
}

/**
 * Store a newly issued record unless a higher revision is already stored: of two listings completed together,
 * the later choice stands, whichever is written last. True when `record` is stored.
 */
async function storeRecord(ctx: Context, record: DirectoryRecord): Promise<boolean> {
  for (let tries = 0; tries < 8; tries++) {
    const stored = await ctx.store.valueOnce<DirectoryRecord | null>(
      RECORDS,
      record.identifier,
      record,
      record.expires,
      iso(ctx.now()),
    );
    if (stored?.revision === record.revision) return true;
    if (stored && stored.revision > record.revision) return false;
    // A lower revision, or an unlisting: take it away, only while it is still what was read, and try again.
    await ctx.store.releaseValue(RECORDS, record.identifier, stored);
  }
  throw unavailable('The directory is busy with this identifier; try again.');
}

export function directoryRoutes(ctx: Context): Route[] {
  const suffixes = ctx.config.publicSuffixFile
    ? loadPublicSuffixes(ctx.config.publicSuffixFile)
    : shippedPublicSuffixes();
  return [
    {
      method: 'GET',
      path: '/simon/lookup',
      async handle(req) {
        const who = await asker(ctx, req);
        // Per agent; per registrable domain of the agent's, so neither minting agents nor minting subdomains
        // under one wildcard record buys more lookups; and per client.
        ctx.rate.hit('directoryLookup', who);
        ctx.rate.hit('directoryLookupDomain', registrableDomain(domainOf(who), suffixes));
        ctx.rate.hit('directoryLookupClient', clientKey(req.ip));
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
          // Listing codes are bounded per asking agent, per client and per identifier; unlisting codes have
          // a bound of their own, so listing requests never stand in the way of a holder leaving.
          ctx.rate.hit('code', agent);
          ctx.rate.hitClient('codeClient', req.ip);
          ctx.rate.hit('code', identifier);
          const { code, stored } = freshCode();
          await ctx.store.setValue(CODES, purpose, stored, later(ctx.now(), CODE_TTL_MS));
          mail(ctx, identifier, { type: 'listing', assistant: agent, code });
          return json({ status: 'code_sent' }, 202);
        }
        await spendCode(ctx, req, purpose, body.code);
        const now = ctx.now();
        const revision = await ctx.store.count(REVISIONS, identifier, NEVER, iso(now));
        const expires = later(now, RECORD_MS);
        const record = signDirectoryRecord(
          { identifier, address: agent, revision, issued: timestamp(now), expires, issuer: ctx.config.origin },
          ctx.config.serverKey,
        );
        // A listing completed together with this one and a later revision stands; this record is still the
        // answer to this call, and lookups answer the later one.
        await storeRecord(ctx, record);
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
        // The holder, with or without an assistant, by a code sent to the identifier. The code is for the
        // record standing now, so one minted for an earlier record or for none never stands in its way.
        const purpose = `unlist\n${identifier}\n${record?.revision ?? 0}`;
        if (body.code === undefined) {
          // The same count and the same work whether or not the identifier is listed: one client bound, one
          // code minted and kept unless one is outstanding, and only the sending told apart, after the answer.
          ctx.rate.hitClient('codeClient', req.ip);
          const reaches = await lists(ctx, identifier);
          const { code, stored } = freshCode();
          const kept = await ctx.store.valueOnce(CODES, purpose, stored, later(ctx.now(), CODE_TTL_MS), iso(ctx.now()));
          // An outstanding code is never replaced: it is the one in the holder's mailbox, whoever asked for it.
          if (kept.nonce === stored.nonce && record && reaches) mail(ctx, identifier, { type: 'unlisting', code });
          return json({ status: 'code_sent' }, 202);
        }
        await spendCode(ctx, req, purpose, body.code);
        await unlist();
        return json({ status: 'unlisted' });
      },
    },
  ];
}
