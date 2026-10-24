/**
 * Eight-digit codes sent to an email address or a phone number, to prove it is the caller's: pairing an
 * agent with a person, signing in to the owner window, adding an identifier. One rule for all of them:
 *
 *   - a code is for one purpose and one holder (an agent's address and key, a sign-in), lasts 15 minutes,
 *     and a new one replaces it;
 *   - each destination gets at most a few codes an hour, from everyone together;
 *   - each asker (a session, a person, an agent registering) sends at most a few a day, to anyone, and the
 *     server sends at most so many text messages and emails a day in all, so nobody can make it pump
 *     codes to numbers that charge for them;
 *   - each try is counted before it is compared, and the fifth wrong try locks the code.
 */
import crypto from 'node:crypto';
import type { Ctx } from '../context.ts';
import { gone, invalid, unprocessable } from './errors.ts';
import { kindOf, reachOf } from './principals.ts';
import { spend } from './rate.ts';
import { hashSecret, randomCode, sameSecret } from './secrets.ts';

const TTL_MS = 15 * 60_000;
const TRIES = 5;

export interface CodeMessage {
  subject: string;
  /** The email's body. */
  text: string;
  /** The text message: short. */
  sms: string;
}

export class Codes {
  readonly #ctx: Ctx;

  constructor(ctx: Ctx) {
    this.#ctx = ctx;
  }

  /** Whether this server can send a code to a principal of this kind. */
  canReach(principal: string): boolean {
    const kind = kindOf(principal);
    return kind === 'email' ? !!this.#ctx.mail : kind === 'phone' ? !!this.#ctx.sms : false;
  }

  /**
   * Send a fresh code to `principal` for `purpose` and `holder`; `message` writes what it says. `askers`
   * name whose daily budget it spends, the holder's by default.
   */
  async send(
    principal: string,
    purpose: string,
    holder: string,
    message: (code: string) => CodeMessage,
    askers: string[] = [holder],
  ): Promise<void> {
    const to = reachOf(principal);
    if (!to || !this.canReach(principal)) {
      throw invalid(`This server sends no codes to ${kindOf(principal)} identifiers.`, { field: 'for' });
    }
    const { api, config } = this.#ctx;
    await spend(api, 'codes', config.rates.codes, principal);
    for (const asker of askers) await spend(api, 'codesByAsker', config.rates.codesByAsker, asker);
    const total = kindOf(principal) === 'email' ? 'emailCodes' : 'smsCodes';
    try {
      await spend(api, total, config.rates[total], 'all');
    } catch (e) {
      api.log('warn', 'code budget spent', { budget: total });
      throw e;
    }
    const code = randomCode();
    const now = api.now();
    const expires = new Date(now.getTime() + TTL_MS).toISOString();
    await api.store.setValue(
      `code:${purpose}`,
      `${holder}\n${principal}`,
      { hash: hashSecret(code), nonce: crypto.randomUUID() },
      expires,
    );
    const m = message(code);
    if (kindOf(principal) === 'email') await this.#ctx.mail!.send({ to, subject: m.subject, text: m.text });
    else await this.#ctx.sms!.send({ to, text: m.sms });
  }

  /** Check a code, spending it when it is right; otherwise `410 code_expired`, `410 code_locked` or `422 wrong_code`. */
  async check(principal: string, purpose: string, holder: string, code: string): Promise<void> {
    const { api } = this.#ctx;
    const now = api.now();
    const id = `${holder}\n${principal}`;
    const sent = await api.store.value<{ hash: string; nonce: string }>(`code:${purpose}`, id, now.toISOString());
    if (!sent) throw gone('code_expired', 'No code is waiting; ask for a new one.');
    const tries = await api.store.count(
      `code-try:${purpose}`,
      `${id}\n${sent.nonce}`,
      new Date(now.getTime() + TTL_MS).toISOString(),
      now.toISOString(),
    );
    if (tries > TRIES) throw gone('code_locked', 'Too many wrong codes; ask for a new one.');
    if (!sameSecret(hashSecret(code), sent.hash)) throw unprocessable('wrong_code', 'That is not the code sent.');
    // A code is spent once, however many right answers arrive together.
    const spent = await api.store.mark(
      `code-spent:${purpose}`,
      `${id}\n${sent.nonce}`,
      new Date(now.getTime() + TTL_MS).toISOString(),
      now.toISOString(),
    );
    if (!spent) throw gone('code_expired', 'This code was used; ask for a new one.');
    await api.store.setValue(`code:${purpose}`, id, null, now.toISOString());
  }
}
