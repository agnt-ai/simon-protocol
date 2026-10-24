/**
 * Key continuity, by possession (spec section 11.1). For each domain this server remembers two sets of its
 * server's keys:
 *
 *   listed   the keys of the last document it trusted, which a newly read document must overlap;
 *   signers  the keys it trusts to sign: those of a document under which a trusted signer signed afresh.
 *
 * Listing a key proves nothing, since anyone can copy a public key into a document of their own. So a
 * document that lists a trusted key still has to sign with one: a signature by any other key is held, and
 * the new keys are trusted only once the change is confirmed after the hold. An honest rotation is never
 * held, because the server lists its new key beside the old one and keeps signing with the old one, which
 * vouches for the new one, until the change completes.
 *
 * A hold names the server and keys it holds. Once it is over, the change is confirmed from fresh answers
 * (`confirm`) before it is trusted; a domain whose server goes back to keys already trusted is not held.
 */
import { later, type Context } from './context.ts';
import { unavailable } from './errors.ts';

interface State {
  listed: string[];
  signers: string[];
  held?: { server: string; keys: string[]; until: string };
}

export interface ContinuityDeps extends Pick<Context, 'store' | 'now' | 'log'> {
  holdSeconds: number;
  /** Whether fresh answers still name this server with exactly these keys. */
  confirm(domain: string, server: string, keys: string[]): Promise<boolean>;
}

const SCOPE = 'continuity';
const sorted = (keys: readonly string[]) => [...keys].sort();
const same = (a: readonly string[], b: readonly string[]) => sorted(a).join() === sorted(b).join();

export class Continuity {
  readonly #d: ContinuityDeps;

  constructor(deps: ContinuityDeps) {
    this.#d = deps;
  }

  /** A document read for a domain's server: trusted when it lists a key trusted before, else held (503). */
  listed(domain: string, server: string, keys: string[]): Promise<void> {
    return this.#check(domain, server, keys, s => keys.some(k => s.listed.includes(k)));
  }

  /** A signature by `key`, under a document listing `keys`: trusted when `key` is a trusted signer, else held. */
  signed(domain: string, server: string, key: string, keys: string[]): Promise<void> {
    return this.#check(domain, server, keys, s => s.signers.includes(key));
  }

  /**
   * A trusted signer signed afresh (not a repeat) under a document listing `keys`: its holder vouches for
   * every key the document lists, so the next key of an honest rotation is trusted before it is used.
   */
  async vouch(domain: string, keys: string[]): Promise<void> {
    const s = await this.#state(domain);
    if (s && !s.held && !same(s.signers, keys)) await this.#save(domain, { listed: keys, signers: keys });
  }

  async #check(domain: string, server: string, keys: string[], trusted: (s: State) => boolean): Promise<void> {
    const s = await this.#state(domain);
    if (!s) return this.#save(domain, { listed: keys, signers: keys });
    const held = s.held && s.held.server === server && same(s.held.keys, keys) ? s.held : null;
    if (held) {
      const now = this.#d.now();
      if (now < new Date(held.until)) throw this.#holding(domain, held.until);
      if (await this.#d.confirm(domain, server, keys)) {
        this.#d.log('warn', 'domain server keys replaced after hold', { domain, server });
        return this.#save(domain, { listed: keys, signers: keys });
      }
    } else if (trusted(s)) {
      if (s.held || !same(s.listed, keys)) await this.#save(domain, { listed: keys, signers: s.signers });
      return;
    }
    const until = later(this.#d.now(), this.#d.holdSeconds * 1000);
    this.#d.log('warn', 'domain server keys changed; holding', { domain, server, until });
    await this.#save(domain, { listed: s.listed, signers: s.signers, held: { server, keys, until } });
    throw this.#holding(domain, until);
  }

  #state = (domain: string) => this.#d.store.value<State>(SCOPE, domain, this.#d.now().toISOString());
  #save = (domain: string, s: State) => this.#d.store.setValue(SCOPE, domain, s, null);

  #holding(domain: string, until: string) {
    const seconds = Math.max(1, Math.ceil((Date.parse(until) - this.#d.now().getTime()) / 1000));
    return unavailable(`${domain}'s server keys changed; holding it before trusting the new ones.`, seconds);
  }
}
