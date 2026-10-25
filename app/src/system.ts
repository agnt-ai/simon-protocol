/**
 * This application's own agents: `notices@` tells agents here what happened to them (an introduction to
 * answer, a thread run on without people), and `bridge@` carries emailed replies back. They are solo
 * agents on the system domain, written straight to the store, with keys derived from the server key, and
 * they send through `api.send` like any agent.
 *
 * A notice is a message with a `notice` header naming its kind, a line of text, and its details as an
 * `application/json` part (spec/registry.md). The text line states facts and never tells its reader what
 * to do. Anything someone else wrote (a requester's brief, a name a person gives themselves) travels only
 * in the JSON part, under `quoted`, each piece as `{author, text}`, so a reader never mistakes another's
 * words for this server's.
 */
import crypto, { type KeyObject } from 'node:crypto';
import {
  keyToken,
  privateKeyFromSeed,
  signMessage,
  timestamp,
  type Message,
  type Part,
} from '@agnt-sdk/simon-protocol';
import type { ServerApi } from '@agnt-sdk/simon-server';

export type SystemName = 'notices' | 'bridge';

/** Words someone other than this server wrote, and who: an agent's address, or a person's id. */
export interface Quoted {
  author: string;
  text: string;
}

/** A notice's details: facts this server states, and under `quoted`, what others wrote. */
export type NoticeData = Record<string, unknown> & { quoted?: Record<string, Quoted> };

export interface Draft {
  to: string[];
  text: string;
  inReplyTo?: string | null;
  headers?: Record<string, string>;
  /** A notice's kind, sent as its `notice` header. */
  notice?: string;
  /** A notice's details, sent as an `application/json` part. */
  data?: Record<string, unknown>;
}

export class SystemAgents {
  readonly #keys: Record<SystemName, KeyObject>;
  readonly #domain: string;
  readonly #api: () => ServerApi;

  constructor(serverKey: KeyObject, domain: string, api: () => ServerApi) {
    this.#domain = domain;
    this.#api = api;
    this.#keys = { notices: derive(serverKey, `notices@${domain}`), bridge: derive(serverKey, `bridge@${domain}`) };
  }

  address(name: SystemName): string {
    return `${name}@${this.#domain}`;
  }

  isSystem(address: string): boolean {
    return address === this.address('notices') || address === this.address('bridge');
  }

  /** Register the agents, or give them this server key's keys if it changed. Run once at startup. */
  async start(): Promise<void> {
    const { store, now } = this.#api();
    for (const name of ['notices', 'bridge'] as const) {
      const address = this.address(name);
      const key = { key: keyToken(this.#keys[name]), added: now().toISOString(), revoked: null };
      const held = await store.agentByAddress(address);
      if (!held) {
        const agent = {
          address,
          kind: 'solo' as const,
          principal: null,
          keys: [key],
          mailbox: false,
          createdAt: key.added,
          retiredAt: null,
        };
        if ((await store.createAgent(agent)) === 'created') continue;
      }
      const current = held ?? (await store.agentByAddress(address));
      if (!current?.keys.some(k => k.key === key.key && !k.revoked)) {
        if (current?.retiredAt || (await store.replaceKeys(address, key)) !== 'replaced') {
          throw new Error(`${address} is held by another agent: this application needs it for itself.`);
        }
      }
    }
  }

  /** Send as one of these agents. Answers the message id. */
  async send(name: SystemName, draft: Draft): Promise<string> {
    const api = this.#api();
    const parts: Part[] = [{ type: 'text/plain', data: draft.text }];
    // A part that is not text carries its bytes in base64 (spec section 5.3).
    if (draft.data)
      parts.push({ type: 'application/json', data: Buffer.from(JSON.stringify(draft.data)).toString('base64') });
    const message = signMessage<Message>(
      {
        v: 1,
        from: this.address(name),
        to: draft.to,
        inReplyTo: draft.inReplyTo ?? null,
        parts,
        headers: { ...draft.headers, ...(draft.notice ? { notice: draft.notice } : {}) },
        sentAt: timestamp(api.now()),
      },
      this.#keys[name],
    );
    return (await api.send(message)).id;
  }

  /** A notice from `notices@` to agents here, after the answer: a failure is logged, never the caller's. */
  notify(to: string[], notice: string, text: string, data: NoticeData = {}, inReplyTo?: string): Promise<void> {
    return this.send('notices', { to, notice, text, data, inReplyTo }).then(
      () => undefined,
      e => this.#api().log('error', 'notice failed', { notice, error: String(e) }),
    );
  }
}

/** A key that only this server key can make: an HMAC of the agent's address, as an Ed25519 seed. */
function derive(serverKey: KeyObject, address: string): KeyObject {
  const secret = serverKey.export({ type: 'pkcs8', format: 'der' });
  const seed = crypto.createHmac('sha256', secret).update(`SIMON-APP-SYSTEM-AGENT\n${address}`).digest();
  return privateKeyFromSeed('ed25519', seed);
}
