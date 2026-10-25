/**
 * The email bridge, for recipients whose domain names no SIMON server (the core's `unroutable` event):
 *
 *   - someone here whose agent speaks for that very address gets the message at that agent, through its
 *     admit chain, as if addressed to it. Someone here whose contact tier excludes the sender gets nothing.
 *     Either way, a person here is never emailed, and the sender sees what any bridged message looks like;
 *   - anyone else gets an email from the bridge domain, with a reply address; their reply comes back as a
 *     message from `bridge@`, in reply to the original, with an `email-from` header. The reply address
 *     works only for mail from the address it went to, for 30 days.
 *
 * Only for messages from an agent here that speaks for a person this server verified by an email address
 * or a phone number, and has no email of its own: this server never sends anonymous mail. A key principal
 * alone is not enough, since anyone can make a key. The limit on mail sent counts per agent and per person. A reply address, and the mail sent with it, are kept
 * for those 30 days and no longer. Hooks: on.unroutable.
 */
import { header, sha256Hex, textOf, type Message } from '@agnt-sdk/simon-protocol';
import type { Events } from '@agnt-sdk/simon-server';
import { z } from 'zod';
import type { Ctx, Module } from '../../context.ts';
import { notFound, unauthorized } from '../../lib/errors.ts';
import { spend } from '../../lib/rate.ts';
import { hashSecret, randomToken, sameSecret, seal, unseal } from '../../lib/secrets.ts';
import { insertOnce } from '../../store/db.ts';
import { Queue } from '../../store/queue.ts';
import { defineRoute, type Caller } from '../../http/route.ts';
import type { CardStore } from '../agents/cards.ts';
import type { Directory } from '../directory/index.ts';
import { contactAllows } from '../directory/relations.ts';

const REPLY_MS = 30 * 86_400_000;

/** A bridged message's reply address: the token's hash, and where a reply goes. */
interface Reply {
  _id: string;
  message: string;
  author: string;
  email: string;
  createdAt: Date;
}

export function bridgeModule(ctx: Ctx, deps: { directory: Directory; cards: CardStore }): { module: Module } {
  const { directory: d, cards } = deps;
  const replies = ctx.db.collection<Reply>('bridge.replies');
  const mail = new Queue<{ message: string; author: string; email: string; token: string }>(
    ctx.db,
    'bridge.mail',
    [120, 240, 480, 960, 1920],
  );
  const { domain, inboundSecret } = ctx.config.bridge;

  /** The unroutable listener: true when the bridge took the recipients. */
  async function take({ id, recipients, message }: Events['unroutable']): Promise<boolean> {
    const author = await ctx.api.store.agentByAddress(message.from);
    const pairing = author && !ctx.system.isSystem(author.address) ? await d.people.pairingOf(author) : null;
    if (!pairing || pairing.recoveredAt || (await cards.card(author!.address)).capabilities.email) return false;
    if (!(await d.people.reachable(pairing.person))) return false;
    try {
      await spend(ctx.api, 'bridgeEmails', ctx.config.rates.bridgeEmails, author!.address);
      await spend(ctx.api, 'bridgeEmails', ctx.config.rates.bridgeEmails, `person:${pairing.person}`);
    } catch {
      return false;
    }
    for (const email of recipients) {
      const member = await d.people.forPrincipal(`mailto:${email}`);
      if (member?.claimed) {
        // Its agents for this very address, through their policies; or, with none, nothing at all.
        const pairs = (await d.people.pairsOf(member._id)).filter(p => p.principal === `mailto:${email}`);
        if (pairs.length) for (const p of pairs) await ctx.api.offer(p.address, id);
        if (pairs.length || !contactAllows(member.listing.contact, await d.relations.of(pairing.person, member._id)))
          continue;
      }
      const token = randomToken(18);
      await insertOnce(() =>
        replies.insertOne({
          _id: hashSecret(token),
          message: id,
          author: author!.address,
          email,
          createdAt: ctx.now(),
        }),
      );
      await mail.push(
        `${id} ${email}`,
        { message: id, author: author!.address, email, token: seal(ctx.config.dataKey, token) },
        ctx.now(),
      );
    }
    return true;
  }

  /** Background work: send queued mail, and drop reply addresses and mail past their 30 days. */
  async function work(): Promise<number> {
    const before = new Date(ctx.now().getTime() - REPLY_MS);
    const expired = (await replies.deleteMany({ createdAt: { $lt: before } })).deletedCount;
    return expired + (await mail.prune(before)) + (await send());
  }

  /** Send queued mail. Mail whose message expired fails rather than counting as sent. */
  const send = () =>
    mail.drain(
      () => ctx.now(),
      50,
      async job => {
        const record = await ctx.api.store.message(job.message);
        if (!record) return { fail: 'the message expired' };
        const m = record.message as Message;
        const others = m.parts.filter(p => !('data' in p && p.type.startsWith('text/'))).length;
        await ctx.mail!.send({
          to: job.email,
          // Whose agent wrote it, and that it came through SIMON; the address is the bridge's.
          from: `"${job.author} via SIMON" <no-reply@${domain}>`,
          replyTo: `reply+${unseal(ctx.config.dataKey, job.token)}@${domain}`,
          subject: (header(m, 'subject') ?? '(no subject)').replace(/[\r\n]+/g, ' '),
          text: textOf(m, '\n\n') + (others ? `\n\n(${others} more part${others > 1 ? 's' : ''} sent on SIMON.)` : ''),
          headers: {
            'Message-ID': `<${record.id}@${domain}>`,
            ...(m.inReplyTo ? { 'In-Reply-To': `<${m.inReplyTo}@${domain}>` } : {}),
            // A hint for a reader that speaks SIMON: it resolves the address and its keys itself.
            'SIMON-Agent': job.author,
          },
        });
        return 'done';
      },
    );

  const provider: Caller<null> = {
    scheme: 'bridgeSecret',
    async resolve(req) {
      const presented = String(req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
      if (!inboundSecret || !sameSecret(presented, inboundSecret))
        throw unauthorized('invalid_bridge_secret', 'Not allowed.');
      return null;
    },
  };

  const inbound = defineRoute({
    method: 'POST',
    path: '/api/bridge/inbound',
    operationId: 'receiveBridgeMail',
    tag: 'Email bridge',
    summary: 'An emailed reply to a message the bridge sent, posted by the inbound-mail provider',
    description: "For the operator's mail provider, not for agents. `id` is null when the reply was taken already.",
    caller: provider,
    body: z.strictObject({
      to: z.string().max(320).meta({ description: 'The reply address the mail was sent to: reply+<token>@<domain>.' }),
      from: z.string().max(320),
      text: z.string().max(100_000),
      messageId: z
        .string()
        .max(1000)
        .nullable()
        .optional()
        .meta({ description: "The mail's Message-ID, so a retry is taken once." }),
    }),
    status: 201,
    response: z.object({ id: z.string().nullable() }),
    async handle({ body, api }) {
      const token = /^reply\+([A-Za-z0-9_-]{10,64})@/.exec(body.to)?.[1];
      const reply = token ? await replies.findOne({ _id: hashSecret(token) }) : null;
      const live =
        reply &&
        body.from.trim().toLowerCase() === reply.email &&
        api.now().getTime() - reply.createdAt.getTime() < REPLY_MS;
      if (!reply || !live) throw notFound('reply_address', 'No message for that reply address.');
      await spend(api, 'bridgeReplies', ctx.config.rates.bridgeReplies, reply._id);
      // The same reply twice (a provider's retry) is taken once: by Message-ID, else by its text. A reply
      // whose send failed moves to its next generation, so the provider's retry is taken then.
      const key = `${reply._id}\n${body.messageId ? `id:${sha256Hex(body.messageId)}` : `text:${sha256Hex(body.text)}`}`;
      const now = api.now().toISOString();
      const expires = new Date(api.now().getTime() + REPLY_MS).toISOString();
      const generation = (await api.store.value<number>('bridge-reply-generation', key, now)) ?? 0;
      if (!(await api.store.mark('bridge-reply', `${key}\n${generation}`, expires, now))) return { id: null };
      const original = await api.store.message(reply.message);
      const subject = original ? header(original.message as Message, 'subject') : null;
      try {
        const id = await ctx.system.send('bridge', {
          to: [reply.author],
          inReplyTo: reply.message,
          headers: {
            'email-from': reply.email,
            ...(subject ? { subject: subject.startsWith('Re:') ? subject : `Re: ${subject}` } : {}),
          },
          text: withoutQuotes(body.text),
        });
        return { id };
      } catch (e) {
        await api.store.setValue('bridge-reply-generation', key, generation + 1, expires);
        throw e;
      }
    },
  });

  return {
    module: {
      name: 'bridge',
      routes: [inbound],
      hooks: { on: { unroutable: take } },
      async init() {
        await mail.init();
        await replies.createIndex({ createdAt: 1 });
        await replies.createIndex({ author: 1 });
      },
      work,
      forget: {
        async agent(address) {
          await replies.deleteMany({ author: address });
          await mail.drop('author', [address]);
        },
      },
    },
  };
}

/** The reply without the quoted history mail clients add below it. */
function withoutQuotes(text: string): string {
  const lines = text.split(/\r?\n/);
  const cut = lines.findIndex(l => /^On .+wrote:$/.test(l.trim()) || /^-{2,}\s*Original Message/i.test(l.trim()));
  return (cut >= 0 ? lines.slice(0, cut) : lines)
    .filter(l => !l.startsWith('>'))
    .join('\n')
    .trim();
}
