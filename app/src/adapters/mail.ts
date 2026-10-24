/**
 * Mail: codes, notices to people, and the email bridge. Any SMTP server in production; in development a
 * file of JSON lines (AGNT_DEV_OUTBOX), so scripts can read codes, or the console.
 *
 *   AGNT_SMTP_HOST, AGNT_SMTP_PORT, AGNT_SMTP_TLS (starttls | tls | none), AGNT_SMTP_USER, AGNT_SMTP_PASS
 *   AGNT_MAIL_FROM     the address codes and notices come from
 *   AGNT_DEV_OUTBOX    development only: append each email to this file
 */
import fs from 'node:fs/promises';
import { fail, int, oneOf, text, type Env } from '../lib/env.ts';

export interface Email {
  to: string;
  subject: string;
  text: string;
  /** The sender; the configured AGNT_MAIL_FROM unless given. */
  from?: string;
  replyTo?: string;
  headers?: Record<string, string>;
}

export interface Mailer {
  send(email: Email): Promise<void>;
}

export interface SmtpConfig {
  host: string;
  port: number;
  /** starttls upgrades a plain connection (587); tls is TLS from the start (465); none is for a local relay. */
  tls: 'starttls' | 'tls' | 'none';
  user: string | null;
  pass: string | null;
  from: string;
}

export type MailConfig = { smtp: SmtpConfig } | { outbox: string } | { console: true };

const LOCAL = ['localhost', '127.0.0.1', '::1'];

/** The mail path the environment names; null when none is set outside development. */
export function readMailConfig(env: Env, dev: boolean): MailConfig | null {
  const host = text(env, 'AGNT_SMTP_HOST');
  if (!host) {
    if (!dev) return null;
    const outbox = text(env, 'AGNT_DEV_OUTBOX');
    return outbox ? { outbox } : { console: true };
  }
  const from = text(env, 'AGNT_MAIL_FROM') ?? fail('AGNT_SMTP_HOST needs AGNT_MAIL_FROM, the address mail comes from.');
  const tls = oneOf(env, 'AGNT_SMTP_TLS', ['starttls', 'tls', 'none'], 'starttls');
  if (!dev && tls === 'none' && !LOCAL.includes(host)) {
    fail('AGNT_SMTP_TLS=none is allowed outside development only for a relay on this host.');
  }
  const port = int(env, 'AGNT_SMTP_PORT', tls === 'tls' ? 465 : tls === 'none' ? 25 : 587);
  return { smtp: { host, port, tls, user: text(env, 'AGNT_SMTP_USER'), pass: text(env, 'AGNT_SMTP_PASS'), from } };
}

export function mailerFor(config: MailConfig): Mailer {
  if ('smtp' in config) return smtpMailer(config.smtp);
  if ('outbox' in config) {
    return { send: async email => fs.appendFile(config.outbox, `${JSON.stringify(email)}\n`) };
  }
  return {
    send: async email =>
      console.error(`[mail] to=${email.to} subject=${JSON.stringify(email.subject)}\n${email.text}\n`),
  };
}

/** The parts of nodemailer used here: it ships no types. */
interface Transport {
  sendMail(mail: Email & { from: string }): Promise<unknown>;
}

export function smtpMailer(smtp: SmtpConfig): Mailer {
  let transport: Promise<Transport> | null = null;
  const connect = async () => {
    const nodemailer = (await import('nodemailer' as string)).default as {
      createTransport(options: Record<string, unknown>): Transport;
    };
    return nodemailer.createTransport({
      host: smtp.host,
      port: smtp.port,
      secure: smtp.tls === 'tls',
      requireTLS: smtp.tls === 'starttls',
      ignoreTLS: smtp.tls === 'none',
      auth: smtp.user ? { user: smtp.user, pass: smtp.pass ?? '' } : undefined,
    });
  };
  return {
    async send(email) {
      transport ??= connect();
      await (await transport).sendMail({ ...email, from: email.from ?? smtp.from });
    },
  };
}
