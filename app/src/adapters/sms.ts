/**
 * Text messages, for codes to `tel:` principals: Twilio's Messages API over fetch, or the console in
 * development. With neither, phone numbers cannot be paired or sign in.
 *
 *   SIMON_TWILIO_SID, SIMON_TWILIO_TOKEN, SIMON_TWILIO_FROM
 */
import { text, type Env } from '../lib/env.ts';

export interface Sms {
  send(message: { to: string; text: string }): Promise<void>;
}

export type SmsConfig = { twilio: { sid: string; token: string; from: string } } | { console: true };

export function readSmsConfig(env: Env, dev: boolean): SmsConfig | null {
  const [sid, token, from] = ['SIMON_TWILIO_SID', 'SIMON_TWILIO_TOKEN', 'SIMON_TWILIO_FROM'].map(n => text(env, n));
  if (sid && token && from) return { twilio: { sid, token, from } };
  return dev ? { console: true } : null;
}

export function smsFor(config: SmsConfig): Sms {
  if ('console' in config) return { send: async m => console.error(`[sms] to=${m.to} ${m.text}`) };
  const { sid, token, from } = config.twilio;
  return {
    async send(m) {
      const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(sid)}/Messages.json`, {
        method: 'POST',
        headers: {
          authorization: `Basic ${Buffer.from(`${sid}:${token}`).toString('base64')}`,
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ To: m.to, From: from, Body: m.text }),
      });
      if (!res.ok) throw new Error(`Twilio answered ${res.status}.`);
    },
  };
}
