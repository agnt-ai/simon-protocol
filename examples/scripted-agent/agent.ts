/**
 * A scripted agent: no model, just a rule. It registers, then syncs messages with an opaque token, and answers any
 * message that asks for a time with three open slots as a text/calendar part, in the same thread.
 *
 *   SIMON_SERVER=http://localhost:8787 SIMON_HOME=./.agent-s node examples/scripted-agent/agent.ts [--once]
 *
 * It leases an address. Its server checked each author's signature before delivering (spec section 6.3);
 * an agent that keeps messages or forwards them checks again with verifyAuthor.
 */
import { parseArgs } from 'node:util';
import { isUnderstood, textOf } from '@agnt-sdk/simon-protocol';
import { defaultHome, openAgent, saveAddress } from '@agnt-sdk/simon-client/credentials';

const { values: opts } = parseArgs({ options: { once: { type: 'boolean', default: false } } });

/** iCalendar UTC time: 20261015T160000Z. */
const icalTime = (t: Date) =>
  t
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d{3}/, '');

/** Three free half hours on the next weekdays at 16:00 UTC, as one VFREEBUSY. A real agent reads a calendar. */
function openSlots(now: Date): string {
  const slots: Date[] = [];
  for (let d = 1; slots.length < 3; d++) {
    const day = new Date(now.getTime() + d * 86_400_000);
    if (day.getUTCDay() % 6 === 0) continue;
    slots.push(new Date(Date.UTC(day.getUTCFullYear(), day.getUTCMonth(), day.getUTCDate(), 16)));
  }
  const end = (t: Date) => new Date(t.getTime() + 30 * 60_000);
  return [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//SIMON examples//scripted agent//EN',
    'BEGIN:VFREEBUSY',
    `DTSTAMP:${icalTime(now)}`,
    ...slots.map(t => `FREEBUSY;FBTYPE=FREE:${icalTime(t)}/${icalTime(end(t))}`),
    'END:VFREEBUSY',
    'END:VCALENDAR',
    '',
  ].join('\r\n');
}

/** The headers this agent understands: none, so it acts on no message that lists one as critical. */
const UNDERSTOOD = new Set<string>();

const home = defaultHome();
const agent = openAgent(home, { server: process.env.SIMON_SERVER });
if (!agent.address) {
  const r = await agent.register();
  if (!('keys' in r)) throw new Error(`Registration is ${r.status}: this example only leases an address.`);
  saveAddress(home, agent);
}
console.log(`${agent.address} on ${agent.server}`);

for (let token: string | undefined; ; ) {
  const page = await agent.sync({ since: token });
  for (const { id, message } of page.messages) {
    if (!message.to.includes(agent.address!)) continue;
    if (!isUnderstood(message, UNDERSTOOD) || !/\b(meet|time|slot|when|available|free)\b/i.test(textOf(message)))
      continue;
    const { id: reply } = await agent.send({
      to: [message.from],
      inReplyTo: id,
      text: 'Here are three times that work. Pick one and I will hold it.',
      parts: [{ type: 'text/calendar', data: openSlots(new Date()) }],
    });
    console.log(`answered ${message.from} (${reply})`);
  }
  token = page.token;
  if (opts.once && !page.more) break;
  if (!page.more) await new Promise(resolve => setTimeout(resolve, 30_000));
}
