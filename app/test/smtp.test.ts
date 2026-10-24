/**
 * Mail for codes over plain SMTP, so anyone can run a server: a tiny SMTP server stands in for the
 * operator's, and the configuration rules hold.
 */
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { readMailConfig, smtpMailer } from '../src/adapters/mail.ts';

/** Just enough SMTP to accept one message: EHLO, MAIL, RCPT, DATA, QUIT. */
function fakeSmtp() {
  const received: { from: string; to: string[]; data: string }[] = [];
  const server = net.createServer(sock => {
    let mail = { from: '', to: [] as string[], data: '' };
    let inData = false;
    let buf = '';
    sock.write('220 fake ESMTP\r\n');
    sock.on('data', chunk => {
      buf += chunk.toString('utf8');
      let i: number;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        if (inData) {
          if (line === '.') {
            inData = false;
            received.push(mail);
            mail = { from: '', to: [], data: '' };
            sock.write('250 queued\r\n');
          } else mail.data += `${line.startsWith('..') ? line.slice(1) : line}\n`;
          continue;
        }
        const cmd = line.slice(0, 4).toUpperCase();
        if (cmd === 'EHLO' || cmd === 'HELO') sock.write('250-fake\r\n250 8BITMIME\r\n');
        else if (cmd === 'MAIL') ((mail.from = line), sock.write('250 ok\r\n'));
        else if (cmd === 'RCPT') (mail.to.push(line), sock.write('250 ok\r\n'));
        else if (cmd === 'DATA') ((inData = true), sock.write('354 go\r\n'));
        else if (cmd === 'QUIT') sock.end('221 bye\r\n');
        else sock.write('250 ok\r\n');
      }
    });
  });
  return { server, received };
}

describe('SMTP mail for codes', () => {
  const smtp = fakeSmtp();
  let port = 0;
  before(async () => {
    await new Promise<void>(r => smtp.server.listen(0, '127.0.0.1', r));
    port = (smtp.server.address() as net.AddressInfo).port;
  });
  after(() => smtp.server.close());

  it('sends through any SMTP server', async () => {
    const mailer = smtpMailer({
      host: '127.0.0.1',
      port,
      tls: 'none',
      user: null,
      pass: null,
      from: 'codes@agents.example.test',
    });
    await mailer.send({
      to: 'ada@example.org',
      subject: 'Your AGNT code: 123456',
      text: 'Code: 123456.',
      replyTo: 'reply+abc@bridge.example.test',
      headers: { 'AGNT-Agent': 'bot@agents.example.test; server=https://agnt.example.test' },
    });
    assert.equal(smtp.received.length, 1);
    const m = smtp.received[0];
    assert.match(m.from, /codes@agents\.example\.test/);
    assert.match(m.to[0], /ada@example\.org/);
    assert.match(m.data, /Subject: Your AGNT code: 123456/);
    assert.match(m.data, /Reply-To: reply\+abc@bridge\.example\.test/);
    assert.match(m.data, /AGNT-Agent: bot@agents\.example\.test/i, 'header names are case-insensitive');
    assert.match(m.data, /Code: 123456\./);
  });

  it('reads the mail path from the environment, and holds production to a real, encrypted one', () => {
    const mail = (env: Record<string, string>, dev = false) => readMailConfig(env, dev);
    assert.deepEqual(mail({}, true), { console: true }, 'development falls back to the console');
    assert.deepEqual(mail({ AGNT_DEV_OUTBOX: '/tmp/out.jsonl' }, true), { outbox: '/tmp/out.jsonl' });
    assert.equal(mail({}), null, 'production has no mail path until one is set');
    assert.throws(() => mail({ AGNT_SMTP_HOST: 'smtp.example.test' }), /AGNT_MAIL_FROM/);
    const smtp = { AGNT_SMTP_HOST: 'smtp.example.test', AGNT_MAIL_FROM: 'a@b.test' };
    assert.throws(() => mail({ ...smtp, AGNT_SMTP_TLS: 'none' }), /only for a relay on this host/);
    assert.throws(() => mail({ ...smtp, AGNT_SMTP_TLS: 'sometimes' }), /starttls, tls, none/);
    assert.deepEqual(mail(smtp), {
      smtp: { host: 'smtp.example.test', port: 587, tls: 'starttls', user: null, pass: null, from: 'a@b.test' },
    });
    assert.deepEqual(
      mail({ ...smtp, AGNT_SMTP_TLS: '', AGNT_SMTP_PORT: '' }),
      mail(smtp),
      'empty settings count as unset',
    );
    assert.equal(
      (mail({ ...smtp, AGNT_SMTP_HOST: '127.0.0.1', AGNT_SMTP_TLS: 'none' }) as { smtp: { tls: string } }).smtp.tls,
      'none',
    );
  });
});
