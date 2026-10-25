/** Configuration: each module reads its own section, and anything the application cannot mean stops it. */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateKey } from '@agnt-sdk/simon-protocol';
import { defineConfig } from '@agnt-sdk/simon-server';
import { loadAppConfig, MODULES } from '../src/config.ts';

const server = (dev: boolean) =>
  defineConfig({
    origin: 'https://simon.example.com',
    dev,
    hostedDomains: ['example.com'],
    serverKey: generateKey().privateKey,
  });
const production = {
  SIMON_DATA_KEY: Buffer.alloc(32, 1).toString('base64'),
  SIMON_SMTP_HOST: 'smtp.example.com',
  SIMON_MAIL_FROM: 'simon@example.com',
  SIMON_BRIDGE_INBOUND_SECRET: 's',
};

describe('configuration', () => {
  it('runs every module by default, with verified humans asked for by no one', () => {
    const c = loadAppConfig({}, server(true));
    assert.deepEqual(c.modules, [...MODULES]);
    assert.equal(c.systemDomain, 'example.com');
    assert.deepEqual(c.policy, { perSender: 200, perDomain: 2000, firstContacts: 30 });
  });

  it('runs the modules named, refusing unknown ones and ones missing what they need', () => {
    assert.deepEqual(loadAppConfig({ SIMON_MODULES: 'policy,webhooks' }, server(true)).modules, ['webhooks', 'policy']);
    assert.throws(() => loadAppConfig({ SIMON_MODULES: 'policy,chat' }, server(true)), /no module is named chat/);
    assert.throws(() => loadAppConfig({ SIMON_MODULES: 'intros,policy' }, server(true)), /intros needs directory/);
  });

  it('needs a mailer outside development only when a module sends codes or mail', () => {
    const { SIMON_SMTP_HOST: _, ...noMail } = production;
    assert.throws(() => loadAppConfig(noMail, server(false)), /directory, owner, bridge send mail/);
    assert.deepEqual(loadAppConfig({ ...noMail, SIMON_MODULES: 'policy,webhooks,uploads' }, server(false)).mail, null);
    assert.ok('smtp' in loadAppConfig(production, server(false)).mail!);
  });

  it('holds production to a data key, a bridge secret, and a scanner or an explicit choice', () => {
    assert.throws(() => loadAppConfig({ ...production, SIMON_DATA_KEY: '' }, server(false)), /SIMON_DATA_KEY/);
    assert.throws(
      () => loadAppConfig({ ...production, SIMON_BRIDGE_INBOUND_SECRET: '' }, server(false)),
      /SIMON_BRIDGE_INBOUND_SECRET/,
    );
    assert.equal(loadAppConfig(production, server(false)).uploads.unscanned, false);
    assert.equal(
      loadAppConfig({ ...production, SIMON_ALLOW_UNSCANNED_UPLOADS: '1' }, server(false)).uploads.unscanned,
      true,
    );
  });

  it('stops at a number or a rate it cannot read', () => {
    assert.throws(() => loadAppConfig({ SIMON_NUDGE_TURNS: 'lots' }, server(true)), /whole number/);
    assert.throws(() => loadAppConfig({ SIMON_APP_RATES: 'discovery=ten/60' }, server(true)), /SIMON_APP_RATES/);
    assert.equal(loadAppConfig({ SIMON_APP_RATES: 'discovery=3/60' }, server(true)).rates.discovery.limit, 3);
    assert.throws(
      () => loadAppConfig({ SIMON_SYSTEM_DOMAIN: 'other.com' }, server(true)),
      /not one of SIMON_HOSTED_DOMAINS/,
    );
  });
});
