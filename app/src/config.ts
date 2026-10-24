/**
 * The application's configuration: the basic server's (server/README.md), and this application's own,
 * read once at startup. Each module reads its own section (its `config.ts`); anything unreadable stops
 * the process. app/README.md lists every variable.
 *
 *   AGNT_MONGO_URI, AGNT_MONGO_DB   the database (default mongodb://127.0.0.1:27017, agnt)
 *   AGNT_MODULES                    the modules to run, comma separated (default: all of them)
 *   AGNT_DATA_KEY                   32 bytes, base64: seals secrets kept at rest (required outside development)
 *   AGNT_SYSTEM_DOMAIN              the domain of this application's own agents (default: the first hosted domain)
 *   AGNT_APP_RATES                  rate overrides (lib/rate.ts)
 */
import { loadConfig, type Config } from '@agnt-protocol/server';
import { normalizeDomain } from '@agnt-protocol/protocol';
import { readMailConfig, type MailConfig } from './adapters/mail.ts';
import { readSmsConfig, type SmsConfig } from './adapters/sms.ts';
import { fail, list, text, type Env } from './lib/env.ts';
import { readRates, type Rates } from './lib/rate.ts';
import { readBridgeConfig, type BridgeConfig } from './modules/bridge/config.ts';
import { readIntrosConfig, type IntrosConfig } from './modules/intros/config.ts';
import { readNudgeConfig, type NudgeConfig } from './modules/nudge/config.ts';
import { readPolicyConfig, type PolicyConfig } from './modules/policy/config.ts';
import { readUploadsConfig, type UploadsConfig } from './modules/uploads/config.ts';

/** Every module, in the order they are assembled. Each is on unless AGNT_MODULES leaves it out. */
export const MODULES = ['webhooks', 'directory', 'policy', 'uploads', 'nudge', 'intros', 'owner', 'bridge'] as const;
export type ModuleName = (typeof MODULES)[number];

/** What a module cannot run without. */
const NEEDS: Partial<Record<ModuleName, ModuleName[]>> = {
  intros: ['directory', 'policy'],
  owner: ['directory'],
  bridge: ['directory'],
};

/** Modules that send codes or mail, so need a mailer outside development. */
const MAILS: ModuleName[] = ['directory', 'owner', 'bridge'];

export interface AppConfig {
  server: Config;
  mongo: { uri: string; db: string };
  modules: ModuleName[];
  dataKey: Buffer;
  systemDomain: string;
  mail: MailConfig | null;
  sms: SmsConfig | null;
  rates: Rates;
  policy: PolicyConfig;
  uploads: UploadsConfig;
  nudge: NudgeConfig;
  intros: IntrosConfig;
  bridge: BridgeConfig;
}

export function loadAppConfig(
  env: Env = process.env,
  server: Config = loadConfig(env as NodeJS.ProcessEnv),
): AppConfig {
  const dev = server.dev;
  const modules = readModules(env);
  const on = (m: ModuleName) => modules.includes(m);
  const mail = readMailConfig(env, dev);
  if (!mail && MAILS.some(on)) {
    fail(
      `${MAILS.filter(on).join(', ')} send mail: set AGNT_SMTP_HOST and AGNT_MAIL_FROM, or leave them out of AGNT_MODULES.`,
    );
  }
  const systemDomain =
    text(env, 'AGNT_SYSTEM_DOMAIN') ??
    server.hostedDomains[0] ??
    fail('AGNT_SYSTEM_DOMAIN or AGNT_HOSTED_DOMAINS is required: this application has agents of its own.');
  if (normalizeDomain(systemDomain) !== systemDomain || !server.hostedDomains.includes(systemDomain)) {
    fail(`AGNT_SYSTEM_DOMAIN ${systemDomain} is not one of AGNT_HOSTED_DOMAINS.`);
  }
  return {
    server,
    mongo: {
      uri: text(env, 'AGNT_MONGO_URI') ?? 'mongodb://127.0.0.1:27017',
      db: text(env, 'AGNT_MONGO_DB') ?? 'agnt',
    },
    modules,
    dataKey: readDataKey(env, dev),
    systemDomain,
    mail,
    sms: readSmsConfig(env, dev),
    rates: readRates(env),
    policy: readPolicyConfig(env),
    uploads: readUploadsConfig(env, dev),
    nudge: readNudgeConfig(env),
    intros: readIntrosConfig(env),
    bridge: on('bridge') ? readBridgeConfig(env, dev, systemDomain) : { domain: '', inboundSecret: null },
  };
}

function readModules(env: Env): ModuleName[] {
  if (env.AGNT_MODULES === undefined) return [...MODULES];
  const names = list(env, 'AGNT_MODULES');
  for (const n of names)
    if (!MODULES.includes(n as ModuleName)) fail(`AGNT_MODULES: no module is named ${n} (${MODULES.join(', ')}).`);
  for (const n of names as ModuleName[]) {
    for (const need of NEEDS[n] ?? []) if (!names.includes(need)) fail(`AGNT_MODULES: ${n} needs ${need}.`);
  }
  return MODULES.filter(m => names.includes(m));
}

function readDataKey(env: Env, dev: boolean): Buffer {
  const raw = text(env, 'AGNT_DATA_KEY');
  if (!raw) return dev ? Buffer.alloc(32, 7) : fail('AGNT_DATA_KEY is required: 32 bytes, base64.');
  const key = Buffer.from(raw, 'base64');
  return key.length === 32 ? key : fail('AGNT_DATA_KEY is 32 bytes, base64.');
}
