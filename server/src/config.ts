/**
 * Configuration: every setting in one place, validated once. `loadConfig(env)` reads the environment (the
 * table below, mirrored in README.md); `defineConfig(input)` builds the same thing from code. Any invalid
 * value throws at startup, never at the first request that needs it.
 *
 *   SIMON_ORIGIN                  this server's origin, https://host[:port]                     required
 *   SIMON_DEV                     1: development (http and local hosts, codes logged, a throwaway key)
 *   SIMON_HOSTED_DOMAINS          domains whose names agents take at once, comma separated
 *   SIMON_LEASE_DOMAIN            the domain addresses are leased on, for `register` with a key alone
 *   SIMON_SERVER_KEY              the signing key: <alg>:<base64url 32-byte seed>               or ..._FILE
 *   SIMON_SERVER_KEY_FILE         the signing key as a PKCS #8 PEM file
 *   SIMON_NEXT_SERVER_KEY         a key announced for rotation: listed, not yet used           or ..._FILE
 *   SIMON_NEXT_SERVER_KEY_FILE
 *   SIMON_DB                      the sqlite file (default simon.sqlite; :memory: for none)
 *   SIMON_PORT                    the port to listen on (default 8080)
 *   SIMON_LISTEN_HOST             the address to listen on, 127.0.0.1 behind a tunnel (default every interface)
 *   SIMON_CLIENT_IP_HEADER        a header proxies set to the client's address, x-forwarded-for or cf-connecting-ip:
 *                                read only from this machine (a tunnel) and from SIMON_TRUSTED_PROXIES
 *   SIMON_TRUSTED_PROXIES         networks a load balancer connects from, CIDR, comma separated (/8 or narrower)
 *   SIMON_KEEP_ALIVE_TIMEOUT      seconds an idle connection is kept open (default 5; above a load balancer's own)
 *   SIMON_TRUSTED_CLAIM_SERVERS   origins whose claims agents here are shown, comma separated
 *   SIMON_DOH_RESOLVERS           two or more DNS-over-HTTPS JSON endpoints that must agree on every TXT answer
 *   SIMON_DNS_SERVERS             DNS servers to ask instead of the system's, IP addresses, comma separated
 *   SIMON_RATES                   overrides, name=count/seconds,...  (names: see DEFAULT_RATES)
 *   SIMON_RATE_EXEMPT_NETWORKS    networks the per-client rates (request, register, codeClient, agentMiss) do not
 *                                count, CIDR, comma separated (/8 or narrower): a hosting service's own, acting for
 *                                many agents
 *   SIMON_KEY_CHANGE_HOLD         seconds to hold a domain whose server keys changed (default 3600)
 *   SIMON_RECOVERY_WAIT           seconds a code recovery waits while the agent holds a valid key (default 259200)
 *   SIMON_MAX_CONNECTIONS         connections served at once (default 1024)
 *   SIMON_RETENTION_DAYS          how long messages are kept (default 30, at least 7)
 *   SIMON_SYNC_DAYS               how long sync shows what entered an agent's stream (default 7, at most the retention)
 *   SIMON_DEV_RESOLVE             development only: domain=origin,... answered without DNS
 *   SIMON_TRUSTED_NETWORKS        private networks outbound calls may reach, CIDR, comma separated (/8 or narrower)
 *   SIMON_TLS_CERT_FILE           serve https with this PEM certificate chain                   with ..._KEY_FILE
 *   SIMON_TLS_KEY_FILE            and this PEM private key
 *   SIMON_PUBLIC_SUFFIX_LIST      a newer copy of the Public Suffix List to judge registrable domains by
 *                                (default: the snapshot that ships with the server)
 *   SIMON_RETIRED_AGENT_DOCUMENTS private or public: whether a retired address answers its signed retired document
 *                                (public) or the same 404 as an unknown address (private, the default)
 */
import crypto, { type KeyObject } from 'node:crypto';
import { isIP } from 'node:net';
import fs from 'node:fs';
import {
  ALGORITHM_NAMES,
  fromB64url,
  envelopeBesideBytes,
  MAX_ENVELOPE_EXTRAS_BYTES,
  MINIMUM_LIMITS,
  normalizeDomain,
  privateKeyFromSeed,
  serverOrigin,
  type Limits,
} from '@agnt-sdk/simon-protocol';
import { parseNetwork, type Network } from './net/ip.ts';

/** A limit of `limit` events per `seconds`, per key. */
export interface Rate {
  limit: number;
  seconds: number;
}

/** What each rate counts, and per what. */
export const DEFAULT_RATES = {
  /** Every request, per client IP (IPv6 by /64). */
  request: { limit: 1200, seconds: 60 },
  /** New registrations, per client IP. */
  register: { limit: 20, seconds: 3600 },
  /** Codes asked for, per address. */
  code: { limit: 5, seconds: 3600 },
  /** Codes asked for, per client IP, so no one client spends the allowance of every address. */
  codeClient: { limit: 20, seconds: 3600 },
  /** Messages sent, per agent. */
  send: { limit: 600, seconds: 3600 },
  /** Distinct recipient domains written to, per agent: what spam needs most. */
  destinations: { limit: 100, seconds: 3600 },
  /** Part uploads, per agent. */
  upload: { limit: 200, seconds: 3600 },
  /** Deliveries and signals past the signature check, per carrying server, repeats included. */
  deliver: { limit: 6000, seconds: 3600 },
  /**
   * Resolutions and server documents fetched for deliveries, per client IP, counted before each is made:
   * deliver makes them on behalf of anyone, before it knows who is asking.
   */
  lookup: { limit: 300, seconds: 3600 },
  /**
   * The same lookups, made before any signature verifies, per registrable domain of the name looked up (by the
   * Public Suffix List's ICANN section), counted in the store so every process shares it (spec section 11.2).
   */
  lookupDomain: { limit: 3600, seconds: 3600 },
  /**
   * Resolutions made for a delivery or signal past the signature check, per carrying server, counted before
   * each is made: its recipients' domains, and the identifiers its claims name.
   */
  carrierLookup: { limit: 3000, seconds: 3600 },
  /** Envelope or message signatures that failed, per (client IP, claimed server), before any more work. */
  badSignature: { limit: 20, seconds: 3600 },
  /**
   * Agent documents asked for addresses with no agent here, per client IP: what probing for addresses
   * costs. Past it, the client is refused every agent document until the window ends, known address or
   * not. Verifying a message asks for an agent that wrote it, so verification seldom counts.
   */
  agentMiss: { limit: 100, seconds: 3600 },
} satisfies Record<string, Rate>;

export type RateName = keyof typeof DEFAULT_RATES;

export interface Config {
  origin: string;
  dev: boolean;
  hostedDomains: string[];
  leaseDomain: string | null;
  serverKey: KeyObject;
  nextServerKey: KeyObject | null;
  database: string;
  port: number;
  trustedClaimServers: string[];
  dohResolvers: string[];
  /** DNS servers c-ares asks instead of the system's (a tailnet's resolver, for one); empty for the system's. */
  dnsServers: string[];
  rates: Record<RateName, Rate>;
  /**
   * Networks whose clients the per-client `request`, `register`, `codeClient` and `agentMiss` rates do not count: a
   * service that registers and speaks for many agents from a few addresses. Per-agent and per-address
   * rates still apply.
   */
  rateExemptNetworks: Network[];
  keyChangeHoldSeconds: number;
  /** How long a code recovery waits when the agent still holds a valid key; 0 recovers at once. */
  recoveryWaitSeconds: number;
  /** Connections the HTTP server serves at once; more are closed as they arrive. */
  maxConnections: number;
  retentionDays: number;
  /** How long `sync` shows what entered an agent's stream, published as `syncDays` (CLIENT.md sync). */
  syncDays: number;
  /** The limits this server publishes and enforces. */
  limits: Limits;
  /**
   * Bytes of parts fetched from one carrying server per hour, counted at each attempt whatever came of it,
   * so the budget never depends on whether a recipient here admitted the message. A fetch past it waits.
   */
  fetchBytesPerHour: number;
  /**
   * This server's bound on everything in an envelope but its message, in canonical bytes (docs/REFERENCE-SERVER.md).
   * Its own limit, not a protocol rule. By default the most a spec-valid envelope can hold at its `recipients`
   * limit (`envelopeBesideBytes`), so it never refuses one.
   */
  envelopeExtrasBytes: number;
  /** Active keys one agent may hold. */
  maxAgentKeys: number;
  /** Development only: resolution answers by domain, consulted before DNS. */
  devResolve: Record<string, string>;
  /**
   * Networks outside the public internet that outbound calls may reach, such as a Tailscale tailnet's
   * 100.64.0.0/10. None by default: the SSRF guard then calls public addresses only.
   */
  trustedNetworks: Network[];
  /** A certificate chain and private key, both PEM, to serve https directly; null serves plain http. */
  tls: { cert: string; key: string } | null;
  /** The address to listen on; null for every interface. */
  listenHost: string | null;
  /** A header proxies set to the client's address; null reads none, and the connection's address is the client's. */
  clientIpHeader: string | null;
  /**
   * Networks whose connections are proxies that `clientIpHeader` is believed from, such as a load balancer's
   * subnets. This machine is always one, for a tunnel's connector.
   */
  trustedProxies: Network[];
  /** Seconds an idle keep-alive connection stays open. Behind a load balancer, longer than its idle timeout. */
  keepAliveSeconds: number;
  /** A copy of the Public Suffix List to read at startup; null for the snapshot that ships with the server. */
  publicSuffixFile: string | null;
  /**
   * Whether a retired address answers its signed retired document (`public`) or the same 404 as an unknown
   * address (`private`). Private by default; public retirement evidence is an explicit host choice.
   */
  retiredAgentDocuments: 'public' | 'private';
}

export type ConfigInput = Partial<
  Omit<Config, 'origin' | 'rates' | 'serverKey' | 'trustedNetworks' | 'trustedProxies' | 'rateExemptNetworks'>
> & {
  origin: string;
  serverKey?: KeyObject;
  rates?: Partial<Record<RateName, Rate>>;
  /** CIDR notation, each /8 or narrower. */
  trustedNetworks?: string[];
  /** CIDR notation, each /8 or narrower. */
  trustedProxies?: string[];
  /** CIDR notation, each /8 or narrower. */
  rateExemptNetworks?: string[];
};

class ConfigError extends Error {
  constructor(message: string) {
    super(`Configuration: ${message}`);
    this.name = 'ConfigError';
  }
}

export function defineConfig(input: ConfigInput): Config {
  const dev = input.dev ?? false;
  const origin = serverOrigin(input.origin, dev);
  if (!origin) throw new ConfigError(`origin ${input.origin} is not https://host[:port]${dev ? ' or http:' : ''}.`);
  const domains = (list: string[], what: string) =>
    list.map(d => normalizeDomain(d) ?? fail(`${what}: ${d} is not a domain.`));
  const origins = (list: string[], what: string) =>
    list.map(o => serverOrigin(o, dev) ?? fail(`${what}: ${o} is not a server origin.`));

  const dohResolvers = input.dohResolvers ?? [];
  if (dohResolvers.length === 1) fail('dohResolvers: confirming takes two or more resolvers.');
  for (const url of dohResolvers) if (!/^https:\/\/[^/]+\//.test(url)) fail(`dohResolvers: ${url} is not https.`);

  const dnsServers = input.dnsServers ?? [];
  for (const ip of dnsServers) if (!isIP(ip)) fail(`dnsServers: ${ip} is not an IP address.`);

  const devResolve = input.devResolve ?? {};
  if (Object.keys(devResolve).length && !dev) fail('devResolve answers resolution without DNS: development only.');
  for (const [d, o] of Object.entries(devResolve)) {
    if (normalizeDomain(d) !== d || !serverOrigin(o, true)) fail(`devResolve: ${d}=${o} is not domain=origin.`);
  }

  const rates = { ...DEFAULT_RATES, ...input.rates };
  for (const [name, r] of Object.entries(rates)) {
    if (!(name in DEFAULT_RATES)) fail(`rates: no rate is named ${name}.`);
    if (!(r.limit >= 1 && r.seconds >= 1) || !Number.isSafeInteger(r.limit) || !Number.isSafeInteger(r.seconds)) {
      fail(`rates: ${name} needs a whole count and seconds, at least 1.`);
    }
  }

  const networks = (list: string[], what: string) =>
    list.map(text => {
      const network = parseNetwork(text);
      return typeof network === 'string' ? fail(`${what}: ${network}`) : network;
    });

  const limits = { ...MINIMUM_LIMITS, ...input.limits };
  for (const [name, n] of Object.entries(limits)) {
    if (!Number.isSafeInteger(n) || n < MINIMUM_LIMITS[name as keyof Limits])
      fail(`limits: ${name} is below the minimum.`);
  }

  const config: Config = {
    origin,
    dev,
    hostedDomains: domains(input.hostedDomains ?? [], 'hostedDomains'),
    leaseDomain: input.leaseDomain ? domains([input.leaseDomain], 'leaseDomain')[0] : null,
    serverKey:
      input.serverKey ?? (dev ? crypto.generateKeyPairSync('ed25519').privateKey : fail('serverKey is required.')),
    nextServerKey: input.nextServerKey ?? null,
    database: input.database ?? 'simon.sqlite',
    port: whole(input.port ?? 8080, 'port', 0, 65535),
    trustedClaimServers: origins(input.trustedClaimServers ?? [], 'trustedClaimServers'),
    dohResolvers,
    dnsServers,
    rates,
    rateExemptNetworks: networks(input.rateExemptNetworks ?? [], 'rateExemptNetworks'),
    keyChangeHoldSeconds: whole(input.keyChangeHoldSeconds ?? 3600, 'keyChangeHoldSeconds', 0),
    recoveryWaitSeconds: whole(input.recoveryWaitSeconds ?? 72 * 3600, 'recoveryWaitSeconds', 0),
    maxConnections: whole(input.maxConnections ?? 1024, 'maxConnections', 1),
    retentionDays: whole(input.retentionDays ?? 30, 'retentionDays', 7),
    syncDays: whole(input.syncDays ?? 7, 'syncDays', 1),
    limits,
    fetchBytesPerHour: whole(input.fetchBytesPerHour ?? 256 * 1024 ** 2, 'fetchBytesPerHour', 0),
    envelopeExtrasBytes: whole(
      input.envelopeExtrasBytes ?? envelopeBesideBytes(limits.recipients),
      'envelopeExtrasBytes',
      MAX_ENVELOPE_EXTRAS_BYTES,
    ),
    maxAgentKeys: whole(input.maxAgentKeys ?? 8, 'maxAgentKeys', 1, 32),
    devResolve,
    trustedNetworks: networks(input.trustedNetworks ?? [], 'trustedNetworks'),
    tls: input.tls ?? null,
    listenHost: input.listenHost
      ? isIP(input.listenHost)
        ? input.listenHost
        : fail(`listenHost: ${input.listenHost} is not an IP address.`)
      : null,
    clientIpHeader: input.clientIpHeader
      ? /^[a-z0-9-]+$/.test(input.clientIpHeader.toLowerCase())
        ? input.clientIpHeader.toLowerCase()
        : fail(`clientIpHeader: ${input.clientIpHeader} is not a header name.`)
      : null,
    trustedProxies: networks(input.trustedProxies ?? [], 'trustedProxies'),
    keepAliveSeconds: whole(input.keepAliveSeconds ?? 5, 'keepAliveSeconds', 1),
    publicSuffixFile: input.publicSuffixFile ?? null,
    retiredAgentDocuments: retiredPolicy(input.retiredAgentDocuments ?? 'private', 'retiredAgentDocuments'),
  };
  if (config.tls && !config.origin.startsWith('https:')) fail('tls is set, so the origin is https.');
  if (config.trustedProxies.length && !config.clientIpHeader) {
    fail('trustedProxies are trusted to set clientIpHeader, so it is set too.');
  }
  if (config.syncDays > config.retentionDays) fail('syncDays is at most retentionDays: sync shows what is kept.');
  if (config.leaseDomain && config.hostedDomains.includes(config.leaseDomain)) {
    fail('leaseDomain is for leased names only; it cannot also be a hosted domain.');
  }
  return config;
}

/** The configuration the environment describes (see the table at the top of this file). */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const list = (name: string) =>
    (env[name] ?? '')
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
  const number = (name: string) => (env[name] === undefined ? undefined : Number(env[name]));
  const dev = env.SIMON_DEV === '1';
  if (env.SIMON_DEV !== undefined && env.SIMON_DEV !== '0' && !dev) fail('SIMON_DEV is 1 or 0.');
  if (!env.SIMON_ORIGIN) fail('SIMON_ORIGIN is required.');
  return defineConfig({
    origin: env.SIMON_ORIGIN!,
    dev,
    hostedDomains: list('SIMON_HOSTED_DOMAINS'),
    leaseDomain: env.SIMON_LEASE_DOMAIN || null,
    serverKey: readKey(env, 'SIMON_SERVER_KEY') ?? undefined,
    nextServerKey: readKey(env, 'SIMON_NEXT_SERVER_KEY'),
    database: env.SIMON_DB,
    port: number('SIMON_PORT'),
    trustedClaimServers: list('SIMON_TRUSTED_CLAIM_SERVERS'),
    dohResolvers: list('SIMON_DOH_RESOLVERS'),
    dnsServers: list('SIMON_DNS_SERVERS'),
    rates: Object.fromEntries(list('SIMON_RATES').map(parseRate)),
    rateExemptNetworks: list('SIMON_RATE_EXEMPT_NETWORKS'),
    keyChangeHoldSeconds: number('SIMON_KEY_CHANGE_HOLD'),
    recoveryWaitSeconds: number('SIMON_RECOVERY_WAIT'),
    maxConnections: number('SIMON_MAX_CONNECTIONS'),
    retentionDays: number('SIMON_RETENTION_DAYS'),
    syncDays: number('SIMON_SYNC_DAYS'),
    devResolve: Object.fromEntries(list('SIMON_DEV_RESOLVE').map(pair => pair.split('=', 2))),
    trustedNetworks: list('SIMON_TRUSTED_NETWORKS'),
    tls: readTls(env),
    listenHost: env.SIMON_LISTEN_HOST || null,
    clientIpHeader: env.SIMON_CLIENT_IP_HEADER || null,
    trustedProxies: list('SIMON_TRUSTED_PROXIES'),
    keepAliveSeconds: number('SIMON_KEEP_ALIVE_TIMEOUT'),
    publicSuffixFile: env.SIMON_PUBLIC_SUFFIX_LIST || null,
    retiredAgentDocuments:
      env.SIMON_RETIRED_AGENT_DOCUMENTS === undefined
        ? undefined
        : retiredPolicy(env.SIMON_RETIRED_AGENT_DOCUMENTS, 'SIMON_RETIRED_AGENT_DOCUMENTS'),
  });
}

/** The certificate chain and key from SIMON_TLS_CERT_FILE and SIMON_TLS_KEY_FILE: both, or neither. */
function readTls(env: NodeJS.ProcessEnv): Config['tls'] {
  const certFile = env.SIMON_TLS_CERT_FILE;
  const keyFile = env.SIMON_TLS_KEY_FILE;
  if (!certFile && !keyFile) return null;
  if (!certFile || !keyFile) fail('set SIMON_TLS_CERT_FILE and SIMON_TLS_KEY_FILE together.');
  const read = (file: string, name: string) => {
    try {
      return fs.readFileSync(file, 'utf8');
    } catch (e) {
      return fail(`${name}: ${(e as Error).message}`);
    }
  };
  const tls = { cert: read(certFile!, 'SIMON_TLS_CERT_FILE'), key: read(keyFile!, 'SIMON_TLS_KEY_FILE') };
  try {
    crypto.createPrivateKey(tls.key);
    new crypto.X509Certificate(tls.cert);
  } catch (e) {
    fail(`SIMON_TLS_CERT_FILE and SIMON_TLS_KEY_FILE are a PEM certificate and its key: ${(e as Error).message}`);
  }
  return tls;
}

/** `<alg>:<base64url seed>` from `NAME`, or a PKCS #8 PEM from `NAME_FILE`; never both. */
function readKey(env: NodeJS.ProcessEnv, name: string): KeyObject | null {
  const inline = env[name];
  const file = env[`${name}_FILE`];
  if (inline && file) fail(`set ${name} or ${name}_FILE, not both.`);
  if (file) {
    try {
      return crypto.createPrivateKey(fs.readFileSync(file, 'utf8'));
    } catch (e) {
      return fail(`${name}_FILE: ${(e as Error).message}`);
    }
  }
  if (!inline) return null;
  const m = /^([a-z0-9-]+):(.+)$/.exec(inline);
  const seed = m && fromB64url(m[2]);
  if (!m || !ALGORITHM_NAMES.includes(m[1]) || seed?.length !== 32) {
    fail(`${name} is <alg>:<base64url of a 32-byte seed>, the alg one of ${ALGORITHM_NAMES.join(', ')}.`);
  }
  return privateKeyFromSeed(m![1], seed!);
}

function parseRate(entry: string): [string, Rate] {
  const m = /^([a-zA-Z]+)=(\d+)\/(\d+)$/.exec(entry);
  if (!m) fail(`SIMON_RATES: ${entry} is not name=count/seconds.`);
  return [m![1], { limit: Number(m![2]), seconds: Number(m![3]) }];
}

function retiredPolicy(value: unknown, name: string): 'public' | 'private' {
  if (value !== 'public' && value !== 'private') fail(`${name} is private or public.`);
  return value as 'public' | 'private';
}

function whole(n: number, name: string, min: number, max = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(n) || n < min || n > max) fail(`${name} must be a whole number from ${min} to ${max}.`);
  return n;
}

function fail(message: string): never {
  throw new ConfigError(message);
}
