/**
 * Configuration: every invalid value throws at startup.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { generateKey, keyToken, privateKeyFromSeed } from '@agnt-sdk/simon-protocol';
import { loadConfig } from '../src/config.ts';

const seed = Buffer.alloc(32, 7).toString('base64url');
const base = { SIMON_ORIGIN: 'https://simon.example.com', SIMON_SERVER_KEY: `ed25519:${seed}` };

describe('configuration', () => {
  it('reads every variable', () => {
    const c = loadConfig({
      ...base,
      SIMON_HOSTED_DOMAINS: 'Example.com, agents.example.com',
      SIMON_LEASE_DOMAIN: 'lease.example.com',
      SIMON_DB: ':memory:',
      SIMON_PORT: '9000',
      SIMON_TRUSTED_CLAIM_SERVERS: 'https://simon.partner.example',
      SIMON_DOH_RESOLVERS: 'https://dns.google/resolve,https://cloudflare-dns.com/dns-query',
      SIMON_RATES: 'send=10/60,destinations=5/3600',
      SIMON_KEY_CHANGE_HOLD: '600',
      SIMON_RETENTION_DAYS: '14',
      SIMON_SYNC_DAYS: '10',
    });
    assert.deepEqual(c.hostedDomains, ['example.com', 'agents.example.com']);
    assert.equal(c.leaseDomain, 'lease.example.com');
    assert.equal(keyToken(c.serverKey), keyToken(privateKeyFromSeed('ed25519', Buffer.alloc(32, 7))));
    assert.deepEqual([c.port, c.keyChangeHoldSeconds, c.retentionDays, c.syncDays], [9000, 600, 14, 10]);
    assert.deepEqual(c.rates.send, { limit: 10, seconds: 60 });
    assert.deepEqual(c.trustedNetworks, [], 'no private network is trusted by default');
    assert.equal(c.tls, null);
    assert.equal(c.rates.deliver.limit, 6000, 'rates not named keep their defaults');
  });

  it('keeps retired agent documents private unless SIMON_RETIRED_AGENT_DOCUMENTS=public', () => {
    assert.equal(loadConfig(base).retiredAgentDocuments, 'private');
    assert.equal(loadConfig({ ...base, SIMON_RETIRED_AGENT_DOCUMENTS: 'private' }).retiredAgentDocuments, 'private');
    assert.equal(loadConfig({ ...base, SIMON_RETIRED_AGENT_DOCUMENTS: 'public' }).retiredAgentDocuments, 'public');
    for (const value of ['', 'PUBLIC', 'Private', 'hidden', '1', ' public'])
      assert.throws(() => loadConfig({ ...base, SIMON_RETIRED_AGENT_DOCUMENTS: value }), {
        name: 'ConfigError',
        message: /SIMON_RETIRED_AGENT_DOCUMENTS is private or public/,
      });
  });

  it('reads trusted networks', () => {
    const c = loadConfig({ ...base, SIMON_TRUSTED_NETWORKS: '100.64.0.0/10, fd7a:115c:a1e0::/48' });
    assert.deepEqual(
      c.trustedNetworks.map(n => n.cidr),
      ['100.64.0.0/10', 'fd7a:115c:a1e0:0:0:0:0:0/48'],
    );
  });

  it('reads the key from a PEM file, and the next key beside it', () => {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'simon-')), 'key.pem');
    const key = generateKey();
    fs.writeFileSync(file, key.privateKeyPem);
    const c = loadConfig({
      SIMON_ORIGIN: base.SIMON_ORIGIN,
      SIMON_SERVER_KEY_FILE: file,
      SIMON_NEXT_SERVER_KEY: base.SIMON_SERVER_KEY,
    });
    assert.equal(keyToken(c.serverKey), key.key);
    assert.ok(c.nextServerKey);
  });

  it('throws on any invalid value', () => {
    const bad: Record<string, string | undefined>[] = [
      { SIMON_ORIGIN: undefined },
      { SIMON_ORIGIN: 'http://simon.example.com' },
      { SIMON_ORIGIN: 'https://simon.example.com/path' },
      { SIMON_SERVER_KEY: undefined },
      { SIMON_SERVER_KEY: 'ed25519:short' },
      { SIMON_SERVER_KEY: `rsa:${seed}` },
      { SIMON_HOSTED_DOMAINS: 'not a domain' },
      { SIMON_LEASE_DOMAIN: 'example.com', SIMON_HOSTED_DOMAINS: 'example.com' },
      { SIMON_PORT: '70000' },
      { SIMON_DOH_RESOLVERS: 'https://dns.google/resolve' },
      { SIMON_DOH_RESOLVERS: 'http://a.example/,http://b.example/' },
      { SIMON_RATES: 'send=10' },
      { SIMON_RATES: 'nonsense=1/1' },
      { SIMON_RETENTION_DAYS: '3' },
      { SIMON_SYNC_DAYS: '0' },
      { SIMON_SYNC_DAYS: '31' },
      { SIMON_DEV: 'yes' },
      { SIMON_DEV_RESOLVE: 'peer.test=http://127.0.0.1:9999' },
      { SIMON_TRUSTED_NETWORKS: '0.0.0.0/0' },
      { SIMON_TRUSTED_NETWORKS: '::/0' },
      { SIMON_TRUSTED_NETWORKS: '100.64.0.0/10,96.0.0.0/4' },
      { SIMON_TRUSTED_NETWORKS: '100.64.0.0' },
      { SIMON_TLS_CERT_FILE: '/nonexistent/cert.pem' },
      { SIMON_TLS_KEY_FILE: '/nonexistent/key.pem' },
      { SIMON_TLS_CERT_FILE: '/nonexistent/cert.pem', SIMON_TLS_KEY_FILE: '/nonexistent/key.pem' },
    ];
    for (const env of bad) assert.throws(() => loadConfig({ ...base, ...env }), /Configuration/, JSON.stringify(env));
  });

  it('allows http, local hosts, a throwaway key and resolution overrides in development only', () => {
    const c = loadConfig({
      SIMON_DEV: '1',
      SIMON_ORIGIN: 'http://localhost:8080',
      SIMON_DEV_RESOLVE: 'peer.test=http://127.0.0.1:9999, other.test=http://localhost:9998',
    });
    assert.equal(c.origin, 'http://localhost:8080');
    assert.deepEqual(c.devResolve, { 'peer.test': 'http://127.0.0.1:9999', 'other.test': 'http://localhost:9998' });
    assert.ok(c.serverKey);
  });

  it('asks named DNS servers only when each is an IP address', () => {
    assert.deepEqual(loadConfig({ ...base, SIMON_DNS_SERVERS: '100.100.100.100' }).dnsServers, ['100.100.100.100']);
    assert.deepEqual(loadConfig(base).dnsServers, []);
    assert.throws(
      () => loadConfig({ ...base, SIMON_DNS_SERVERS: 'dns.example' }),
      /dnsServers: dns\.example is not an IP address/,
    );
  });
});
