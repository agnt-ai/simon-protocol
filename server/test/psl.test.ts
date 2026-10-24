/** Registrable domains by the Public Suffix List's ICANN section (PROTOCOL.md section 11.2). */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateKey } from '@agnt-sdk/simon-protocol';
import { defineConfig } from '../src/config.ts';
import { createServer } from '../src/server.ts';
import { SqliteStore } from '../src/store/sqlite.ts';
import { PUBLIC_SUFFIX_RULES } from '../src/net/public-suffixes.ts';
import { loadPublicSuffixes, parsePublicSuffixes, registrableDomain, shippedPublicSuffixes } from '../src/net/psl.ts';

describe('registrable domains', () => {
  it('are one label below the public suffix, by the shipped snapshot', () => {
    for (const [domain, registrable] of [
      ['a.b.example.com', 'example.com'],
      ['example.com', 'example.com'],
      ['x.example.co.uk', 'example.co.uk'],
      ['co.uk', 'co.uk'],
      ['foo.bar.ck', 'foo.bar.ck'], // *.ck: every second-level name under ck is a suffix
      ['a.www.ck', 'www.ck'], // !www.ck: the exception
      ['a.b.c.kobe.jp', 'b.c.kobe.jp'],
      ['a.city.kobe.jp', 'city.kobe.jp'],
      ['agents.xn--fiqs8s', 'agents.xn--fiqs8s'], // an internationalised suffix, as A-labels
      ['x.github.io', 'github.io'], // the private section is not read: a host's subdomains share its bound
      ['a.b.unlisted', 'b.unlisted'],
      ['EXAMPLE.COM', 'example.com'],
      ['a.b.0.bg', 'b.0.bg'], // an all-digit label stays one label: 0.bg is a suffix
      ['a.b.7.bg', 'b.7.bg'],
    ]) {
      assert.equal(registrableDomain(domain), registrable, domain);
    }
    assert.ok(shippedPublicSuffixes().rules.size > 6000);
    assert.ok(shippedPublicSuffixes().rules.has('0.bg'));
    assert.ok(![...shippedPublicSuffixes().rules].some(r => r.includes('0.0.0')), 'no label read as an IPv4 address');
  });

  it('reads the ICANN section of a newer copy of the list, its Unicode labels as A-labels', () => {
    const list = parsePublicSuffixes(
      [
        '// ===BEGIN ICANN DOMAINS===',
        'example',
        '*.wild.example',
        '!keep.wild.example',
        '公司.cn',
        '// ===END ICANN DOMAINS===',
        '// ===BEGIN PRIVATE DOMAINS===',
        'host.example',
        '// ===END PRIVATE DOMAINS===',
      ].join('\n'),
    );
    assert.equal(registrableDomain('a.b.example', list), 'b.example');
    assert.equal(registrableDomain('a.b.wild.example', list), 'a.b.wild.example');
    assert.equal(registrableDomain('a.keep.wild.example', list), 'keep.wild.example');
    assert.equal(registrableDomain('a.b.xn--55qx5d.cn', list), 'b.xn--55qx5d.cn');
    assert.equal(registrableDomain('a.b.host.example', list), 'host.example', 'the private section is left out');
    assert.deepEqual(
      [...list.rules].sort(),
      ['*.wild.example', 'example', 'xn--55qx5d.cn'],
      'no marker read as a rule',
    );
    assert.ok(![...shippedPublicSuffixes().rules].some(r => r.includes('=')), 'nor in the shipped snapshot');
  });

  it('refuses a copy of the list without its ICANN section, or too short to be whole, so the server does not start', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'simon-psl-'));
    const write = (name: string, text: string) => (fs.writeFileSync(path.join(dir, name), text), path.join(dir, name));
    const whole = [
      '// ===BEGIN ICANN DOMAINS===',
      PUBLIC_SUFFIX_RULES,
      '// ===END ICANN DOMAINS===',
      '// ===BEGIN PRIVATE DOMAINS===',
      'github.io',
      '// ===END PRIVATE DOMAINS===',
    ].join('\n');
    try {
      assert.ok(loadPublicSuffixes(write('whole.dat', whole)).rules.has('co.uk'));
      for (const [name, text] of [
        ['empty.dat', ''],
        ['page.html', '<html><body>Service unavailable</body></html>'],
        ['unmarked.dat', PUBLIC_SUFFIX_RULES + '\ngithub.io\n'],
        ['short.dat', '// ===BEGIN ICANN DOMAINS===\ncom\nuk\n// ===END ICANN DOMAINS==='],
      ]) {
        const file = write(name, text);
        assert.throws(() => loadPublicSuffixes(file), /Public Suffix List|ICANN rules/, name);
        const config = defineConfig({
          origin: 'https://simon.x.test',
          serverKey: generateKey().privateKey,
          publicSuffixFile: file,
        });
        assert.throws(() => createServer({ config, store: new SqliteStore(), worker: false }), name);
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
