#!/usr/bin/env node
/**
 * A release tag against the packages it publishes: `node scripts/release-version.ts vX.Y.Z` fails unless the
 * tag is a plain version and each of the six npm packages has exactly that version and depends on the
 * others at exactly that version.
 */
import fs from 'node:fs';
import path from 'node:path';

const PACKAGES = ['protocol', 'server', 'store-mongo', 'clients/js', 'clients/cli', 'clients/mcp'];
const ROOT = path.resolve(import.meta.dirname, '..');
const tag = process.argv[2] ?? '';
const m = /^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/.exec(tag);
if (!m) fail(`the tag ${JSON.stringify(tag)} is not vX.Y.Z.`);
const version = m[1];

const manifests = PACKAGES.map(dir => JSON.parse(fs.readFileSync(path.join(ROOT, dir, 'package.json'), 'utf8')));
const names = new Set(manifests.map(p => p.name));
for (const p of manifests) {
  if (p.version !== version) fail(`${p.name} is at ${p.version}, not ${version}.`);
  for (const [dep, range] of Object.entries(p.dependencies ?? {}))
    if (names.has(dep) && range !== version) fail(`${p.name} depends on ${dep}@${range}, not ${version}.`);
}
console.log(`release ${version}: ${[...names].join(', ')}`);

function fail(message: string): never {
  console.error(`release-version: ${message}`);
  process.exit(1);
}
