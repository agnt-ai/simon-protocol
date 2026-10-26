#!/usr/bin/env node
/**
 * The six npm packages, the protocol library, the reference server, its MongoDB store, the JavaScript
 * client, the CLI and the MCP server, as tarballs for Node 24, which cannot run TypeScript from
 * node_modules: `node scripts/pack.ts [out-dir]` compiles each to JavaScript with type declarations and
 * packs it into out-dir (packed/ by default). The sources stay the source of truth: nothing compiled is
 * committed. Each build is its own version,
 * `<version>-g<commit>`, so a cache never serves one build for another, and each package depends on the
 * others of the same build; a dependency from npm (the store's peer `mongodb`) keeps its range, and
 * development dependencies are dropped. The tree must be committed first.
 *
 * `--release` packs a release instead: the versions in the package.json files, which must all be the same,
 * with dependencies on exactly that version. The publish workflow publishes these tarballs, in this order.
 *
 *   npm install ./packed/agnt-sdk-simon-protocol-0.2.0-g<commit>.tgz ./packed/agnt-sdk-simon-client-0.2.0-g<commit>.tgz
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** The oldest Node the packages run on: node:crypto has ML-DSA-65 keys from 24.6.0. */
const NODE = '>=24.6.0';
const ROOT = path.resolve(import.meta.dirname, '..');
/** In dependency order: each is packed after the packages it depends on. */
const PACKAGES = ['protocol', 'server', 'store-mongo', 'clients/js', 'clients/cli', 'clients/mcp'];
const TSC = path.join(ROOT, 'node_modules/typescript/bin/tsc');

const run = (cmd: string, args: string[], cwd = ROOT) => execFileSync(cmd, args, { cwd, encoding: 'utf8' }).trim();

if (run('git', ['status', '--porcelain', '--', ...PACKAGES])) {
  console.error(`pack: ${PACKAGES.join(', ')} must have no uncommitted changes; a package is the build of a commit.`);
  process.exit(1);
}
const commit = run('git', ['rev-parse', 'HEAD']);
const args = process.argv.slice(2);
const release = args.includes('--release');
const out = path.resolve(args.find(a => !a.startsWith('--')) ?? path.join(ROOT, 'packed'));
const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'simon-pack-'));
fs.mkdirSync(out, { recursive: true });

/** An export of the sources, `./src/<name>.ts`, as its compiled files. */
function compiled(file: string) {
  const m = /^\.\/src\/(.+)\.ts$/.exec(file);
  if (!m) throw new Error(`pack: the export ${file} is not a source file.`);
  return { types: `./dist/${m[1]}.d.ts`, default: `./dist/${m[1]}.js` };
}

/** A bin of the sources, `./src/<name>.ts`, as its compiled file. */
function compiledBin(file: string) {
  return compiled(file).default;
}

const manifests = PACKAGES.map(dir => JSON.parse(fs.readFileSync(path.join(ROOT, dir, 'package.json'), 'utf8')));
const ours = new Set<string>(manifests.map(p => p.name));
const versions = new Set(manifests.map(p => p.version));
if (release && versions.size !== 1) fail(`a release has one version; the packages have ${[...versions].join(', ')}.`);

try {
  const builds = new Map<string, string>();
  for (const dir of PACKAGES) {
    const source = path.join(ROOT, dir);
    const target = path.join(stage, dir);
    run(process.execPath, [TSC, '-p', path.join(source, 'tsconfig.build.json'), '--outDir', path.join(target, 'dist')]);
    const {
      scripts: _,
      devDependencies: __,
      ...pkg
    } = JSON.parse(fs.readFileSync(path.join(source, 'package.json'), 'utf8'));
    const version = release ? pkg.version : `${pkg.version}-g${commit.slice(0, 12)}`;
    builds.set(pkg.name, version);
    const dependencies = pkg.dependencies && {
      dependencies: Object.fromEntries(
        Object.entries(pkg.dependencies as Record<string, string>).map(([name, range]) => [
          name,
          ours.has(name) ? (builds.get(name) ?? fail(`${name} is not packed first.`)) : range,
        ]),
      ),
    };
    const packed = {
      ...pkg,
      version,
      ...(pkg.exports && {
        exports: Object.fromEntries(
          Object.entries(pkg.exports as Record<string, string>).map(([k, f]) => [k, compiled(f)]),
        ),
      }),
      ...(pkg.bin && {
        bin: Object.fromEntries(Object.entries(pkg.bin as Record<string, string>).map(([k, f]) => [k, compiledBin(f)])),
      }),
      engines: { node: NODE },
      ...dependencies,
      files: ['dist', 'README.md', 'LICENSE', 'NOTICE'],
      gitHead: commit,
    };
    fs.writeFileSync(path.join(target, 'package.json'), `${JSON.stringify(packed, null, 2)}\n`);
    for (const file of ['LICENSE', 'NOTICE']) fs.copyFileSync(path.join(ROOT, file), path.join(target, file));
    const readme = path.join(source, 'README.md');
    if (fs.existsSync(readme)) fs.copyFileSync(readme, path.join(target, 'README.md'));
    console.log(path.join(out, run('npm', ['pack', '--silent', '--pack-destination', out], target)));
  }
} finally {
  fs.rmSync(stage, { recursive: true, force: true });
}

function fail(message: string): never {
  throw new Error(`pack: ${message}`);
}
