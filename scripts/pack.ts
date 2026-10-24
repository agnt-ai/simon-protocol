#!/usr/bin/env node
/**
 * The protocol library and the JavaScript client as npm tarballs for Node 24, which cannot run TypeScript
 * from node_modules: `node scripts/pack.ts [out-dir]` compiles protocol/ and clients/js/ to JavaScript with
 * type declarations and packs each into out-dir (packed/ by default). The sources stay the source of
 * truth: nothing compiled is committed. Each build is its own version, `<version>-g<commit>`, so a cache
 * never serves one build for another, and the client depends on the protocol package of the same build.
 * The tree must be committed first.
 *
 *   npm install ./packed/agnt-protocol-protocol-0.1.0-g<commit>.tgz ./packed/agnt-protocol-client-0.1.0-g<commit>.tgz
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** The oldest Node the packages run on: node:crypto has ML-DSA-65 keys from 24.6.0. */
const NODE = '>=24.6.0';
const ROOT = path.resolve(import.meta.dirname, '..');
const PACKAGES = ['protocol', 'clients/js'];
const TSC = path.join(ROOT, 'node_modules/typescript/bin/tsc');

const run = (cmd: string, args: string[], cwd = ROOT) => execFileSync(cmd, args, { cwd, encoding: 'utf8' }).trim();

if (run('git', ['status', '--porcelain', '--', ...PACKAGES])) {
  console.error('pack: protocol/ or clients/js/ has uncommitted changes; a package is the build of a commit.');
  process.exit(1);
}
const commit = run('git', ['rev-parse', 'HEAD']);
const out = path.resolve(process.argv[2] ?? path.join(ROOT, 'packed'));
const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'simon-pack-'));
fs.mkdirSync(out, { recursive: true });

/** An export of the sources, `./src/<name>.ts`, as its compiled files. */
function compiled(file: string) {
  const m = /^\.\/src\/(.+)\.ts$/.exec(file);
  if (!m) throw new Error(`pack: the export ${file} is not a source file.`);
  return { types: `./dist/${m[1]}.d.ts`, default: `./dist/${m[1]}.js` };
}

try {
  const builds = new Map<string, string>();
  for (const dir of PACKAGES) {
    const source = path.join(ROOT, dir);
    const target = path.join(stage, dir);
    run(process.execPath, [TSC, '-p', path.join(source, 'tsconfig.build.json'), '--outDir', path.join(target, 'dist')]);
    const { scripts: _, ...pkg } = JSON.parse(fs.readFileSync(path.join(source, 'package.json'), 'utf8'));
    const version = `${pkg.version}-g${commit.slice(0, 12)}`;
    builds.set(pkg.name, version);
    const dependencies = pkg.dependencies && {
      dependencies: Object.fromEntries(
        Object.keys(pkg.dependencies).map(name => [name, builds.get(name) ?? fail(`${name} is not packed first.`)]),
      ),
    };
    const packed = {
      ...pkg,
      version,
      exports: Object.fromEntries(
        Object.entries(pkg.exports as Record<string, string>).map(([k, f]) => [k, compiled(f)]),
      ),
      engines: { node: NODE },
      ...dependencies,
      files: ['dist', 'NOTICE'],
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
