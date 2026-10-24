/**
 * The protocol's and the JavaScript client's own suites, run against their packed builds: an import that
 * resolves into protocol/src or clients/js/src resolves instead to the compiled file of the package
 * installed under AGNT_BUILT, a directory whose node_modules holds both. scripts/test-built.sh runs:
 *
 *   AGNT_BUILT=<dir> NODE_OPTIONS=--import=<this file> node --test 'protocol/test/**' 'clients/js/test/**'
 *
 * NODE_OPTIONS, not --import, so that a test's own child processes resolve the builds too.
 */
import fs from 'node:fs';
import { registerHooks } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

if (!process.env.AGNT_BUILT) throw new Error('AGNT_BUILT names the directory the packed packages are installed in.');
const root = pathToFileURL(path.resolve(import.meta.dirname, '..')).href;
// The real path, as Node resolves installed packages: one module, never two copies under two paths.
const installed = pathToFileURL(fs.realpathSync(path.resolve(process.env.AGNT_BUILT, 'node_modules'))).href;
const BUILDS: [string, string][] = [
  [`${root}/protocol/src/`, `${installed}/@agnt-protocol/protocol/dist/`],
  [`${root}/clients/js/src/`, `${installed}/@agnt-protocol/client/dist/`],
];

registerHooks({
  resolve(specifier, context, next) {
    const resolved = next(specifier, context);
    const build = BUILDS.find(([source]) => resolved.url.startsWith(source));
    if (!build) return resolved;
    const file = resolved.url.slice(build[0].length).replace(/\.ts$/, '.js');
    return { ...resolved, url: build[1] + file, format: 'module' };
  },
});
