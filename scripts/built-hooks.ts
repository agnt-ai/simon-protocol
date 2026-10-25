/**
 * The packages' own suites, run against their packed builds: an import that resolves into protocol/src,
 * server/src, store-mongo/src, clients/js/src, clients/cli/src or clients/mcp/src resolves instead to the
 * compiled file of the package installed under SIMON_BUILT, a directory whose node_modules holds all six.
 * The MongoDB driver resolves to the copy installed there too, the one the store's build uses, so an error
 * a test makes is the class the store recognises. scripts/test-built.sh runs:
 *
 *   SIMON_BUILT=<dir> NODE_OPTIONS=--import=<this file> node --test 'protocol/test/**' 'clients/js/test/**' ...
 *
 * NODE_OPTIONS, not --import, so that a test's own child processes resolve the builds too.
 */
import fs from 'node:fs';
import { registerHooks } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

if (!process.env.SIMON_BUILT) throw new Error('SIMON_BUILT names the directory the packed packages are installed in.');
const root = pathToFileURL(path.resolve(import.meta.dirname, '..')).href;
// The real path, as Node resolves installed packages: one module, never two copies under two paths.
const installed = pathToFileURL(fs.realpathSync(path.resolve(process.env.SIMON_BUILT, 'node_modules'))).href;
const BUILDS: [string, string][] = [
  [`${root}/protocol/src/`, `${installed}/@agnt-sdk/simon-protocol/dist/`],
  [`${root}/server/src/`, `${installed}/@agnt-sdk/simon-server/dist/`],
  [`${root}/store-mongo/src/`, `${installed}/@agnt-sdk/simon-store-mongo/dist/`],
  [`${root}/clients/js/src/`, `${installed}/@agnt-sdk/simon-client/dist/`],
  [`${root}/clients/cli/src/`, `${installed}/@agnt-sdk/simon-cli/dist/`],
  [`${root}/clients/mcp/src/`, `${installed}/@agnt-sdk/simon-mcp/dist/`],
];
/** Packages from npm the builds and the suites must share: one copy, the installed one. */
const SHARED: [string, string][] = ['mongodb'].map(name => [`${root}/node_modules/${name}/`, `${installed}/${name}/`]);

registerHooks({
  resolve(specifier, context, next) {
    const resolved = next(specifier, context);
    const shared = SHARED.find(([source]) => resolved.url.startsWith(source));
    if (shared) return { ...resolved, url: shared[1] + resolved.url.slice(shared[0].length) };
    const build = BUILDS.find(([source]) => resolved.url.startsWith(source));
    if (!build) return resolved;
    const file = resolved.url.slice(build[0].length).replace(/\.ts$/, '.js');
    return { ...resolved, url: build[1] + file, format: 'module' };
  },
});
