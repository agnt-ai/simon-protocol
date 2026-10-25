/**
 * The application is built only through the basic server's extension points: it imports the server's
 * package and the MongoDB store's, through their published entry points, never a file inside either; and
 * nothing outside app/ imports it.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';

const ROOT = path.resolve(import.meta.dirname, '../..');

function sources(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => {
    const p = path.join(dir, e.name);
    return e.isDirectory() ? (e.name === 'node_modules' ? [] : sources(p)) : p.endsWith('.ts') ? [p] : [];
  });
}

const imports = (file: string) =>
  [...fs.readFileSync(file, 'utf8').matchAll(/^(?:import|export)[^'"]*from '([^']+)'/gm)].map(m => m[1]);

describe('boundaries', () => {
  it('reaches the server and its store only through their packages and published entry points', () => {
    const allowed = new Set([
      '@agnt-sdk/simon-server',
      '@agnt-sdk/simon-server/contract',
      '@agnt-sdk/simon-server/testing',
      '@agnt-sdk/simon-store-mongo',
      '@agnt-sdk/simon-store-mongo/testing',
    ]);
    for (const file of sources(path.join(ROOT, 'app'))) {
      for (const spec of imports(file)) {
        if (/^@agnt-sdk\/simon-(server|store-mongo)/.test(spec)) assert.ok(allowed.has(spec), `${file}: ${spec}`);
        assert.ok(!/(^|\/)(server|store-mongo)\/src\//.test(spec), `${file}: ${spec}`);
        // Relative imports stay in the application, but for the published grading rubric in skill/.
        const target = path.resolve(path.dirname(file), spec);
        if (spec.startsWith('.'))
          assert.ok(
            ['app', 'skill'].some(d => target.startsWith(path.join(ROOT, d))),
            `${file}: ${spec}`,
          );
      }
    }
  });

  it('is imported by nothing outside app/', () => {
    for (const dir of ['protocol', 'server', 'store-mongo', 'clients', 'conformance', 'examples']) {
      for (const file of sources(path.join(ROOT, dir))) {
        for (const spec of imports(file))
          assert.ok(!spec.includes('protocol-app') && !spec.includes('/app/'), `${file}: ${spec}`);
      }
    }
  });
});
