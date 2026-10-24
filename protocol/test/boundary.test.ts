/**
 * What each project may import (docs/ARCHITECTURE.md, "What may import what"). The protocol imports only
 * Node; the basic server, the conformance suite and the JavaScript client import only Node and the
 * protocol; the CLI and the MCP server add the client. A relative import stays inside its own project,
 * except that the CLI's and the MCP server's tests share the client's test server. The application has a
 * boundary test of its own (app/test/boundary.test.ts), and nothing here may import it.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';

const ROOT = path.resolve(import.meta.dirname, '../..');

/** What the CLI and the MCP server import: the protocol, and the client with any of its subpaths. */
const CLIENT_USERS = ['@agnt-protocol/protocol', '@agnt-protocol/client', '@agnt-protocol/client/*'];

/** Each project, and the packages beyond Node's own (`node:`) that its files may import; `/*` admits subpaths. */
const ALLOWED: Record<string, string[]> = {
  protocol: [],
  server: ['@agnt-protocol/protocol'],
  conformance: ['@agnt-protocol/protocol'],
  'clients/js': ['@agnt-protocol/protocol'],
  'clients/cli': CLIENT_USERS,
  'clients/mcp': CLIENT_USERS,
};

/** Relative imports that leave their project on purpose. */
const SHARED = ['clients/js/test/fake-server.ts'];

function sources(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => {
    const p = path.join(dir, e.name);
    return e.isDirectory() ? (e.name === 'node_modules' ? [] : sources(p)) : p.endsWith('.ts') ? [p] : [];
  });
}

const imports = (file: string) =>
  [...fs.readFileSync(file, 'utf8').matchAll(/^(?:import|export)[^'"]*from '([^']+)'/gm)].map(m => m[1]);

describe('boundaries between the projects', () => {
  for (const [project, allowed] of Object.entries(ALLOWED)) {
    it(`${project} imports Node${allowed.length ? `, ${allowed.join(', ')}` : ''} and itself only`, () => {
      const files = sources(path.join(ROOT, project));
      assert.ok(files.length > 0, `${project} has sources`);
      for (const file of files) {
        for (const spec of imports(file)) {
          const where = `${path.relative(ROOT, file)}: ${spec}`;
          if (spec.startsWith('node:')) continue;
          if (!spec.startsWith('.')) {
            assert.ok(
              allowed.some(a => a === spec || (a.endsWith('/*') && spec.startsWith(a.slice(0, -1)))),
              where,
            );
            continue;
          }
          const target = path.relative(ROOT, path.resolve(path.dirname(file), spec));
          assert.ok(target.startsWith(`${project}/`) || SHARED.includes(target), where);
        }
      }
    });
  }
});
