/**
 * PROTOCOL.md Appendix B against what tests the spec: every section of the vectors and every conformance check
 * (as conformance/README.md lists them) is named in the table, so a new test cannot land without saying which
 * rule it tests. Every check id it names exists, and every vector section and member; only a pattern ending in
 * `*` may match nothing.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '../..');
const read = (file: string) => fs.readFileSync(path.join(root, file), 'utf8');
const vectors = JSON.parse(read('spec/vectors/v1.json'));
const checks = [...read('conformance/README.md').matchAll(/^\| `([A-Za-z0-9.-]+)` \|/gm)].map(m => m[1]!);

const spec = read('spec/PROTOCOL.md');
const appendix = spec.slice(spec.indexOf('## Appendix B.'));
const rows = appendix
  .split('\n')
  .filter(line => line.startsWith('| ') && !line.startsWith('| Rule |') && !line.startsWith('| ---'))
  .map(line => line.split(' | '));
/** Each vector section a row names, with the members it names in parentheses after it. */
const sections = rows.flatMap(cells =>
  [...(cells[2] ?? '').matchAll(/`([^`]+)`(?: \(([^)]*)\))?/g)].map(m => ({
    section: m[1]!,
    members: [...(m[2] ?? '').matchAll(/`([^`]+)`/g)].map(n => n[1]!),
  })),
);
const patterns = rows.flatMap(cells => [...(cells[3] ?? '').matchAll(/`([^`]+)`/g)].map(m => m[1]!));
const matches = (pattern: string, id: string) =>
  pattern.endsWith('*') ? id.startsWith(pattern.slice(0, -1)) : id === pattern;

describe('PROTOCOL.md Appendix B', () => {
  it('has a row for each rule, with four columns', () => {
    assert.ok(rows.length > 30, `${rows.length} rows`);
    for (const cells of rows) assert.equal(cells.length, 4, cells.join(' | '));
  });

  it('names every section of the vectors', () => {
    const named = new Set(sections.map(s => s.section));
    assert.deepEqual(
      Object.keys(vectors).filter(k => k !== 'about' && !named.has(k)),
      [],
    );
  });

  it('names only sections of the vectors, and members each section has', () => {
    const unknown = sections.flatMap(({ section, members }) =>
      !(section in vectors) ? [section] : members.filter(m => !(m in vectors[section])).map(m => `${section} (${m})`),
    );
    assert.deepEqual(unknown, []);
  });

  it('names every conformance check', () => {
    assert.ok(checks.length > 200, `${checks.length} checks in conformance/README.md`);
    assert.deepEqual(
      checks.filter(id => !patterns.some(p => matches(p, id))),
      [],
    );
  });

  it('names only checks that exist, except a pattern ending in *', () => {
    assert.deepEqual(
      patterns.filter(p => !p.endsWith('*') && !checks.includes(p)),
      [],
    );
  });
});
