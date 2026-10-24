/** The API as documented: app/openapi.json is current, and every route keeps the API's rules. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { describe, it } from 'node:test';
import { documentFile, DOCUMENT } from '../scripts/write-openapi.ts';

describe('the API document', async () => {
  const committed = fs.readFileSync(DOCUMENT, 'utf8');
  const doc = JSON.parse(committed);
  const operations = Object.entries(doc.paths as Record<string, Record<string, any>>).flatMap(([path, ops]) =>
    Object.entries(ops).map(([method, op]) => ({ path, method, op })),
  );

  it('is current (npm run openapi -w app)', async () => {
    assert.equal(committed, await documentFile());
  });

  it('gives every operation a unique id, a summary and a security declaration', () => {
    const ids = operations.map(o => o.op.operationId);
    assert.equal(new Set(ids).size, ids.length);
    for (const { op } of operations) assert.ok(op.summary && Array.isArray(op.security), op.operationId);
  });

  it("keeps the API's paths: the agent's own under /api/agents/me, a person's under /api/me", () => {
    for (const { path } of operations) assert.match(path, /^\/(api\/|\.well-known\/)/, path);
    const owner = operations.filter(o => o.op.security.some((s: object) => 'ownerBearer' in s));
    for (const { path } of owner) assert.match(path, /^\/api\/me(\/|$)/, path);
    const lists = operations.filter(
      o => o.method === 'get' && o.op.parameters.some((p: { name: string }) => p.name === 'after'),
    );
    for (const { op } of lists) {
      const schema = op.responses['200'].content['application/json'].schema;
      assert.deepEqual(Object.keys(schema.properties).sort(), ['cursor', 'items', 'more'], op.operationId);
    }
  });

  it('refuses unknown members in every JSON body an agent or a person sends', () => {
    const resolve = (s: any): any => (s?.$ref ? doc.components.schemas[s.$ref.split('/').pop()] : s);
    for (const { op } of operations) {
      const body = resolve(op.requestBody?.content['application/json']?.schema);
      if (!body || op.security.length === 0 || body.type !== 'object' || !body.properties) continue;
      assert.equal(body.additionalProperties, false, op.operationId);
    }
  });
});
