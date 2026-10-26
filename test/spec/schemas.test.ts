/**
 * The JSON schemas (spec/schemas) against the published vectors: every wire object a vector accepts is valid
 * under its schema, and every one a vector refuses for a rule a schema can state is invalid under it. The
 * schemas are documentation for implementers; this keeps them from drifting from the code that makes the
 * vectors. Rules a schema cannot state (spec/schemas/README.md) are named below, each with its reason.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { Ajv2020 } from 'ajv/dist/2020.js';

const root = path.resolve(import.meta.dirname, '../..');
const vectors = JSON.parse(fs.readFileSync(path.join(root, 'spec/vectors/v1.json'), 'utf8'));
const dir = path.join(root, 'spec/schemas');
const ajv = new Ajv2020({ strict: false, allErrors: true });
for (const file of fs.readdirSync(dir).filter(f => f.endsWith('.json')))
  ajv.addSchema(JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8')));

function validator(id: string) {
  const validate = ajv.getSchema(id);
  assert.ok(validate, id);
  return (value: unknown) => validate(value) === true;
}
const message = validator('message.json');
const envelope = validator('envelope.json');
const signal = validator('signal.json');
const serverDocument = validator('server-document.json');
const agentDocument = validator('agent-document.json');
const published = validator('published.json');
const problem = validator('problem.json');

/** JSON this protocol parses, or undefined: the schemas describe values, not bytes. */
function parsed(bytes: string): unknown {
  try {
    return JSON.parse(bytes);
  } catch {
    return undefined;
  }
}

const isV1 = (m: unknown) => typeof m === 'object' && m !== null && (m as { v?: unknown }).v === 1;

/**
 * Refusals a schema cannot state (spec/schemas/README.md): sizes in bytes and the limits, canonical form and
 * canonical base64, a real calendar date, signatures, the receiving server's own context (its origin, the
 * domains it serves, its clock), and the hints' match with `to`. Each is named, so a new refused vector
 * either fails its schema or is added here with its reason.
 */
const BEYOND_A_SCHEMA = new Set([
  // Messages.
  'files adding up to one byte over 32 times partBytes',
  '262145 bytes',
  '101 recipients',
  '30 February',
  'a part one byte over partBytes',
  'base64 with non-zero trailing bits',
  'noncanonical nested base64 is refused',
  'a signature with non-zero trailing bits',
  'not in canonical form (the refusal carries the canonical form)',
  // Envelopes.
  'a hint for an address in to but not in recipients',
  'a hint for an address not in to',
  'claims and hints of 16385 canonical bytes',
  'a message not in canonical form',
  'not JSON this protocol parses (a repeated member)',
  'for another server (step 5)',
  'a recipient not in to (step 5)',
  'claims whose claimsSignature is over other claims (step 7)',
  'a recipient on a domain this server does not serve (step 8, after the signature)',
  // Signals.
  'for another server',
  'of 4097 bytes without its signature',
  'a body of 16385 bytes',
  "signed by a key that is not the server's",
  'changed after signing',
  'a recipient on a domain this server does not serve',
  'sent 301 s ago',
  'sent 301 s ahead',
]);

/** A message carried inline is base64 to the schema: what is inside it is the library's to check. */
const carriedInterior = (c: { name: string; field?: string }) =>
  c.field === 'parts' && /carried|carrier|deep/.test(c.name);

describe('the JSON schemas against the vectors', () => {
  it('every version 1 message the vectors sign is valid under message.json', () => {
    let n = 0;
    for (const c of vectors.messages.cases) {
      if (!isV1(c.message)) continue;
      assert.ok(message(c.message), c.name);
      n++;
    }
    assert.ok(n > 5);
  });

  it('every version 1 message the checks accept is valid, and every one refused for a rule a schema states is not', () => {
    const passing: string[] = [];
    for (const c of vectors.messageChecks.cases) {
      const m = parsed(c.bytes);
      if (!isV1(m)) continue;
      if (c.accepted) assert.ok(message(m), `accepted: ${c.name}`);
      else if (message(m) && !BEYOND_A_SCHEMA.has(c.name) && !carriedInterior(c)) passing.push(c.name);
    }
    assert.deepEqual(passing, [], 'refused by the vectors, but valid under message.json');
  });

  it('the placement rules: a message to no one needs an audience, and a misplaced rel or feed is valid', () => {
    const base = vectors.messages.cases.find((c: { message: { v: number } }) => isV1(c.message)).message;
    const at = (to: string[], headers: Record<string, string>) => ({ ...base, to, headers });
    assert.equal(message(at([], {})), false, 'to no one, no audience');
    assert.equal(message(at([], { audience: 'public' })), true);
    assert.equal(message(at(['bob@example.net'], { audience: 'public' })), false, 'an audience with recipients');
    assert.equal(message(at(['bob@example.net'], { feed: 'updates' })), true, 'a feed with recipients is ignored');
    assert.equal(message({ ...at(['bob@example.net'], { rel: 'reaction' }), inReplyTo: null }), true, 'rel, no target');
  });

  it('every accepted envelope and signal is valid under its schema, and every refused one invalid unless named', () => {
    for (const c of vectors.envelopes.accepted) assert.ok(envelope(parsed(c.bytes)), c.name);
    for (const c of vectors.signals.accepted) assert.ok(signal(parsed(c.bytes)), c.name);
    const passing = [
      ...vectors.envelopes.refused.filter((c: { bytes: string }) => envelope(parsed(c.bytes))),
      ...vectors.signals.refused.filter((c: { bytes: string }) => signal(parsed(c.bytes))),
    ]
      .map((c: { name: string }) => c.name)
      .filter((name: string) => !BEYOND_A_SCHEMA.has(name));
    assert.deepEqual(passing, [], 'refused by the vectors, but valid under their schema');
  });

  it('every document a reader reads is valid under its schema', () => {
    for (const c of vectors.documents.server) if (c.read !== null) assert.ok(serverDocument(parsed(c.body)), c.name);
    for (const c of vectors.documents.agent) if (c.read !== null) assert.ok(agentDocument(parsed(c.body)), c.name);
  });

  it("the published answer, the feed's posts and the problems are valid under theirs", () => {
    const { post, feed } = vectors.publications;
    assert.ok(published(post.response), 'the published answer');
    assert.ok(message(post.response.message), 'its message');
    for (const m of feed.stored) assert.ok(message(m), `a stored post of ${feed.name}`);
    for (const c of vectors.problems.cases) assert.ok(problem(c.body), c.name);
  });
});
