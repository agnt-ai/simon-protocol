import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { readDirectoryRecord, readServerDocument, signRequest } from '@agnt-sdk/simon-protocol';
import type { Reply } from '../src/http.ts';
import { replyBody } from '../src/testing.ts';
import { Federation, toRequest, type TestAgent, type TestServer } from './harness.ts';

describe('discovery (discovery profile)', async () => {
  const fed = new Federation();
  after(() => fed.close());
  const alpha = await fed.server('alpha');
  const dir = await fed.server('dir', { config: { directory: true } });
  const beta = await fed.server('beta');
  const ada = await alpha.agent('ada');
  const bob = await beta.agent('bob');
  const cat = await beta.agent('cat');

  /** A call to `at`, signed with `signer`'s agent key, or unsigned. */
  async function call(
    at: TestServer,
    method: 'GET' | 'POST' | 'DELETE',
    target: string,
    signer: TestAgent | null,
    body?: object,
  ): Promise<{ status: number; json: any; bytes: Buffer }> {
    const url = new URL(at.origin + target);
    const bytes = body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body));
    const headers: Record<string, string> = signer
      ? signRequest(signer.key, { method, url: url.href, body: bytes, now: fed.clock.t, agent: signer.address })
      : {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    const reply: Reply = await at.server.handle(toRequest(method, url, headers, bytes, '192.0.2.7'));
    const out = replyBody(reply);
    return { status: reply.status, json: out.length ? JSON.parse(out.toString()) : null, bytes: out };
  }
  const lookup = (at: TestServer, identifier: string, signer: TestAgent | null = ada) =>
    call(at, 'GET', `/simon/lookup?identifier=${encodeURIComponent(identifier)}`, signer);
  /** List `agent` at `at` as the assistant of `identifier`, by the code sent to it. */
  async function list(at: TestServer, agent: TestAgent, identifier: string) {
    const first = await call(at, 'POST', '/simon/directory', agent, { identifier });
    assert.deepEqual([first.status, first.json], [202, { status: 'code_sent' }]);
    await fed.work();
    const note = at.mail.filter(n => n.type === 'listing').at(-1)!;
    assert.deepEqual([note.address, note.type === 'listing' && note.assistant], [identifier.slice(7), agent.address]);
    return call(at, 'POST', '/simon/directory', agent, { identifier, code: note.type === 'listing' ? note.code : '' });
  }

  it("lists an assistant for an address on a domain it serves, once the address's holder sends back the code", async () => {
    const listed = await list(alpha, bob, 'mailto:sarah@alpha.test');
    assert.equal(listed.status, 200);
    const doc = await call(alpha, 'GET', '/simon/server', null);
    const keys = readServerDocument(doc.bytes, alpha.origin, fed.clock.now())!.keys;
    const record = readDirectoryRecord(listed.json.record, 'mailto:sarah@alpha.test', keys, fed.clock.now());
    assert.deepEqual([record?.address, record?.revision, record?.issuer], [bob.address, 1, alpha.origin]);
    const found = await lookup(alpha, 'mailto:sarah@alpha.test');
    assert.deepEqual([found.status, found.json], [200, listed.json]);
  });

  it('answers every identifier it has no record for alike, and only a signed asker', async () => {
    const none = await lookup(alpha, 'mailto:nobody@alpha.test');
    const elsewhere = await lookup(alpha, 'tel:+14155550100');
    assert.equal(none.status, 404);
    assert.deepEqual(elsewhere.bytes, none.bytes, 'the same bytes');
    assert.equal((await lookup(alpha, 'mailto:sarah@alpha.test', null)).status, 401);
    assert.deepEqual([(await lookup(alpha, 'sarah@alpha.test')).status], [400]);
  });

  it('lists an address on any domain only when it keeps a directory, and never by a wrong code', async () => {
    const refused = await call(alpha, 'POST', '/simon/directory', bob, { identifier: 'mailto:sarah@webmail.example' });
    assert.deepEqual([refused.status, refused.json.details.field], [400, 'identifier']);
    const wrong = await call(dir, 'POST', '/simon/directory', bob, { identifier: 'mailto:sarah@webmail.example' });
    assert.equal(wrong.status, 202);
    const guess = await call(dir, 'POST', '/simon/directory', bob, {
      identifier: 'mailto:sarah@webmail.example',
      code: '00000000',
    });
    assert.deepEqual([guess.status, guess.json.code], [401, 'bad_proof']);
    assert.equal((await list(dir, bob, 'mailto:sarah@webmail.example')).status, 200);
  });

  it('replaces a record with the next choice, and unlists only for the listed assistant', async () => {
    const identifier = 'mailto:sam@webmail.example';
    assert.equal((await list(dir, bob, identifier)).json.record.revision, 1);
    const next = await list(dir, cat, identifier);
    assert.deepEqual([next.json.record.address, next.json.record.revision], [cat.address, 2]);
    const del = (signer: TestAgent) => call(dir, 'DELETE', '/simon/directory', signer, { identifier });
    assert.deepEqual((await del(bob)).json, { status: 'unlisted' }, 'the same answer');
    assert.equal((await lookup(dir, identifier)).json.record.address, cat.address, 'but bob is not listed');
    assert.deepEqual((await del(cat)).json, { status: 'unlisted' });
    assert.equal((await lookup(dir, identifier)).status, 404);
    assert.equal((await list(dir, bob, identifier)).json.record.revision, 3, 'a later choice, a higher revision');
  });

  it("lets an identifier's holder unlist it by a code, with no assistant at all", async () => {
    const identifier = 'mailto:pat@webmail.example';
    await list(dir, bob, identifier);
    const asked = await call(dir, 'DELETE', '/simon/directory', null, { identifier });
    assert.deepEqual([asked.status, asked.json], [202, { status: 'code_sent' }]);
    await fed.work();
    const note = dir.mail.filter(n => n.type === 'unlisting').at(-1)!;
    assert.equal(note.address, 'pat@webmail.example');
    const code = note.type === 'unlisting' ? note.code : '';
    const wrong = await call(dir, 'DELETE', '/simon/directory', null, { identifier, code: '00000000' });
    assert.equal(wrong.status, 401);
    const done = await call(dir, 'DELETE', '/simon/directory', null, { identifier, code });
    assert.deepEqual([done.status, done.json], [200, { status: 'unlisted' }]);
    assert.equal((await lookup(dir, identifier)).status, 404);
    const sent = dir.mail.length;
    const unlisted = await call(dir, 'DELETE', '/simon/directory', null, {
      identifier: 'mailto:nobody@webmail.example',
    });
    assert.deepEqual([unlisted.status, unlisted.json], [202, { status: 'code_sent' }], 'answered alike');
    await fed.work();
    assert.equal(dir.mail.length, sent, 'but nothing sent for an identifier with no record');
  });

  it('lets a record lapse after a year', async () => {
    const identifier = 'mailto:lee@webmail.example';
    await list(dir, bob, identifier);
    fed.clock.advance(366 * 24 * 3600_000);
    assert.equal((await lookup(dir, identifier)).status, 404);
  });
});
