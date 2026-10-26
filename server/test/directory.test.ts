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
    ip = '192.0.2.7',
  ): Promise<{ status: number; json: any; bytes: Buffer }> {
    const url = new URL(at.origin + target);
    const bytes = body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body));
    const headers: Record<string, string> = signer
      ? signRequest(signer.key, { method, url: url.href, body: bytes, now: fed.clock.t, agent: signer.address })
      : {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    const reply: Reply = await at.server.handle(toRequest(method, url, headers, bytes, ip));
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

  /** An unsigned request for an unlisting code, from `ip`. */
  const askUnlist = (at: TestServer, identifier: string, ip: string) =>
    call(at, 'DELETE', '/simon/directory', null, { identifier }, ip);
  const unlistingCodes = (at: TestServer, identifier: string) =>
    at.mail.filter(n => n.type === 'unlisting' && n.address === identifier.slice(7));

  it('answers a request for an unlisting code alike, and counts it alike, whether or not the identifier is listed', async () => {
    // The default bounds on codes: 5 an hour per identifier, 20 per client.
    const rates = { code: { limit: 5, seconds: 3600 }, codeClient: { limit: 20, seconds: 3600 } };
    const at = await fed.server('quiet', { config: { directory: true, rates } });
    await list(at, bob, 'mailto:listed@webmail.example');
    const probe = async (identifier: string, ip: string) => {
      const answers = [];
      for (let i = 0; i < 22; i++) answers.push(await askUnlist(at, identifier, ip));
      return answers.map(a => `${a.status} ${a.bytes.toString()}`);
    };
    const listed = await probe('mailto:listed@webmail.example', '198.51.100.1');
    const unlisted = await probe('mailto:unlisted@webmail.example', '198.51.100.2');
    assert.deepEqual(listed, unlisted, 'the same answers, the same bytes, the same limit');
    assert.equal(listed.filter(a => a.startsWith('202')).length, 20, 'the per-client bound');
    await fed.work();
    assert.equal(unlistingCodes(at, 'mailto:listed@webmail.example').length, 1, 'one code outstanding at a time');
    assert.equal(unlistingCodes(at, 'mailto:unlisted@webmail.example').length, 0);
  });

  it('never lets anyone else spoil, outnumber or lock the code that lets a holder leave', async () => {
    const rates = { code: { limit: 5, seconds: 3600 }, codeClient: { limit: 20, seconds: 3600 } };
    const at = await fed.server('leave', { config: { directory: true, rates } });
    const identifier = 'mailto:kim@webmail.example';
    await list(at, bob, identifier);
    // Listing requests from other agents spend the identifier's listing bound, not its way out.
    for (let i = 0; i < 6; i++) await call(at, 'POST', '/simon/directory', cat, { identifier }, `203.0.113.${i + 1}`);
    assert.equal((await askUnlist(at, identifier, '198.51.100.9')).status, 202);
    await fed.work();
    const [note] = unlistingCodes(at, identifier);
    const code = note?.type === 'unlisting' ? note.code : '';
    // Another request, and wrong guesses from another client, leave the holder's code working.
    assert.equal((await askUnlist(at, identifier, '203.0.113.50')).status, 202);
    for (let i = 0; i < 6; i++) {
      const guess = await call(
        at,
        'DELETE',
        '/simon/directory',
        null,
        { identifier, code: '00000000' },
        '203.0.113.50',
      );
      assert.equal(guess.status, 401, 'a wrong code');
    }
    await fed.work();
    assert.equal(unlistingCodes(at, identifier).length, 1, 'no second code replaced the first');
    const done = await call(at, 'DELETE', '/simon/directory', null, { identifier, code }, '198.51.100.9');
    assert.deepEqual([done.status, done.json], [200, { status: 'unlisted' }]);
    assert.equal((await lookup(at, identifier)).status, 404);
  });

  it('keeps the higher revision when two listings complete together', async () => {
    let release: () => void = () => {};
    let first = true;
    let held = 0;
    const at = await fed.server('race', {
      config: { directory: true },
      wrapStore: store =>
        new Proxy(store, {
          get(target, name) {
            if (name !== 'valueOnce') return Reflect.get(target, name).bind(target);
            return async (scope: string, ...rest: [string, unknown, string | null, string]) => {
              // The first listing to store waits until the second has stored: the lower revision writes last.
              if (scope === 'directory' && first) {
                first = false;
                held = (rest[1] as { revision: number }).revision;
                await new Promise<void>(resolve => (release = resolve));
              }
              const stored = await target.valueOnce(scope, ...rest);
              if (scope === 'directory') release();
              return stored;
            };
          },
        }),
    });
    const identifier = 'mailto:ray@webmail.example';
    const codeFor = async (agent: TestAgent) => {
      await call(at, 'POST', '/simon/directory', agent, { identifier });
      await fed.work();
      const note = at.mail.filter(n => n.type === 'listing' && n.assistant === agent.address).at(-1)!;
      return note.type === 'listing' ? note.code : '';
    };
    const [bobCode, catCode] = [await codeFor(bob), await codeFor(cat)];
    const [b, c] = await Promise.all([
      call(at, 'POST', '/simon/directory', bob, { identifier, code: bobCode }),
      call(at, 'POST', '/simon/directory', cat, { identifier, code: catCode }),
    ]);
    const highest = [b, c].map(r => r.json.record).sort((x, y) => y.revision - x.revision)[0];
    assert.ok(held > 0 && held < highest.revision, 'the lower revision was held back, to write last');
    assert.deepEqual((await lookup(at, identifier)).json.record, highest);
  });

  it('says in its server document that it answers lookups', async () => {
    const doc = await call(alpha, 'GET', '/simon/server', null);
    assert.equal(readServerDocument(doc.bytes, alpha.origin, fed.clock.now())?.discovery, true);
  });

  it('lets a record lapse after a year', async () => {
    const identifier = 'mailto:lee@webmail.example';
    await list(dir, bob, identifier);
    fed.clock.advance(366 * 24 * 3600_000);
    assert.equal((await lookup(dir, identifier)).status, 404);
  });
});
