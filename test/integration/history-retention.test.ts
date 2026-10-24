/** Historical signature checks require retained evidence; a saved message alone is insufficient. */
import assert from 'node:assert/strict';
import { it } from 'node:test';
import {
  generateKey,
  messageVerdict,
  serverDocument,
  signAgentDocument,
  signMessage,
  type KeyEntry,
  type Message,
  type ResolverIO,
} from '@agnt-sdk/simon-protocol';
import { listedKeys } from '../../server/src/public.ts';
import type { Agent } from '../../server/src/store/store.ts';
import { fetchAgentDocument, verifyAuthor } from '../../clients/js/src/read.ts';
import type { Fetch } from '../../clients/js/src/http.ts';

it('distinguishes a local check with retained validated keys from a cold reader after history pruning', async () => {
  const now = new Date('2026-10-22T12:00:00.000Z');
  const added = '2026-10-01T00:00:00.000Z';
  const revoked = '2026-10-21T00:00:00.000Z';
  const server = generateKey();
  const old = generateKey();
  const current = generateKey();
  const origin = 'https://history.test';
  const address = 'ada@history.test';
  const oldEntry: KeyEntry = { key: old.key, added, revoked };
  const currentEntry: KeyEntry = { key: current.key, added, revoked: null };
  const account: Agent = {
    address,
    kind: 'solo',
    principal: null,
    keys: [oldEntry, currentEntry],
    mailbox: false,
    createdAt: added,
    retiredAt: null,
  };
  const m = signMessage<Message>(
    {
      v: 1,
      from: address,
      to: ['bob@elsewhere.test'],
      sentAt: '2026-10-20T12:00:00.000Z',
      inReplyTo: null,
      headers: {},
      parts: [{ type: 'text/plain', data: 'A message before revocation.' }],
    },
    old.privateKey,
  );
  const serverDoc = serverDocument(origin, [{ key: server.key, added, revoked: null }]);
  const resolver: ResolverIO = { txt: async () => [[`v=simon1; server=${origin}`]], get: async () => null };
  let hidden = false;
  let retireAt: string | null = null;
  const paths: string[] = [];
  const fetch: Fetch = async url => {
    const parsed = new URL(url);
    paths.push(parsed.pathname);
    assert.equal(parsed.origin, origin, 'the reader uses the domain-selected origin');
    if (parsed.pathname === '/simon/server') return Response.json(serverDoc);
    assert.ok(parsed.pathname.startsWith('/simon/agents/'));
    if (hidden) return new Response('', { status: 404 });
    return Response.json(
      signAgentDocument(
        {
          address,
          kind: 'solo',
          keys: listedKeys(account, now.getTime()),
          ...(retireAt ? { retired: retireAt } : {}),
        },
        server.privateKey,
      ),
    );
  };
  const opts = { fetch, resolver, now: () => now };
  const retained = await fetchAgentDocument(address, opts);
  assert.ok(retained, 'key evidence was authenticated through real DNS/document reader code');
  assert.equal((await verifyAuthor(m, opts)).verified, true);

  // Real reference count projection retains31 revoked keys plus the current key, dropping the oldest.
  account.keys = [
    oldEntry,
    ...Array.from({ length: 31 }, (): KeyEntry => ({ key: generateKey().key, added, revoked })),
    currentEntry,
  ];
  const projected = listedKeys(account, now.getTime());
  assert.equal(projected.length, 32);
  assert.equal(
    projected.some(k => k.key === old.key),
    false,
  );
  const beforeCold = paths.length;
  const cold = await verifyAuthor(m, opts);
  assert.equal(cold.verified ? 'verified' : cold.reason, 'bad_signature');
  assert.ok(paths.slice(beforeCold).includes('/simon/server'), 'cold verification fetched current server evidence');
  assert.ok(
    paths.slice(beforeCold).some(p => p.startsWith('/simon/agents/')),
    'and the current agent document',
  );
  // Only the evidence deliberately retained in this fixture supports this local signature check.
  // Production verifyAuthor does not persist it, and this does not prove signing time or historical DNS.
  assert.equal(messageVerdict(m, retained.keys), 'verified');
  const mutated = { ...m, parts: [{ type: 'text/plain', data: 'Changed content.' }] };
  assert.equal(messageVerdict(mutated, retained.keys), 'bad_signature');

  // Retirement evidence works only while the required history is actually disclosed.
  retireAt = revoked;
  account.keys = [oldEntry, { ...currentEntry, revoked }];
  const disclosed = await verifyAuthor(m, opts);
  assert.equal(disclosed.verified, true);
  assert.ok(disclosed.verified && disclosed.retired === retireAt);
  hidden = true;
  const privateRetired = await verifyAuthor(m, opts);
  assert.equal(privateRetired.verified ? 'verified' : privateRetired.reason, 'no_agent');
  assert.equal(
    messageVerdict(m, retained.keys),
    'verified',
    'local retained-evidence check has a different trust basis',
  );
});
