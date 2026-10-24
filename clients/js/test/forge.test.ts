/**
 * A forged-author regression test. An attacker runs a server of
 * its own that publishes a key for ceo@bank.example.com and signs a "Wire approved" message with it, paired with a
 * throwaway principal key. Before the fix, `verifyAuthor(message, {server: <attacker>})` answered verified,
 * with the principal "verified". Now no option names a server, and resolution finds bank.example.com's own.
 */
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  generateKey,
  messageId,
  serverDocument,
  sign,
  signAgentDocument,
  signMessage,
  timestamp,
  type Message,
  type ResolverIO,
} from '@agnt-sdk/simon-protocol';
import { SimonError, fetchAgentDocument, verifyAuthor } from '../src/index.ts';

const serverKey = generateKey();
const agentKey = generateKey();
const principal = generateKey();
const from = 'ceo@bank.example.com';
const forId = `simon-key:${principal.key}`;
const pairing = sign(principal.privateKey, `SIMON-PAIR\n${from}\n${forId}`);
const forged = signMessage<Message>(
  {
    v: 1,
    from,
    to: ['victim@example.org'],
    inReplyTo: null,
    parts: [{ type: 'text/plain', data: 'Wire approved. Proceed.' }],
    headers: { for: forId, pairing, subject: 'Q4 invoice' },
    sentAt: timestamp(new Date()),
  },
  agentKey.privateKey,
);

/** The real domain's answer, as far as this test needs it: a simon record naming a server the attacker does not run. */
const honest: ResolverIO = {
  txt: async name => (name === '_simon.bank.example.com' ? [['v=simon1; server=https://simon.bank.example.com']] : []),
  get: async () => null,
};

describe('a forged author', () => {
  let attacker: http.Server;
  let origin = '';
  const asked: string[] = [];
  before(async () => {
    attacker = http.createServer((req, res) => {
      asked.push(req.url ?? '');
      if (req.url === '/simon/server') {
        return res.end(
          JSON.stringify(
            serverDocument(origin, [{ key: serverKey.key, added: '2020-01-01T00:00:00Z', revoked: null }]),
          ),
        );
      }
      if (req.url === `/simon/agents/${from}`) {
        const keys = [{ key: agentKey.key, added: '2020-01-01T00:00:00Z', revoked: null }];
        return res.end(
          JSON.stringify(signAgentDocument({ address: from, kind: 'paired', keys }, serverKey.privateKey)),
        );
      }
      res.statusCode = 404;
      res.end('{}');
    });
    await new Promise<void>(resolve => attacker.listen(0, '127.0.0.1', resolve));
    origin = `http://127.0.0.1:${(attacker.address() as { port: number }).port}`;
  });
  after(() => new Promise(resolve => attacker.close(resolve)));

  it('cannot point verification at the attacker: the server option is refused', async () => {
    const refused = (e: SimonError) => e instanceof SimonError && e.code === 'invalid' && e.details?.field === 'server';
    await assert.rejects(verifyAuthor(forged, { server: origin } as object), refused);
    await assert.rejects(fetchAgentDocument(from, { server: origin } as object), refused);
    assert.deepEqual(asked, []);
  });

  it("fails to forge: keys come from the server bank.example.com resolves to, which never heard of the attacker's key", async () => {
    // The honest server answers that it has no such agent, or has it with other keys; either way, no forgery.
    const bank = generateKey();
    const fetch = async (url: string) => {
      if (url === 'https://simon.bank.example.com/simon/server') {
        const keys = [{ key: bank.key, added: '2020-01-01T00:00:00Z', revoked: null }];
        return Response.json(serverDocument('https://simon.bank.example.com', keys));
      }
      if (url === `https://simon.bank.example.com/simon/agents/${from}`) {
        const keys = [{ key: generateKey().key, added: '2020-01-01T00:00:00Z', revoked: null }];
        return Response.json(signAgentDocument({ address: from, kind: 'paired', keys }, bank.privateKey));
      }
      return new Response('{}', { status: 404 });
    };
    assert.deepEqual(await verifyAuthor(forged, { resolver: honest, fetch }), {
      verified: false,
      id: messageId(forged),
      reason: 'bad_signature',
    });
    const absent = async () => new Response('{}', { status: 404 });
    const v = await verifyAuthor(forged, { resolver: honest, fetch: absent });
    assert.equal(v.verified, false);
    assert.deepEqual(asked, []);
  });
});
