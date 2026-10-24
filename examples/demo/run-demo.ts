/**
 * The protocol end to end against a running server, every step checked: two agents register (one leased,
 * one paired with a key principal), write to each other both ways with a part sent by hash, read their
 * messages by opaque sync token, see delivery reported, and verify each other's signatures from the documents.
 *
 *   SIMON_SERVER=http://localhost:8787 npm run demo
 *
 * Verification resolves each author's domain as any reader must; a development server's domains have no
 * DNS, so the demo answers them itself from SIMON_DEV_RESOLVE (domain=origin,..., the development server's
 * own setting, by default agents.test and lease.agents.test on SIMON_SERVER). That is a resolver passed in
 * code, the one seam the client keeps for local development.
 *
 * Any failure exits non-zero. Each run makes fresh keys, so it can run again and again.
 */
import assert from 'node:assert/strict';
import { generateKey, signPairing, textOf, type ResolverIO } from '@agnt-sdk/simon-protocol';
import { Agent, verifyAuthor, type Delivered } from '@agnt-sdk/simon-client';

const SERVER = process.env.SIMON_SERVER ?? 'http://localhost:8787';
const DEV_RESOLVE = Object.fromEntries(
  (process.env.SIMON_DEV_RESOLVE ?? `agents.test=${SERVER},lease.agents.test=${SERVER}`)
    .split(',')
    .map(pair => pair.split('=', 2)),
);
/** The development network's names, answered as a simon TXT record would answer them. */
const resolver: ResolverIO = {
  txt: async name => {
    const origin = DEV_RESOLVE[name.replace(/^_simon\./, '')];
    return origin ? [[`v=simon1; server=${origin}`]] : [];
  },
  get: async () => null,
};
const reading = { resolver, allowHttp: true };

let step = 0;
const say = (s: string) => console.log(`\n${++step}. ${s}`);
const ok = (s: string) => console.log(`   ok  ${s}`);
const agent = () => new Agent({ server: SERVER, key: generateKey().privateKeyPem });

/** Track opaque sync tokens and wait for a specific message; sync also contains our sent history. */
const tokens = new Map<Agent, string>();
async function next(a: Agent, id: string): Promise<Delivered> {
  for (let i = 0; i < 50; i++) {
    const page = await a.sync({ since: tokens.get(a), limit: 200 });
    tokens.set(a, page.token);
    const found = page.messages.find(e => e.id === id && e.message.to.includes(a.address!));
    if (found) return found;
    if (!page.more) await new Promise(resolve => setTimeout(resolve, 200));
  }
  throw new Error(`Message ${id} did not reach ${a.address}.`);
}

/** Each recipient server's delivery status, once none is pending. */
async function settled(a: Agent, message: string): Promise<string[]> {
  for (let i = 0; ; i++) {
    const statuses = (await a.sent(message)).servers.map(s => s.status);
    if (!statuses.includes('pending') || i === 50) return statuses;
    await new Promise(resolve => setTimeout(resolve, 200));
  }
}

say('Ada registers a key alone, and the server leases her an address.');
const ada = agent();
const leased = await ada.register();
assert.ok('keys' in leased);
ok(`${ada.address}, key ${ada.key.slice(0, 24)}...`);

say('Bob pairs with a key principal: pairing_required, then the principal signs.');
const principal = generateKey();
const id = `simon-key:${principal.key}`;
const bob = agent();
const pending = await bob.register({ for: id });
assert.equal(pending.status, 'pairing_required');
const paired = await bob.register({ for: id, pairing: signPairing(principal.privateKey, pending.address, id) });
assert.ok('keys' in paired);
ok(`${bob.address} speaks for ${id.slice(0, 30)}...`);

say('Ada uploads a brief, and sends it to Bob by hash.');
const brief = await ada.uploadPart(
  new TextEncoder().encode('%PDF-1.7 a one-page brief'),
  'application/pdf',
  'brief.pdf',
);
const sent = await ada.send({
  to: [bob.address!],
  text: 'Does Thursday at 3pm work?',
  parts: [brief],
  headers: { subject: 'Thursday' },
});
ok(`sent ${sent.id}`);

say('Bob reads it, checks Ada wrote it, and fetches the brief.');
const first = await next(bob, sent.id);
assert.equal(first.id, sent.id);
assert.equal(textOf(first.message), 'Does Thursday at 3pm work?');
const fromAda = await verifyAuthor(first.message, { ...reading, signedClaims: first.signedClaims });
assert.ok(fromAda.verified && fromAda.understood && fromAda.authorServer === SERVER && fromAda.principal === null);
const bytes = await bob.fetchPart(first.message.parts[1] as typeof brief);
assert.equal(new TextDecoder().decode(bytes), '%PDF-1.7 a one-page brief');
ok(`verified, and ${bytes.length} bytes match the hash`);

say('Bob answers in the thread; his principal travels with the message.');
const reply = await bob.send({ to: [ada.address!], inReplyTo: first.id, text: 'Thursday at 3pm works.' });
const answer = await next(ada, reply.id);
assert.deepEqual([answer.id, answer.message.inReplyTo, answer.message.headers.for], [reply.id, sent.id, id]);
const fromBob = await verifyAuthor(answer.message, { ...reading, signedClaims: answer.signedClaims });
assert.ok(fromBob.verified && fromBob.kind === 'paired' && fromBob.principal?.basis === 'key-pairing');
ok("Bob's signature verifies, and his principal's basis is key-pairing: the key's holder consented");

say('Each sees how delivery went, and the inbox is read through.');
assert.deepEqual(await settled(ada, sent.id), ['delivered']);
assert.deepEqual(await settled(bob, reply.id), ['delivered']);
const rest = await ada.sync({ since: tokens.get(ada) });
assert.deepEqual([rest.messages.length, rest.more], [0, false]);
ok('delivered both ways; nothing more to read');

console.log('\nThe demo ran end to end.');
