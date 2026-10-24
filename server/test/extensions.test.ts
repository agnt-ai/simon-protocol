/**
 * The extension seam: what an application adds without editing the core.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import {
  generateKey,
  pairingBytes,
  readServerDocument,
  verifyClaims,
  sha256Hex,
  sign,
  signMessage,
  signPairing,
  signRecovery,
  verify,
  WireError,
  type Claim,
  type Message,
} from '@agnt-protocol/protocol';
import type { AddressRequest, Arrival, Events, Extension } from '../src/extensions.ts';
import { json } from '../src/http.ts';
import { defineConfig } from '../src/config.ts';
import { createServer } from '../src/server.ts';
import { SqliteStore } from '../src/store/sqlite.ts';
import { Federation } from './harness.ts';

describe('extensions', async () => {
  const seen: { event: keyof Events; payload: unknown }[] = [];
  const offered: Arrival[] = [];
  const listen = (event: keyof Events) => (payload: unknown) => void seen.push({ event, payload });

  /** A policy: refuse "spam", hold "later", and say nothing otherwise. */
  const policy: Extension = {
    name: 'policy',
    admit(arrival) {
      offered.push(arrival);
      const text = JSON.stringify(arrival.message);
      return text.includes('spam') ? 'refuse' : text.includes('later') ? 'later' : undefined;
    },
  };
  /** Never consulted for what policy decided, since the first decision ends the chain. */
  const allowAll: Extension = { name: 'allow-all', admit: () => 'accept' };
  const failing: Extension = {
    name: 'failing',
    on: {
      inbox: () => {
        throw new Error('a listener bug');
      },
    },
  };
  const recorder: Extension = {
    name: 'recorder',
    on: {
      stored: listen('stored'),
      inbox: listen('inbox'),
      delivered: listen('delivered'),
      deliveryFailed: listen('deliveryFailed'),
      unroutable: listen('unroutable'),
    },
  };
  const actsFor: Extension = {
    name: 'acts-for',
    claimsFor: (m, agent) =>
      agent.principal
        ? [
            {
              type: 'acts-for',
              agent: m.from,
              for: agent.principal,
              scope: ['converse'],
              verifiedAt: '2026-10-01T00:00:00Z',
            } as Claim,
          ]
        : [],
  };
  /** Pairs mailto: principals after a fixed confirmation. */
  const email: Extension = {
    name: 'email',
    verifyPrincipal: ({ principal, body }) =>
      !principal.startsWith('mailto:')
        ? undefined
        : body.confirmation === 'yes'
          ? { status: 'verified' }
          : { status: 'pending', body: { status: 'confirmation_sent' } },
  };
  const whoami: Extension = {
    name: 'whoami',
    routes: [
      {
        method: 'GET',
        path: '/app/whoami',
        handle: async (req, api) => json({ address: (await api.authenticate(req)).address }),
      },
    ],
  };

  const fed = new Federation();
  after(() => fed.close());
  const alpha = await fed.server('alpha', { extensions: [email, actsFor, whoami] });
  const beta = await fed.server('beta', {
    extensions: [policy, allowAll, failing, recorder],
    config: { trustedClaimServers: ['https://simon.alpha.test'] },
  });
  const ann = alpha.newAgent();
  const bob = await beta.agent('bob');

  it('pairs through verifyPrincipal, and carries claimsFor claims to a server that trusts them', async () => {
    const pending = await ann.register({ address: 'ann@alpha.test', for: 'mailto:ann@example.org' });
    assert.deepEqual([pending.status, pending.json], [202, { status: 'confirmation_sent' }]);
    const done = await ann.register({ address: 'ann@alpha.test', for: 'mailto:ann@example.org', confirmation: 'yes' });
    assert.equal(done.status, 200);
    await ann.send(ann.message([bob.address], 'hello', { headers: { for: 'mailto:ann@example.org' } }), {
      [bob.address]: { invite: 'K7' },
    });
    await fed.work();
    const [entry] = await bob.received();
    assert.deepEqual(entry.claims, [
      {
        type: 'acts-for',
        agent: ann.address,
        for: 'mailto:ann@example.org',
        scope: ['converse'],
        verifiedAt: '2026-10-01T00:00:00Z',
        authoritative: false,
      },
    ]);
    assert.deepEqual(offered.at(-1)?.hints, { invite: 'K7' }, 'hints reach the admit chain');
  });

  it('publishes the claims it makes about a published message beside it, signed for the message', async () => {
    const post = ann.message([], 'a public post', { headers: { for: 'mailto:ann@example.org' } });
    const { json: sent } = await ann.send(post);
    const res = await ann.request('GET', `/simon/messages/${sent.id}`, { sign: false });
    assert.equal(res.status, 200);
    assert.deepEqual(res.json.claims, [
      {
        type: 'acts-for',
        agent: ann.address,
        for: 'mailto:ann@example.org',
        scope: ['converse'],
        verifiedAt: '2026-10-01T00:00:00Z',
      },
    ]);
    const doc = readServerDocument(
      (await ann.request('GET', '/simon/server', { sign: false })).bytes,
      alpha.origin,
      fed.clock.now(),
    )!;
    assert.equal(verifyClaims({ claims: res.json.claims, signature: res.json.claimsSignature }, post, doc.keys), true);
  });

  it('runs the admit chain: the first decision ends it, and the sender learns nothing', async () => {
    const spam = await ann.send(ann.message([bob.address], 'spam', { headers: { for: 'mailto:ann@example.org' } }));
    const held = await ann.send(ann.message([bob.address], 'later', { headers: { for: 'mailto:ann@example.org' } }));
    await fed.work();
    assert.deepEqual(await bob.texts(), ['hello']);
    for (const { json: s } of [spam, held]) assert.equal((await ann.sent(s.id)).json.servers[0].status, 'delivered');
    assert.equal(await beta.server.api.admit(bob.address, held.json.id), true, 'an extension releases what it held');
    assert.deepEqual(await bob.texts(), ['hello', 'later']);
    assert.equal(await beta.store.message(spam.json.id), null, 'a message nobody took is not kept');
  });

  it('tells listeners what happened, and a failing listener changes nothing', async () => {
    const events = seen.map(s => s.event);
    assert.ok(events.includes('inbox') && events.includes('stored'));
    await fed.work();
    const from = seen.length;
    await bob.send(bob.message(['x@nowhere.example', ann.address], 'two ways'));
    await fed.work();
    const tail = seen
      .slice(from)
      .map(s => s.event)
      .sort();
    assert.deepEqual(tail, ['delivered', 'deliveryFailed', 'stored', 'unroutable']);
  });

  it('serves extension routes, which may use the core to authenticate', async () => {
    assert.deepEqual((await ann.request('GET', '/app/whoami')).json, { address: ann.address });
    assert.equal((await ann.request('GET', '/app/whoami', { sign: false })).status, 401);
  });

  it('refuses an extension route that would replace a core one', () => {
    const config = defineConfig({ origin: 'https://simon.x.test', serverKey: generateKey().privateKey });
    const shadow: Extension = {
      name: 'shadow',
      routes: [{ method: 'POST', path: '/simon/send', handle: () => json({}) }],
    };
    assert.throws(
      () => createServer({ config, store: new SqliteStore(), extensions: [shadow], worker: false }),
      /Two routes/,
    );
  });
});

describe('extensions acting for an application', async () => {
  const events: { event: string; payload: any }[] = [];
  const bridge: Extension = {
    name: 'bridge',
    on: {
      unroutable: ({ recipients }) => recipients.every(r => r.endsWith('@mail.example')),
      deliveryFailed: payload => void events.push({ event: 'deliveryFailed', payload }),
      recovered: payload => void events.push({ event: 'recovered', payload }),
    },
  };
  const scanner: Extension = {
    name: 'scanner',
    upload({ bytes }) {
      if (bytes.includes('EICAR')) throw new WireError(422, 'infected', 'The upload failed its malware scan.');
    },
  };
  const quiet: Extension = {
    name: 'quiet',
    admit: ({ message }) => (message.from.startsWith('eve') ? 'refuse' : undefined),
  };

  const fed = new Federation();
  after(() => fed.close());
  const gamma = await fed.server('gamma', {
    extensions: [bridge, scanner, quiet],
    config: { recoveryWaitSeconds: 0 },
  });
  const ada = await gamma.agent('ada');
  const bob = await gamma.agent('bob');
  const eve = await gamma.agent('eve');

  it('lets its own agent send through api.send, checked as send checks it', async () => {
    const notices = gamma.newAgent();
    const now = new Date(fed.clock.t).toISOString();
    await gamma.store.createAgent({
      address: 'notices@gamma.test',
      kind: 'solo',
      principal: null,
      keys: [{ key: notices.token, added: now, revoked: null }],
      mailbox: false,
      createdAt: now,
      retiredAt: null,
    });
    notices.address = 'notices@gamma.test';
    const sent = await gamma.server.api.send(notices.message([ada.address], 'welcome'));
    assert.match(sent.id, /^[0-9a-f]{64}$/);
    const forged = signMessage<Message>({ ...ada.message([bob.address], 'forged') }, notices.key);
    await assert.rejects(gamma.server.api.send(forged), /does not verify/);
    await assert.rejects(gamma.server.api.send({ ...forged, from: 'nobody@gamma.test' }), /not an agent here/);
    await fed.work();
    assert.deepEqual(await ada.texts(), ['welcome']);
  });

  it('offers a stored message to another agent here through the admit chain', async () => {
    const { json: fromAda } = await ada.send(ada.message(['ann@mail.example'], 'for ann'));
    const { json: fromEve } = await eve.send(eve.message(['ann@mail.example'], 'from eve'));
    assert.equal(await gamma.server.api.offer(bob.address, fromAda.id), true);
    assert.equal(await gamma.server.api.offer(bob.address, fromEve.id), false, 'the chain refused it');
    assert.deepEqual(await bob.texts(), ['for ann']);
  });

  it('counts recipients an unroutable listener took as delivered, and fails the rest', async () => {
    const taken = await ada.send(ada.message(['ann@mail.example'], 'by mail'));
    const left = await ada.send(ada.message(['cy@nowhere.example'], 'nowhere'));
    await fed.work();
    assert.deepEqual((await ada.sent(taken.json.id)).json.servers, [
      { server: null, recipients: ['ann@mail.example'], status: 'delivered' },
    ]);
    assert.equal((await ada.sent(left.json.id)).json.servers[0].reason, 'not_found');
    const failed = events.filter(e => e.event === 'deliveryFailed').map(e => e.payload.recipients);
    assert.ok(failed.some(r => r.includes('cy@nowhere.example')));
    assert.ok(!failed.some(r => r.includes('ann@mail.example')));
  });

  it('refuses an upload an upload check refuses, and keeps nothing of it', async () => {
    const bad = Buffer.from('X5O!P%@AP EICAR test');
    const res = await ada.upload(bad);
    assert.deepEqual([res.status, res.json.code], [422, 'infected']);
    assert.equal(await gamma.store.part(sha256Hex(bad), { uploader: ada.address }), null);
    assert.equal((await ada.upload(Buffer.from('fine'))).status, 200);
  });

  it('tells listeners when an address was recovered by code', async () => {
    fed.dns.point('mail.gamma.test', gamma.origin);
    const old = gamma.newAgent();
    await old.register({ address: 'rec@mail.gamma.test' });
    await old.register({ address: 'rec@mail.gamma.test', code: gamma.code('rec@mail.gamma.test') });
    const fresh = gamma.newAgent();
    await fresh.recover({ address: 'rec@mail.gamma.test' });
    await fresh.recover({ address: 'rec@mail.gamma.test', code: gamma.code('rec@mail.gamma.test') });
    assert.deepEqual(events.find(e => e.event === 'recovered')?.payload, {
      address: 'rec@mail.gamma.test',
      key: fresh.token,
      by: 'mailbox',
    });
  });

  it('tells listeners when a key principal recovered its agent', async () => {
    const principal = generateKey();
    const forValue = `simon-key:${principal.key}`;
    const old = gamma.newAgent();
    await old.register({
      address: 'kp@gamma.test',
      for: forValue,
      pairing: signPairing(principal.privateKey, 'kp@gamma.test', forValue),
    });
    const fresh = gamma.newAgent();
    const at = new Date(fed.clock.t).toISOString();
    const recover = signRecovery(principal.privateKey, 'kp@gamma.test', fresh.token, at);
    assert.equal((await fresh.recover({ address: 'kp@gamma.test', at, recover })).status, 200);
    assert.deepEqual(events.findLast(e => e.event === 'recovered')?.payload, {
      address: 'kp@gamma.test',
      key: fresh.token,
      by: 'principal',
    });
  });
});

describe('a host deciding who takes names', async () => {
  const asked: AddressRequest[] = [];
  /** The host's own backend signs each name it gives: the address and the key, so no proof is replayed. */
  const host = generateKey();
  const proofString = (address: string, key: string) => `HOST-NAME\n${address}\n${key}`;
  const proof = (address: string, key: string) => sign(host.privateKey, proofString(address, key));
  /** Keeps support@ for the host's people, whatever proof comes with it: the first decision ends the chain. */
  const kept: Extension = {
    name: 'kept',
    allowAddress: ({ address }) => (address.startsWith('support@') ? 'refuse' : undefined),
  };
  /** Hosted names only with the host's proof; no opinion on leases. */
  const proven: Extension = {
    name: 'proven',
    allowAddress(request, api) {
      asked.push(request);
      if (request.address.endsWith(`@${api.config.leaseDomain}`)) return undefined;
      const given = verify(host.key, proofString(request.address, request.key), request.body['delta.test:proof']);
      return given ? 'allow' : 'refuse';
    },
  };

  const fed = new Federation();
  after(() => fed.close());
  const delta = await fed.server('delta', { extensions: [kept, proven] });

  it("refuses a hosted name without the host's proof, and gives it with it", async () => {
    const squatter = delta.newAgent();
    const refused = await squatter.register({ address: 'sally@delta.test' });
    assert.deepEqual([refused.status, refused.json.code], [409, 'address_taken']);
    const replayed = await squatter.register({
      address: 'sally@delta.test',
      'delta.test:proof': proof('sally@delta.test', delta.newAgent().token),
    });
    assert.equal(replayed.status, 409, 'a proof for another key is no proof for this one');
    const sally = delta.newAgent();
    const given = proof('sally@delta.test', sally.token);
    const taken = await sally.register({ address: 'Sally@delta.test', 'delta.test:proof': given });
    assert.deepEqual([taken.status, taken.json.address], [200, 'sally@delta.test']);
    assert.deepEqual(asked.at(-1), {
      address: 'sally@delta.test',
      key: sally.token,
      body: { key: sally.token, address: 'Sally@delta.test', 'delta.test:proof': given },
    });
  });

  it('answers a refusal in the words a held name gets', async () => {
    const refused = await delta.newAgent().register({ address: 'bob@delta.test' });
    const held = await delta.newAgent().register({ address: 'sally@delta.test' });
    assert.deepEqual(refused.json, held.json);
  });

  it('ends the chain at the first decision', async () => {
    const before = asked.length;
    const agent = delta.newAgent();
    const res = await agent.register({
      address: 'support@delta.test',
      'delta.test:proof': proof('support@delta.test', agent.token),
    });
    assert.equal(res.status, 409);
    assert.equal(asked.length, before, 'the later extension was not asked');
  });

  it('asks on each call of a pairing, so the proof goes on each', async () => {
    const principal = generateKey();
    const ann = delta.newAgent();
    const body = { address: 'ann@delta.test', for: `simon-key:${principal.key}` };
    const before = asked.length;
    const first = await ann.register({ ...body, 'delta.test:proof': proof('ann@delta.test', ann.token) });
    assert.deepEqual([first.status, first.json.status], [202, 'pairing_required']);
    const pairing = sign(principal.privateKey, pairingBytes('ann@delta.test', body.for));
    assert.equal((await ann.register({ ...body, pairing })).status, 409, 'without the proof the second time');
    const done = await ann.register({ ...body, pairing, 'delta.test:proof': proof('ann@delta.test', ann.token) });
    assert.equal(done.status, 200);
    assert.equal(asked.length, before + 3);
  });

  it('is asked about leases, and its silence leaves them to anyone', async () => {
    const leased = await delta.newAgent().register();
    assert.equal(leased.status, 200);
    assert.equal(asked.at(-1)?.address, leased.json.address);
  });

  it('is never asked about an address held, retired, or bound by a code to its mailbox', async () => {
    const before = asked.length;
    const held = await delta.newAgent().register({ address: 'sally@delta.test' });
    assert.equal(held.status, 409);
    await delta.server.api.retire('sally@delta.test');
    const retired = await delta.newAgent().register({ address: 'sally@delta.test' });
    assert.equal(retired.status, 409);
    fed.dns.point('mail.delta.test', delta.origin);
    const cy = delta.newAgent();
    await cy.register({ address: 'cy@mail.delta.test' });
    const bound = await cy.register({ address: 'cy@mail.delta.test', code: delta.code('cy@mail.delta.test') });
    assert.equal(bound.status, 200);
    assert.equal(asked.length, before);
  });
});
