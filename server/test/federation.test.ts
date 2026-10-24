/**
 * Servers delivering to each other (spec section 6), and to their own agents, end to end.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { Federation, messageId } from './harness.ts';

describe('federation', () => {
  const fed = new Federation();
  after(() => fed.close());

  it('delivers a message both ways between two servers, with the carrier and delivery status', async () => {
    const alpha = await fed.server('alpha');
    const beta = await fed.server('beta');
    const ada = await alpha.agent('ada');
    const bob = await beta.agent('bob');

    const question = ada.message([bob.address], 'Does 3pm work?');
    const sent = await ada.send(question);
    assert.equal(sent.status, 200, JSON.stringify(sent.json));
    assert.equal(sent.json.id, messageId(question));
    await fed.work();

    const box = await bob.received();
    assert.equal(box.length, 1);
    assert.deepEqual(box[0].message, question);
    assert.equal(box[0].carrier, alpha.origin);
    assert.deepEqual((await ada.sent(sent.json.id)).json, {
      id: sent.json.id,
      servers: [{ server: beta.origin, recipients: [bob.address], status: 'delivered' }],
    });

    const reply = bob.message([ada.address], 'It does.', { inReplyTo: sent.json.id });
    assert.equal((await bob.send(reply)).status, 200);
    await fed.work();
    assert.deepEqual(await ada.texts(), ['It does.']);
  });

  it('delivers between agents of one server through the same path', async () => {
    const gamma = await fed.server('gamma');
    const [cat, dan] = [await gamma.agent('cat'), await gamma.agent('dan')];
    const m = cat.message([dan.address, cat.address], 'note to us both');
    await cat.send(m);
    await fed.work();
    assert.deepEqual(await dan.texts(), ['note to us both']);
    assert.deepEqual(await cat.texts(), ['note to us both']);
    const box = await dan.received();
    assert.equal(box[0].carrier, gamma.origin);
  });

  it('federates a server whose origin is its own domain, resolved by the well-known answer it serves', async () => {
    const laptop = await fed.server('laptop', { wellKnown: true });
    const delta = await fed.server('delta');
    const [lee, dee] = [await laptop.agent('lee'), await delta.agent('dee')];
    const known = await lee.request('GET', '/.well-known/agnt', { sign: false });
    assert.deepEqual([known.status, known.json], [200, { server: 'https://laptop.test' }]);
    assert.equal(fed.dns.records.has('_agnt.laptop.test'), false, 'no TXT record');
    assert.equal((await dee.request('GET', '/.well-known/agnt', { sign: false })).status, 404, 'not its own host');

    await lee.send(lee.message([dee.address], 'over the tailnet'));
    await fed.work();
    assert.deepEqual(await dee.texts(), ['over the tailnet']);
    await dee.send(dee.message([lee.address], 'and back'));
    await fed.work();
    assert.deepEqual(await lee.texts(), ['and back']);
  });

  it("sends each server only its own recipients, and each recipient's hints only to its server", async () => {
    const theta = await fed.server('theta');
    const iota = await fed.server('iota');
    const [tom, ida] = [await theta.agent('tom'), await iota.agent('ida')];
    const envelopes: Record<string, unknown>[] = [];
    const real = fed.net.request.bind(fed.net);
    fed.net.request = async r => {
      if (r.url.endsWith('/agnt/deliver')) envelopes.push(JSON.parse(Buffer.from(r.body!).toString()));
      return real(r);
    };
    await tom.send(tom.message([ida.address, 'ivy@iota.test', 'zoe@zeta.test'], 'to two servers'), {
      [ida.address]: { invite: 'I' },
      'zoe@zeta.test': { invite: 'Z' },
    });
    await fed.work();
    fed.net.request = real;
    const toIota = envelopes.find(e => e.server === iota.origin)!;
    assert.deepEqual(toIota.recipients, [ida.address, 'ivy@iota.test']);
    assert.deepEqual(toIota.hints, { [ida.address]: { invite: 'I' } });
    assert.equal(envelopes.length, 1, 'zeta.test names no server');
  });

  it('delivers nothing to a stale former host of a domain, which the envelope does not name', async () => {
    const kappa = await fed.server('kappa', { config: { hostedDomains: ['kappa.test', 'moved.test'] } });
    const lambda = await fed.server('lambda', { config: { hostedDomains: ['lambda.test', 'moved.test'] } });
    fed.dns.point('moved.test', kappa.origin);
    const stale = kappa.newAgent();
    await stale.register({ address: 'carol@moved.test' });
    fed.dns.point('moved.test', lambda.origin);
    const current = lambda.newAgent();
    await current.register({ address: 'carol@moved.test' });
    const kim = await kappa.agent('kim');
    const lia = await lambda.agent('lia');
    fed.clock.advance(11 * 60_000);
    await lia.send(lia.message([kim.address, 'carol@moved.test'], 'for kim and carol'));
    await fed.work();
    assert.deepEqual(await kim.texts(), ['for kim and carol']);
    assert.deepEqual(await current.texts(), ['for kim and carol']);
    assert.deepEqual(await stale.texts(), [], 'kappa no longer serves moved.test');
  });

  it('keeps an invite hint for a second domain on the same server, sent in a later envelope', async () => {
    const seen: string[] = [];
    const mu = await fed.server('mu', {
      config: { hostedDomains: ['mu.test', 'nu.test'] },
      extensions: [{ name: 'invites', admit: a => (seen.push(`${a.recipient} ${a.hints.invite ?? '-'}`), undefined) }],
    });
    fed.dns.point('nu.test', mu.origin);
    const xi = await fed.server('xi');
    const [max, nat] = [await mu.agent('max'), mu.newAgent()];
    await nat.register({ address: 'nat@nu.test' });
    const xia = await xi.agent('xia');
    fed.dns.failing.add('_agnt.nu.test');
    fed.clock.advance(11 * 60_000);
    await xia.send(xia.message([max.address, nat.address], 'two domains, one server'), {
      [nat.address]: { invite: 'N' },
    });
    await fed.work();
    fed.dns.failing.delete('_agnt.nu.test');
    fed.clock.advance(2 * 60_000);
    await fed.work();
    assert.deepEqual(seen.sort(), ['max@mu.test -', 'nat@nu.test N']);
    assert.deepEqual(await nat.texts(), ['two domains, one server']);
  });
});
