/**
 * Spec section 6.4: signals, as this server receives them. Whose signals reach an agent is this server's own
 * policy: it passes a signal to a recipient here who holds the message it is about, from a party to that
 * message, whether or not the recipient ever wrote to its sender.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { canonicalBytes, messageId, signSignal, timestamp, type Signal } from '@agnt-protocol/protocol';
import type { Extension } from '../src/extensions.ts';
import { Federation, Peer } from './harness.ts';

describe('signals (spec section 6.4)', async () => {
  const told: { recipient: string; signal: Signal }[] = [];
  const listener: Extension = { name: 'listener', on: { signal: e => void told.push(e) } };
  const fed = new Federation();
  after(() => fed.close());
  const alpha = await fed.server('alpha', { extensions: [listener] });
  const peer = new Peer(fed, 'gamma');
  const zed = peer.agent('zed');
  const ada = await alpha.agent('ada');

  const post = async (s: Signal) => {
    const res = await fed.net.request({
      method: 'POST',
      url: `${alpha.origin}/simon/signal`,
      body: canonicalBytes(s),
      maxBytes: 1 << 20,
    });
    await fed.work();
    return res.status;
  };
  const about = (id: string) =>
    signSignal(
      { type: 'typing', from: zed, to: [ada.address], about: id, at: timestamp(fed.clock.t), server: alpha.origin },
      peer.key,
    );

  it('passes a signal about a message the recipient holds, though the recipient never wrote to its sender', async () => {
    const m = peer.message(zed, [ada.address], 'hello from a stranger');
    assert.equal((await peer.post(alpha, peer.envelope(m))).status, 202);
    await fed.work();
    assert.equal(await post(about(messageId(m))), 202);
    assert.deepEqual(
      told.map(t => [t.recipient, t.signal.from, t.signal.type]),
      [[ada.address, zed, 'typing']],
    );
  });

  it('passes a signal of a type it does not know, as the registry names types and servers read none', async () => {
    told.length = 0;
    const m = peer.message(zed, [ada.address], 'about to wave');
    assert.equal((await peer.post(alpha, peer.envelope(m))).status, 202);
    await fed.work();
    const wave = signSignal(
      {
        type: 'x-wave',
        from: zed,
        to: [ada.address],
        about: messageId(m),
        at: timestamp(fed.clock.t),
        server: alpha.origin,
      },
      peer.key,
    );
    assert.equal(await post(wave), 202);
    assert.deepEqual(
      told.map(t => [t.recipient, t.signal.type]),
      [[ada.address, 'x-wave']],
    );
  });

  it('answers 202 and passes nothing about a message the recipient does not hold', async () => {
    told.length = 0;
    assert.equal(await post(about('f'.repeat(64))), 202);
    assert.deepEqual(told, []);
  });

  it('answers 202 and passes nothing from someone who is not a party to the message', async () => {
    told.length = 0;
    const m = peer.message(zed, [ada.address], 'one for ada');
    assert.equal((await peer.post(alpha, peer.envelope(m))).status, 202);
    await fed.work();
    const yan = peer.agent('yan');
    const fromStranger = signSignal(
      {
        type: 'typing',
        from: yan,
        to: [ada.address],
        about: messageId(m),
        at: timestamp(fed.clock.t),
        server: alpha.origin,
      },
      peer.key,
    );
    assert.equal(await post(fromStranger), 202);
    assert.deepEqual(told, []);
  });
});
