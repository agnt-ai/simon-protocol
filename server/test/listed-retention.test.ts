/** Accepted same-author listing suppression survives deletion and reacceptance of its target. */
import assert from 'node:assert/strict';
import { it } from 'node:test';
import { messageId, type AnyMessage } from '@agnt-protocol/protocol';
import { Federation } from './harness.ts';

it('keeps a reaccepted relation out of the HTTP listing after its accepted retraction record is removed', async () => {
  const fed = new Federation();
  try {
    const alpha = await fed.server('alpha'),
      beta = await fed.server('beta');
    const ada = await alpha.agent('ada'),
      bob = await beta.agent('bob'),
      eve = await beta.agent('eve');
    const post = await ada.send(ada.message([], 'A published post.'));
    assert.equal(post.status, 200);
    const reply = bob.message([ada.address], 'A relation whose writer opted in.', {
      inReplyTo: post.json.id,
      headers: { rel: 'comment', listed: 'yes' },
    });
    const id = messageId(reply);
    assert.equal((await bob.send(reply)).status, 200);
    await fed.work();
    const related = async () => {
      const res = await ada.request('GET', `/simon/messages/${post.json.id}/related`, { sign: false });
      assert.equal(res.status, 200);
      return res.json.messages.map((m: AnyMessage) => messageId(m));
    };
    assert.deepEqual(await related(), [id], 'an unsuppressed relation is visible through the actual route');
    const saved = await alpha.store.message(id);
    assert.ok(saved);

    // A different writer cannot suppress Bob's signed opt-in relation.
    const wrongAuthor = await eve.send(
      eve.message([ada.address], '', {
        inReplyTo: id,
        headers: { rel: 'retract' },
      }),
    );
    assert.equal(wrongAuthor.status, 200);
    await fed.work();
    const deliveredWrongAuthor = await alpha.store.message(wrongAuthor.json.id);
    assert.ok(deliveredWrongAuthor, 'the wrong-author retraction actually reached the listing server');
    assert.equal(deliveredWrongAuthor.message.from, eve.address);
    assert.deepEqual(await related(), [id]);

    const accepted = await bob.send(
      bob.message([ada.address], '', {
        inReplyTo: id,
        headers: { rel: 'retract' },
      }),
    );
    assert.equal(accepted.status, 200);
    await fed.work();
    assert.ok(await alpha.store.message(accepted.json.id), 'the signed retraction was actually delivered');
    assert.deepEqual(await related(), []);

    // Exercise retained suppression after both live records disappear, then create a new target/inbox
    // incarnation. Deletion is explicit here; the shared Store contract separately checks expiry.
    await alpha.store.deleteMessage(accepted.json.id);
    assert.equal(await alpha.store.message(accepted.json.id), null, 'no live retraction remains to rescan');
    await alpha.store.deleteMessage(id);
    assert.equal(await alpha.store.message(id), null);
    await alpha.store.putMessage(saved);
    assert.ok(await alpha.store.addToInbox(ada.address, id, fed.clock.now().toISOString()));
    assert.ok(await alpha.store.inInbox(ada.address, id), 'the original is a real new listing candidate');
    const candidates = await alpha.store.repliesTo(ada.address, post.json.id, null, 50);
    assert.ok(
      candidates.records.some(r => r.message.id === id),
      'raw listing candidates include the reaccepted target',
    );
    assert.deepEqual(await related(), [], 'accepted suppression remains effective through the HTTP listing');
  } finally {
    await fed.close();
  }
});
