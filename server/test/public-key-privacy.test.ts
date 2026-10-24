/** Public key evidence must not carry private account device labels. */
import assert from 'node:assert/strict';
import { it } from 'node:test';
import { addKeyProofString, generateKey, readAgentDocument, readServerDocument, sign } from '@agnt-sdk/simon-protocol';
import { Federation } from './harness.ts';

it('keeps labels in account state and omits them from signed documents and public message keys', async () => {
  const fed = new Federation();
  try {
    const alpha = await fed.server('alpha');
    const ada = await alpha.agent('ada');
    const phone = generateKey();
    const label = 'Private device name';
    const added = await ada.request('POST', '/simon/keys', {
      body: JSON.stringify({
        key: phone.key,
        proof: sign(phone.privateKey, addKeyProofString(ada.address, phone.key)),
        label,
      }),
    });
    assert.equal(added.status, 200);
    const account = await ada.request('GET', '/simon/account');
    assert.equal(account.status, 200);
    assert.equal(account.json.keys.find((k: { key: string }) => k.key === phone.key).label, label);

    const serverResponse = await ada.request('GET', '/simon/server', { sign: false });
    const server = readServerDocument(serverResponse.bytes, alpha.origin, fed.clock.now());
    assert.ok(server);
    const documentResponse = await ada.request('GET', `/simon/agents/${ada.address}`, { sign: false });
    assert.equal(documentResponse.status, 200);
    const document = readAgentDocument(documentResponse.bytes, ada.address, server.keys, fed.clock.now());
    assert.ok(document, 'the stripped document still has a valid server signature');
    const expected = account.json.keys.map(
      ({ key, added, revoked }: { key: string; added: string; revoked: string | null }) => ({
        key,
        added,
        revoked,
      }),
    );
    assert.deepEqual(documentResponse.json.keys, expected);

    const sent = await ada.send(ada.message([], 'A public post with labelled account keys'));
    assert.equal(sent.status, 200);
    const publicMessage = await ada.request('GET', `/simon/messages/${sent.json.id}`, { sign: false });
    assert.equal(publicMessage.status, 200);
    assert.deepEqual(publicMessage.json.keys, expected, 'public convenience keys contain only public key-entry fields');
  } finally {
    await fed.close();
  }
});
