/** The owner window: signing in over OAuth 2.1, and what a person sees and controls of their agents. */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { pkceS256, randomToken } from '../src/lib/secrets.ts';
import { World } from './harness.ts';

describe('the owner window', async () => {
  const world = new World();
  after(() => world.close());
  const alpha = await world.app('alpha');
  const peer = await world.basic('beta', { trustedClaimServers: [alpha.origin] });
  const form = (body: Record<string, string>) => ({
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body).toString(),
  });

  it("shows what a person's agents sent and received for them, and everything they did, in order", async () => {
    const ann = await alpha.joined('ann@o1.test');
    const bob = await peer.agent('bob');
    const { id } = await ann.agent.send({ to: [bob.address!], text: 'hello' });
    await world.work();
    await bob.send({ to: [ann.agent.address!], text: 'hi back', inReplyTo: id });
    await world.work();
    const owner = await alpha.owner('ann@o1.test');
    const messages = (await owner.messages()).items;
    assert.deepEqual(
      messages.map(m => [m.direction, m.agent]),
      [
        ['sent', ann.agent.address],
        ['received', ann.agent.address],
      ],
    );
    assert.equal(messages[0].id, id);
    const kinds = (await owner.activity()).items.map(e => e.kind);
    assert.deepEqual(kinds.slice(0, 4), ['person_claimed', 'agent_paired', 'owner_signed_in', 'listing_changed']);
    const page = await owner.activity({ limit: 2 });
    assert.equal(page.more, true);
    assert.equal((await owner.activity({ after: page.cursor! })).items[0].kind, kinds[2]);
  });

  it('shows an attestation about the owner to others once they confirm it, and hides it when they say so', async () => {
    const subject = await alpha.joined('subject@o2.test');
    const writer = await alpha.joined('writer@o2.test');
    const reader = await alpha.joined('reader@o2.test');
    await writer.approved.attest({ person: subject.person }, [{ field: 'title', value: 'Unflattering summary' }]);
    const shown = async () =>
      (await reader.api.profile(subject.person)).facts.some(f => f.value === 'Unflattering summary');
    assert.equal(await shown(), false);
    const owner = await alpha.owner('subject@o2.test');
    const target = (await owner.attestations('about')).items.find(a => a.value === 'Unflattering summary')!;
    await owner.dispose(target.id, 'confirmed');
    assert.equal(await shown(), true);
    await owner.dispose(target.id, 'hidden');
    assert.equal(await shown(), false);
  });

  it('refuses agent signatures where an owner token is needed, and owner tokens where a signature is', async () => {
    const p = await alpha.joined('cross@o3.test');
    const { access_token } = await alpha.signIn('cross@o3.test');
    const res = await world.fetch(`${alpha.origin}/api/agents/me/home`, {
      headers: { authorization: `Bearer ${access_token}` },
    });
    assert.equal(res.status, 401);
    await assert.rejects(p.agent.call('GET', '/api/me'), { code: 'owner_token_required' });
  });

  it('names the app by the host it signs people in to, and keeps API keys for scripts', async () => {
    await alpha.joined('olive@o4.test');
    const owner = await alpha.owner('olive@o4.test');
    assert.match(world.outbox.last('olive@o4.test')!.text, /an app at portal\.example\.com/);
    const { key, id } = await owner.createApiKey('nightly');
    const scripted = await world.fetch(`${alpha.origin}/api/me`, { headers: { authorization: `Bearer ${key}` } });
    assert.equal(scripted.status, 200);
    await owner.revokeApiKey(id);
    assert.equal(
      (await world.fetch(`${alpha.origin}/api/me`, { headers: { authorization: `Bearer ${key}` } })).status,
      401,
    );
  });

  it('enforces PKCE, exact redirect URIs and one-time codes, and spends a refresh token once', async () => {
    const register = (body: unknown) =>
      world.fetch(`${alpha.origin}/api/oauth/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
    const client = await (await register({ client_name: 'Viewer', redirect_uris: ['https://viewer.test/cb'] })).json();
    assert.equal((await register({ redirect_uris: ['http://evil.test/cb'] })).status, 400);
    assert.equal(
      (await register({ client_name: 'see evil.test', redirect_uris: ['https://viewer.test/cb'] })).status,
      400,
    );
    const verifier = randomToken();
    const authorize = (o: Record<string, string> = {}) =>
      world.fetch(
        `${alpha.origin}/api/oauth/authorize?${new URLSearchParams({ response_type: 'code', client_id: client.client_id, code_challenge: pkceS256(verifier), code_challenge_method: 'S256', redirect_uri: 'https://viewer.test/cb', ...o })}`,
      );
    assert.equal((await authorize({ redirect_uri: 'https://viewer.test/other' })).status, 400);
    assert.equal((await authorize({ code_challenge_method: 'plain' })).status, 400);
    const login = (await authorize()).headers.get('location')!;
    assert.match(await (await world.fetch(`${alpha.origin}${login}`)).text(), /Viewer/);
    await world.fetch(`${alpha.origin}${login}/identifier`, form({ identifier: 'pkce@o5.test' }));
    const done = await world.fetch(`${alpha.origin}${login}/code`, form({ code: world.outbox.code('pkce@o5.test') }));
    const code = new URL(done.headers.get('location')!).searchParams.get('code')!;
    const token = (v: string) =>
      world.fetch(
        `${alpha.origin}/api/oauth/token`,
        form({
          grant_type: 'authorization_code',
          code,
          code_verifier: v,
          client_id: client.client_id,
          redirect_uri: 'https://viewer.test/cb',
        }),
      );
    assert.deepEqual(await (await token('wrong-verifier-wrong-verifier-wrong-verifier')).json(), {
      error: 'invalid_grant',
      error_description: 'PKCE verification failed.',
    });
    assert.equal((await token(verifier)).status, 400, 'any attempt spends the code');

    const session = await alpha.signIn('refresh@o5.test');
    const refresh = () =>
      world.fetch(
        `${alpha.origin}/api/oauth/token`,
        form({ grant_type: 'refresh_token', refresh_token: session.refresh_token, client_id: session.client_id }),
      );
    assert.deepEqual((await Promise.all([refresh(), refresh()])).map(r => r.status).sort(), [200, 400]);
  });
});
