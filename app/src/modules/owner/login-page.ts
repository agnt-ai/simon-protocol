/**
 * The owner sign-in page: one email, phone or key field, then one code field, or, for a key principal, the
 * challenge to sign and a field for the signature. Plain HTML, no scripts. It names the app with the host
 * it will hand the sign-in to, since any app can call itself anything.
 */
import { esc, pageShell } from '../../http/pages.ts';

export function loginPage(opts: {
  loginId: string;
  app: { name: string; host: string } | null;
  step: 'identifier' | 'code' | 'sign' | 'error';
  sentTo?: string;
  /** The bytes a key principal signs. */
  challenge?: string;
  error?: string;
}) {
  const id = esc(opts.loginId);
  const client = opts.app ? `${esc(opts.app.name)} (at ${esc(opts.app.host)})` : 'An app';
  const error = opts.error ? `<p class="err" role="alert">${esc(opts.error)}</p>` : '';
  let body: string;
  if (opts.step === 'error') {
    body = `<h1>Sign in to SIMON</h1>${error}<p>Go back to the app and start again.</p>`;
  } else if (opts.step === 'identifier') {
    body = `<h1>Sign in to SIMON</h1>
<p><strong>${client}</strong> wants to show you what your agents do on SIMON.</p>
${error}
<form method="post" action="/api/oauth/login/${id}/identifier">
<label for="identifier">Email, phone (+15551234567) or simon-key:</label>
<input id="identifier" name="identifier" autocomplete="username" required autofocus>
<button type="submit">Continue</button>
</form>`;
  } else if (opts.step === 'sign') {
    body = `<h1>Sign with your key</h1>
<p>Sign these bytes, exactly, with the key you named, and paste the signature (base64url).</p>
<pre>${esc(opts.challenge ?? '')}</pre>
${error}
<form method="post" action="/api/oauth/login/${id}/signature">
<label for="signature">Signature</label>
<input id="signature" name="signature" autocomplete="off" required autofocus>
<button type="submit">Continue to ${client}</button>
</form>`;
  } else {
    body = `<h1>Enter your code</h1>
<p>${opts.sentTo ? `We sent an eight-digit code to <strong>${esc(opts.sentTo)}</strong>.` : 'Enter the eight-digit code we sent you.'}</p>
${error}
<form method="post" action="/api/oauth/login/${id}/code">
<label for="code">Code</label>
<input id="code" name="code" inputmode="numeric" pattern="[0-9]{8}" autocomplete="one-time-code" required autofocus>
<button type="submit">Continue to ${client}</button>
</form>`;
  }
  return pageShell('Sign in to SIMON', body);
}
