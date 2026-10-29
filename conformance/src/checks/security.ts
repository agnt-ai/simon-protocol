/**
 * PROTOCOL sections 9 and 11.2, the part of them a live server can be asked about: its TLS (when the suite
 * is pointed at an https origin), whether it follows a redirect when it fetches a document or posts a
 * webhook, the content types it uses, a compressed body that decodes to far more than any cap, and how often
 * it refetches a server document after a failed signature.
 *
 * What a live server cannot be asked is in conformance/readme.md, "What the suite cannot test": whether it
 * connects to a private address (the suite itself needs one allowed), whether it checks the certificate of
 * the servers it calls (the simulator is not behind a certificate), and the deployment-wide bound on
 * lookups. Redirects are tested on two of the calls a server makes, an agent document and a webhook.
 */
import net from 'node:net';
import tls from 'node:tls';
import zlib from 'node:zlib';
import { canonicalize, generateKey } from '@agnt-sdk/simon-protocol';
import { buildFrom, type Ctx } from '../context.ts';
import { poll, problem, sleep, type T } from '../harness.ts';
import { def } from './common.ts';
import { requireControl } from './deliver.ts';
import { plain } from './outbound.ts';

const S = 'PROTOCOL 9';
const S2 = 'PROTOCOL 11.2';

/** The host and port of the origin the suite was pointed at, when it is https. */
function secure(t: T, ctx: Ctx) {
  const url = new URL(ctx.origin);
  if (url.protocol !== 'https:') {
    t.skip(
      `the server under test is at ${ctx.origin}, which is not https: point the suite at the https address your ` +
        'deployment serves (a local run is http by section 3), and see "What the suite cannot test"',
    );
  }
  return { host: url.hostname.replace(/^\[|\]$/g, ''), port: Number(url.port || 443) };
}

interface Handshake {
  protocol: string | null;
  authorized: boolean;
  authorizationError: string | null;
  error: string | null;
}

/** One TLS handshake with the server, offering only the versions given; verifying its certificate or not. */
function handshake(
  host: string,
  port: number,
  o: { minVersion?: tls.SecureVersion; maxVersion?: tls.SecureVersion },
): Promise<Handshake> {
  return new Promise(resolve => {
    const socket = tls.connect({
      host,
      port,
      servername: net.isIP(host) ? undefined : host,
      rejectUnauthorized: false,
      ...o,
    });
    const done = (h: Partial<Handshake>) => {
      socket.destroy();
      resolve({ protocol: null, authorized: false, authorizationError: null, error: null, ...h });
    };
    socket.setTimeout(15_000, () => done({ error: 'no handshake within 15 s' }));
    socket.once('secureConnect', () =>
      done({
        protocol: socket.getProtocol(),
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
      }),
    );
    socket.once('error', e => done({ error: e.message }));
  });
}

def(
  {
    id: 'security.tls-version',
    section: `${S} "HTTP", ${S2} "Transport"`,
    level: 'must',
    title: 'The server speaks TLS 1.3 and refuses anything older',
    expected:
      'a handshake offering TLS 1.3 only completes as TLS 1.3; a handshake offering TLS 1.2 at most fails (needs an https origin; skipped for a local http run)',
  },
  async (t: T, ctx: Ctx) => {
    const { host, port } = secure(t, ctx);
    const modern = await handshake(host, port, { minVersion: 'TLSv1.3' });
    t.assert(
      modern.protocol === 'TLSv1.3',
      `a TLS 1.3 handshake gave ${modern.protocol ?? `an error: ${modern.error}`}`,
    );
    const old = await handshake(host, port, { maxVersion: 'TLSv1.2' });
    t.assert(old.protocol === null, `a handshake offering TLS 1.2 at most completed as ${old.protocol}`);
  },
);

def(
  {
    id: 'security.tls-certificate',
    section: `${S} "HTTP", ${S2} "Transport"`,
    level: 'must',
    title: 'The server authenticates itself as RFC 9525 says',
    expected:
      "the certificate the server presents verifies, against the system's trusted roots, for the host name (or address) of the origin the suite was given (needs an https origin; skipped for a local http run)",
  },
  async (t: T, ctx: Ctx) => {
    const { host, port } = secure(t, ctx);
    const h = await handshake(host, port, { minVersion: 'TLSv1.3' });
    t.assert(h.protocol, `no TLS 1.3 handshake to check the certificate in: ${h.error}`);
    t.assert(h.authorized, `the certificate for ${host} does not verify: ${h.authorizationError}`);
  },
);

def(
  {
    id: 'security.no-redirect-agent-document',
    section: `${S} "HTTP", ${S2} "Transport", PROTOCOL 6.3`,
    level: 'must',
    title: 'A redirect is not followed when a document is fetched',
    expected:
      'a delivery from an agent whose document the simulator answers with a 302 to a path that serves the valid document is not accepted, and the simulator sees no request for the path it redirected to',
  },
  async (t: T, ctx: Ctx) => {
    await requireControl(ctx);
    const a = await ctx.agent('a');
    const p = ctx.peer.agent('redirected', { doc: 'redirect' });
    const m = buildFrom(p, [a.address], ctx.now());
    const res = await ctx.deliver(t, ctx.peer.envelope(m), 'a delivery from an author whose document redirects');
    const followed = ctx.peer.requests.filter(r => r.target.startsWith('/simon/agents-moved/'));
    t.assert(
      followed.length === 0,
      `the server followed the redirect: ${followed.length} request(s) for ${followed[0]?.target}`,
    );
    t.assert(
      res.status >= 400,
      `the message of an author whose document redirects was answered ${res.status}, not refused`,
    );
  },
);

def(
  {
    id: 'security.no-redirect-webhook',
    section: `${S} "HTTP", ${S2} "Transport", CLIENT webhooks`,
    level: 'must',
    title: 'A redirect is not followed when a webhook is posted',
    expected:
      'a webhook URL that answers the verify post with a 307 is posted to once; the simulator sees no request for the path it redirected to',
  },
  async (t: T, ctx: Ctx) => {
    await requireControl(ctx);
    const a = await ctx.agent('hooks');
    const name = `redirect-${ctx.runId}`;
    ctx.peer.answerHook(name, 'redirect');
    const res = await a.call(
      t,
      'POST',
      '/simon/webhooks',
      canonicalize({ url: ctx.peer.hookUrl(name) }),
      {},
      'create a webhook that redirects',
    );
    if (res.status === 404 || res.status === 405) t.skip('the server offers no webhooks (POST /simon/webhooks)');
    if (res.status === 400 && problem(res)?.details?.field === 'url' && ctx.peer.origin.startsWith('http:'))
      t.skip('the server takes only https webhook URLs; put the simulator behind a tunnel (--peer-origin)');
    t.status(res, [200, 201], 'creating the webhook');
    try {
      const first = await poll(async () => ctx.peer.postsTo(name)[0], ctx.opts.deliveryWaitMs, 100);
      if (!first) t.fail('the server never posted to the webhook URL');
      await sleep(2000);
      const followed = ctx.peer.requests.filter(r => r.target.startsWith('/hooks-moved/'));
      t.assert(
        followed.length === 0,
        `the server followed the redirect: ${followed.length} request(s) for ${followed[0]?.target}`,
      );
    } finally {
      await a.call(t.scratch(), 'DELETE', `/simon/webhooks/${res.json.id}`).catch(() => undefined);
    }
  },
);

/** The media type of an answer or request, without parameters, in lower case. */
const mediaType = (value: string | undefined) => (value ?? '').split(';')[0]!.trim().toLowerCase();

def(
  {
    id: 'security.json-content-type',
    section: `${S} "HTTP"`,
    level: 'must',
    title: 'JSON bodies are sent as application/json',
    expected:
      'the server document, an agent document, a sync answer, the 202 of a delivery and the delivery the server makes to the simulator each have Content-Type application/json (parameters allowed)',
  },
  async (t: T, ctx: Ctx) => {
    await requireControl(ctx);
    const a = await ctx.agent('a');
    const seen: [string, string | undefined][] = [];
    const get = async (what: string, res: { headers: Record<string, string>; status: number }, status = 200) => {
      t.assert(res.status === status, `${what}: expected ${status}, got ${res.status}`);
      seen.push([what, res.headers['content-type']]);
    };
    await get('the server document', (await ctx.serverDoc()).res);
    await get(
      'an agent document',
      await t.http({ method: 'GET', origin: ctx.origin, target: `/simon/agents/${a.address}` }),
    );
    await get('sync', await a.sync(t));
    const p = ctx.peer.agent('content-type');
    await get(
      'a delivery',
      await ctx.deliver(t, ctx.peer.envelope(buildFrom(p, [a.address], ctx.now())), 'a delivery'),
      202,
    );
    const { m } = await plain(ctx);
    const text = canonicalize(m);
    const out = await poll(async () => ctx.peer.received.find(r => r.messageText === text), ctx.opts.deliveryWaitMs);
    if (out) seen.push(['the server’s delivery to the simulator', out.headers['content-type']]);
    const wrong = seen.filter(([, type]) => mediaType(type) !== 'application/json');
    t.assert(
      wrong.length === 0,
      wrong.map(([what, type]) => `${what} has Content-Type ${JSON.stringify(type)}`).join('; '),
    );
  },
);

def(
  {
    id: 'security.content-encoding',
    section: `${S2} "Resource exhaustion"`,
    level: 'must',
    title: 'A compressed body is bounded by what it decodes to, not by what was transferred',
    expected:
      'a delivery whose gzip, deflate or Brotli body is under 100 KB and decodes to 48 MiB is refused with a 4xx (the encoding refused, or the decoded size), is answered promptly, and leaves the server answering',
  },
  async (t: T, ctx: Ctx) => {
    const zeros = Buffer.alloc(48 * 1024 * 1024);
    const encoders: [string, Buffer][] = [
      ['gzip', zlib.gzipSync(zeros)],
      ['deflate', zlib.deflateSync(zeros)],
      ['br', zlib.brotliCompressSync(zeros)],
    ];
    for (const [encoding, body] of encoders) {
      t.assert(body.length < 100 * 1024, `the ${encoding} test body is ${body.length} bytes`);
      const res = await t.http(
        {
          method: 'POST',
          origin: ctx.origin,
          target: '/simon/deliver',
          headers: { 'content-encoding': encoding },
          body,
        },
        { label: `a ${encoding} body that decodes to 48 MiB` },
      );
      t.assert(
        res.status >= 400 && res.status < 500,
        `a ${encoding} body of ${body.length} bytes that decodes to 48 MiB was answered ${res.status}, expected a 4xx`,
      );
    }
    const alive = await t.http(
      { method: 'GET', origin: ctx.origin, target: '/simon/server' },
      { label: 'the server afterwards' },
    );
    t.status(alive, 200, 'the server after the compressed bodies');
  },
);

def(
  {
    id: 'security.refetch-bounded',
    section: `${S2}, PROTOCOL 4`,
    level: 'must',
    title: 'Bad signatures make a server refetch a server document at most once a minute',
    expected:
      'twenty envelopes naming the simulator, signed by a key its document does not list, are all refused, and the simulator sees at most one request for its server document while they are sent',
  },
  async (t: T, ctx: Ctx) => {
    await requireControl(ctx);
    const a = await ctx.agent('a');
    const p = ctx.peer.agent('refetch');
    const stranger = generateKey().privateKey;
    const documents = () =>
      ctx.peer.requests.filter(r => r.method === 'GET' && r.target.split('?')[0] === '/simon/server').length;
    const before = documents();
    // One after another: requests made together may share one fetch, which proves nothing about the bound.
    const answers = [];
    for (let i = 0; i < 20; i++) {
      const m = buildFrom(p, [a.address], ctx.now());
      answers.push(
        await ctx.deliver(t, ctx.peer.envelope(m, { signer: stranger }), `delivery ${i + 1} signed by an unlisted key`),
      );
    }
    const taken = answers.filter(r => r.status === 202).length;
    t.assert(taken === 0, `${taken} envelope(s) signed by a key the simulator does not list were accepted`);
    const fetched = documents() - before;
    t.assert(
      fetched <= 1,
      `the server fetched the simulator's server document ${fetched} times within a few seconds of bad signatures`,
    );
  },
);
