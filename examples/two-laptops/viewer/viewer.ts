/**
 * A read-only, terminal-looking transcript of every message a local SIMON server holds, live in a browser.
 *
 *   node viewer.ts [--db ~/simon/server/simon.sqlite] [--port 8090] [--address agent@host]
 *
 * It serves 127.0.0.1 only, opens the database read-only, and never writes to it. The server's store
 * (server/src/store/sqlite.ts) cannot open a file read-only (it sets WAL and creates the schema), and has no
 * "every message" query, so this reads the tables directly. Written for schema version 3 of that file.
 */
import { createHash } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { homedir } from 'node:os';
import { DatabaseSync } from 'node:sqlite';

/** The `PRAGMA user_version` of server/src/store/sqlite.ts this was written against. */
const SCHEMA_VERSION = 3;
const LIMIT = 1000;

export function openDb(path: string): DatabaseSync {
  let db: DatabaseSync;
  try {
    db = new DatabaseSync(path, { readOnly: true });
  } catch (e) {
    throw new Error(`Cannot open ${path} read-only: ${(e as Error).message}. Is the server's database there?`);
  }
  db.exec('PRAGMA query_only = 1');
  const version = (db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version;
  if (version !== SCHEMA_VERSION) {
    db.close();
    throw new Error(
      `${path} has schema version ${version}; this viewer reads version ${SCHEMA_VERSION} (server/src/store/sqlite.ts). Update the viewer.`,
    );
  }
  return db;
}

/** Invisible or control characters as visible markers, e.g. ⟨U+E0041⟩. Newlines and tabs stay. */
const INVISIBLE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f­؜᠎​-‏‪-‮⁠-⁯﻿￹-￻\u{e0000}-\u{e007f}]/gu;
export const visible = (s: unknown): string =>
  String(s ?? '').replace(INVISIBLE, c => `⟨U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}⟩`);

type Row = Record<string, any>;

/** How many bytes a part's inline data holds: a JSON value's text, or what base64 decodes to. */
const inlineBytes = (p: Row) =>
  typeof p.data === 'string' && !/^\s*(application\/json|[^;\s/]+\/[^;\s]*\+json)\s*(;|$)/.test(p.type)
    ? Buffer.byteLength(p.data, 'base64')
    : Buffer.byteLength(JSON.stringify(p.data ?? null));

/** Every message held here, oldest first, optionally only those from or to one address. */
export function snapshot(db: DatabaseSync, address: string | null = null) {
  const all = (sql: string, ...p: any[]) => db.prepare(sql).all(...p) as Row[];
  const agents = all('SELECT address FROM agents ORDER BY address').map(r => r.address as string);
  const rows = all(
    `SELECT * FROM (SELECT rowid AS seq, * FROM messages ORDER BY received_at DESC, rowid DESC LIMIT ?)
     ORDER BY received_at, seq`,
    LIMIT,
  );
  const inboxOf = (id: string) => all('SELECT address FROM inbox WHERE id = ? ORDER BY cursor', id).map(r => r.address);
  const depth = new Map<string, number>();
  const messages = [];
  for (const r of rows) {
    const m = JSON.parse(r.json);
    const inbox = inboxOf(r.id) as string[];
    const to: string[] = Array.isArray(m.to) ? m.to : [];
    if (address && m.from !== address && !to.includes(address) && !inbox.includes(address)) continue;
    const sent = agents.includes(m.from);
    const parent = typeof m.inReplyTo === 'string' ? m.inReplyTo : null;
    const d = parent && depth.has(parent) ? Math.min(depth.get(parent)! + 1, 6) : 0;
    depth.set(r.id, d);
    messages.push({
      id: r.id as string,
      at: r.received_at as string,
      sentAt: visible(m.sentAt),
      from: visible(m.from),
      to: to.map(visible),
      inReplyTo: parent && visible(parent),
      depth: d,
      // The sender's word only: the registry counts only a principal's signature as evidence.
      human: m.headers?.['human-consulted'] === 'true',
      parts: (Array.isArray(m.parts) ? m.parts : []).map((p: Row) =>
        typeof p.data === 'string' && /^text\//.test(p.type)
          ? { text: visible(p.data) }
          : { label: `[part: ${visible(p.type)}, ${p.size ?? inlineBytes(p)} bytes]` },
      ),
      direction: sent ? 'sent' : 'received',
      deliveries: sent
        ? all('SELECT domain, server, status, reason FROM deliveries WHERE id = ? ORDER BY domain', r.id).map(d => ({
            domain: visible(d.domain),
            server: visible(d.server),
            status: d.status,
            reason: visible(d.reason),
          }))
        : [],
      carrier: visible(r.carrier),
      inbox: inbox.map(visible),
    });
  }
  return { agents: agents.map(visible), address, messages };
}

const STYLE = `
:root { color-scheme: dark; }
body { background: #0b0d0c; color: #c8d3c5; font: 14px/1.45 ui-monospace, Menlo, Consolas, monospace; margin: 0; padding: 16px; }
header { color: #6f7d6c; border-bottom: 1px solid #222; padding-bottom: 6px; margin-bottom: 10px; white-space: pre-wrap; }
.msg { margin: 0 0 12px; white-space: pre-wrap; overflow-wrap: anywhere; }
.head { color: #8fb3ff; } .t { color: #6f7d6c; } .id { color: #555f54; } .re { color: #b39ddb; }
.ok { color: #7bd88f; } .pending { color: #e6c07b; } .failed { color: #ff6b6b; } .meta { color: #6f7d6c; }
.label { color: #9aa59a; font-style: italic; }
.human { border-left: 3px solid #ffb000; padding-left: 8px; color: #ffd27a; }
.tag { background: #ffb000; color: #000; font-weight: bold; padding: 0 4px; }
.cursor { display: inline-block; width: 8px; height: 15px; background: #c8d3c5; animation: b 1s steps(1) infinite; }
@keyframes b { 50% { opacity: 0; } }`;

const SCRIPT = `
const $ = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const out = document.getElementById('log'), head = document.getElementById('head');
let last = '';
const time = iso => { const d = new Date(iso); return isNaN(d) ? iso : d.toLocaleTimeString([], { hour12: false }); };
function line(m) {
  const box = $('div', 'msg' + (m.human ? ' human' : ''));
  box.style.marginLeft = (m.depth * 2) + 'ch';
  const h = $('div');
  h.append($('span', 't', '[' + time(m.at) + '] '), $('span', 'head', m.from + ' → ' + m.to.join(', ')), $('span', 'id', '  #' + m.id.slice(0, 8)));
  if (m.human) h.append(' ', $('span', 'tag', 'HUMAN, SAYS THE SENDER'));
  if (m.direction === 'sent') {
    for (const d of m.deliveries) {
      const cls = d.status === 'delivered' ? 'ok' : d.status;
      h.append($('span', cls, '  (' + d.status + (m.deliveries.length > 1 ? ' @' + d.domain : '') + (d.reason ? ': ' + d.reason : '') + ')'));
    }
    if (!m.deliveries.length) h.append($('span', 'meta', '  (local)'));
  } else h.append($('span', 'meta', '  (via ' + m.carrier + ')'));
  box.append(h);
  if (m.inReplyTo) box.append($('div', 're', '↳ re #' + m.inReplyTo.slice(0, 8)));
  for (const p of m.parts) box.append(p.text != null ? $('div', '', p.text) : $('div', 'label', p.label));
  return box;
}
async function poll() {
  try {
    const res = await fetch('messages.json', { cache: 'no-store' });
    const text = await res.text();
    if (text !== last) {
      last = text;
      const data = JSON.parse(text);
      const pinned = innerHeight + scrollY >= document.body.scrollHeight - 40;
      head.textContent = 'simon viewer · ' + (data.address || data.agents.join(', ') || 'no agents') + ' · ' + data.messages.length + ' messages · read-only';
      out.replaceChildren(...data.messages.map(line));
      if (pinned) scrollTo(0, document.body.scrollHeight);
    }
  } catch (e) { head.textContent = 'simon viewer · cannot reach the viewer: ' + e.message; }
  setTimeout(poll, 2000);
}
poll();`;

const sha = (s: string) => `'sha256-${createHash('sha256').update(s).digest('base64')}'`;
const PAGE = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>simon viewer</title><style>${STYLE}</style></head>
<body><header id="head">simon viewer · loading…</header><div id="log"></div><span class="cursor"></span>
<script>${SCRIPT}</script></body></html>`;
const CSP = `default-src 'none'; script-src ${sha(SCRIPT)}; style-src ${sha(STYLE)}; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;

export function viewer(db: DatabaseSync, opts: { address?: string | null } = {}): Server {
  return createServer((req, res) => {
    const headers = {
      'Content-Security-Policy': CSP,
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
    };
    // Only this machine's own names: a page elsewhere that rebinds DNS to 127.0.0.1 is refused.
    const port = (req.socket.address() as { port: number }).port;
    if (![`127.0.0.1:${port}`, `localhost:${port}`].includes(req.headers.host ?? '') || req.method !== 'GET') {
      res.writeHead(403, headers).end('forbidden');
      return;
    }
    const path = new URL(req.url ?? '/', 'http://x').pathname;
    if (path === '/') res.writeHead(200, { ...headers, 'Content-Type': 'text/html; charset=utf-8' }).end(PAGE);
    else if (path === '/messages.json') {
      try {
        const body = JSON.stringify(snapshot(db, opts.address ?? null));
        res.writeHead(200, { ...headers, 'Content-Type': 'application/json; charset=utf-8' }).end(body);
      } catch (e) {
        res.writeHead(500, headers).end(String((e as Error).message));
      }
    } else res.writeHead(404, headers).end('not found');
  });
}

if (import.meta.main) {
  const args = process.argv.slice(2);
  const flag = (name: string) => {
    const i = args.indexOf(`--${name}`);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const dbPath = (flag('db') ?? `${homedir()}/simon/server/simon.sqlite`).replace(/^~(?=\/)/, homedir());
  const port = Number(flag('port') ?? 8090);
  try {
    const db = openDb(dbPath);
    viewer(db, { address: flag('address') ?? null }).listen(port, '127.0.0.1', () =>
      console.log(`simon viewer: http://127.0.0.1:${port} (reading ${dbPath} read-only)`),
    );
  } catch (e) {
    console.error((e as Error).message);
    process.exit(1);
  }
}
