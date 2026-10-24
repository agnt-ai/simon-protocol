/**
 * This application's few HTML pages (owner sign-in, the link sent after a key recovery): one frame,
 * escaping, and the headers every page is served with. No scripts.
 */
import type { Reply } from '@agnt-protocol/server';

export const esc = (s: string) =>
  s.replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!);

/** The shared frame for this server's few plain pages: no scripts, light and dark. */
export function pageShell(title: string, body: string) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<style>
:root{color-scheme:light dark;--bg:#fafaf9;--fg:#1c1917;--muted:#57534e;--line:#d6d3d1;--accent:#1c1917;--accent-fg:#fafaf9;--err:#b91c1c}
@media (prefers-color-scheme:dark){:root{--bg:#0c0a09;--fg:#f5f5f4;--muted:#a8a29e;--line:#44403c;--accent:#f5f5f4;--accent-fg:#0c0a09;--err:#f87171}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;padding:16px;box-sizing:border-box}
main{width:100%;max-width:360px}h1{font-size:22px;margin:0 0 8px}p{color:var(--muted)}label{display:block;margin:16px 0 6px;font-size:14px}
input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:transparent;color:var(--fg);font-size:16px}
button{margin-top:16px;width:100%;padding:10px 12px;border:0;border-radius:8px;background:var(--accent);color:var(--accent-fg);font-size:16px;cursor:pointer}
button.secondary{background:transparent;color:var(--fg);border:1px solid var(--line)}code{font-size:14px}
pre{font-size:13px;white-space:pre-wrap;word-break:break-all;border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.err{color:var(--err)}
</style></head><body><main>${body}</main></body></html>`;
}

/** A page as a reply: nothing loads from elsewhere, nothing frames it, nothing caches it. */
export const htmlPage = (html: string, status = 200): Reply => ({
  status,
  bytes: Buffer.from(html),
  headers: {
    'content-type': 'text/html; charset=utf-8',
    'content-security-policy':
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https: http://127.0.0.1:* http://localhost:*; frame-ancestors 'none'",
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    'cache-control': 'no-store',
  },
});

/** A redirect, for the browser to follow. */
export const redirect = (location: string): Reply => ({
  status: 302,
  headers: { location, 'cache-control': 'no-store' },
});
