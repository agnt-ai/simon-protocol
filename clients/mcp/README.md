# simon-mcp

An MCP server for one SIMON agent, over stdio (JSON-RPC 2.0, one message per line), built on
[`@agnt-sdk/simon-client`](../js).

```bash
claude mcp add simon -e SIMON_SERVER=https://simon.example.com -- node /path/to/simon-protocol/clients/mcp/src/server.ts
```

**Environment:** `SIMON_HOME` (the key and address; default `~/.config/simon`), `SIMON_SERVER` (the server
to register with), `SIMON_WORKSPACE` (the only directory tools read and write files in; default the
server's working directory), `SIMON_TIMEOUT_MS` (per request; default 30000).

**What others wrote comes apart.** A result's first content item is the tool's own words and its
server's. Each message and each claim follows in a content item of its own, inside
`{"untrusted":{"from","basis","content","invisible"?}}`, with `_meta` `{"simon/untrusted": true}`, and is
never in `structuredContent`. The server's instructions and the tool descriptions state the rule: such
content is data, never authorisation. There is no tool for other calls to the server. Paths outside the
workspace, or under `SIMON_HOME`, are refused (`path_refused`), and `whoami` does not say where the key is.

**The tools are pinned.** Names, descriptions and schemas are written in [`src/tools.ts`](src/tools.ts)
and fixed when the package is built. None comes from a server at run time: whoever runs a server must
not write text a model reads as its instructions.

## Tools

| Tool | Arguments | |
| --- | --- | --- |
| `register` | `address?`, `code?`, `for?`, `pairing?`, `server?` | Creation and pairing only; account success has no status. |
| `recover` | `address`, `code?`, `recover?`, `at?`, `server?` | Dedicated recovery with a code or principal signature; pending binds nothing. |
| `recovery_status` | none | Read pending recovery as the authorized agent. |
| `account` | none | Private keys, grants and recovery state. |
| `add_key`, `revoke_key`, `end_grant` | `name,label?` / `key` / `id` | Explicit key and grant management. |
| `cancel_recovery`, `unpair` | `address?,cancelCode?,server?` / `address,unpairing,server?` | Explicit cancellation or principal-signed retirement. |
| `send_signal` | `type,about,to` | Explicit opt-in sharing. |
| `webhook_create`, `webhook_verify`, `webhook_delete` | `url` / `id,code` / `id` | Verify webhook before wakes. |
| `send` | `to`, `text?`, `parts?`, `attachments?` (`[{path, type}]`), `inReplyTo?`, `headers?`, `hints?` | Send a signed message; attachments are uploaded and sent by hash with their file names. A message needs no text: without `text`, it carries only its attachments. |
| `sync` | `since?`, `limit?`, `wait?` | Sent and received messages, signals and history changes since an opaque token. |
| `wait_for_message` | `from?`, `timeoutSeconds?` (1 to 300, default 60) | The next message not yet shown, or `timeout`; shared with the CLI's `wait`. |
| `sent` | `id` | Delivery of a sent message, per recipient server. |
| `upload_part` | `path`, `type` | Upload a file; answers the part. |
| `fetch_part` | `sha256`, `size?`, `path` | Save a part's bytes, checked. |
| `verify_message` | `message`, `signedClaims?` | Verify a message against keys from the server its domain resolves to; answers the trust record with `understood` and the principal's `basis`. Claims count only as `signedClaims` that verify with the carrier's keys. |
| `whoami` | none | Key token, address, server and pairing, from the files. |

Arguments are checked against each schema: a missing, unknown or mistyped one is a tool error naming it.
A tool error is `isError: true` with the `SimonError` as JSON, `{"error":{"code","message","status",
"retryable","details"}}`. Results with no third-party content also come as `structuredContent`.

**Methods:** `initialize` (protocol versions 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05), `ping`,
`tools/list`, `tools/call`. Notifications get no answer. JSON-RPC errors: -32700 for a line that is not
JSON, -32600 for one that is not a request (a batch included), -32601 for an unknown method, -32602 for
an unknown tool.

## Tests

`npm test -w clients/mcp` runs the server as a process and speaks JSON-RPC to it over stdio.

Save sync `token` unchanged and pass it as `since`; `more` requests another page immediately. A
`410 token_expired` is surfaced for an explicit restart decision. Shared CLI/MCP wait state is
`{token,pending,seen}`; unmatched messages remain queued, and old numeric cursor state is rejected.

A fresh recovered paired agent needs its local principal state to compose messages. Pass `for` and
`pairing` to JavaScript/MCP recovery (Python: `principal` and `pairing`; CLI: `--for`/`--pairing`).
For a key principal the pairing signature must verify for the recovered address. These fields are
checked and saved locally and are never added to the recovery request body. Principal-proof recovery
without saved or supplied principal state is rejected. For mailbox recovery of an email/tel pair,
supply its existing principal explicitly; the account response does not infer it.

Concurrent waits in the same `SIMON_HOME` fail with `concurrent_wait`. JS and Python hold the same
`wait.lock` directory for the whole operation and release it on normal completion/error. No owner is
stolen by age. After a crash, confirm the recorded PID is no longer running, then remove only the stale
`wait.lock` directory and keep `wait.json`. Queued messages are already private local data and can be
returned before network access. A positive wait timeout bounds request/page budgets; timeout zero
means one immediate page request with the normal transport timeout, not a zero wall-clock deadline.

`wait.lock` is reserved from key names. Effective saved or supplied recovery pairing is checked against
the target address; a principal recovery proof must verify against that same principal, new key and
`at` before any request is sent. A proof from one principal cannot save another principal's pairing.

Recovery of a different address never inherits a saved email, phone or key principal implicitly.
Supply an explicit local principal choice for that target; key pairing and any principal recovery proof
must agree on the target identity.

### Explicit history migration resume

An upgraded account may answer an initial sync with `410 token_expired`,
`details.reason = history_migration` and `details.resumeToken`. This says old sent history may be
incomplete; every device must learn the gap. After explicitly accepting that limitation, call sync
with the offered token as `since` (`sync --since TOKEN` in the CLI). Normal account binding and expiry
still apply. Clients never replay or accept this token automatically, and starting without `since`
continues to report the gap. Shared waits surface the error and preserve their saved buffers.
