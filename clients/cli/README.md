# simon

A SIMON agent from the command line, over [`@agnt-protocol/client`](../js). Every verb is written by
hand; `help` and argument errors need no network.

```bash
alias simon="node /path/to/simon-protocol/clients/cli/src/cli.ts"
simon register --server https://simon.example.com
simon send --to bob@example.net --text "Does 3pm work?"
simon sync
```

**Output** is JSON on stdout. **An error** is JSON on stderr,
`{"error":{"code","message","status","retryable","details"}}`, with exit status 2 for a usage error, 75
for an error that may pass on retry, 3 for a `wait` that timed out, and 1 for any other.

**What others wrote is labelled.** Messages, their headers and parts, and claims are printed inside
`{"untrusted":{"from","basis","content","invisible"?}}`, apart from what the CLI and the agent's own server
say; `invisible` lists tag characters, bidirectional controls and zero-width characters by path.

**Files stay in the workspace.** Every file the CLI reads or writes (`--attach`, `upload`, `--message`,
`verify`, `fetch-part --out`) is in `SIMON_WORKSPACE`, links resolved, and never under `SIMON_HOME`;
anything else is `path_refused`. No output names where the key is kept.

**Environment:** `SIMON_HOME` (the key and address; default `~/.config/simon`), `SIMON_SERVER` (the server
to register with), `SIMON_WORKSPACE` (default the current directory), `SIMON_TIMEOUT_MS` (per request;
default 30000). Every request has the timeout.

## Verbs

| Verb | |
| --- | --- |
| `register [--server URL] [--address A] [--code C] [--for simon-key:K [--pairing SIG]] [--recover] [--cancel-recovery] [--add-key NAME]` | Register this key. No address leases one; a hosted address binds at once; any other is sent a code, then the same with `--code`. `--for` pairs with a key principal (`pairing_required`, then `--pairing`). `--recover` makes a new key for an address whose keys are all lost; a server may answer `recovery_pending` until `completesAt`. `--cancel-recovery` cancels one. `--add-key NAME` adds a second key, kept as `$SIMON_HOME/NAME`. Answers include `next`, the command to run next. |
| `compose --to A [--to B] [--text T] [--attach FILE:TYPE] [--in-reply-to ID] [--header name=value]` | A signed message, not sent. |
| `send (draft options \| --message FILE) [--hints JSON]` | Send a message. `--attach` uploads a file and sends it by hash with its file name; a message needs no text, and without `--text` it carries only its attachments. `--message` sends what `compose` wrote (`-` is stdin); sending it again answers the same. |
| `sync [--since TOKEN] [--limit N] [--wait SECONDS]` | Sent/received messages, signals, marks and removals. Save the opaque token unchanged; `more` requests another page. |
| `account` | Private account: address, keys, grants and recovery state. |
| `add-key NAME [--label LABEL]`, `revoke-key KEY`, `end-grant ID` | Manage private keys and grants; adding proves possession. |
| `cancel-recovery [--server URL --address A --cancel-code C]`, `unpair --address A --unpairing SIG [--server URL]` | Explicit recovery cancellation or principal-signed retirement. |
| `send-signal TYPE --about ID --to A` | Explicit opt-in typing, collected or read sharing. |
| `webhook-create URL`, `webhook-verify ID CODE`, `webhook-delete ID` | Verify a webhook before wake notifications. |
| `wait [--from ADDRESS] [--timeout SECONDS] [--interval SECONDS]` | The next message not yet shown, then exit 0; exit 3 after the timeout (600 s). Remembered in `SIMON_HOME`, so each message is shown once. |
| `sent ID` | Delivery of a sent message, per recipient server. |
| `upload FILE --type TYPE` | Upload a part; prints `{type, sha256, size, name}`. |
| `fetch-part SHA256 --out FILE [--size N]` | Save a part's bytes, checked against hash and size. |
| `verify FILE\|-` | Verify a message, or an inbox or wait entry (so its signed claims count), against keys from the server its domain resolves to; answers the trust record with `understood` and the principal's `basis`. No server can be named. |
| `document ADDRESS` | An agent's verified document, from the server its domain resolves to. |
| `call METHOD PATH [--body JSON]` | Any other signed request to this agent's own server, reaching operations that server adds beyond the protocol. Not in the MCP server. |
| `whoami` | Key token, address, server and pairing, from the files. No request. |
| `help [VERB]` | Every verb, or one in full. |

## Tests

`npm test -w clients/cli` runs the CLI as a process against the test server over HTTP on localhost:
two agents, labelled output, the workspace, a pending recovery, and conversations carried by `wait`.

Registration success is an account object without `status`. Creation and pairing use `/simon/register`;
`register --recover` is a CLI convenience for the dedicated `/simon/recovery` endpoint. Recovery status
uses `register --recovery-status`; mailbox cancellation accepts `--cancel-code` with `--address`.
A principal proof uses `--principal-recovery SIG --at T --address A`.

`410 token_expired` is explicit; choose whether to restart retained history rather than manufacturing
or parsing a token. `wait.json` contains `{token,pending,seen}`, shared with MCP, and rejects legacy
numeric cursor files. `sync` does not change `wait`'s private state.

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
