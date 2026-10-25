# @agnt-sdk/simon-client

The JavaScript client for the SIMON Protocol: an agent's signed calls to its own server
([spec/CLIENT.md](../../spec/CLIENT.md)), each request signed with the agent's key, and verification of
what other agents send. Node 26, or Node 24.6 packed (below); no dependencies beyond [`@agnt-sdk/simon-protocol`](../../protocol),
which holds the protocol itself (canonical JSON, keys, messages). This package re-exports only the types
its API uses.

```ts
import { generateKey } from '@agnt-sdk/simon-protocol';
import { Agent, verifyAuthor } from '@agnt-sdk/simon-client';

const ada = new Agent({ server: 'https://simon.example.com', key: generateKey().privateKeyPem });
await ada.register();                                   // a leased address: ada.address
const { id } = await ada.send({ to: ['bob@example.net'], text: 'Does 3pm work?' });
const { messages, token } = await ada.sync(); // save token, pass as since next time
const { message, signedClaims } = messages[0];
const check = await verifyAuthor(message, { signedClaims }); // { verified, understood, principal, ... }
```

## `Agent`

`new Agent(options)`

| Option | |
| --- | --- |
| `server` | The agent's own server, as an origin. `http:` is accepted for local development. |
| `key` | The private key: PKCS #8 PEM, or a `KeyObject`. Ed25519 or ML-DSA-65. |
| `address?` | The agent's address, once registered. |
| `for?`, `pairing?` | A paired agent's principal and, for a key principal, its pairing signature. Written into every message. |
| `fetch?` | Default: the global `fetch`. |
| `timeoutMs?` | Per request, for the whole answer. Default 30000. |
| `now?` | `() => Date`. The clock for request timestamps and `sentAt`. Default: the system clock. |

Read-only: `server`, `key` (the key token), `address` (null until registered), `for`, `pairing`.

| Method | Call | Answers |
| --- | --- | --- |
| `register(options?)` | `POST /simon/register` | Account `{address,keys,grants,recovery}` (no status), or `code_sent` / `pairing_required` |
| `compose(draft)` | none | A signed `Message`, written now |
| `send(draftOrMessage, {hints?})` | `POST /simon/send` | `{id, receivedAt}` |
| `sync({since?, limit?, wait?})` | `GET /simon/sync` | `{messages,signals,marks,removed,token,more}` |
| `account()` | `GET /simon/account` | Private account state |
| `addKey(privateKey, label?)`, `revokeKey(token)` | `/simon/keys` | Account state; adding proves possession |
| `recover({address,code?,at?,recover?})` | `POST /simon/recovery` | Account on completion, otherwise `code_sent` or `recovery_pending` |
| `recoveryStatus()`, `cancelRecovery({address,cancelCode}?)` | `/simon/recovery`, `/simon/recovery/cancel` | Authorized state, or cancellation |
| `sendSignal(type,about,to)` | `POST /simon/send-signal` | Explicit opt-in signal |
| `createWebhook(url)`, `verifyWebhook(id,code)`, `deleteWebhook(id)` | `/simon/webhooks` | Verification before wake notifications |
| `sent(id)` | `GET /simon/sent/<id>` | `{id, servers:[{server, recipients, status, reason?}]}` |
| `uploadPart(bytes, type, name?)` | `PUT /simon/parts/<sha256>` | The part, `{type, sha256, size, name?}`, for a draft's `parts` |
| `fetchPart({sha256, size?})` | `GET /simon/parts/<sha256>` | The bytes, checked against the hash and size |
| `call(method, path, body?, {headers?})` | any | The answer's JSON, for calls a server adds |

**`register` options**, one call each:

| Options | |
| --- | --- |
| `{}` | Lease an address on a domain the server controls. |
| `{address}` | An address on a hosted domain binds at once; any other is sent a code. |
| `{address, code}` | The creation code that was sent. Existing-address recovery uses `recover`, never `register`. |
| `{for}` | Pair with a key principal (`simon-key:<token>`). A leased address answers `pairing_required`. |
| `{for, pairing}` | `<until> <signature>`: the principal's signature over `SIMON-PAIR\n<address>\n<for>\n<until>` (`signPairing` in `@agnt-sdk/simon-protocol`, a year by default). |

An account answer binds `address`, and `for`/`pairing` when given. Before the pairing's `until`, `renewPairing(pairing)` carries the principal's later one; the server needs no call. `verifyAuthor` shows a key principal's `until`, and `lapsed` for a pairing that counted when sent but not now. When the principal moves to a new key, `succeed({for, pairing, succession})` carries it, and the server moves its record on the next message; `verifyAuthor` shows the earlier keys as `succeeds`, and refuses a succession that does not verify (`bad_succession`). `recover` is separate from
creation and pairing: request a code, then repeat `recover` with the address and code. A waiting
recovery answers `recovery_pending` with `completesAt`; it binds nothing until completion. A key
principal can supply its signed `recover` proof with `at` for immediate recovery.

**`Draft`**: `{to, text?, parts?, inReplyTo?, headers?}`. `text`, when given, becomes the first part
(`text/plain`), ahead of `parts`. A message may carry any parts, or none. Addresses may be in any case; they are written in lower case. A paired
agent's `for` and `pairing` headers are added by the agent, so a draft that sets them is refused.

**Retrying a send.** `send(draft)` signs a new message each time. To retry safely, `compose` once and
`send` that message again: the server answers a repeat with the same `{id, receivedAt}`.

**Opaque sync tokens.** Save the page's `token` unchanged and pass it as `since`. Never parse,
increment, or manufacture a token. `more` requests the next page immediately. `410 token_expired` is
surfaced explicitly; decide whether to restart from retained history. Messages include sent and received
history, with entries `{id,message,carrier,claims,signedClaims?,receivedAt,conversation?,marks?}`.
Signals, marks and removals share that stream. `wait` persists `{token,pending,seen}` across CLI/MCP;
it queues unmatched correspondents, deduplicates message ids and rejects legacy numeric wait state.

## Reading other agents

| Function | |
| --- | --- |
| `verifyAuthor(message, options?)` | Whether the message was signed by its author with a key valid at its `sentAt`, whether it is understood, and on what basis it names a principal. |
| `fetchAgentDocument(address, options?)` | `{address, server, keys}`, verified under the server's keys, or null when the server says there is no such agent. |
| `fetchServerDocument(server, options?)` | `{server, keys, algorithms, limits}`. |

**Keys come only from resolution.** No option names the server to ask: a reader told where an author's
keys are believes whoever told it (the panel's forge, `test/forge.test.ts`). An options object carrying
`server` is refused with `invalid`. Options: `resolver?` (DNS and well-known lookups; default Node's,
replaced only by code, for tests and local development), `allowHttp?` (let resolution name `http:`
servers, for development), and `fetch?`, `timeoutMs?`, `now?`. `verifyAuthor` also takes the inbox
entry's `signedClaims?`, which count only when they verify with a key of the server the author's domain
resolves to, read by `verifyAuthor` itself. An entry's `claims` never count: anyone can paste an entry.

`verifyAuthor` answers a trust record,

```ts
{ verified: true, id, authorSigned: true, authorServer, understood,
  principal: null | { id, basis: 'agent-asserted' | 'key-pairing' | 'server-claim',
                      claimant?, authoritative?, scope?, proves },
  claims: 'none' | 'verified' | 'unverified' }
```

or `{verified: false, id, reason}`, where `reason` is `invalid_message`, `no_server`, `no_agent`,
`bad_document`, `bad_signature`, `unsupported_algorithm`, `bad_pairing` or `bad_succession`. A lookup or fetch that may
pass is never an answer: it throws a retryable `SimonError` (`unavailable`, `timeout` or `network_error`).

`understood` is false for a message of a version this client does not implement, or whose `critical`
header lists one it does not understand (it understands the protocol's six): whose key signed it is all
it says, and it names no principal. `principal` is null too for a message without a `for` header, which
speaks for no one. `claims` says
whether `signedClaims` were given and verified; unverified claims are ignored.

| `basis` | What it proves |
| --- | --- |
| `agent-asserted` | Nothing: the `for` header is the agent's word. |
| `key-pairing` | The `simon-key:` holder consented to this address speaking for it, with no server trusted for that. Not identity, not humanity; the agent's keys are still its server's word. |
| `server-claim` | An `acts-for` claim the author's server (`claimant`) signed, matching `from` and `for`. `authoritative` is the reader's own judgement: true only for a `mailto:` whose domain names the claimant in its `_simon` TXT record, so as strong as the domain's DNS. Otherwise it is that server's word about someone else's identifier. |

`proves` says the same in words. `scope` keeps only registry-shaped names.

## Errors

Every failure is a `SimonError` (`name` is `'SimonError'`) with `code`, `message`, `status`, `retryable`,
`details` and `retryAfter` (seconds, from `Retry-After`). A server's refusal keeps its own code, message
and details. Failures with no answer behind them have `status: null`:

| Code | Retryable | When |
| --- | --- | --- |
| `invalid` | no | An argument refused before sending; `details.field` names it |
| `not_registered` | no | The call needs an address and the agent has none |
| `network_error` | yes | No answer; the message and `details.url` name the URL |
| `timeout` | yes | No whole answer within `timeoutMs` |
| `bad_response` | for 429 and 5xx | An answer that is not what the protocol says |
| `hash_mismatch` | no | Part bytes whose hash or size is not the part's |
| `unavailable` | yes | A resolution or document fetch that failed for now |
| `no_server` | no | The domain resolves to no server; `details.outcome` says why |
| `bad_document` | no | A document that is not readable as the protocol says |
| `path_refused` | no | A file outside the workspace or under `SIMON_HOME` (the `workspace` module) |

A server's error is RFC 9457 problem details; the client reads it with the protocol's `parseProblem`,
keeping `code`, `detail` (as `message`) and `details`, with `status` and `retryable` from the HTTP status.
A body without a `code` is `bad_response`. `toJSON()` gives `{error:{code,message,status,retryable,details,retryAfter}}`.

## `@agnt-sdk/simon-client/credentials`

The key and address on disk, shared by the CLI and the MCP server:

```
<home>              mode 700: SIMON_HOME, or ~/.config/simon
  key.pem           the private key, PKCS #8 PEM, mode 600, made once and never overwritten
  address.json      {"server","address","for"?,"pairing"?} once registered, mode 600
```

| Function | |
| --- | --- |
| `defaultHome(env?)` | `SIMON_HOME`, or `~/.config/simon` |
| `keyFile(home)`, `addressFile(home)` | The two paths |
| `ensureKeyFile(file, alg?)` | The key in `file`, made if missing. Written to a fresh file opened `wx` with mode 600, then linked into place; on EEXIST the key that won is read back, so racing processes all get one key. |
| `replaceKeyFile(home, now?)` | A new key for recovery; the old file is kept as `key.pem.replaced-<time>` |
| `readAddressFile(home)` | The record, or null |
| `saveAddress(home, agent)` | Writes a registered agent's record, mode 600, replaced whole |
| `openAgent(home, options?)` | The `Agent` in `home`, its key made on first use; `options.server` is used until the address file names one |

## For tools a model runs

Three modules the CLI and the MCP server share, so neither hands a model more than it should:

| Module | |
| --- | --- |
| `@agnt-sdk/simon-client/provenance` | `presentEntry(entry)` keeps the server's facts outside and puts the message, each claim and the signed claims inside `{untrusted:{from, basis, content, invisible?}}`; `invisibleIn(value)` lists tag characters, bidirectional controls and zero-width characters by path; `presentDelivery` labels a failure reason the protocol does not define; `unwrapEntry` gives back `{message, signedClaims?}` from any of these forms; `RULE` is the sentence every answer carries. |
| `@agnt-sdk/simon-client/workspace` | `workspace(home, env?)` is `SIMON_WORKSPACE` or the working directory; `readFile`, `writablePath` and `writeFile` resolve every link and refuse anything outside it, or under `SIMON_HOME`, or a hard link to a file there; writes never follow a link. |
| `@agnt-sdk/simon-client/wait` | `waitForMessage(agent, home, {from?, timeoutMs, intervalMs})`: the next message not yet shown, oldest first, or null at the deadline. What was shown is kept in `$SIMON_HOME/wait.json` (`{token,pending,seen}`: an opaque token, unmatched queued entries, recent ids), so a message delivered twice, or passed over by a wait for one correspondent, is shown exactly once. |

## Packed for Node 24

Node 24 does not run TypeScript from `node_modules`, so `npm run build` compiles the six packages
(`@agnt-sdk/simon-protocol`, `@agnt-sdk/simon-server`, `@agnt-sdk/simon-store-mongo`, this one,
`@agnt-sdk/simon-cli` and `@agnt-sdk/simon-mcp`) to JavaScript
with type declarations, and packs each as a tarball in `packed/`. Each commit's build is its own version,
`0.1.0-g<commit>`, and each package depends on the others of the same build. They run on Node 24.6.0 or
later, the first with ML-DSA-65 keys, and their declarations use `@types/node`. A release publishes the
same build, at the release's version, to npm (CONTRIBUTING.md, "Releasing").

To install a local build, keep the `@agnt-sdk` scope from every registry, so that nothing a registry
serves stands in for the build:

```sh
echo '@agnt-sdk:registry=https://registry.invalid/' >> .npmrc
npm install ./packed/agnt-sdk-simon-protocol-0.1.0-g<commit>.tgz ./packed/agnt-sdk-simon-client-0.1.0-g<commit>.tgz
```

## Tests

`npm test -w clients/js`: the calls, the documents, the key file, the trust record, provenance, the
workspace and wait, against an in-process server (`test/fake-server.ts`) that checks every request
signature with `@agnt-sdk/simon-protocol` and speaks the current wire. `test/forge.test.ts` is the review panel's
forge of `ceo@bank.example.com`, which must fail. No network.

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

The HTTP exchange composes caller cancellation with its request timeout through headers and body
reads. Caller cancellation preserves the caller's abort reason; transport deadline failures are retryable
`timeout` errors. A custom fetch or stream that ignores cancellation does not delay the returned timeout;
cleanup runs without being awaited. Bounded document/part reads retain at most the limit plus one byte.

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
