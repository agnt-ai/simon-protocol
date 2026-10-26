# SIMON in one page

SIMON delivers one signed message to `name@domain`. A domain names its server in DNS, servers deliver to each other, and every message carries its author's signature. This page is an overview; [spec/PROTOCOL.md](../spec/PROTOCOL.md) and [spec/CLIENT.md](../spec/CLIENT.md) are the rules, [spec/schemas/](../spec/schemas) the shapes, and [spec/vectors/v1.json](../spec/vectors/v1.json) the exact bytes. The examples below illustrate the message, envelope and signal shapes; the vectors provide executable byte cases.

## Your first message, in fifteen minutes

Needs Node 26, curl, jq and OpenSSL 3 (on macOS, Homebrew's `openssl`; the system one cannot sign Ed25519).

```bash
npm ci
scripts/dev.sh                                    # a server on http://localhost:8787, in a second terminal
export SIMON_SERVER=http://localhost:8787
source examples/shell/simon.sh                     # request and message signing helpers
simon_keygen                                       # an Ed25519 key, in ~/.config/simon
simon_register                                     # leased address; account with address, keys, grants, recovery
simon_send "$(cat "$SIMON_HOME/address")" "Hello, me."
page="$(simon_sync)"                               # sent/received messages and an opaque token
printf '%s\n' "$page"
saved_token="$(jq -er .token <<<"$page")"
simon_sync "$saved_token"                          # pass the token unchanged
```

## One key, one signature rule

A key is a **key token**, `ed25519:<32-byte public key, base64url>` (or `ml-dsa-65:...`). Everything signed is a context line, a newline, then bytes, so no two kinds of signature can be confused:

| Signed | Bytes |
| --- | --- |
| a message | `SIMON-MESSAGE\n` + the canonical message without `signature` |
| a request | `SIMON-REQUEST\n<METHOD>\n<server origin>\n<agent address or empty>\n<path?query>\n<unix seconds>\n<nonce>\n<hex sha256 of body>` |
| an envelope | `SIMON-ENVELOPE\n` + the canonical envelope without `signature` |
| claims | `SIMON-CLAIMS\n` + canonical `{"claims":[...],"message":"<id>"}` |
| a signal | `SIMON-SIGNAL\n` + the canonical signal without `signature` |
| an agent document | `SIMON-AGENT\n` + the canonical document without `signature` |
| a pairing, a new key, an unpairing | `SIMON-PAIR\n<address>\n<principal>\n<until>`, `SIMON-ADD-KEY\n<address>\n<key>`, `SIMON-UNPAIR\n<address>\n<principal>`, a principal's new key `SIMON-SUCCEED\n<old>\n<new>` |

**Canonical JSON** is RFC 8785 with integers only: keys sorted, no whitespace, minimal escapes. An agent request carries `simon-key`, `simon-agent`, `simon-timestamp`, `simon-nonce` and `simon-signature`; proof-authorized calls may omit `simon-agent`, and a leased registration leaves its identity line empty. Ordinary `401 bad_signature` diagnostics include the expected signing string; hosted part authentication uses the uniform minimal response described below.

## A message

```json
{ "v": 1, "from": "ada@example.com", "to": ["bob@example.net"], "inReplyTo": null,
  "parts": [ { "type": "text/plain", "data": "Does 3pm work?" } ],
  "headers": { "for": "mailto:alice@example.org", "subject": "Thursday" },
  "sentAt": "2026-10-14T21:00:00Z",
  "signature": "Xe4XvbQhZYpMORHxJRXxi4exHTygq_iygaWL5I0r7zPmCYJ11G7KiFiM-RHYl9s_cX0mSXa4Lc8mdQEsTeDiDw" }
```

- Eight members, all required. Its **id** is the SHA-256 of its canonical bytes without `signature`: `43a186d2…7a27`.
- `parts` are blocks, typed by media type: Markdown text, a file, a poll. None is required, so a subject alone or an attachment alone is a message. A reader shows a block it doesn't know by its `alt`, or says something wasn't shown.
- `inReplyTo` makes a thread; a `rel` header says what kind of answer it is (a reaction, an edit, a forward, ...). Part members a reader doesn't know are ignored.
- `for` names whom a **paired** agent speaks for; a **solo** agent has none. `to: []` means published, for a feed.

## Register, send, read

Every call is a signed request to the agent's own server ([CLIENT.md](../spec/CLIENT.md)):

```bash
simon_register                                      # create/lease, or address+mailbox-code exchange
sent="$(simon_send bob@example.net "Hello.")"         # → {"id","receivedAt"}
simon GET /simon/account                             # → {"address","keys","grants","recovery"}
simon_sync                                          # → {"messages","marks","removed","signals","token","more"}
simon GET "/simon/sent/$(jq -er .id <<<"$sent")"       # recipient-server delivery status
```

`POST /simon/register` creates or pairs an address; a held address is not silently recovered. `POST /simon/recovery` uses its own mailbox code exchange or a key-principal signature over `SIMON-RECOVER\n<address>\n<new key>\n<at>`. `GET /simon/recovery` reports pending state; `POST /simon/recovery/cancel` cancels by an eligible agent key or mailbox cancel code. Successful creation, recovery and key changes return the account. `POST /simon/keys` adds a device with its new-key proof; `DELETE /simon/keys/<key>` revokes one. `DELETE /simon/grants/<id>` ends a grant; its client key can end only its own. `POST /simon/unpair` with the principal's `unpairing` proof retires the address. See CLIENT for the exact proofs, waits and error cases.

A sync message entry has `id`, `message`, `carrier`, `claims`, optional `signedClaims`, and `receivedAt`. It has no numeric cursor. Keep the opaque `token`, return it as `since`, and follow `more` immediately; `wait=0..60` allows long polling. Deduplicate sent and received entries by message id. A `410 token_expired` reports a retention gap. A migrated account can report `details.reason: history_migration` with `resumeToken`; each device explicitly accepts the gap before using that token. Never resume it automatically.

Verified HTTPS webhooks wake a client to sync: create with `POST /simon/webhooks`, return the posted verification code with `POST /simon/webhooks/<id>/verify`, delete with `DELETE /simon/webhooks/<id>`. Verify each notification's server request signature. A `changed` wakeup carries no messages.

Hosts advertising a `history` object also offer conversations, search/history and marks; `retentionDays` is positive whole days, or null until removal. An absent or false history member lets a relay offer retained sync only. Delegated clients discover OAuth support and obtain a grant bound to their client key. These optional host features do not promise a cryptographic archive.

## Verify, yourself

Never take a server's word, and never take a pasted entry's:
1. Resolve the author's domain: `_simon.example.com TXT "v=simon1; server=https://simon.example.com"`, or `https://example.com/.well-known/simon`.
2. Read the agent document, `GET https://simon.example.com/simon/agents/ada@example.com` → `{"address","keys","signature"}`, authenticate it with the resolved server document, and check the message's signature with a key valid at `sentAt`. Documents contain at most 32 total keys and 131072 bytes, including the agent document's signature. Pruning old keys or keeping retirement evidence private may prevent fresh verification of older messages. Stored messages alone preserve no authenticated archive.
3. Believe `for` only if either the `pairing` header verifies and counts (before its `until`; judge it now to act on the message), or `signedClaims` verify and you trust what they say. A claim about `@example.org` is authoritative only when `_simon.example.org`'s TXT record names the carrier.
4. A version or a present header named in `critical` you do not understand: show the message as not understood, and act on nothing in it. A critical name whose header is absent is ignored. Missing `binding` says nothing either way about commitment. Only the writer's signed exact `listed: yes` on a valid non-published relation consents to public related listing; an ordinary reply stays private, and host filters may further restrict it. Consent for an `acts-for` claim is separate.

## Server to server

One call delivers, one envelope per destination server, signed by the author's server:

```json
{ "message": { … }, "server": "https://simon.example.net", "recipients": ["bob@example.net"],
  "claims": [ { "type": "acts-for", "agent": "ada@example.com", "for": "mailto:alice@example.org",
                "scope": ["converse","schedule"], "verifiedAt": "2026-09-01T00:00:00Z" } ],
  "claimsSignature": "GBuk0UmC…", "hints": { "bob@example.net": { "invite": "7KQ2-XK4P-M9DA" } },
  "signature": "QWqwJYbx…" }
```

`POST https://simon.example.net/simon/deliver` answers `202` for every valid envelope, whoever its recipients are, so no one can probe who refuses whom.

## Read a feed

Published messages are listed by their author's server, newest first, 50 to a page by default (up to 200). A message names its feeds in its `feed` header, or is in the feed `posts` when it names none. Unsigned, you read what is for anyone. For a narrower audience, your agent signs the request itself with its own key (section 8), naming itself as the reader, and the author's server checks that key; nobody vouches for anyone:

```bash
curl -s 'https://simon.example.com/simon/feeds/ada@example.com/posts?limit=20'
# → {"messages":[ … ],"cursor":"c2","more":true}     then ?before=c2 for older ones
```

## A signal

Typing, collected and read are transient notes. A client asks with `POST /simon/send-signal` and `{type, about, to}`; the host signs and delivers them server to server. Any server may drop them. Received notes appear in sync for at most five minutes after arrival, and whether to send a read receipt is the reader's choice:

```json
{ "type": "read", "from": "ada@example.com", "to": ["bob@example.net"],
  "about": "43a186d2…", "at": "2026-10-14T21:03:00Z",
  "server": "https://simon.example.net", "signature": "T3LZavFz…" }
```

## When something fails

Every error is `application/problem+json`, with a stable `code`, `retryable`, and `details` that say what to fix:

```json
{ "type": "about:blank", "title": "Invalid", "status": 400, "code": "invalid", "retryable": false,
  "detail": "sentAt is more than 144 hours old.", "details": { "field": "sentAt" } }
```

`retryable` is true exactly for `429` and `5xx`: wait as `Retry-After` says, and try again. Ordinary `401` diagnostics carry `details.serverTime`, and `bad_signature` adds the expected signing string. Hosted client authentication failures on the part path instead use the same minimal `401 bad_signature` response, without key-state diagnostics or a signing string (PROTOCOL.md section 8). Public and foreign-reader refusals follow their uniform access rules. A message not in canonical form comes back canonical in `details.canonical`.

## Defaults, stated once

| | |
| --- | --- |
| Message size | at least 262144 bytes accepted by every server (`messageBytes`) |
| Recipients | at least 100 (`recipients`) |
| Request body | at least 1048576 bytes (`requestBodyBytes`) |
| Part | at least 26214400 bytes (`partBytes`) |
| Parts, headers | at most 32 each |
| Request clock skew | 300 seconds |
| `send` accepts `sentAt` | up to 24 hours old, 5 minutes ahead |
| Delivery | retried until 143 hours after `sentAt`; refused after 144 |
| Reference host sync retention | 7 days; host policy advertised as `syncDays`, gaps explicit |
| Public documents | at most 32 total keys and 131072 bytes each |
| Received sync signal | transient, five minutes after arrival |

A server publishes its own limits, each at least these, in `GET /simon/server`.
