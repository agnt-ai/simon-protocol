# SIMON client API, version 1 (draft)

How an agent, or a client acting for it, uses the agent's own server. Any agent can use any conforming server with one client, and anyone can write a client for any server, the way Apple Mail and Superhuman read mail that Gmail hosts.

**Conventions.** The conventions of [PROTOCOL.md](PROTOCOL.md) apply:
- the BCP 14 key words, read as in RFC 2119 and RFC 8174 when in capitals;
- the indicative mood, which has the force of MUST;
- the HTTP rules and the problem-details error shape of its section 9.

**Requests.**
- Every request is signed as the protocol's section 8 says: the eight-line signing string, `simon-key` set to the token of a key the server knows for the agent (one of the agent's keys, or a client key it granted, below), and `simon-agent` set to the agent's address. The calls authorised by a proof they carry (`register`, recovery, `unpair`, a cancel by code) may be signed by any key, and may leave `simon-agent` out, because the body names the address they act on and the signature covers the body; when present, it names that address. A first `register` asking for a leased address carries none, and its identity line is empty. A no-address repeat may omit `simon-agent` or name the address already bound to its signing key ("The agent's address and keys"; PROTOCOL.md 8, "Exceptions").
- Request bodies are `application/json` under the protocol's section 5.1 rules, but need not be canonical, except the upload's raw bytes.
- A server refuses a body larger than its `requestBodyBytes` with `413 body_too_large`, except an upload, which is bounded by `partBytes` (section "parts").

## Who may call

Two kinds of key sign requests. Both use the one signature of the protocol's section 8, so a client implements one way to sign.

**An agent key** is one of the keys the agent's document publishes. It signs the agent's messages, and it authorises every call in this document. An agent may hold several, one per device, as Signal's linked devices and Nostr's device keys do: each is added with the add-key proof (`POST /simon/keys`), labelled for the agent's own clients, and revoked on its own. A device that holds an agent key needs nobody's permission to write.

**A grant** lets a client the agent's principal approved use the agent without holding an agent key, as Superhuman uses a Gmail account through OAuth. The client holds a key of its own, its **client key**. The server knows that key, never publishes it, and authorises it for the grant's scopes only:

| Scope | Authorises |
| --- | --- |
| `read` | `sync`, `sent`, fetching parts, receiving signals, and reading the history |
| `organize` | marking the history, removing from it, and webhooks |
| `send` | `send`, signed by the server with a key it keeps for the agent; uploading parts; sending signals |

A call the grant's scopes do not cover is `403 scope_required`, and no scope covers the calls of "The agent's address and keys", except that a client may end its own grant, as a client signing out revokes its own token (RFC 7009). A client key never signs a message, so recipients never see it and never need to trust it. Keys and grants change only by an agent key or by the principal. How a grant is obtained is the section "Delegated access".

- **One client key, one agent.** A client key is bound to at most one agent on a server, and a request it signs for any other agent is `401 unknown_key`. A client with several accounts on one server holds a key for each. A new grant for the same key and agent replaces the old one.
- **Nothing to probe.** A server answers a request signed by a client key it does not know, or no longer honours, `401 unknown_key` alike, so no one can learn whether a client is in use there.

**The host's signing key.** A host that signs for its agents through grants (`send`) keeps an agent key of its own for each such agent, listed in the agent's document like any other. It is added with the add-key proof, by an agent key or, for an agent the host made for a principal, when the agent is made. Recovery replaces it like every key. A host that ranks keys by age keeps this key outside the ranking ("Recommended host practice").

**What else a server reserves.** A server MAY reserve its other operations to the agent's principal, by a credential the principal holds. Examples are changing who may reach the agent, what is published about it, and retiring it.

## The calls

Every server offers these:

```
POST   /simon/register                 create or pair an address for a key
POST   /simon/recovery                 recover a held address
GET    /simon/recovery                 pending recovery, signed by an agent key
GET    /simon/account                  the agent's address, keys, grants and pending recovery
POST   /simon/keys                     add a key
DELETE /simon/keys/<key>               revoke a key
DELETE /simon/grants/<id>              end a grant
POST   /simon/recovery/cancel          cancel a pending recovery
POST   /simon/unpair                   retire a paired agent, by its principal's unpairing
POST   /simon/send                     a message in canonical form
POST   /simon/send-signal              a signal for the server to send
GET    /simon/sync?since=<token>&wait=<seconds>  what arrived, and what changed
POST   /simon/webhooks                 a URL to wake the agent
POST   /simon/webhooks/<id>/verify     the code the server posted to it
DELETE /simon/webhooks/<id>
GET    /simon/sent/<id>
PUT    /simon/parts/<sha256>           the bytes
GET    /simon/parts/<sha256>
```

A server that hosts people's agents also keeps each agent's history and offers these, and `sync` then carries the history's changes too (section "History"):

```
GET    /simon/conversations                  the agent's conversations, latest activity first
GET    /simon/conversations/<id>             one conversation's messages
GET    /simon/history                        every message, searched and filtered
POST   /simon/marks                          add or remove marks
DELETE /simon/history/<id>                   remove a message from this agent's history
```

**Which servers keep a history.** A server that hosts people's agents offers these calls, so a person can bring any client to any host, and says so with the `history` member of its server document (registry). A server that only relays for agents that keep their own messages may leave them out, and then answers `404 not_found` on them. There is one history API, this one: a host never offers one of its own design instead.

## The agent's address and keys

These calls take and keep an address, and manage the keys and grants that act for it. Only an agent key, or the proof a call names, authorises them.

- **Bodies.** The members this section names are strings, and any other value is `400 invalid`. A server ignores other members unless it defines them. A server that defines members of its own names them so no later version of this API can take them, for example with its domain as a prefix (`example.com:invitation`). The application template's `agnt.ai:pairingCode` and `agnt.ai:scope` are such members: one host's extensions under its own domain, not part of this API.
- **Signed by a key the server may not know.** `register`, recovery, `unpair` and a cancel by code are authorised by the proof they carry, not by the signing key, so they may be signed by any key. Every other call is signed by a key the server knows for the agent.
- **Repeats.** A repeat of registration, recovery, or adding a key that succeeded returns the same result. Revoking a key, ending a grant or cancelling by key a recovery that is already gone answers `404 not_found`. A repeated cancel by code answers as section "Cancelling a recovery" says: `422 wrong_code`, the same bytes.

**The account.** `GET /simon/account`, signed by an agent key, answers the agent's state, so a client can show its devices and grants:

```json
{ "address": "ada@example.com",
  "keys": [ { "key": "ed25519:...", "added": "...", "revoked": null, "label": "Ada's phone" } ],
  "grants": [ { "id": "...", "client": "https://app.example/client.json", "scopes": ["read"],
                "createdAt": "...", "lastUsedAt": "..." } ],
  "recovery": null }
```

- `keys` are the agent's key entries, each with its `label` when it has one;
- `grants` are the agent's grants still in force, where `client` is the client's `client_id` (section "Delegated access");
- `recovery` is `{"completesAt","cancellable"}` while a recovery is pending, and `null` otherwise. `cancellable` says whether the key that asked may cancel it.

Registration and recovery on success, adding a key, revoking a key and ending a grant answer with this object too, as it stands after the call.

### register

`POST /simon/register` binds a key to an address. It is signed by the key being registered, and carries it as `key`, equal to `simon-key`, with whatever proves the key may have the address. The first of these that applies decides:

- **A key alone** leases an address on a domain the server controls. A server that leases none answers `400 address_required`.
- **An address on a domain the server hosts** is the agent's at once, unless the server keeps it for itself or another agent holds it (`409 address_taken`).
- **Who may take these.** A hosted name or a lease is the server's to give, so a server may decide which keys take one, by a proof of its own carried as a member of the body it defines. The agent sends the proof on every call that would create the address, including the repeat after a `202`. The server refuses the rest with `409 address_taken`, the answer a held name gets.
- **Another address whose domain resolves to this server:** the server sends a code there, by email for an address that receives mail, and answers `202 {"status":"code_sent","address"}`. The same call with `code` then binds the key. An address whose domain names another server is `409 address_homed_elsewhere` with `details.server`. One whose domain names no server is the same answer with `details.server` set to `null`. A server that cannot send codes answers `400 invalid` with `details.field` set to `address`. A server limits the codes it sends, in its own way ("Recommended host practice").
- **Pairing with a key principal.** The call that creates an address may also carry `for`, a `simon-key:` identifier, and `pairing`, that key's signature over `SIMON-PAIR\n<address>\n<for>`. The agent is then paired with that principal for the life of the address. When the server leases the address, the agent learns it only from the answer. It calls with `for` and without `pairing`. The server answers `202 {"status":"pairing_required","address"}`, and repeating the call with the signature completes it. A `pairing` that does not verify is `401 bad_proof`. Without `for`, the agent is solo. Pairing with an email or phone principal is a server feature, outside this API.

**Codes.** A registration or recovery code is bound to the address and the key that asked for it, and binds only that key. An ordinary request for a code by another key cannot replace it, spend its attempts or lock it; the pending-recovery rules below still invalidate codes sent before that recovery began. A code has a finite lifetime; after it expires the answer is `410 code_expired`. A wrong code is `422 wrong_code`; after the host's allowance of wrong guesses is spent, the answer is `410 code_locked`, and the requesting key asks for a new code. The lifetime and attempt allowance are host policy. Cancel codes follow their separate rules below and are never locked.

### Recovery

`POST /simon/recovery` recovers an address an agent there already holds. It is signed by the proposed new key, carries `key` equal to `simon-key`, and may omit `simon-agent`; if present it names the recovered address. Registration never silently recovers a held address. `GET /simon/recovery`, signed by an agent key, answers `{"recovery":null}` or `{"recovery":{"completesAt":"...","cancellable":true}}` for that signer. When it completes, the new key replaces every old key, those are marked revoked, and every grant ends.

- **By the address's mailbox:** the same code exchange, on the recovery resource. An address with no mailbox behind it, such as a leased one or a name on a hosted domain, cannot be recovered this way, only by a key it still holds or, where the server offers it, by its principal.
  - A server may make it wait. The code exchange then answers `202 {"status":"recovery_pending","address","completesAt"}`, the account shows it as `recovery`, and repeating the code call after `completesAt` completes it.
  - While it waits it can be cancelled (`POST /simon/recovery/cancel`).
  - A server that holds one recovery of an address at a time starts no second one. A call asking for a code while one is pending is answered as any other (`202 {"status":"code_sent","address"}`), without sending another code or recovery reminder; the existing completion and cancellation proofs keep their authority. A code sent before the recovery started no longer binds a key (`422 wrong_code`). An unproved caller gets the same wrong-code, lockout and expiry exchange as when no recovery is pending; how the host makes those exchanges indistinguishable is its own implementation. So no answer tells anyone who does not read the mailbox whether the address is being recovered.
- **By a key principal:** whether a principal can recover its agent is host policy (PROTOCOL.md sections 2.4 and 11.2). A server MAY let a key principal (`simon-key:`) recover its paired agent at once, whatever the agent's keys and any pending recovery say; a server that does uses this call, so clients of every such server make it the same way. The call carries `address`, `key`, `at`, a timestamp, and `recover`: the principal's base64url signature over these bytes, which the server verifies with the key named in the agent's `for` (`401 bad_proof` otherwise):

  ```
  SIMON-RECOVER
  <the agent's address>
  <the new key token>
  <at>
  ```

  `at` is at most 24 hours old and at most 5 minutes ahead (`400 invalid`, with `details.field` set to `at`), so a signed recovery never waiting to be used is never a standing key to the agent. The recovery also ends any pending one, and no key can cancel it. A key principal is the agent's root of trust, as a rotation key is for an AT Protocol identity. An email or phone principal recovers through the server's own principal credential, outside this API.

### Keys and grants

**Adding a key.** `POST /simon/keys` with `{"key","proof"}`, signed by an agent key, adds `key` to the agent, a new device for instance. `proof` is the new key's signature over these bytes, so no agent can list a key it does not hold (a missing or failing proof is `401 bad_proof`):

```
SIMON-ADD-KEY
<the agent's address>
<the new key token>
```

Lines are joined by single newlines. `label`, at most 64 characters, names the device for the agent's own clients; it is never published. An agent holding as many active keys as the server allows is refused with `400 too_many_keys`. A key this agent held before is refused with `409 key_in_use`, since a revoked key is never valid again. Whether one key may also serve another address is the host's policy, and a host that refuses answers `409 key_in_use` too. An agent that wants its addresses unlinked uses a key for each, since one key on two addresses links them for every reader (PROTOCOL.md 12).

**Revoking a key.** `DELETE /simon/keys/<key token>`, signed by an agent key, revokes that key of the agent at once: its `revoked` becomes the time of the call, and never earlier (the protocol's section 2.4: history only grows forward; a stolen key can still sign messages dated before the call, as its section 11.2 says). An unknown key is `404 not_found`. A server may refuse a revocation its policy does not allow: `409 key_senior` when the signing key may not revoke that one, and `409 last_key` for the agent's last active key ("Recommended host practice").

**Ending a grant.** `DELETE /simon/grants/<id>`, signed by an agent key or by that grant's own client key, ends that grant at once; an unknown grant is `404 not_found`. Signed by an agent key, it answers the account; signed by the client key, `200 {"status":"ended"}`, since that key then reaches nothing. The principal can end grants too, through the server's own principal credential.

### Cancelling a recovery

`POST /simon/recovery/cancel` cancels the pending recovery of an address, in either of two ways:
- **By key:** an empty body `{}`, signed by an agent key. A server refuses a key its policy does not let cancel with `409 recovery_not_cancellable`. With no recovery pending, the answer is `404 not_found`.
- **By code:** `{"address","cancelCode"}`, signed by any key. A **cancel code** is what a server that sends one gives the address with the news of a recovery. It cancels that recovery only, and is valid while it is pending.
  - It is a random string of at least 128 bits, so it cannot be guessed, and no number of wrong tries locks it. A lockable code would let anyone kill the mailbox holder's one defence by guessing wrongly on purpose.
  - A wrong code, a code for a recovery that has ended, and an address with no recovery pending all answer `422 wrong_code`, the same bytes, so no stranger learns whether an address is being recovered.

The answer is `200 {"status":"cancelled","address"}`.

### Unpairing

`POST /simon/unpair` with `{"address","unpairing"}`, where `unpairing` is the principal's base64url signature over `SIMON-UNPAIR\n<address>\n<for>` (the protocol's section 2.2), retires that paired agent's address at once, whatever its keys say: its keys no longer authorize current client requests, and its published messages and their parts are no longer served. A host MAY serve signed retirement evidence under PROTOCOL.md section 4; keeping that evidence private is also a host choice. It may be signed by any key, since the unpairing is what authorises it. An unpairing that does not verify with the key the agent's `for` names, or an address with no such agent, is `401 bad_proof`. The answer, and the answer to a repeat, is `200 {"status":"retired","address"}`.

## Recommended host practice

Recovery and key management protect only a host's own users, so how a host runs them is its own policy, as account recovery is Google's, Apple's or Microsoft's: the calls above carry no timings and no counts. This is the practice the reference server follows by default, and the reason for each part. A host that departs from it should know which attack it reopens.

**The attack.** Mallory reads Ada's mail for an hour, on a laptop Ada left signed in. She asks Ada's server to recover Ada's agent and receives the code. If the server binds her key at once, she holds the agent, and Ada's own devices are locked out.

**The practice:**
1. **Wait 72 hours** before a mailbox recovery completes, while the agent holds a valid key, and tell the agent at once with a message from the server itself. Ada's devices see it within the wait.
2. **Send a cancel code** to the address with the news of every recovery. Whoever holds the mailbox now can cancel any recovery with it, so once Ada has her mailbox back, she stops whatever Mallory started.
3. **Let a key cancel once in 30 days.** A key the agent held before the recovery started may cancel it; a key added while it is pending may not, so Mallory cannot cancel with a key of her own making. A recovery started within 30 days after one a key cancelled can be cancelled only by its cancel code. When a key cancels, tell the address. A thief who stole a key can delay the mailbox's holder once, never for good.
4. **One pending recovery per address,** answered as the recovery section says, so Mallory cannot stack recoveries until one slips past, nor learn from the server whether one is under way.
5. **Count code requests per address and per client network,** and never count a call that carries a code, or that is signed by a key the agent holds, against the shared allowance. A limit caps the mail sent, never the holder's answer to it, so Mallory cannot use the limits to lock Ada out.
6. **Rank keys by age.** A key may revoke itself and any key added after it, never one added before it (`409 key_senior`), and never the agent's last active key (`409 last_key`). A thief who copies a newer device's key cannot evict the older ones, and they can evict it; a thief holding the oldest key is evicted by recovery, which ends every key. The host's signing key is outside the ranking both ways: it revokes no key, and any key may revoke it.
7. **Complete a principal's recovery at once,** by a key principal's signature or, for an email or phone principal, the host's own sign-in, ending every old key, every grant and any pending recovery.

**What remains, on purpose.** Someone who keeps the mailbox wins after about two waits, about six days, with the agent told both times. The mailbox is the address's root, as it is for email.

## send

`send` answers `200 {"id","receivedAt"}` once the server has accepted the message for delivery; delivery follows. A server checks in this order and answers with the first failure: the protocol's section 6.3 steps 1, 3 and 4, then:

- The message's version is one the server implements. Otherwise `400 unsupported_version`, so no agent can step around a version's rules by naming another.

- `from` must be the authenticated agent's address (`400 invalid`, with `details.field` set to `from`).
- `from` must be on a domain that still names this server (`409 address_not_served`).
- The message's signature must verify with one of the agent's keys valid at its `sentAt` (`401 bad_signature`).
- A paired agent's message must carry its principal as `for`, along with the `pairing` header when the principal is a key. A solo agent's message must carry neither. Otherwise `400 invalid`, with `details.field` set to `headers`.
- `sentAt` must be at most 24 hours old and at most 5 minutes ahead (`400 invalid`, with `details.field` set to `sentAt`).
- Every file the message names must be held by this server for this agent, at its declared size: uploaded by it, or fetched for a message delivered to it, so a received part can be forwarded without uploading it again. That covers the message's own content-addressed parts and the files named by every message it carries inline, at any depth, which count as named by it (PROTOCOL.md sections 5.3 and 7.2). Otherwise `400 part_not_uploaded`, with `details.sha256`.

**Hints.** An optional `simon-hints` header carries per-recipient hints, as a JSON object keyed by recipient address. The object is written in ASCII, with every non-ASCII character escaped as `\uXXXX`, because HTTP header values carry only ASCII. It may name only addresses in `to`, and must be small enough to fit an envelope beside the server's claims. The server passes each recipient's hints only to that recipient's server, in its envelope. The header is not part of the signing string, because hints carry no authority of their own: an invite code is checked by the server that issued it.

**Through a grant.** A request signed by a client key whose grant has the `send` scope carries the message without `signature`, in canonical form. The server checks it as above, except the signature, and then signs it with a key it keeps for the agent, which its agent document lists. The answer adds the signed message: `200 {"id","receivedAt","message"}`. A server that keeps no key for the agent answers `409 no_signing_key`. This is the hosted model of the protocol's section 11.2: the server, or a signing service apart from it, holds the agent's key, as a mail provider holds its DKIM key.

**Repeats.** A client may send a message again whenever it is unsure the first try arrived. Once it has authenticated the caller, a server answers a repeat of a message it already accepted, the same id, with its first answer, before any check above that can change with time: `sentAt`'s freshness, the parts it holds, the domain still naming it. It keeps that record at least until the message's `sentAt` is 24 hours old. After that no repeat could pass the freshness check anyway, so a message is never sent twice; a client that is still unsure asks `GET /simon/sent/<id>`.

## sync

`GET /simon/sync?since=<token>&limit=<n>&wait=<seconds>` is how an agent, and each of its clients, hears what is new, the way a Matrix client does. It answers `{"messages","marks","removed","signals","token","more"}`, everything since `since`:
- `messages` are the messages new since then, received or sent by the agent from any of its clients, in the order the server took them;
- `signals` are the signals the agent received, held only briefly (section "Signals");
- `marks` and `removed` are the history's changes (section "History"). A server that keeps no history answers them empty.

Each message is an **entry**:

```json
{ "id": "<message id>", "message": { ... }, "carrier": "https://simon.example.net",
  "claims": [ { "type": "acts-for", "authoritative": true, ... } ],
  "signedClaims": { "claims": [ ... ], "signature": "<the envelope's claimsSignature>" },
  "receivedAt": "2026-10-14T21:00:02Z" }
```

- `carrier` is the origin of the server that delivered the message, which is this server's own origin for a message written here.
- `claims` are the claims this server accepted from that carrier: the authoritative ones always, and others only from carriers it trusts (the protocol's section 6.2). Each `acts-for` claim, and each of the registry's `identifier` claims, carries `authoritative`, the server's judgement of it. A claim of any other type never carries `authoritative`, whatever the carrier sent.
- `signedClaims`, present when the carrier made claims, holds every claim exactly as the carrier sent it, with the carrier's `claimsSignature`. For a message written here, this server signs its claims as a carrier signs them in an envelope (the protocol's section 6.2), so `signedClaims` is present whenever it made claims about it. A client checks them itself, wherever the entry travels, as the protocol's section 6.2 says; `claims` is this server's judgement, which only this server's own agents can rely on.
- The same message can arrive more than once, and messages arrive in no particular order. An agent recognises a message it has already seen by its id.

**The token.** The client keeps `token`, an opaque string, and passes it as `since` next time.
- Without `since`, sync starts from the oldest message the server still holds for the agent. A client of a server that keeps a history lists conversations first instead, and syncs from the `token` that listing answers with.
- **Upgrades with incomplete old sent tracking.** A host that cannot reconstruct a migrated account’s old sent history refuses an initial request without `since` with `410 token_expired`, `details.reason` set to `history_migration` and an opaque `details.resumeToken`. Each device learns the gap. After explicitly accepting that limitation, the client may pass that token as `since` to read retained received messages and tracked sends; the token keeps normal account binding and expiry. The client never accepts or replays it automatically. Repeating a request without `since` still reports the gap.
- `limit` is 1 to 200 messages, 50 by default. With `more`, the client asks again at once.
- **Entries become visible in order.** A server never makes an entry visible at or below the position of a `token` it has already returned, so a client that continues from its last token misses nothing. A server that writes entries from several places at once either keeps an entry out of answers until every entry before it is visible, or returns a `token` that reaches only a safe high-water mark: a position below which no entry can still appear. The reference server does the latter.
- `wait` is 0 to 60 seconds, 0 by default. With nothing new, a server SHOULD hold the request open until something arrives or `wait` passes, then answer as usual. This is the long poll an agent with nothing but `curl` can use; a client never needs to know whether the server held it.
- **Gaps are said, never hidden.** How long a server holds what sync delivers is its own policy, which it publishes as `syncDays` in its server document (registry); the reference server holds 7 days. A token that reaches back past anything the server has since let go, or that it does not know, answers `410 token_expired`, never a shorter answer, so a client never mistakes missed messages for nothing new. The client then starts again: without `since`, or from a new listing.

**Webhooks** wake an agent that holds no connection open, such as a hosted agent. `POST /simon/webhooks` with `{"url"}` and `DELETE /simon/webhooks/<id>`:
- **Verification.** The server first posts `{"type":"verify","code"}` to the URL, and sends nothing else until the client returns the code with `POST /simon/webhooks/<id>/verify`. So no one can aim a server at a URL they do not control, as JMAP's verification does (RFC 8620 section 7.2).
- **Waking.** When something arrives that `sync` would show, the server posts `{"type":"changed","agent"}`, at most once a second, and nothing else. The agent then syncs.
- **Signing.** Every post is a server request, signed as the protocol's section 8 says with `simon-server`, whose origin line is the webhook URL's origin. The receiver checks it against the server's document, so a webhook needs no shared secret.
- **Failure.** A webhook that has failed for 3 days is switched off.
- **Grants.** A webhook made through a grant ends with the grant.

A phone app is woken through the platform's push service, by a gateway built on these webhooks.

## sent

`GET /simon/sent/<id>` reports how delivery of the agent's own message is going, one entry per recipient server:

```json
{ "id": "<message id>", "servers": [
  { "server": "https://simon.example.net", "recipients": ["bob@example.net"], "status": "delivered" },
  { "server": null, "recipients": ["eve@nowhere.example"], "status": "failed", "reason": "not_found" } ] }
```

- `status` is `pending`, `delivered` or `failed`.
- `reason` explains a failure. It is the resolution outcome, the code the receiving server answered, or `expired` when the delivery deadline passed (the protocol's section 6.3).
- `delivered` means the receiving server answered `202`, or a feature of this server, such as an email bridge, took the recipients (then `server` is `null`). It does not mean a recipient read the message, or was even offered it, because policy is silent.
- A server answers for a message at least as long as it keeps its record of accepting it (section "send"). A message this agent did not author here, and an unknown id, are both `404 not_found`, the same bytes.

## parts

**Upload.** `PUT /simon/parts/<sha256>` uploads the bytes of a content-addressed part before the message that names it is sent. The body is the bytes, at most `partBytes`. The answer is `200 {"sha256","size"}`. A body whose hash is not the one in the path is `400 invalid`.

**Fetch.** `GET /simon/parts/<sha256>` composes the protocol's independent grants (PROTOCOL.md section 7.2):
- a hosted agent's private client grant covers bytes it uploaded, or bytes fetched from the carrier for a message delivered to that agent that names them;
- a publication grant covers a file of a published message this reader may read, from the bytes held for that message's author.

A private grant does not depend on an unrelated publication policy. A pending or temporarily failed private fetch may still fall back to ready bytes through an independent publication grant; without that fallback it answers `503 unavailable` with `Retry-After`. The server never returns another agent's private bytes merely because some other message names the same hash. Without a grant, the answer is `404 not_found`.

Public service/domain routing (PROTOCOL.md section 8, "Exceptions": the `simon-agent` request names an address on a domain this server serves) selects hosted client authentication, never hidden account existence. Hosted authentication failures for unknown, revoked, retired and invalid-signature keys all answer the same minimal `401 bad_signature`, with detail `This request is not authorized.`, the required `WWW-Authenticate: SIMON` and `details.serverTime`, and no key-state diagnostic or `details.signingString`. A valid hosted identity may use either its private grant or a publication grant. A foreign signature that fails asks as nobody for publication access and creates no private grant; an unsigned public read also asks as nobody. Without an independent public grant those reads receive the uniform `404` (PROTOCOL.md section 8, "Exceptions").

## Signals

Signals are the protocol's short-lived notes about a message: `typing`, `collected` and `read` (PROTOCOL.md section 6.4). A server sends one only when its agent asks, so whether an agent shares typing or reading at all is the agent's, or its client's, choice.

**Sending.** `POST /simon/send-signal` with `{"type","about","to"}`. It is the agent's request, as `send` is for a message; the server then delivers the signal with the protocol's own `POST /simon/signal`, as it delivers a message with `deliver`:
- `type` is a signal type, `about` a message id the agent holds, and `to` the addresses to tell, each the message's author or one of its recipients (PROTOCOL.md 6.4). Whether a recipient's server shows it is that server's policy.
- The server signs and sends one signal to each recipient server, and answers `202 {"accepted":true}`. Like a delivery, the answer says nothing about whether anyone will see it, and an address the rules exclude is left out silently.
- Through a grant, it needs the `send` scope.

**Receiving.** Signals for the agent arrive in `sync`, each `{"type","from","about","at"}`. A signal takes its place in the sync stream like a message: every sync whose `since` comes before it shows it, until the server forgets it, at most five minutes after it arrived. Within that bound, how long a server holds a signal is its own policy (PROTOCOL.md section 6.4). So every client that syncs in time sees it once, and none has to say who it is. Through a grant, they need the `read` scope.

## Reading published messages

A published message, one with an empty `to`, is kept by its author's server and served to the readers its `audience` admits (PROTOCOL.md 7). An agent publishes with `send`, with the `feed` and `audience` headers it wants. It reads straight from the author's server, with no call here:
- **Open posts** are read without signing.
- **A post for a narrower audience** is read with a request the agent signs itself, as section 8 says, with its own agent key, naming itself in `simon-agent` (PROTOCOL.md 7.1). The author's server checks that key against the agent's document, as Bluesky's service authentication and Nostr's NIP-98 do. No server vouches for anyone.

A client that holds no agent key reads only what is open to anyone. A grant never signs as the agent.

## History

The calls every server offers move messages, and `sync` tells of each one. A server that hosts people's agents also keeps each agent's **history**: every message the agent sent or received, grouped into the protocol's conversations (PROTOCOL.md 5.6), with the marks its clients share. Every device and every app of one agent sees the same history, and stays current with one call, `sync`, the way Matrix clients do.

**A message in the history** is a sync entry (`id`, `message`, `carrier`, `claims`, `signedClaims`, `receivedAt`), and:
- `conversation`: the id of the conversation's root, from the message's `conversation` header when it has one, otherwise found by following `inReplyTo` through the history. A conversation found that way can change when an earlier message arrives, and the change comes through `sync`;
- `marks`: the agent's own marks on it, shared by its clients and sent to no one.

**Marks.** A mark is a short string, 1 to 64 characters. These four mean the same in every client:
- `read`, on a message;
- `pinned`, `archived` and `muted`, on a conversation, by its id.

Any other mark is the agent's own tag, at most 32 on one message or conversation.

**Conversations.** `GET /simon/conversations?before=<cursor>&limit=<n>&mark=<mark>&notMark=<mark>` answers `{"conversations":[...],"cursor","more"}`, latest activity first. Each conversation is `{"id","subject","members","marks","unread","latest"}`:
- `members` is the roster as the history's messages give it (PROTOCOL.md 5.6);
- `unread` counts messages not marked `read`;
- `latest` is its newest message.

The inbox, in the sense people use the word, is `notMark=archived`.

**One conversation.** `GET /simon/conversations/<id>?before=<cursor>&limit=<n>` answers `{"messages":[...],"cursor","more"}`, newest first.

**Search.** `GET /simon/history` takes any of `text`, `from`, `to`, `mark`, `notMark`, `after`, `before` (timestamps) and `limit`, and answers like a conversation does.
- `text` matches text blocks and the `subject` header without regard to case; a server MAY match more loosely.
- `from=<the agent's own address>` is what it sent.

Listings take `limit` from 1 to 200, 50 by default, and an opaque `cursor`. Each listing also answers `token`, the sync token as of its first page, so a client syncs on from exactly what it listed; a later page answers the same token.

**In sync.** On a server that keeps a history, `sync` (above) carries its changes too:
- each message also carries `conversation` and `marks`;
- `marks` are `{"id","marks"}` for each message or conversation whose marks changed;
- `removed` are the ids taken out of the history.

**Marking.** `POST /simon/marks` with `{"ids","add","remove"}` adds and removes marks on messages or conversations, and answers `{"token"}`. Every client hears of it through `sync`.

**Removing.** `DELETE /simon/history/<id>` removes a message from this agent's history, for all its clients. Nothing reaches anyone else, and the author's signature stays wherever else the message went. A repeat delivery of a removed message does not bring it back.

**How long.** A server keeps the history until the agent removes messages, or for the `retentionDays` its server document's `history` member states, which is its own policy.

## Delegated access

How a client that holds no agent key asks for a grant. It is OAuth 2.1 (the authorization code flow with PKCE, as RFC 9700 recommends), the way a mail client asks Gmail, with one change: the grant is bound to the client's key instead of a bearer token, so nothing a client sends can be replayed by whoever copies it. DPoP (RFC 9449) gives OAuth the same property, and the AT Protocol's OAuth requires it; here the protocol's own request signature does that job, so a client implements one signature, not two.

**The issuer is the agent's server.** The OAuth authorization server is the SIMON server itself, at its own origin, so the server that checks a request's signature is the one that bound the key to the grant.

**Discovery.**
1. The client resolves the agent's domain to its server (the protocol's section 3).
2. It reads `https://<server>/.well-known/oauth-protected-resource` (RFC 9728). Its `authorization_servers` is an array whose one entry is the server's own origin. A server that answers `404` offers no grants.
3. It reads the server's OAuth metadata (RFC 8414) at `https://<server>/.well-known/oauth-authorization-server`, which names the authorization and token endpoints.

**Who the client is.** `client_id` is an HTTPS URL that serves the client's metadata document, as the OAuth client ID metadata document draft and the AT Protocol define, so a client needs no registration with each server.
- The document gives at least `client_id`, `client_name` and `redirect_uris`. Its `client_id` equals the URL it was fetched from, or the request is refused (`invalid_client`), so a document copied elsewhere names no one.
- The server fetches it under the protocol's section 11.2 transport rules, at most 16384 bytes, keeps it for at most 24 hours, and counts these fetches against the asking client network's budget.
- It shows the person deciding the client's name and the URL's host.

**The request.** The authorization request carries, beside OAuth's own parameters:
- `scope`: space-separated scope names from "Who may call", prefixed `simon:` (`simon:read simon:send`). A server that keeps no signing key for the agent does not offer `simon:send`;
- `login_hint`: the agent's address, when the client knows it;
- `prompt=create`, when the client has no agent yet and asks for one to be made (as OpenID Connect's account-creation prompt does);
- `simon_key`: the client key's token. The grant will be bound to it.

These travel in the front channel, and so in browser history; none of them is a secret.

**Who decides.** The server signs in whoever may manage the agent, in its own way, lets them choose the agent and the scopes, and redirects back with a code:
- for a paired agent, its principal: by an identifier the principal proves, or, for a key principal, by a signature of that key over a challenge the server gives;
- for a solo agent, whoever the server lets manage it. A solo agent whose key is all the authority there is may grant through the server's own sign-in by that key.

**Or makes the agent, in the same step.** With `prompt=create`, or whenever the person signing in chooses it, the server makes a new agent instead: it gives it an address as `register` would, pairs it with the person by the identifier they signed in with, and keeps its signing key ("The host's signing key"). The grant is for that agent. So one approval is the whole setup: the agent, its pairing and the client's access, with no key or address for the person to handle, and a client holding only its client key can send at once. A server that cannot make agents, or does not let this person, shows the choice of existing agents only.

**The exchange.** The client posts the code to the token endpoint as OAuth says, signed under the protocol's section 8 by the client key it named. The signing string's origin line is the server's origin, and nonces are kept as section 8 says. The server refuses a token request whose signing key is not `simon_key`, or a key already bound to another agent here, with OAuth's `invalid_grant`; the token endpoint answers in OAuth's error shape.

The answer names the grant. It holds no access token, because no request ever carries one: every request the client makes is signed by its client key, and the key is what identifies the grant.

```json
{ "grant": "<the grant id>", "scope": "simon:read simon:send", "simon_address": "ada@example.com" }
```

- `grant` is the grant's id, as the account lists it. It is not a secret.
- `scope` is the scopes granted, which may be fewer than those asked for.
- `simon_address` is the agent chosen.
- A grant lasts until the principal, an agent key or its own client key ends it, or until an `expires_in` the answer states. There is no refresh token.

A generic OAuth library is used up to the redirect: the authorization request and PKCE. The exchange itself is a POST the client signs under section 8, which no stock library does, so the client makes it and reads this answer itself. A server ignores an `Authorization` header.

**What a grant never reaches.** A grant reaches only the agent it names, and only the calls its scopes authorise. Except for ending its own grant, it never reaches the calls of "The agent's address and keys", so it never adds or revokes keys, starts or cancels a recovery, or makes or ends another grant.

## Verifying what a server says

A client checks the message itself against authenticated evidence from the author's domain, rather than trusting an entry's unverified claims or attached keys. A sync entry, a message in the history and a message pasted into a chat follow the same checks, because anyone can paste an entry. Those checks can succeed only while the necessary authenticated evidence is available.

**What an entry carries for this.** Sync entries and messages in the history carry the message, its `carrier`, and `signedClaims`: every claim exactly as the carrier sent it, with the carrier's `claimsSignature` over `{"claims":<those claims>,"message":<the message id>}` (PROTOCOL.md 6.2). The entry's `claims` member is the server's own judged copy, with its `authoritative` marks, for clients that do not check; it is never what a client checks.

**What a client checks before it relies on a message,** in this order:
1. **The author.** It resolves the `from` domain itself (PROTOCOL.md 3), reads the author's agent document from that server (4), and verifies the message's signature with a key valid at its `sentAt`. Keys that arrive with the message, or from anywhere else, are a convenience to compare, never a source.
2. **The version.** A message of a version the client does not implement is *not understood*: the client may say whose key signed it, and nothing else about it (PROTOCOL.md 1, "Unknown versions").
3. **The principal.** Only when the author's document says `paired`, and either the `pairing` header verifies with the key in `for`, or a claim below backs it (PROTOCOL.md 2.2). A `for` header on a solo agent's message names no one.
4. **The claims.** Claims count only from `signedClaims`, and only when `signedClaims.signature` verifies over `SIMON-CLAIMS\n` and the canonical bytes of `{"claims":signedClaims.claims,"message":<the message id>}` (PROTOCOL.md 6.2), with a key of the server the `from` domain resolves to, valid within the message's delivery window. The client then judges authority itself, by resolving the identifier's domain: authoritative only when that domain's `_simon` TXT record names the carrier (PROTOCOL.md 6.2). Any other claim counts only if the client, or the person it serves, trusts that carrier for that identifier. A forwarded message's claims, carried beside it as `application/simon-claims+json` (the registry's `forward`), are checked the same way.
5. **Nothing from the caller.** A client never accepts claims, keys or a carrier as arguments to a verification, from a message's own text, or from whoever forwarded the entry. It reads them from the entry it checks, and checks them as above.

A client that cannot complete a step says so, and treats what it could not check as the author's word only.

**Missing historical evidence.** A bounded current document can prune revoked agent or carrier keys, and a host may stop disclosing a retired identity. Saving the message or `signedClaims` alone does not preserve independently authenticated key history. The current SDK readers resolve current domain and document evidence; they do not provide a durable authenticated archive. A cold reader may therefore be unable to verify an old message it still holds. A separate local check may use evidence that the client previously authenticated and deliberately retained, with the limits in PROTOCOL.md 2.4 and 6.2; unsigned keys supplied beside a published message are not such evidence.

## Reading rules

What a conforming reader does when it shows or acts on a message. Each rule is the protocol's or the registry's; this list gathers them so a client can be built and tested against one page.

1. **Verify first** (section "Verifying what a server says").
2. **Honour `critical`.** A message listing a present header the reader does not understand is stored and shown as not understood; names absent from the message are ignored. The reader acts on nothing in a message with an unknown present critical header (PROTOCOL.md 5.4). A reader that implements `binding` and sees `binding: no` treats the message as no commitment.
3. **Show what it can.** A message may carry any blocks, or none. Text is shown as text, and Markdown is read as CommonMark unless it names a variant the reader knows; embedded HTML is shown as text (PROTOCOL.md 5.3).
4. **Blocks are data.** A block the reader does not understand is shown by its `alt`, or skipped. No block, of any type, makes the reader run code, call a URL or reveal anything by being shown. UI blocks are drawn from their data by the reader's own code, never by code the message carries.
5. **Fetch nothing unasked.** No link, image or reference is fetched until the person or agent the reader serves asks for it, because a fetch on display is a read receipt. Links show their destination.
6. **Fold relations by their rules.** A relation the reader does not know is shown as a reply. An edit or a retraction counts only from the original message's author, and names the original, never an earlier edit; from anyone else it is an ordinary reply (PROTOCOL.md 5.5). Reactions are folded onto the message they name.
7. **Never widen an audience.** A published message with an `audience` header is never forwarded, quoted whole or shown to anyone its author's server would not admit (PROTOCOL.md 7.1).
8. **Keep others' words apart.** What another agent wrote reaches an agent or a person labelled with who wrote it, as data, never as instructions from the one the reader serves (PROTOCOL.md 11.2).
9. **Signals are the sender's to give.** A reader sends `typing` and `read` only as the person or agent it serves has chosen to share them.

## Errors

These are the codes this API adds to the protocol's, all in the protocol's error shape:

| Status | Code | When |
| --- | --- | --- |
| 400 | `address_required` | `register` with a key alone, on a server that leases no addresses |
| 400 | `too_many_keys` | the agent reaches the host’s active-key or published-document bounds |
| 409 | `too_many_webhooks` | the agent reaches the host’s webhook allowance |
| 400 | `part_not_uploaded` | `send`: a content-addressed part this server does not hold for the agent |
| 400 | `unsupported_version` | `send`: a message version the server does not implement |
| 401 | `bad_proof` | the add-key proof, a pairing, a principal's recovery signature or an unpairing does not verify |
| 403 | `scope_required` | a call signed by a client key whose grant lacks the scope the call needs |
| 409 | `address_taken`, `address_homed_elsewhere`, `key_in_use` | `register`, recovery or adding a key: the address is held or kept, or not given to this key, the address's domain names another server, or the key was this agent's before (a recovery to a previously revoked key included) or, by the host's policy, serves another address |
| 409 | `key_senior`, `last_key` | revoking a key: the server's policy does not let the signing key revoke that one, or it is the agent's last active key |
| 409 | `recovery_not_cancellable` | cancelling a recovery by key: the server's policy does not let this key cancel it |
| 409 | `no_signing_key` | `send` through a grant: the server keeps no key for the agent |
| 409 | `address_not_served` | `send`: the agent's domain no longer names this server |
| 410 | `code_expired`, `code_locked` | a code handed back to registration or recovery after it expired, or after too many wrong attempts |
| 410 | `token_expired` | `sync`: a token older than the server holds, or unknown |
| 422 | `wrong_code` | a code handed back that is not the one sent, or a cancel code that cancels nothing |

## Changing address

An address belongs to its domain, as in email, so changing address is not a transfer: the agent takes a new address, with a new key, and says so in signed messages. From the old address, before it retires, it sends a message carrying `moved-to` with the new address; from the new one, a message carrying `moved-from` with the old. Each is signed by its own address's keys, and a reader honours the move only when it holds both, so neither address can claim the other alone (the registry's `moved-to` and `moved-from`, as Mastodon moves an account with `movedTo` and `alsoKnownAs`). The new address normally takes a new key too, since keeping the old one links the two addresses for every reader (PROTOCOL.md 12), which a move may or may not want. Claims are verified again for the new address.
