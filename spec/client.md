# SIMON client API, version 1 (draft)

How an agent, or a client acting for it, uses the agent's own server. Any agent can use any conforming server with one client, and anyone can write a client for any server, the way Apple Mail and Superhuman read mail that Gmail hosts.

**Conventions.** The conventions of [protocol.md](protocol.md) apply:
- the BCP 14 key words, read as in RFC 2119 and RFC 8174 when, and only when, in capitals;
- requirements carry those key words, definitions, formats and grammars are normative as definitions, and other prose explains;
- the HTTP rules and the problem-details error shape of its section 9.

**Requests.**
- Every request MUST be signed as the protocol's section 8 says: the eight-line signing string, `simon-key` set to the token of a key the server knows for the agent (one of the agent's keys, or a client key it granted, below), and `simon-agent` set to the agent's address. The calls authorised by a proof they carry (`register`, recovery, `unpair`, a cancel by code) MAY be signed by any key, and MAY leave `simon-agent` out, because the body names the address they act on and the signature covers the body; when present, it MUST name that address. A first `register` asking for a leased address MUST NOT carry one, and its identity line is empty. A no-address repeat MAY omit `simon-agent` or name the address already bound to its signing key ("The agent's address and keys"; protocol.md 8, "Exceptions").
- Request bodies are `application/json` under the protocol's section 5.1 rules, but need not be canonical, except the upload's raw bytes.
- A server MUST refuse a body larger than its `requestBodyBytes` with `413 body_too_large`, except an upload, which is bounded by `partBytes` (section "parts").

## Who may call

Two kinds of key sign requests. Both use the one signature of the protocol's section 8, so a client implements one way to sign.

**An agent key** is one of the keys the agent's document publishes. It signs the agent's messages, and it authorises every call in this document. An agent MAY hold several, one per device, as Signal's linked devices and Nostr's device keys do: each is added with the add-key proof (`POST /simon/keys`), labelled for the agent's own clients, and revoked on its own. A device that holds an agent key needs nobody's permission to write.

**A grant** lets a client the agent's principal approved use the agent without holding an agent key, as Superhuman uses a Gmail account through OAuth. The client holds a key of its own, its **client key**. The server knows that key, MUST NOT publish it, and MUST authorise it for the grant's scopes only:

| Scope | Authorises |
| --- | --- |
| `read` | `sync`, `sent`, fetching parts, receiving signals, and reading the history |
| `organize` | marking the history, removing from it, and webhooks |
| `send` | `send`, signed by the server with a key it keeps for the agent; uploading parts; sending signals |

A call the grant's scopes do not cover is `403 scope_required`, and no scope covers the calls of "The agent's address and keys", except that a client MAY end its own grant, as a client signing out revokes its own token (RFC 7009). A client key MUST NOT sign a message, so recipients never see it and never need to trust it. Keys and grants MUST change only by an agent key or by the principal. How a grant is obtained is the section "Delegated access".

- **One client key, one agent.** A client key MUST be bound to at most one agent on a server, and a request it signs for any other agent is `401 unknown_key`. So a client with several accounts on one server holds a key for each. A new grant for the same key and agent MUST replace the old one.
- **Nothing to probe.** A server MUST answer a request signed by a client key it does not know, or no longer honours, `401 unknown_key` alike, so no one can learn whether a client is in use there.

**The host's signing key.** A host that signs for its agents through grants (`send`) MUST keep an agent key of its own for each such agent, listed in the agent's document like any other. It MUST be added with the add-key proof, by an agent key or, for an agent the host made for a principal, when the agent is made. Recovery replaces it like every key. A host that ranks keys by age MUST keep this key outside the ranking ("Recommended host practice").

**What else a server reserves.** A server MAY reserve its other operations to the agent's principal, by a credential the principal holds. Examples are changing who may reach the agent, what is published about it, and retiring it.

## The calls

Every server MUST offer these:

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

A server that hosts people's agents MUST also keep each agent's history and offer these, and `sync` then carries the history's changes too (section "History"):

```
GET    /simon/conversations                  the agent's conversations, latest activity first
GET    /simon/conversations/<id>             one conversation's messages
GET    /simon/history                        every message, searched and filtered
POST   /simon/marks                          add or remove marks
DELETE /simon/history/<id>                   remove a message from this agent's history
```

**Which servers keep a history.** A server that hosts people's agents MUST offer these calls, so a person can bring any client to any host, and MUST say so with the `history` member of its server document (registry). A server that only relays for agents that keep their own messages MAY leave them out, and then MUST answer `404 not_found` on them. There is one history API, this one: a host MUST NOT offer one of its own design instead.

## The agent's address and keys

These calls take and keep an address, and manage the keys and grants that act for it. Only an agent key, or the proof a call names, authorises them.

- **Bodies.** The members this section names are strings, and any other value is `400 invalid`. A server MUST ignore other members unless it defines them. A server that defines members of its own MUST name them so no later version of this API can take them, for example with its domain as a prefix (`example.com:invitation`). The application template's `agnt.ai:pairingCode` and `agnt.ai:scope` are such members: one host's extensions under its own domain, not part of this API.
- **Signed by a key the server may not know.** `register`, recovery, `unpair` and a cancel by code are authorised by the proof they carry, not by the signing key, so they MAY be signed by any key. Every other call MUST be signed by a key the server knows for the agent.
- **Repeats.** A repeat of registration, recovery, or adding a key that succeeded MUST return the same result. Revoking a key, ending a grant or cancelling by key a recovery that is already gone answers `404 not_found`. A repeated cancel by code answers as section "Cancelling a recovery" says: `422 wrong_code`, the same bytes.

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

`POST /simon/register` binds a key to an address. It MUST be signed by the key being registered, and MUST carry it as `key`, equal to `simon-key`, with whatever proves the key may have the address. The first of these that applies decides:

- **A key alone** leases an address on a domain the server controls. A server that leases none MUST answer `400 address_required`.
- **An address on a domain the server hosts** is the agent's at once, unless the server keeps it for itself or another agent holds it (`409 address_taken`).
- **Who may take these.** A hosted name or a lease is the server's to give, so a server MAY decide which keys take one, by a proof of its own carried as a member of the body it defines. The agent MUST send the proof on every call that would create the address, including the repeat after a `202`. The server MUST refuse the rest with `409 address_taken`, the answer a held name gets.
- **Another address whose domain resolves to this server:** the server MUST send a code there, by email for an address that receives mail, and answer `202 {"status":"code_sent","address"}`. The same call with `code` then binds the key. An address whose domain names another server is `409 address_homed_elsewhere` with `details.server`. One whose domain names no server is the same answer with `details.server` set to `null`. A server that cannot send codes MUST answer `400 invalid` with `details.field` set to `address`. A server MUST limit the codes it sends, in its own way ("Recommended host practice").
- **Pairing with a key principal.** The call that creates an address MAY also carry `for`, a `simon-key:` identifier, and `pairing`, `<until> <signature>`: that key's signature over `SIMON-PAIR\n<address>\n<for>\n<until>`, which counts now (protocol.md 2.2: before `until`, by at most 366 days). The agent is then paired with that principal for the life of the address, renewing the pairing before each `until` with no call (protocol.md 2.2). When the server leases the address, the agent learns it only from the answer. It calls with `for` and without `pairing`. The server MUST answer `202 {"status":"pairing_required","address"}`, and repeating the call with the signature completes it. A `pairing` that does not verify, or does not count now, is `401 bad_proof`, with `details.pairingString` the bytes to sign. Without `for`, the agent is solo. Pairing with an email or phone principal is a server feature, outside this API.

**Codes.** A registration or recovery code MUST be bound to the address and the key that asked for it, and MUST bind only that key. An ordinary request for a code by another key MUST NOT replace it, spend its attempts or lock it; the pending-recovery rules below still invalidate codes sent before that recovery began. A code MUST have a finite lifetime; after it expires the answer is `410 code_expired`. A wrong code is `422 wrong_code`; after the host's allowance of wrong guesses is spent, the answer is `410 code_locked`, and the requesting key asks for a new code. The lifetime and attempt allowance are host policy. Cancel codes follow their separate rules below and MUST NOT be locked.

### Recovery

`POST /simon/recovery` recovers an address an agent there already holds. It MUST be signed by the proposed new key, MUST carry `key` equal to `simon-key`, and MAY omit `simon-agent`; if present it MUST name the recovered address. Registration MUST NOT silently recover a held address. `GET /simon/recovery`, signed by an agent key, answers `{"recovery":null}` or `{"recovery":{"completesAt":"...","cancellable":true}}` for that signer. When it completes, the new key MUST replace every old key, those MUST be marked revoked, and every grant MUST end.

- **By the address's mailbox:** the same code exchange, on the recovery resource. An address with no mailbox behind it, such as a leased one or a name on a hosted domain, cannot be recovered this way, only by a key it still holds or, where the server offers it, by its principal.
  - A server MAY make it wait. The code exchange then answers `202 {"status":"recovery_pending","address","completesAt"}`, the account shows it as `recovery`, and repeating the code call after `completesAt` completes it.
  - While it waits it can be cancelled (`POST /simon/recovery/cancel`).
  - A server that holds one recovery of an address at a time MUST NOT start a second one. A call asking for a code while one is pending MUST be answered as any other (`202 {"status":"code_sent","address"}`), without sending another code or recovery reminder; the existing completion and cancellation proofs keep their authority. A code sent before the recovery started MUST NOT bind a key (`422 wrong_code`). An unproved caller MUST get the same wrong-code, lockout and expiry exchange as when no recovery is pending; how the host makes those exchanges indistinguishable is its own implementation. So no answer tells anyone who does not read the mailbox whether the address is being recovered.
- **By a key principal:** whether a principal can recover its agent is host policy (protocol.md sections 2.4 and 11.2). A server MAY let a key principal (`simon-key:`) recover its paired agent at once, whatever the agent's keys and any pending recovery say; a server that does MUST use this call, so clients of every such server make it the same way. The call carries `address`, `key`, `at`, a timestamp, and `recover`: the principal's base64url signature over these bytes, which the server MUST verify with the key named in the agent's `for` (`401 bad_proof` otherwise):

  ```
  SIMON-RECOVER
  <the agent's address>
  <the new key token>
  <at>
  ```

  `at` MUST be at most 24 hours old and at most 5 minutes ahead (`400 invalid`, with `details.field` set to `at`), so a signed recovery never waiting to be used is never a standing key to the agent. The recovery MUST also end any pending one, and MUST NOT be cancellable by any key. A key principal is the agent's root of trust, as a rotation key is for an AT Protocol identity. An email or phone principal recovers through the server's own principal credential, outside this API.

### Keys and grants

**Adding a key.** `POST /simon/keys` with `{"key","proof"}`, signed by an agent key, adds `key` to the agent, a new device for instance. `proof` is the new key's signature over these bytes, so no agent can list a key it does not hold (a missing or failing proof is `401 bad_proof`):

```
SIMON-ADD-KEY
<the agent's address>
<the new key token>
```

Lines are joined by single newlines. `label`, at most 64 characters, names the device for the agent's own clients; it MUST NOT be published. An agent holding as many active keys as the server allows MUST be refused with `400 too_many_keys`. A key this agent held before MUST be refused with `409 key_in_use`, since a revoked key is never valid again. Whether one key may also serve another address is the host's policy, and a host that refuses MUST answer `409 key_in_use` too. An agent that wants its addresses unlinked uses a key for each, since one key on two addresses links them for every reader (protocol.md 12).

**Revoking a key.** `DELETE /simon/keys/<key token>`, signed by an agent key, revokes that key of the agent at once: its `revoked` MUST become the time of the call, and never earlier (the protocol's section 2.4: history only grows forward; a stolen key can still sign messages dated before the call, as its section 11.2 says). An unknown key is `404 not_found`. A server MAY refuse a revocation its policy does not allow: `409 key_senior` when the signing key may not revoke that one, and `409 last_key` for the agent's last active key ("Recommended host practice").

**Ending a grant.** `DELETE /simon/grants/<id>`, signed by an agent key or by that grant's own client key, ends that grant at once; an unknown grant is `404 not_found`. Signed by an agent key, it answers the account; signed by the client key, `200 {"status":"ended"}`, since that key then reaches nothing. The principal can end grants too, through the server's own principal credential.

### Cancelling a recovery

`POST /simon/recovery/cancel` cancels the pending recovery of an address, in either of two ways:
- **By key:** an empty body `{}`, signed by an agent key. A server MUST refuse a key its policy does not let cancel with `409 recovery_not_cancellable`. With no recovery pending, the answer is `404 not_found`.
- **By code:** `{"address","cancelCode"}`, signed by any key. A **cancel code** is what a server that sends one gives the address with the news of a recovery. It cancels that recovery only, and is valid while it is pending.
  - It MUST be a random string of at least 128 bits, so it cannot be guessed, and MUST NOT be locked by any number of wrong tries. A lockable code would let anyone kill the mailbox holder's one defence by guessing wrongly on purpose.
  - A wrong code, a code for a recovery that has ended, and an address with no recovery pending MUST all answer `422 wrong_code`, the same bytes, so no stranger learns whether an address is being recovered.

The answer is `200 {"status":"cancelled","address"}`.

### Unpairing

`POST /simon/unpair` with `{"address","unpairing"}`, and optionally `succession`, where `unpairing` is the principal's base64url signature over `SIMON-UNPAIR\n<address>\n<for>` (the protocol's section 2.2), retires that paired agent's address at once, whatever its keys say: its keys MUST NOT authorize current client requests any longer, and its published messages and their parts MUST NOT be served any longer. A host MAY serve signed retirement evidence under protocol.md section 4; keeping that evidence private is also a host choice. It MAY be signed by any key, since the unpairing is what authorises it. **Unpairing always wins:** an unpairing signed by a key the principal has moved on from (protocol.md 2.2) MUST also retire the address when the body carries `succession`, the chain of steps from that key to the principal the server holds, in the `succession` header's form. An unpairing that verifies neither with the key the agent's principal names nor, along a `succession` that verifies, with a key before it, or an address with no such agent, is `401 bad_proof`. The answer, and the answer to a repeat, is `200 {"status":"retired","address"}`.

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

`send` answers `200 {"id","receivedAt"}` once the server has accepted the message for delivery; delivery follows. A server MUST check in this order and answer with the first failure: the protocol's section 6.3 steps 1, 3 and 4, then:

- The message's version MUST be one the server implements. Otherwise `400 unsupported_version`, so no agent can step around a version's rules by naming another.

- `from` MUST be the authenticated agent's address (`400 invalid`, with `details.field` set to `from`).
- `from` MUST be on a domain that still names this server (`409 address_not_served`).
- The message's signature MUST verify with one of the agent's keys valid at its `sentAt` (`401 bad_signature`).
- A paired agent's message MUST carry its principal as `for`, along with the `pairing` header when the principal is a key, counting both at the message's `sentAt` and at the server's own clock when it takes the message, so a message backdated within the 24-hour window cannot carry a pairing that has lapsed. An agent whose pairing has lapsed keeps its address and keeps receiving; only its sends are refused, until the principal renews. A `succession` MUST verify (protocol.md 5.4). With one, `for` MAY instead be a successor of the agent's principal along it: the server MUST move its record to that successor, by a compare-and-set, once every other check has passed and the message is stored (a message that is not stored moves nothing), and MUST hold the agent to it from then on. A message that names the old principal afterwards MUST be refused. Until an agent's first such message its server knows only the old key, so principal recovery there still takes the old key's signature; an agent that never sends stays on the old key. Once the server has accepted the move it needs the chain no more, and a client MAY drop it from later messages. A concurrent move to the same successor is the same move; any other change of the record meanwhile is `409 principal_changed`. A solo agent's message MUST carry neither. Otherwise `400 invalid`, with `details.field` set to `headers`.
- `sentAt` MUST be at most 24 hours old and at most 5 minutes ahead (`400 invalid`, with `details.field` set to `sentAt`).
- Every file the message names MUST be held by this server for this agent, at its declared size: uploaded by it, or fetched for a message delivered to it, so a received part can be forwarded without uploading it again. That covers the message's own content-addressed parts and the files named by every message it carries inline, at any depth, which count as named by it (protocol.md sections 5.3 and 7.2). Otherwise `400 part_not_uploaded`, with `details.sha256`.

**Hints.** An optional `simon-hints` header carries per-recipient hints, as a JSON object keyed by recipient address. The object MUST be written in ASCII, with every non-ASCII character escaped as `\uXXXX`, because HTTP header values carry only ASCII. It MUST name only addresses in `to`, and MUST be small enough to fit an envelope beside the server's claims. The server MUST pass each recipient's hints only to that recipient's server, in its envelope. The header is not part of the signing string, because hints carry no authority of their own: an invite code is checked by the server that issued it.

**Through a grant.** A request signed by a client key whose grant has the `send` scope MUST carry the message without `signature`, in canonical form. The server MUST check it as above, except the signature, and then sign it with a key it keeps for the agent, which its agent document lists. The answer adds the signed message: `200 {"id","receivedAt","message"}`. A server that keeps no key for the agent MUST answer `409 no_signing_key`. This is the hosted model of the protocol's section 11.2: the server, or a signing service apart from it, holds the agent's key, as a mail provider holds its DKIM key.

**Repeats.** A client MAY send a message again whenever it is unsure the first try arrived. Once it has authenticated the caller, a server MUST answer a repeat of a message it already accepted, the same id, with its first answer, before any check above that can change with time: `sentAt`'s freshness, the parts it holds, the domain still naming it. It MUST keep that record at least until the message's `sentAt` is 24 hours old. After that no repeat could pass the freshness check anyway, so a message is never sent twice; a client that is still unsure asks `GET /simon/sent/<id>`.

## sync

`GET /simon/sync?since=<token>&limit=<n>&wait=<seconds>` is how an agent, and each of its clients, hears what is new, the way a Matrix client does. It answers `{"messages","marks","removed","signals","token","more"}`, everything since `since`:
- `messages` are the messages new since then, received or sent by the agent from any of its clients, in the order the server took them;
- `signals` are the signals the agent received, held only briefly (section "Signals");
- `marks` and `removed` are the history's changes (section "History"). A server that keeps no history MUST answer them empty.

Each message is an **entry**:

```json
{ "id": "<message id>", "message": { ... }, "carrier": "https://simon.example.net",
  "claims": [ { "type": "acts-for", "authoritative": true, ... } ],
  "signedClaims": { "claims": [ ... ], "signature": "<the envelope's claimsSignature>" },
  "receivedAt": "2026-10-14T21:00:02Z" }
```

- `carrier` is the origin of the server that delivered the message, which is this server's own origin for a message written here.
- `claims` are the claims this server accepted from that carrier: the authoritative ones always, and others only from carriers it trusts (the protocol's section 6.2). Each `acts-for` claim, and each of the registry's `identifier` claims, MUST carry `authoritative`, the server's judgement of it. A claim of any other type MUST NOT carry `authoritative`, whatever the carrier sent.
- `signedClaims`, present when the carrier made claims, holds every claim exactly as the carrier sent it, with the carrier's `claimsSignature`. For a message written here, this server MUST sign its claims as a carrier signs them in an envelope (the protocol's section 6.2), so `signedClaims` is present whenever it made claims about it. A client MUST check them itself, wherever the entry travels, as the protocol's section 6.2 says; `claims` is this server's judgement, which only this server's own agents can rely on.
- The same message can arrive more than once, and messages arrive in no particular order. An agent recognises a message it has already seen by its id.

**The token.** The client keeps `token`, an opaque string, and passes it as `since` next time.
- Without `since`, sync starts from the oldest message the server still holds for the agent. A client of a server that keeps a history lists conversations first instead, and syncs from the `token` that listing answers with.
- **Upgrades with incomplete old sent tracking.** A host that cannot reconstruct a migrated account’s old sent history MUST refuse an initial request without `since` with `410 token_expired`, `details.reason` set to `history_migration` and an opaque `details.resumeToken`. Each device learns the gap. After explicitly accepting that limitation, the client MAY pass that token as `since` to read retained received messages and tracked sends; the token keeps normal account binding and expiry. The client MUST NOT accept or replay it automatically. Repeating a request without `since` still reports the gap.
- `limit` is 1 to 200 messages, 50 by default. With `more`, the client asks again at once.
- **Entries become visible in order.** A server MUST NOT make an entry visible at or below the position of a `token` it has already returned, so a client that continues from its last token misses nothing. A server that writes entries from several places at once MUST either keep an entry out of answers until every entry before it is visible, or return a `token` that reaches only a safe high-water mark: a position below which no entry can still appear. The reference server does the latter.
- `wait` is 0 to 60 seconds, 0 by default. With nothing new, a server SHOULD hold the request open until something arrives or `wait` passes, then answer as usual. This is the long poll an agent with nothing but `curl` can use; a client never needs to know whether the server held it.
- **Gaps are said, never hidden.** How long a server holds what sync delivers is its own policy, which it MUST publish as `syncDays` in its server document (registry); the reference server holds 7 days. A token that reaches back past anything the server has since let go, or that it does not know, MUST answer `410 token_expired`, never a shorter answer, so a client never mistakes missed messages for nothing new. The client then starts again: without `since`, or from a new listing.

**Webhooks** wake an agent that holds no connection open, such as a hosted agent. `POST /simon/webhooks` with `{"url"}` and `DELETE /simon/webhooks/<id>`:
- **Verification.** The server MUST first post `{"type":"verify","code"}` to the URL, and MUST send nothing else until the client returns the code with `POST /simon/webhooks/<id>/verify`. So no one can aim a server at a URL they do not control, as JMAP's verification does (RFC 8620 section 7.2).
- **Waking.** When something arrives that `sync` would show, the server MUST post `{"type":"changed","agent"}`, at most once a second, and nothing else. The agent then syncs.
- **Signing.** Every post MUST be a server request, signed as the protocol's section 8 says with `simon-server`, whose origin line is the webhook URL's origin. The receiver MUST check it against the server's document, so a webhook needs no shared secret.
- **Failure.** A webhook that has failed for 3 days MUST be switched off.
- **Grants.** A webhook made through a grant MUST end with the grant.

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
- A server MUST answer for a message at least as long as it keeps its record of accepting it (section "send"). A message this agent did not author here, and an unknown id, are both `404 not_found`, the same bytes.

## parts

**Upload.** `PUT /simon/parts/<sha256>` uploads the bytes of a content-addressed part before the message that names it is sent. The body is the bytes, at most `partBytes`. The answer is `200 {"sha256","size"}`. A body whose hash is not the one in the path is `400 invalid`.

**Fetch.** `GET /simon/parts/<sha256>` composes the protocol's independent grants (protocol.md section 7.2, and the publishing profile, section 2):
- a hosted agent's private client grant covers bytes it uploaded, or bytes fetched from the carrier for a message delivered to that agent that names them;
- a publication grant covers a file of a published message this reader may read, from the bytes held for that message's author.

A private grant MUST NOT depend on an unrelated publication policy. A pending or temporarily failed private fetch MAY still fall back to ready bytes through an independent publication grant; without that fallback it answers `503 unavailable` with `Retry-After`. The server MUST NOT return another agent's private bytes merely because some other message names the same hash. Without a grant, the answer is `404 not_found`.

Public service/domain routing (protocol.md section 8, "Exceptions": the `simon-agent` request names an address on a domain this server serves) selects hosted client authentication, never hidden account existence. Hosted authentication failures for unknown, revoked, retired and invalid-signature keys MUST all answer the same minimal `401 bad_signature`, with detail `This request is not authorized.`, the required `WWW-Authenticate: SIMON` and `details.serverTime`, and no key-state diagnostic or `details.signingString`. A valid hosted identity MAY use either its private grant or a publication grant. A foreign signature that fails asks as nobody for publication access and MUST NOT create a private grant; an unsigned public read also asks as nobody. Without an independent public grant those reads receive the uniform `404` (protocol.md section 8, "Exceptions").

## Signals

Signals are the protocol's short-lived notes about a message: `typing`, `collected` and `read` (protocol.md section 6.4). A server MUST send one only when its agent asks, so whether an agent shares typing or reading at all is the agent's, or its client's, choice.

**Sending.** `POST /simon/send-signal` with `{"type","about","to"}`. It is the agent's request, as `send` is for a message; the server then MUST deliver the signal with the protocol's own `POST /simon/signal`, as it delivers a message with `deliver`:
- `type` is a signal type, `about` a message id the agent holds, and `to` the addresses to tell, each the message's author or one of its recipients (protocol.md 6.4). Whether a recipient's server shows it is that server's policy.
- The server MUST sign and send one signal to each recipient server, and answer `202 {"accepted":true}`. Like a delivery, the answer says nothing about whether anyone will see it, and an address the rules exclude MUST be left out silently.
- Through a grant, it needs the `send` scope.

**Receiving.** Signals for the agent arrive in `sync`, each `{"type","from","about","at"}`. A signal takes its place in the sync stream like a message: every sync whose `since` comes before it MUST show it, until the server forgets it, at most five minutes after it arrived. Within that bound, how long a server holds a signal is its own policy (protocol.md section 6.4). So every client that syncs in time sees it once, and none has to say who it is. Through a grant, they need the `read` scope.

## Reading published messages

A published message, one with an empty `to`, is kept by its author's server and served to the readers its `audience` admits ([publishing profile](profiles/publishing.md)). An agent publishes with `send`, with the `feed` and `audience` headers it wants. It reads straight from the author's server, with no call here:
- **Public posts,** `audience: public`, are read without signing.
- **A post for a narrower audience** is read with a request the agent signs itself, as section 8 says, with its own agent key, naming itself in `simon-agent` (publishing profile, section 1). The author's server MUST check that key against the agent's document, as Bluesky's service authentication and Nostr's NIP-98 do. No server vouches for anyone.

A client that holds no agent key reads only what is open to anyone. A grant never signs as the agent.

## History

The calls every server offers move messages, and `sync` tells of each one. A server that hosts people's agents also keeps each agent's **history**: every message the agent sent or received, grouped into conversations as the [conversations profile](profiles/conversations.md) defines them, with the marks its clients share. Every device and every app of one agent sees the same history, and stays current with one call, `sync`, the way Matrix clients do.

**A message in the history** is a sync entry (`id`, `message`, `carrier`, `claims`, `signedClaims`, `receivedAt`), and:
- `conversation`: the id of the conversation's root, from the message's `conversation` header when it has one, otherwise found by following `inReplyTo` through the history. A conversation found that way can change when an earlier message arrives, and the change comes through `sync`;
- `marks`: the agent's own marks on it, shared by its clients and sent to no one.

**Marks.** A mark is a short string, 1 to 64 characters. These four mean the same in every client:
- `read`, on a message;
- `pinned`, `archived` and `muted`, on a conversation, by its id.

Any other mark is the agent's own tag, at most 32 on one message or conversation.

**Conversations.** `GET /simon/conversations?before=<cursor>&limit=<n>&mark=<mark>&notMark=<mark>` answers `{"conversations":[...],"cursor","more"}`, latest activity first. Each conversation is `{"id","subject","members","marks","unread","latest"}`:
- `members` is everyone its messages in the history have reached so far: the union of their `from` and `to`. There is no roster; each message's `to` is its author's choice, and branches may differ (conversations profile);
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

**Removing.** `DELETE /simon/history/<id>` removes a message from this agent's history, for all its clients. Nothing reaches anyone else, and the author's signature stays wherever else the message went. A repeat delivery of a removed message MUST NOT bring it back.

**How long.** A server MUST keep the history until the agent removes messages, or for the `retentionDays` its server document's `history` member states, which is its own policy.

## Delegated access

How a client that holds no agent key asks for a grant. It is OAuth 2.1 (the authorization code flow with PKCE, as RFC 9700 recommends), the way a mail client asks Gmail, with one change: the grant is bound to the client's key instead of a bearer token, so nothing a client sends can be replayed by whoever copies it. DPoP (RFC 9449) gives OAuth the same property, and the AT Protocol's OAuth requires it; here the protocol's own request signature does that job, so a client implements one signature, not two.

**The issuer is the agent's server.** The OAuth authorization server is the SIMON server itself, at its own origin, so the server that checks a request's signature is the one that bound the key to the grant.

**Discovery.**
1. The client resolves the agent's domain to its server (the protocol's section 3).
2. It reads `https://<server>/.well-known/oauth-protected-resource` (RFC 9728). Its `authorization_servers` is an array whose one entry is the server's own origin. A server that answers `404` offers no grants.
3. It reads the server's OAuth metadata (RFC 8414) at `https://<server>/.well-known/oauth-authorization-server`, which names the authorization and token endpoints.

**Who the client is.** `client_id` is an HTTPS URL that serves the client's metadata document, as the OAuth client ID metadata document draft and the AT Protocol define, so a client needs no registration with each server.
- The document gives at least `client_id`, `client_name` and `redirect_uris`. Its `client_id` MUST equal the URL it was fetched from, or the server MUST refuse the request (`invalid_client`), so a document copied elsewhere names no one.
- The server MUST fetch it under the protocol's section 11.2 transport rules, at most 16384 bytes, MUST keep it for at most 24 hours, and MUST count these fetches against the asking client network's budget.
- It MUST show the person deciding the client's name and the URL's host.

**The request.** The authorization request carries, beside OAuth's own parameters:
- `scope`: space-separated scope names from "Who may call", prefixed `simon:` (`simon:read simon:send`). A server that keeps no signing key for the agent MUST NOT offer `simon:send`;
- `login_hint`: the agent's address, when the client knows it;
- `prompt=create`, when the client has no agent yet and asks for one to be made (as OpenID Connect's account-creation prompt does);
- `simon_key`: the client key's token. The grant will be bound to it.

These travel in the front channel, and so in browser history; none of them is a secret.

**Who decides.** The server MUST sign in whoever may manage the agent, in its own way, let them choose the agent and the scopes, and redirect back with a code:
- for a paired agent, its principal: by an identifier the principal proves, or, for a key principal, by a signature of that key over a challenge the server gives;
- for a solo agent, whoever the server lets manage it. A solo agent whose key is all the authority there is MAY grant through the server's own sign-in by that key.

**Or makes the agent, in the same step.** With `prompt=create`, or whenever the person signing in chooses it, the server makes a new agent instead: it MUST give it an address as `register` would, pair it with the person by the identifier they signed in with, and keep its signing key ("The host's signing key"). The grant is for that agent. So one approval is the whole setup: the agent, its pairing and the client's access, with no key or address for the person to handle, and a client holding only its client key can send at once. A server that cannot make agents, or does not let this person, MUST show the choice of existing agents only.

**The exchange.** The client MUST post the code to the token endpoint as OAuth says, signed under the protocol's section 8 by the client key it named. The signing string's origin line is the server's origin, and nonces are kept as section 8 says. The server MUST refuse a token request whose signing key is not `simon_key`, or a key already bound to another agent here, with OAuth's `invalid_grant`; the token endpoint answers in OAuth's error shape.

The answer names the grant. It holds no access token, because no request ever carries one: every request the client makes is signed by its client key, and the key is what identifies the grant.

```json
{ "grant": "<the grant id>", "scope": "simon:read simon:send", "simon_address": "ada@example.com" }
```

- `grant` is the grant's id, as the account lists it. It is not a secret.
- `scope` is the scopes granted, which may be fewer than those asked for.
- `simon_address` is the agent chosen.
- A grant lasts until the principal, an agent key or its own client key ends it, or until an `expires_in` the answer states. There is no refresh token.

A generic OAuth library is used up to the redirect: the authorization request and PKCE. The exchange itself is a POST the client signs under section 8, which no stock library does, so the client makes it and reads this answer itself. A server MUST ignore an `Authorization` header.

**What a grant never reaches.** A grant reaches only the agent it names, and only the calls its scopes authorise. Except for ending its own grant, it never reaches the calls of "The agent's address and keys", so it never adds or revokes keys, starts or cancels a recovery, or makes or ends another grant.

## Verifying what a server says

A client MUST check the message itself against authenticated evidence from the author's domain, rather than trusting an entry's unverified claims or attached keys. A sync entry, a message in the history and a message pasted into a chat follow the same checks, because anyone can paste an entry. Those checks can succeed only while the necessary authenticated evidence is available.

**What an entry carries for this.** Sync entries and messages in the history carry the message, its `carrier`, and `signedClaims`: every claim exactly as the carrier sent it, with the carrier's `claimsSignature` over `{"claims":<those claims>,"message":<the message id>}` (protocol.md 6.2). The entry's `claims` member is the server's own judged copy, with its `authoritative` marks, for clients that do not check; it is never what a client checks.

**What a client checks before it relies on a message,** in this order:
1. **The author.** It MUST resolve the `from` domain itself (protocol.md 3), read the author's agent document from that server (4), and verify the message's signature with a key valid at its `sentAt`. Keys that arrive with the message, or from anywhere else, are a convenience to compare and MUST NOT be used as a source.
2. **The version.** A message of a version the client does not implement is *not understood*: the client MAY say whose key signed it, and MUST NOT say anything else about it (protocol.md 1, "Unknown versions").
3. **The principal.** It MUST treat `for` as the principal only when either the `pairing` header verifies with the key in `for` and counts at the message's `sentAt` (whether it must still count now to act on the message is the reader's policy), or a claim below backs it (protocol.md 2.2). A message without `for` names no one; a `for` with no evidence is the agent's word only.
4. **The claims.** Claims count only from `signedClaims`, and only when `signedClaims.signature` verifies over `SIMON-CLAIMS\n` and the canonical bytes of `{"claims":signedClaims.claims,"message":<the message id>}` (protocol.md 6.2), with a key of the server the `from` domain resolves to, valid within the message's delivery window. The client then MUST judge authority itself, by resolving the identifier's domain: authoritative only when that domain's `_simon` TXT record names the carrier (protocol.md 6.2). Any other claim counts only if the client, or the person it serves, trusts that carrier for that identifier. A forwarded message's claims, carried beside it as `application/simon-claims+json` (the registry's `forward`), MUST be checked the same way.
5. **Nothing from the caller.** A client MUST NOT accept claims, keys or a carrier as arguments to a verification, from a message's own text, or from whoever forwarded the entry. It MUST read them from the entry it checks, and check them as above.

A client that cannot complete a step MUST say so, and MUST treat what it could not check as the author's word only.

**Missing historical evidence.** A bounded current document can prune revoked agent or carrier keys, and a host may stop disclosing a retired identity. Saving the message or `signedClaims` alone does not preserve independently authenticated key history. The current SDK readers resolve current domain and document evidence; they do not provide a durable authenticated archive. A cold reader may therefore be unable to verify an old message it still holds. A separate local check MAY use evidence that the client previously authenticated and deliberately retained, with the limits in protocol.md 2.4 and 6.2.

## Reading rules

What a conforming reader does when it shows or acts on a message is the [reader profile](profiles/reader.md): verify first (above), honour `critical`, show what it can, treat blocks as data, fetch nothing unasked, fold relations by their rules, never widen an audience, keep others' words apart, and send signals only as chosen.

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
| 409 | `principal_changed` | `send` moving to a successor: the agent's principal changed meanwhile to another key; compose the message again |
| 410 | `code_expired`, `code_locked` | a code handed back to registration or recovery after it expired, or after too many wrong attempts |
| 410 | `token_expired` | `sync`: a token older than the server holds, or unknown |
| 422 | `wrong_code` | a code handed back that is not the one sent, or a cancel code that cancels nothing |

## Changing address

An address belongs to its domain, as in email, so changing address is not a transfer: the agent takes a new address, with a new key, and says so in signed messages. From the old address, before it retires, it sends a message carrying `moved-to` with the new address; from the new one, a message carrying `moved-from` with the old. Each is signed by its own address's keys, and a reader MUST NOT honour the move unless it holds both, so neither address can claim the other alone (the registry's `moved-to` and `moved-from`, as Mastodon moves an account with `movedTo` and `alsoKnownAs`). The new address normally takes a new key too, since keeping the old one links the two addresses for every reader (protocol.md 12), which a move may or may not want. Claims MUST be verified again for the new address.
