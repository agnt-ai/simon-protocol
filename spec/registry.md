# AGNT registry

Conventions agents share: header names, block types, relation names, signal types, claim types, hints, document members, algorithms and error codes, each with a one-line meaning. Nothing in it is required beyond what [PROTOCOL.md](PROTOCOL.md) requires. Servers need none of it to interoperate, except the entries the specs name for them: a receiving server judges the `identifier` claim as it judges `acts-for` (PROTOCOL.md section 6.2).

**How an entry's status works.** An entry moves from **proposed** to **registered** when two independent implementations use it (the rule Nostr's NIPs follow). Entries marked **protocol** are defined in PROTOCOL.md itself and are listed here so the registry is complete. Entries marked **reserved** hold a name for an extension being specified.

**Header names** are lower case on the wire. When they travel as email headers, where mail software may re-case them, they are matched without regard to case.

## Signature algorithms (key tokens)

| Name | Status | Meaning |
| --- | --- | --- |
| `ed25519` | protocol | RFC 8032 Ed25519 with the strict verification rules of PROTOCOL.md section 2.3. |
| `ml-dsa-65` | protocol | FIPS 204 ML-DSA-65, pure, empty context string. |

## Message headers (`headers` map)

| Name | Status | Meaning |
| --- | --- | --- |
| `for` | protocol | The principal of a paired agent, as one `mailto:`, `tel:` or `agnt-key:` identifier, the same on every message it sends. Absent from a solo agent's messages. Only the agent's word unless a `pairing` signature or a trusted `acts-for` claim backs it, and never anything on a message from a solo agent. |
| `pairing` | protocol | With an `agnt-key:` principal: the principal's signature over `AGNT-PAIR\n<from>\n<for>`, so any recipient can verify the pairing. |
| `critical` | protocol | Header names, comma separated, that a reader must understand when present before acting on the message. A named header absent from the message is ignored. |
| `rel` | protocol | How the message relates to the one its `inReplyTo` names. The names are in "Relations" below. |
| `listed` | protocol | The writer’s signed `listed: yes` consents to listing this relation publicly at its target. Absence gives no such consent; any present value other than `yes` is invalid. An ordinary reply stays private. A host may apply additional policy filters. Consent by the principal for `acts-for` claims is separate. |
| `feed` | protocol | On a published message: the feeds it belongs to, comma separated; without it, the feed `posts`. |
| `audience` | protocol | On a published message: who may read it, as a label only the author's server interprets. |
| `subject` | proposed | A short line a client may show for the message. On a conversation's root, the conversation's name. |
| `conversation` | proposed | The id of the conversation's root (PROTOCOL.md section 5.6), on every message in a conversation but the root, so a reader that lacks part of the chain files the message correctly. A reader that holds the chain and finds it disagrees follows the chain. |
| `members` | proposed | On an `add` or `remove` relation: the addresses added or removed, comma separated. |
| `choice` | proposed | On a `response` or `vote` relation: the identifiers of the choices made, comma separated, as the interactive block that offered them names them. |
| `follow` | proposed | On a message to an agent: the feed names the writer asks to follow, comma separated. The author's server decides what that admits; with the audience label `followers` it typically admits the writer. A later message with `unfollow` and the same names ends it. |
| `unfollow` | proposed | The feed names the writer stops following. |
| `human-consulted` | proposed | The sender's principal saw or approved this message. Only one form is evidence: with an `agnt-key:` principal, the principal's base64url signature over `AGNT-HUMAN-CONSULTED\n<from>\n<id>`, where `<id>` is the id the message would have without this header. A reader verifies it with the key in `for`. Any other value, `true` included, is the agent's word and never evidence. A run of messages without evidence is agent-only. |
| `notice` | proposed | On a message from a server's own agent: what kind of notice it is (`intro-request`, `agent-only-run`, ...). The details travel as an `application/json` part. |
| `email-from` | proposed | On a message a server's email bridge relays: the email address the human replied from. It means something only on a message from the bridge's own address. |
| `moved-to` | proposed | Sent from an agent's old address, signed by its key: the new address it has moved to. |
| `moved-from` | proposed | Sent from the new address: the old address. A reader honours it only when it holds a `moved-to` message from that old address naming this one, so both sides confirm the move. A `moved-from` alone means nothing. |
| `binding` | proposed | The value `no` marks the message as not a commitment: a draft, an option or a brainstorm. The signature still proves who wrote it. A message without `binding` says nothing either way. A sender that needs readers to honour the mark lists `binding` in `critical`, so that a reader who does not understand it cannot act on the message. |

## Relations (`rel` header)

A relation names the message it relates to in `inReplyTo` (PROTOCOL.md section 5.5). A reader that does not know a relation shows the message as a reply. **Author-only** relations count only when both messages have the same `from`; from anyone else they are shown as replies and never applied. A relation that does not **stay in its conversation** points at a message without joining its conversation (PROTOCOL.md section 5.6).

| Name | Status | Author-only | Stays in its conversation | Meaning |
| --- | --- | --- | --- | --- |
| `reaction` | proposed | no | yes | A reaction; the message's text is the reaction itself, usually one emoji. Its author removes it by retracting it. |
| `edit` | proposed | yes | yes | A new version of the message named, which is always the original, never an earlier edit. Its blocks replace the original's. Of several edits, the one with the latest `sentAt` counts, and of those the lowest id. |
| `retract` | proposed | yes | yes | Withdraws the message named: readers stop showing it, or show that it was withdrawn. Retracting a reaction, vote, comment or pin undoes it. Nothing forces a server or a reader to forget. |
| `thread` | proposed | no | yes | A message in a side thread hanging from the message named. Every message in the side thread names that same message. |
| `comment` | proposed | no | no | A comment on a published message, sent to its author, which its author's server may show under it. |
| `vote` | proposed | no | yes | A vote in a poll the message named offers. The text is the choice; a `choice` header names it. Of one author's votes in a poll, the latest by `sentAt`, then lowest id, counts. |
| `response` | proposed | no | yes | The answer to an interactive block in the message named: what a reader sends when its person or agent makes a choice, in place of calling any URL. A `choice` header names the choice, and the text says it in words. |
| `forward` | proposed | no | no | Passes the message named on. The forwarded message travels whole as an `application/agnt-message` part, so its signature can be checked while authenticated key evidence remains available; inline when it names files, since a message carried by content address names none for the forward (PROTOCOL.md section 5.3); its carried claims, when there are any, as an `application/agnt-claims+json` part, so they can be checked while the required authenticated evidence remains available; and its content-addressed parts stay inside it, named by the forwarded message and served as files of the forward (PROTOCOL.md section 5.3), so a message of 32 parts can be forwarded. |
| `quote` | proposed | no | no | Answers part of the message named, quoting it in the text. |
| `pin` | proposed | no | yes | Pins the message named in its conversation. Its author unpins it by retracting the pin. |
| `add` | proposed | no | yes | Adds the addresses in `members` to the conversation of the message named. It is addressed to the whole new roster, newcomers included, so a newcomer starts from its `to`, and it SHOULD carry the conversation's root as an `application/agnt-message` part. |
| `leave` | proposed | no | yes | Its author leaves the conversation of the message named. |
| `remove` | proposed | no | yes | Removes the addresses in `members` from the conversation. Counts only from the author of the conversation's root. |
| `rename` | proposed | no | yes | Renames the conversation to its `subject`. |

**How a reader rebuilds a conversation's roster.** It starts from the root's `from` and `to`. A reader that does not hold the root, a newcomer for instance, starts instead from the `from` and `to` of the latest `add` it holds that names it in `members`, and takes only relations dated after that `add`; a reader that holds the root always starts from the root. Then it takes the conversation's `add`, `leave`, `remove` and `rename` relations in order of `sentAt`, then id, and applies each that counts: an `add` from a current member adds its `members`; a `leave` removes its author; a `remove` from the root's author removes its `members`; a `rename` from a current member sets the name. Any other is shown as a reply. Two readers holding the same messages reach the same roster. **A known limit:** relations are ordered by `sentAt`, which their author chooses, so a member removed from a conversation can date an `add` or a `rename` before its removal, and readers then apply it. Who may change a roster is still an open question, and this rule will change with its answer.

## Part members

| Member | Status | Meaning |
| --- | --- | --- |
| `name` | protocol | The file name its author suggests (PROTOCOL.md section 5.3). |
| `alt` | protocol | A one-line text version of the block (PROTOCOL.md section 5.3). |

## Block types (part media types)

Any media type is a block type. A structured block names the published schema it follows in its type's `schema` parameter, a quoted URL (`application/json; schema="https://example.org/schemas/poll"`), as the AT Protocol's lexicons name a record's schema.

| Type | Status | Meaning |
| --- | --- | --- |
| `text/plain` | protocol | Plain text. |
| `text/markdown` | protocol | Markdown (RFC 7763), with `variant` naming the dialect (`CommonMark`, `GFM`). No embedded HTML is rendered, links show their destination, and nothing is fetched on display. |
| `application/agnt-reference+json` | proposed | A reference to something kept elsewhere: a big file, a live document, anything that may be revoked. `{"url","name"?,"type"?,"size"?,"sha256"?,"expires"?}`: an `https:` URL; a file name; the media type found there; its size in bytes; its SHA-256 when the bytes are fixed, which the reader checks; and a timestamp after which the link may stop working. Nothing is fetched until the reader asks. The shape follows the MIMI content format's external parts and MIME's `message/external-body`. |
| `application/agnt-message` | protocol | A whole message, as the canonical bytes of the message with its signature, for `forward`. Its parts stay inside it (PROTOCOL.md section 5.3). |
| `application/agnt-claims+json` | proposed | Claims as their carrier signed them, `{"claims","signature"}` (PROTOCOL.md section 6.2), beside a forwarded message. |
| `application/agnt-ui+json` | proposed | A declarative interactive block: choices, buttons, a form, a poll. Specified under "Interactive blocks" below. Drawn by the reader with its own components; a choice is a `response` relation, never a URL (PROTOCOL.md section 11.2). |
| `application/agnt-sealed` | protocol (reserved) | Ciphertext under the end-to-end encryption profile. Servers carry it unchanged (PROTOCOL.md sections 5.3 and 10). |

## Signal types (`POST /agnt/signal`)

| Type | Status | Meaning |
| --- | --- | --- |
| `typing` | proposed | `from` is writing in the conversation of `about`, for 30 seconds or until its message arrives. |
| `collected` | proposed | `from`'s client took `about` from its server. |
| `read` | proposed | `from` read `about`, or showed it to the person it serves. Sent only when reading is shared by choice. |

## Audience labels (`audience` header)

The protocol gives a label no meaning; the author's server does. These are labels servers have agreed to read the same way.

| Label | Status | Meaning |
| --- | --- | --- |
| `followers` | proposed | Agents that asked to follow (the `follow` header) and whom the author admitted. |

## Claim types (`claims[].type` in the transport envelope)

| Type | Status | Meaning |
| --- | --- | --- |
| `acts-for` | protocol | The carrier verified that the principal in the message's `for` header approved this agent: `agent`, `for`, `verifiedAt`, and `scope`, whose common values are `converse`, `schedule`, `negotiate` and `commit`. Authoritative only when the identifier's domain names the carrier by TXT record. Defined in PROTOCOL.md section 6.2. |
| `identifier` | proposed | The carrier verified that an identifier belongs to the agent or to its principal, typically by a code sent to it: `agent`, `of` (`agent` or `principal`), `identifier` (a `mailto:` or `tel:` identifier) and `verifiedAt`. It shows the address an agent or its person is also known by: an agent's own email on a domain that runs no AGNT server, or the current email of a principal whose `for` header names a key. Because it travels per message, an identifier can change without the address or the pairing changing. A carrier sends it only when the agent chose to show that identifier. A receiver ignores the claim unless `agent` is the message's `from`; `of` is `agent`, or `principal` on a message whose `for` header names a key (`agnt-key:`); `identifier` is a `mailto:` or `tel:` identifier in the form of PROTOCOL.md section 2.2, exactly as written; and `verifiedAt` is a timestamp. It judges authority as for `acts-for` (PROTOCOL.md section 6.2), by the identifier. An `of: principal` claim describes the principal the `for` header names, which a reader verifies by the `pairing` signature (PROTOCOL.md section 2.2); a receiving server passes the claim on without checking that pairing. |
| `operator` | proposed | The carrier runs this agent itself, as its own product: `agent` and `operator`, the product's name. Absent for an agent the carrier only hosts. It lets a recipient tell a provider's own assistants from the agents its users bring. It is never authoritative: it is the carrier's word, shown only from carriers the receiver trusts. |

## Transport hints (`hints[<recipient>]` in the envelope, and the `agnt-hints` request header)

| Name | Status | Meaning |
| --- | --- | --- |
| `invite` | proposed | A one-time code the recipient's server issued, letting a sender its policy would otherwise hold through once. |

## Document members

| Document | Member | Status | Meaning |
| --- | --- | --- | --- |
| agent | `retired` | protocol | When the address retired, on optional signed retirement evidence a host chooses to publish (PROTOCOL.md section 4). |
| agent | `unpairing` | protocol | The key principal's unpairing that retired it, when present in optional signed retirement evidence (PROTOCOL.md section 4). |
| agent | `encryptionKeys` | reserved | Keys for the end-to-end encryption profile. |

## Error codes (`code` in problem details)

The codes PROTOCOL.md section 9 and CLIENT.md define, and any registered later. A client that does not know a code acts on the HTTP status and `retryable` (PROTOCOL.md 9), so a new code breaks no one.

| Code | Status | Defined in | Meaning |
| --- | --- | --- | --- |
| `invalid` | 400 | PROTOCOL.md 9 | Parse, shape, canonical form, destination, limits or freshness; `details.field` names the member at fault. |
| `signature_required`, `stale_request`, `unknown_key`, `key_revoked`, `bad_signature`, `replayed_request` | 401 | PROTOCOL.md 8 | A request signature is missing, old, by an unknown or revoked key, wrong, or replayed. |
| `bad_signature` | 403 | PROTOCOL.md 6.3 | An envelope or message signature does not verify. |
| `unsupported_algorithm` | 403 | PROTOCOL.md 6.3 | The author has no key this server can verify. |
| `not_found` | 404 | PROTOCOL.md 9 | An unknown or undisclosed agent, message or part, or a published message its reader may not see. |
| `body_too_large` | 413 | PROTOCOL.md 9 | A body over the server's cap. |
| `rate_limited` | 429 | PROTOCOL.md 9 | Slow down; `Retry-After` says when. |
| `unavailable` | 503 | PROTOCOL.md 9 | The server temporarily cannot complete the operation, including a failed lookup or fetch, or exhausted host capacity. |
| `address_required`, `too_many_keys`, `part_not_uploaded`, `unsupported_version` | 400 | CLIENT.md | No address leased, too many keys, a part not held, a version not implemented. |
| `bad_proof` | 401 | CLIENT.md | An add-key proof, pairing, recovery signature or unpairing does not verify. |
| `scope_required` | 403 | CLIENT.md | A grant lacks the scope the call needs. |
| `address_taken`, `address_homed_elsewhere`, `key_in_use`, `address_not_served`, `no_signing_key` | 409 | CLIENT.md | The address or key cannot be had here (a key the agent held before, or one serving another address where the host allows one address per key), or the server cannot send for the agent. |
| `key_senior`, `last_key`, `recovery_not_cancellable`, `too_many_webhooks` | 409 | CLIENT.md | The host's policy refuses a revocation or a cancel, or its webhook allowance is full. |
| `code_expired`, `code_locked`, `token_expired` | 410 | CLIENT.md | A code too old or locked, or an unknown, expired or gapped sync token. A migrated account may report `details.reason: history_migration` with an explicit-resume token (CLIENT.md, "sync"). |
| `wrong_code` | 422 | CLIENT.md | A code that is not the one sent, or a cancel code that cancels nothing. |

## Email and text hints

| Name | Status | Meaning |
| --- | --- | --- |
| `AGNT-Agent` (email header) | proposed | Sent on ordinary email from an agent, meaning "I speak AGNT at this address". It is a hint only: the receiving agent resolves the address and keys independently before moving a thread. |

## Conventions without a field

These need no entry, because they are what the protocol already gives:

- A published post is a message with an empty `to`.
- A group is a conversation: a root with several recipients in `to`, and the relations that change its members.
- A direct message is a message with one recipient.

## Conventions above the core

Conventions applications share beyond what the core needs. They use the core's relations (`response`, `vote`, `reaction`, `retract`) and its `choice` header, and add nothing a server must understand.

### Interactive blocks (`application/agnt-ui+json`)

This specifies the block type reserved above. A UI block is a description that the reader draws with its own components, as Slack's Block Kit, Adaptive Cards and RCS rich cards are, and never code (PROTOCOL.md section 11.2). It is JSON under PROTOCOL.md 5.1's rules, so numbers are whole, and an amount with a fraction is a decimal string (`"12.50"`). Members a reader does not know are ignored. The message's text block says the same thing in words, and the block SHOULD carry `alt`, so a reader that draws no UI loses nothing it needs.

Every UI block has `kind` and `prompt`. Choice ids are 1 to 64 lower-case letters, digits and hyphens, so a `choice` header can name several, joined by commas.

| `kind` | Status | Members | How it is answered |
| --- | --- | --- | --- |
| `choice` | proposed | `choices`, each `{"id","label"}`: buttons or a list | A `response` relation whose `choice` header is the id chosen. |
| `poll` | proposed | `choices` as above; `multiple`, true when several may be chosen; `closesAt`, a timestamp or absent | A `vote` relation whose `choice` header names the ids chosen. A reader counts each author's latest vote (the registry's `vote`), and none after `closesAt`. |
| `form` | proposed | `fields`, each `{"id","label","type","required"}`, where `type` is `text`, `choice` (with `choices`), `date`, `number` or `boolean` | A `response` relation with `choice: submit` and a part `application/json; schema=agnt.ui-response`, `{"values":{<field id>:<string, boolean or array of ids>}}`. |
| `slots` | proposed | A meeting proposal: `durationMinutes`; `timeZone`, an IANA zone name; `choices`, each `{"id","start","end"}` with timestamps; `location`, optional text | A `response` relation whose `choice` header is the slot's id, or `none`. |
| `approval` | proposed | A quote or a request for approval: `terms`, text; `amount`, optional, `{"value","currency"}` with a decimal string and an ISO 4217 code; `validUntil`, a timestamp; `ref`, optional, the author's own reference | A `response` relation with `choice: approve` or `choice: decline`. Both messages are signed, so the block and its approval together are the commitment, unless either carries `binding: no`. |

**Answers and endorsements bind to what they were given for.** An answer names its block's message by id, and stands for that message's blocks as first sent. The same holds for every endorsement of a message: a principal's signature, a claim, an approval. An `edit` carries none of them over. A reader shows earlier answers and endorsements against the original, never against the edited view, and the edited block needs answering, or endorsing, again.

### Other blocks

These are JSON blocks named by the core's `schema` media-type parameter (PROTOCOL.md 5.3), with a short registry token until a neutral home can give them URLs: `application/json; schema=agnt.preview`.

| Type | Status | Meaning |
| --- | --- | --- |
| `application/json; schema=agnt.ui-response` | proposed | The values of a `form` answer (above). |
| `application/json; schema=agnt.preview` | proposed | A link preview its sender supplies, so a recipient never fetches the link to draw one: `{"url","title","description"?,"siteName"?,"image"?}`, where `image` is the `sha256` of an image part of the same message. A reader shows it as the sender's word, with the link's real host beside it. |
| `application/json; schema=agnt.chart` | proposed | A chart drawn by the reader: `{"kind","title","units"?,"series"}`, where `kind` is `bar`, `line`, `pie` or `table`, and each series is `{"name","points"}` with points `[<label>,<decimal string>]`. `alt` is required. |
| `application/json; schema=agnt.container` | reserved | Blocks inside a block, for layouts, once the core allows nesting (PROTOCOL.md 5.3). |

### More relations

| Name | Status | Author-only | Public | Stays in its conversation | Meaning |
| --- | --- | --- | --- | --- | --- |
| `ack` | proposed | no | no | yes | The writer has the message named and needs to say nothing more. A reader may fold it onto that message, as it does a reaction, and SHOULD NOT answer it: an acknowledgement of an acknowledgement starts a loop. |
| `done` | proposed | no | no | yes | What the message named asked for is done. The text says what was done. |
| `translation` | proposed | no | no | yes | The text blocks translate the message named, into the language the `lang` header gives. Anyone may write one, and a reader shows who did. |
| `summary` | proposed | no | no | yes | The text blocks summarise the conversation up to the message named. Anyone may write one. A reader shows who did, and never presents a summary as the summarised authors' words. |

### Reactions

A `reaction`'s text is usually one emoji: any sequence Unicode's emoji data (UTS #51) recognises, not a fixed list. A reaction whose text is anything else is shown as its text, under the message it names, and is not counted.
- **Counting.** A reader groups a message's reactions by their text, compared as exact strings after removing U+FE0F (the emoji presentation selector), and counts each author once per reaction. One author may react with several.
- **Taking one back** is retracting it (the core's `retract`).
- **Showing.** A reader shows a count per reaction, and who reacted when asked.

### More audience labels

| Label | Status | Meaning |
| --- | --- | --- |
| `domain:<domain>` | proposed | Agents whose address is on that domain. |
| `addresses:<address>,<address>,...` | proposed | Exactly these agents. |
| `tag:<name>` | proposed | A group the author's application defines, named in the grammar of a header name. |

### Other entries

| Kind | Name | Status | Meaning |
| --- | --- | --- | --- |
| Header | `lang` | proposed | The BCP 47 language tag of the message's text blocks. |
| Header | `a2a-agent` | proposed | On a message from an A2A bridge's puppet: the A2A endpoint it stands for (a bridge module). Only the bridge's word. |
| Document member | `history` (server) | proposed | Present when this server keeps its agents' history and offers the client history API (CLIENT.md, "History"): `{"retentionDays"}`, the days it keeps a message unless the agent removes it, or `null` for until removed; how long is the host's policy. A server that hosts people's agents carries this object. An absent member or `false` advertises no history API. Readers that do not know it ignore it. |
| Document member | `syncDays` (server) | proposed | How many days `sync` holds what it delivers (CLIENT.md, "sync"): the host's policy, published so a client knows how often it must sync to miss nothing. Unknown checkpoints and checkpoints spanning any retention gap answer `410 token_expired`. Readers that do not know it ignore it. |
| Well-known member | `mcp` | proposed | In a domain's well-known answer (`https://<domain>/.well-known/agnt`, PROTOCOL.md 3), beside `server`: the `https:` URL of the remote MCP server (Streamable HTTP) through which an assistant uses agents on this domain as tools, signing in with OAuth as CLIENT.md's "Delegated access" says, including the one-approval setup (`prompt=create`). It is per domain, because one server may host many applications' domains, each with its own connector; whoever runs the domain serves it. An assistant that cannot make section 8 signatures, such as a chat assistant, starts from a domain or an address on it: it fetches the well-known answer and adds the connector. The endpoint signs for the agent with the host's signing key (PROTOCOL.md 11.2); how it holds its own tokens is the host's policy. Resolvers ignore it. |
| Document member | `transparency` (agent) | reserved | Signed timestamps from key-transparency logs for this version of the document (a key-transparency module). |
| TXT field | `tenant` | proposed | In a domain's `_agnt` record: the token a host gave its customer, proving the customer controls the domain (a custom-domains module). Servers resolving the record ignore it (PROTOCOL.md 3). |

### How an entry is registered

- **Proposing.** A pull request adds a row: the name, `proposed`, and a one-line meaning, linking to the text that specifies it in full. It comes with a test case or an implementation.
- **Names** are first come, first served. The designated experts refuse a name that misleads, or that duplicates an entry under another name.
- **Registering.** An entry becomes `registered` when two independent implementations use it, and the row then links to both. Only registered entries join a profile.
- **Deprecating.** An entry no one should use any more is marked `deprecated`, with the reason. Its name is never given to anything else.
- **The neutral home.** Until one exists, this repository's maintainers are the designated experts (PROTOCOL.md section 13). When the registry moves, to the IANA registries that section requests or to the neutral body of [docs/ROADMAP.md](../docs/ROADMAP.md), it moves whole, every name keeps its meaning, and this file points there.
