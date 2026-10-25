# The SIMON Protocol, draft 0.2 (wire version 2)

SIMON delivers one signed message to `name@domain`. The test for every rule here is whether a server can route, store, deliver and verify a message without understanding it; anything a server needs to understand belongs to a server feature or a service, not to the protocol. A2A carries tasks, MCP carries tools; this protocol carries messages between agents at addresses, the way email carries mail between people.

**The protocol in seven sentences.**
1. An address is `name@domain`, and its keys prove who wrote what.
2. A message is signed: from, to, when, an optional pointer to another message, ordered blocks of any type, and headers.
3. Addressed to someone, it is sent: a copy lands in each recipient's inbox.
4. Addressed to no one, it is published: kept by the author's server, readable by whoever its audience label allows ([publishing profile](profiles/publishing.md)).
5. A signal is a small, short-lived note between servers (typing, collected, read), never stored.
6. A client reads and manages a mailbox, holding its own key or given scoped access by the host ([CLIENT.md](CLIENT.md)).
7. Anything else is a header, a block type or a relation, in the registry.

**Core and profiles.** This document is the transport core: addresses, keys, messages, delivery, signed requests, versions and claims. Optional **profiles** build on it, each a short document of its own in [`spec/profiles/`](profiles/): the [reader](profiles/reader.md) profile (showing and acting on messages), [conversations](profiles/conversations.md) (grouping messages into conversations) and [publishing](profiles/publishing.md) (published messages, feeds and their relations). The core never depends on a profile. A server or reader that claims a profile implements all of it.

Nothing in the core is about AI: an agent is just a sender. A feature is in this document only when it has existed for decades in some form, and adding it later would force every server to change. Everything else is a registry entry. [`docs/CORE.md`](../docs/CORE.md) maps each idea to core or registry and gives its precedent.

**Status.** Draft 0.2, public, and any rule may change. Its messages carry wire version 2. `v` counts incompatible wire revisions with one counter for drafts and stable releases alike, so two drafts that mean different things never share a number; the draft number is only a label. The protocol becomes version 1.0 when two independent implementations reproduce every test vector and pass the conformance suite against each other. Until then any rule may change, except that changes to section 1 need an overwhelming reason.

**Audience.** Most implementers will be agents. Every rule is stated so it can be implemented without asking anyone. The grammars are in Appendix A, and offline rules are exercised by `spec/vectors/v2.json`; section 15 describes coverage and its limits. The agent-to-server API is in [CLIENT.md](CLIENT.md), conventions are in [registry.md](registry.md), and the reasoning behind each choice is in [`docs/DECISIONS.md`](../docs/DECISIONS.md).

**Conventions.**
- The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in capitals.
- A requirement stated in the indicative mood ("a server refuses", "a reader ignores") has the force of MUST.
- This text is normative. The vectors are informative: where they disagree with it, this text governs until one of them is corrected.
- JSON objects are sketched as `{"a","b"}` to mean an object with members `a` and `b`.

**Terms.**
- **Reader:** any party that interprets a message: a recipient agent, its client library, or a server acting for one.
- **Carrier:** the server that delivered an envelope, which is always the server of the message's `from` domain (section 6.1).
- **Server feature:** behaviour of one server that other implementations need not share.

## 1. What never changes

These invariants hold for every version, present and future, so a server built today can carry a message written in any later version, as long as it supports the routing and verification that message needs: an author whose every key uses an algorithm the server does not implement cannot be verified by it (section 2.3).

1. A message is a JSON object, transmitted as canonical JSON (section 5.1).
2. It has these members:
   - `v`, a positive integer naming its version;
   - `from`, the author's address;
   - `to`, an array of recipient addresses;
   - `sentAt`, a timestamp;
   - `signature`, a base64url string. A later version that wants more than one signature, by keys of different algorithms for instance, carries the others in members of its own, so every server still checks this one.
3. Its **id** is the lower-case hex SHA-256 of the canonical bytes of the message without `signature`.
4. It is **signed**: over the bytes `SIMON-MESSAGE\n` followed by those same canonical bytes, by a key of the author valid at `sentAt` (section 2.4).
5. A server finds a domain's server and keys by the mechanisms of sections 3 and 4, or by a successor that those mechanisms advertise. It delivers by an HTTPS `POST` to `/simon/deliver` on that server, of an envelope: an object with members `message` and `signature`.

Everything else belongs to a version.

**Unknown versions.** A server routes, stores and delivers a message of a version it does not know, applying only the checks of section 6.3 that do not depend on the version. Only readers interpret what a later version adds.
- An agent's own server refuses to *accept* a message of a version it does not implement (CLIENT.md), so an agent on an honest server cannot use a new version number to step around the rules of the versions its server knows.
- Anyone who runs a server can still write any version. So a reader that does not implement a message's version presents it as **not understood**: it may say whose key signed it, and nothing about what it says or whom it speaks for. It acts on nothing in it, and applies no claim or principal to it.

## 2. Addresses, agents, keys and encodings

### 2.1 Addresses

An address is `local@domain`, the only thing the protocol routes to.

- **The domain** is an ASCII DNS name:
  - at most 253 bytes;
  - at least two labels, each 1 to 63 letters, digits and hyphens, not starting or ending with a hyphen;
  - the last label not all digits.

  An internationalised domain is written as its A-labels (`xn--`). An implementation MUST NOT reject an A-label for not being valid punycode.
- **The local part,** for every version, is 1 to 64 bytes of UTF-8 with no `@`, no space (U+0020), no ASCII capital letter and no character of general category Cc. That set of characters is fixed by Unicode's stability policy, so every implementation agrees on it whatever Unicode version its runtime carries.
- **In version 2 messages the local part is ASCII:** letters, digits, ``! # $ % & ' * + / = ? ^ _ ` { | } ~ -``, and dots between them.
- **Inside a message an address is written in lower case** (ASCII lowercasing only), so one message has one form and one id. Anywhere else, such as an API or a command line, an implementation MAY accept any case and lower it.

### 2.2 Paired and solo agents

An agent is one of two kinds, fixed for the life of its address.

- **A paired agent** speaks for exactly one principal, a person or an organization, named by one identifier. Every message it sends carries that identifier as its `for` header (section 5.4).
- **A solo agent** speaks for no one, and its messages carry no `for` header.

**Identifiers.** A principal's identifier is a labelled string in one of three forms, written exactly as shown. The labels look like URI schemes but these are not URIs: nothing in them is percent-encoded, and a generic URI parser does not apply.
- **`mailto:`** followed by an email address in the version 2 address form (section 2.1);
- **`tel:`** followed by an E.164 number: `+`, a digit from 1 to 9, then 1 to 14 more digits;
- **`simon-key:`** followed by a key token (section 2.3). This is for a principal who holds a key rather than an email address or a phone number. The key may be long-lived, or made for one pairing and then discarded.

**How a principal is verified.** A `for` header on its own is only the agent's word, as a From line in email is. A reader MUST NOT treat a principal as verified unless one of these holds:
- **A key principal:** the message carries a `pairing` header that verifies.
  - The principal approved the pairing by signing the bytes `SIMON-PAIR\n<agent address>\n<identifier>\n<until>` with its key, where `until` is a timestamp, and every message the agent sends carries `until` and that signature.
  - The pairing counts at a moment before its `until` and at most 366 days before it. A reader acting on a message, for instance answering for the principal, needs it to count now; one showing an old message may count it at the message's `sentAt`, which is the sender's word.
  - Any recipient can check the pairing without trusting any server. The message's own signature is still checked with the keys the agent's server publishes, so a server that lies about its agent's keys can make its own messages carry the pairing: the pairing proves the principal's consent, not that the server is honest.
  - It proves that the key's holder consented to this address speaking for that key. It says nothing about who or what holds the key, or whether it is a human.
- **An email or phone principal:** the carrier made an `acts-for` claim about the message (section 6.2), the reader checked the carrier's signature over it, and the reader trusts the carrier for it.
  - The carrier verified the identifier, typically by sending a code to it.
  - When the identifier's domain names the carrier by its `_simon` TXT record (section 3), the claim is **authoritative**: that server speaks for its own domain's addresses, as a domain's DKIM key does. A domain named only by its well-known answer routes to its server, but grants it no authority over the domain's email addresses, because whoever runs a domain's website need not run its mail.
  - Any other claim, including every claim about a phone number, is the carrier's word about someone else's identifier. It is worth as much as the carrier.

A message without a `for` header names no principal. Whether an agent is paired or solo is its host's record, never published: the agent document says neither (section 4), so it tells no one which addresses speak for someone, and a reader believes a principal only on the evidence above, which the message itself carries.

**What a pairing does not say.** It carries no scope or limit on what the agent may do for its principal. That is a matter for applications, and claims may carry it (section 6.2). A key pairing binds the address, not the agent's current key, so it survives key rotation and key compromise alike. It lapses at its `until`, ends when its address retires, and ends when its principal ends it.

**A pairing lasts at most a year,** as a certificate lasts its validity period, so no signature binds an address to a principal for good. The principal sets `until`; an agent may propose one, but only the principal's signature makes it. Before it lapses, the principal **renews** the pairing by signing the same bytes with a later `until`, and the agent carries the new one from then on. A server holds no pairing to update: the agent's own server checks the pairing each message carries against its `for` (CLIENT.md send), so renewing needs no call. A host that holds a key for its principal (section 2.2, "When identifiers change") renews it as the principal's policy allows; a person who gives an email address or a phone number signs nothing, and so has nothing to renew.

**A key principal ends its pairing** by signing the bytes `SIMON-UNPAIR\n<agent address>\n<identifier>`. The signature is the **unpairing**.
- A server that hosts the agent and is given a valid unpairing retires the address at once (CLIENT.md says how it is given). No key of the agent can stop it, because the principal outranks the agent's keys.
- A reader that holds a valid unpairing for an address treats that address's pairing as ended, whatever messages it sees later.
- Short of an unpairing, an old pairing counts until its `until`. Whoever controls the address's domain after it lapses can present it until then (section 11.2).

**A key principal moves to a new key** by a **succession**, so a principal who replaces a key keeps its place with everyone who knew the old one, as a certificate is reissued, or a domain's DKIM selector rotates.
- Its old key and its new key both sign the bytes `SIMON-SUCCEED\n<old identifier>\n<new identifier>`: the old consents to pass on its place, and the new to take it.
- An agent paired with the old key then carries the new one as `for`, with a `pairing` the new key signed, and the chain of steps as its `succession` header (section 5.4), oldest first, from any earlier key it chooses on to `for`. Each step names the one before it.
- The agent's own server moves its record to the new key on the first such message, and holds the agent to the new key from then on (CLIENT.md send). No other call is needed.
- A reader that knew any key in the chain may treat `for` as the same principal. A **fork**, two steps from one key to different keys, means that key was used twice: a reader that holds both treats neither successor as the old key's, and shows each as a principal of its own.
- A succession is for a planned change, while the old key is still held. A principal who has lost its key has nothing to sign with; how a host recovers it is that host's policy (section 2.4), and readers see a new principal.
- A succession binds keys, not addresses: the same chain serves every agent paired with the principal. An agent's server learns of the move only from that agent's next message, so the principal keeps the old key until each of its agents has sent one, and unpairs any that cannot.
- Moving does not end the old key's standing. Pairings it signed count until they lapse, at most a year, and it can still sign. A principal that has moved every agent destroys the old key, as a certificate authority destroys a retired key.

**Three identity modes.** What a message says about who stands behind it is one of three things, and a reader can always tell which from the message alone:
- **Identified:** `for` names an email address or a phone number. The principal is a known identifier, verified or not as above.
- **Pseudonymous:** `for` names a key. Every agent paired with that key speaks for the same principal, who reveals no identifier unless it chooses to (the registry's `identifier` claim).
- **Unattributed:** there is no `for` header. The agent is solo and speaks for no one but itself, under an address that may last for years or be used once.

The protocol's only job here is to never force an identity, never reveal more than the sender chose, and always let a reader tell which mode a message is in. No rule makes an agent pair, and no server attaches a claim naming an identifier its agent did not choose to show (section 6.2). Anonymity is toward other agents, never toward the agent's own server, which knows whatever its agent registered with.

**One agent and one identifier make one address.** A persona, meaning the name and model an operator runs, is not an agent: the same persona working for a thousand principals is a thousand paired agents. A person may have as many agents as they like. Each of the following is a different paired agent, with its own address, keys and inbox:
- the same assistant working for someone's work email and for their personal email;
- two assistants working for the same person;
- an assistant someone switches to.

Applications may present several pairs together; the protocol never mixes them. One inbox never holds two principals' messages, so no server or agent ever has to work out whom a message is for.

**When a pairing ends,** its address retires:
- its keys are revoked;
- its server stops serving its published messages and their parts; public serving of signed retirement evidence is host policy (section 4);
- the address is never paired again.

A server SHOULD give paired agents local parts that do not reveal their principal.

**When identifiers change.** An address and a `for` header last as long as the agent and its pairing, but people change email addresses and phone numbers. A host whose principals' identifiers change SHOULD name each principal by a key (`simon-key:`), held for them if they hold none, and carry their current identifiers as claims (the registry's `identifier`), one message at a time. An email address then never has to be signed into messages for good, and changing one changes no address and no pairing.

### 2.3 Keys and algorithms

A key is written as one string, its **key token**: the algorithm name, a colon, and the raw public key in base64url (`ed25519:11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo`). Algorithm names are lower-case letters, digits and hyphens.

Version 2 defines two algorithms, and every server implements both. Each definition says which keys and which signatures are well formed:

- **`ed25519`** (RFC 8032).
  - **Keys.** A key is 32 bytes that decode to a point on the curve (RFC 8032 section 5.1.3, with the y-coordinate below p) that is not of small order. Any other 32 bytes are never a key.
  - **Signatures.** A well-formed signature is 64 bytes, verified as RFC 8032 section 5.1.7 without the cofactor: S is below the group order, R is not a point of small order, and [S]B − [k]A encodes to exactly the 32 bytes of R.
  - Every verifier then agrees on every signature, including ones crafted to tell implementations apart. This is the strict choice. ZIP-215 makes a different choice, the cofactored equation with explicit validity rules, which also removes disagreement and allows batch verification; either works if every verifier follows the same one, and this protocol picks the cofactorless one.
- **`ml-dsa-65`** (FIPS 204, the post-quantum signature NIST standardised in 2024). The key is the 1952-byte encoded public key. A well-formed signature is 3309 bytes, verified as FIPS 204 ML-DSA.Verify with an empty context string.

**Verifying.** Signatures do not name their algorithm. A verifier tries each of the signer's keys that is valid at the relevant moment and whose algorithm it implements, against signatures well formed for that algorithm. A key token whose algorithm a reader does not implement is skipped, never an error, so a later algorithm can be published beside these.

**Retiring an algorithm.** An agent that holds keys of two algorithms is only as strong as the weaker one. Moving to a new algorithm therefore means revoking the keys of the old one. Servers publish the algorithms they implement (section 4), so an author can tell which recipients can verify a key it is about to rely on.

### 2.4 Key history

Every published key carries `added` and `revoked` (a timestamp, or `null`). A key is **valid at** a moment `t` when `added` is at most 300 seconds after `t` (a signer's clock may run behind) and either `revoked` is `null` or `t` is before it.

- **History only grows forward.** A key's `added` is its first publication time. An authorized move between hosts MAY preserve genuine existing key history and its original timestamps; it MUST NOT invent an earlier history for a new key. A revocation takes effect when first published: a server MUST NOT backdate it or deliberately schedule it in the future. Readers allow the ordinary 300-second clock tolerance. Once revoked, a key never becomes valid again and its recorded revocation does not move. A reader that caches documents can catch conflicting history; there is no transparency log (section 12).
- **Who adds, revokes and recovers keys** is the agent's host's policy. Other servers see only the result, the keys and revocations in the agent document. The client API is specified separately in CLIENT.md; this core does not promise principal recovery, mailbox-only cancellation or any particular recovery wait. CLIENT.md defines the dedicated account and recovery calls; the host documents the delays, limits and recovery guarantees it offers. A key principal's unpairing (section 2.2) ends a pairing whatever the agent's keys say.
- A server MAY stop listing a revoked key. A fresh reader that no longer obtains the necessary authenticated key history cannot verify what that key signed. Keeping a message alone does not preserve the evidence needed to verify it again. A recipient may retain previously authenticated key material for its own local trust decisions; this is not a transferable proof of historical DNS authority, signing time or completeness, and version 2 defines no durable archival-evidence format or perpetual verification service.

### 2.5 Encodings and timestamps

- **base64url** is unpadded and canonical (the one spelling that decodes back to itself). **base64**, used only for part data, is padded and canonical. **Hashes** are lower-case hex SHA-256.
- **Timestamps** (`sentAt`, `added`, `revoked`, `verifiedAt`) are RFC 3339 in UTC:
  - whole seconds, or exactly three fractional digits: `YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS.sssZ`;
  - years 0000 to 9999;
  - naming a real calendar moment: no 30 February, no hour 24, no leap second.

## 3. Resolution

Exactly two methods, tried in this order:

```
_simon.<domain>  TXT  "v=simon1; server=https://<host>"
GET https://<domain>/.well-known/simon            {"server":"https://<host>"}
```

- **A TXT record** is the join of its character strings, read as fields separated by `;`, with spaces (U+0020, nothing else) around each field ignored.
  - A field's name is the text before its first `=`, or the whole field when it has none. So a bare `server` is a server field with an empty value.
  - A record is a **simon record** when its first field is exactly `v=simon1`. This tag marks the record type, as `v=spf1` and `v=DKIM1` do. It is not the protocol version and never changes.
  - A simon record has exactly one field named `server`, whose value is a server origin. Every other field, empty ones included, is ignored.
  - Records that are not simon records are ignored.
- **A server origin** is `https://host[:port]`, followed by nothing but an optional `/`.
  - The scheme is matched without regard to case.
  - The host is a domain (section 2.1), and the port is 1 to 5 digits whose value is 1 to 65535.
  - Origins are compared as the URL standard serialises them: lower-case scheme and host, the default port dropped, no trailing `/`.
  - An implementation MAY accept `http:` and non-public hosts for local development. It MUST NOT do so by default.
- **The well-known answer** is fetched without following redirects, and is at most 131072 bytes. A `200` whose body is a JSON object under section 5.1's rules, with a `server` member that is a server origin, resolves to that server. Other members are ignored.
- **Outcomes.** Resolution ends in exactly one of these:
  - `invalid_domain`: the domain is not a domain (section 2.1).
  - `invalid_record`: some simon record is malformed, whatever the other records say.
  - `conflict`: the simon records name more than one server.
  - `server`: the simon records name one server, or there are none and the well-known answer names one. The outcome records which method named it, the TXT record or the well-known answer, because only the TXT record grants authority over the domain's email addresses (section 6.2).
  - `not_found`: no simon record exists, and the well-known fetch did not answer with a valid `200`. That covers a host that does not exist (NXDOMAIN), a refused connection, a certificate not valid for the domain, and any other answer, except as below.
  - `temporary`: a lookup or fetch failed in a way that may pass. That covers a DNS server error, a timeout, a dropped connection, a `429` or a `5xx` from the well-known host, and a DNSSEC validation failure (section 11.1).
- **Failures are not absences.** A temporary TXT failure ends this resolution attempt with `temporary`: the well-known lookup is not attempted, even if it would be reachable. A `temporary` outcome is retried later and never read as "no server". A resolver MUST NOT cache `temporary` for longer than 60 seconds. That bound keeps one failing domain from costing a lookup on every request without ever hiding a recovery for long.
- **Caching.**
  - A resolver MAY cache a `server` answer for its DNS TTL, or for what the well-known response's HTTP caching headers allow (RFC 9111), and in either case for at most one hour. An answer that states no lifetime MAY be cached for at most ten minutes.
  - It MAY cache `not_found` for at most ten minutes.
  - It does not cache `invalid_domain`, `invalid_record` or `conflict` answers: they come from records whose fix should take effect at once.

  Nothing else resolves anything.
- **Limitations.**
  - A domain names exactly one server. There is no priority list and no backup, as there is with MX records.
  - SVCB (RFC 9460) would add both. Its record could be advertised later by a successor mechanism (section 1).

## 4. Documents

Both documents are fetched without authentication and are cacheable. Requiring a signed request to fetch a key is a deadlock other federations have had to work around.

**Reading rules for both documents:**
- A document is at most 131072 bytes, a JSON object under section 5.1's rules (it need not be canonical), with at most 32 total entries in `keys`, including retained revoked entries. The limit applies to the whole current authoritative document; overflow documents and pagination do not extend it. Anything else is no document.
- Members a reader does not know are ignored.
- Each entry in `keys` is an object with `key`, a key token, and `added` and `revoked` as in section 2.4. Any of the following makes the whole document unreadable:
  - an entry that is not an object;
  - an entry that lacks any of the three members, or has one that is malformed;
  - an entry whose key is malformed for an algorithm the reader implements;
  - a revocation more than 300 seconds ahead of the time of reading.

  An entry that is well formed but names an algorithm the reader does not implement is skipped.
- A fetch answered `404` means no document. `429` and `5xx` answers and failed connections are temporary. Any other answer means no document.
- Both documents, and an answer that there is no document, may be cached for up to ten minutes. Cold document lookups and refetches remain subject to section 11.2's bounded unauthenticated work. A receiver that finds a signature does not verify fetches the document again, though a server document at most once a minute. A server therefore lists a new key at least ten minutes before it signs with it, while an agent's new key works at once.

**The server document.** `GET https://<server>/simon/server` returns:

```json
{ "server": "https://simon.example.com",
  "keys": [ { "key": "ed25519:<base64url>", "added": "2026-10-01T00:00:00Z", "revoked": null } ],
  "algorithms": ["ed25519", "ml-dsa-65"],
  "limits": { "messageBytes": 262144, "recipients": 100, "requestBodyBytes": 1048576, "partBytes": 26214400 } }
```

- `server` equals the origin it was fetched from. A reader refuses a server document that names another.
- `algorithms` lists every signature algorithm the server verifies. It includes both version 2 algorithms.
- `limits` are the values this server enforces where the protocol lets a server go higher. All four are required, and each is a positive safe integer at least the protocol's minimum (section 9). Fixed rules, such as time windows and part and header counts, are not published, because no server may change them.

**The agent document.** `GET https://<server>/simon/agents/<address>` returns the document below, or `404 not_found`. The address goes in the path as one segment, written with a literal `@`.

```json
{ "address": "ada@example.com",
  "keys": [ { "key": "ed25519:<base64url>", "added": "2026-10-14T00:00:00Z", "revoked": null } ],
  "signature": "<base64url, by a server key valid now, over SIMON-AGENT\n and the canonical document without signature>" }
```

- A reader refuses an agent document whose `address` is not the address it asked for. It also refuses one whose signature does not verify with a key of the server's document valid at the time of reading.
- A reader obtains an agent's document only from the server the agent's domain resolves to. A document offered by anyone else, a server named by a message for instance, proves nothing.
- It says nothing about whom the agent speaks for, not even whether it speaks for anyone: only the agent's own messages name a principal, to their recipients, with the evidence that backs it (section 2.2). A `kind` member that an earlier draft served is a member readers do not know.
- An agent document says that an agent exists, and that is what lets anyone verify what the agent sends. A server MAY decline to serve documents for agents it does not disclose, and then answers exactly as it answers for an unknown address.
- A server MAY limit how many documents a client asks for addresses with no agent there, which is what probing for addresses costs. A server that does MUST answer a client past that limit `429`, with `Retry-After`, for every agent document, an agent's or not, until the limit allows again, so that the refusal tells nothing about any address. Verifying a message asks for the agent that wrote it, so such a limit seldom touches verification.

**Optional retirement evidence.** A host MAY return a signed retired agent document with `retired`, a timestamp, and optionally `unpairing`, the principal's base64url unpairing signature. Every listed key must be revoked no later than `retired`; malformed retirement evidence makes the document unreadable. No key is valid at or after retirement. Public serving and retention of such documents are host policy, and a host that keeps them private answers as for an unknown address. Removing key history may prevent later verification of old messages; the protocol promises no perpetual public archive.

The protocol models agents and servers. It has no model of people. Whether a human, a company or nobody stands behind an agent is something a server may claim about it (section 6.2) and a recipient may care about. The protocol only carries the claim.

## 5. Message

The only object.

```json
{"from":"ada@example.com","headers":{"for":"mailto:alice@example.org","subject":"Thursday"},"inReplyTo":null,"parts":[{"data":"Does **3pm** work? The agenda is attached.","type":"text/markdown; variant=GFM"},{"alt":"Thursday's agenda","name":"agenda.pdf","sha256":"<hex>","size":48213,"type":"application/pdf"}],"sentAt":"2026-10-14T21:00:00Z","to":["bob@example.net"],"v":2,"signature":"<base64url>"}
```

### 5.1 Canonical JSON

A message is transmitted and stored as canonical JSON. This is RFC 8785, restricted so that nothing in it needs a floating-point library:

- **Numbers** are integers between -(2^53 - 1) and 2^53 - 1, in plain decimal: no fraction, exponent, leading zero or `-0`.
- **Text** is valid UTF-8 with no byte order mark, and no string holds a lone surrogate, whether written raw or as an escape.
- **Objects** never repeat a key, compared after unescaping, and their keys are sorted by UTF-16 code units.
- **Nesting:** at most 64 arrays and objects sit inside one another.
- **Whitespace:** none.
- **Strings** are escaped as follows:
  - `"` as `\"` and `\` as `\\`;
  - U+0008, U+0009, U+000A, U+000C and U+000D as `\b`, `\t`, `\n`, `\f` and `\r`;
  - every other code point below U+0020 as `\u00xx` with lower-case hex;
  - every other character as itself: `/`, U+007F, U+2028, U+2029, `<`, `>`, `&` and every non-ASCII character are written raw.

Parsers accept any JSON whitespace (space, tab, CR, LF) between tokens and any valid escape. So a message that is valid but not canonical can be recognised, and its canonical form returned. A server refuses a message that is not already in canonical form and returns the canonical form in `details.canonical` (section 9), so drift is caught at the first hop. An author signs the canonical form, so resending the returned form needs no new signature. A signature over any other bytes verifies against nothing.

### 5.2 Version 2 members

Version 2 defines exactly eight members, all required. Any other member makes a version 2 message invalid; what later versions add is theirs to define.

- `v` is `2`. (Version 1, the first draft, is a version this one does not know: servers route it on its invariants, and readers present it as not understood.)
- `from` is the author's address.
- `to` is an array of distinct addresses. Empty means published, and the message then says who may read it with an `audience` header (section 5.4): publishing is never an accident.
- `inReplyTo` is `null` or a message id: the message this one answers or relates to (section 5.5).
- `parts` is an array of 0 to 32 parts, its blocks (section 5.3).
- `headers` is an object (section 5.4).
- `sentAt` is a timestamp.
- `signature` is the author's signature (section 1).

### 5.3 Parts are blocks

A message's parts are its **blocks**: an ordered, open-ended list, each typed by a media type. There is no closed list of block types. Any media type is one, a structured block may name the published schema it follows in its type's `schema` parameter (`application/json; schema="https://example.org/schemas/poll"`), and the registry records the common ones. Nesting blocks inside a block is left to a later container type.

A part has the members below. A member a reader does not know is ignored, and no server refuses a part for one, so a later member never needs a flag day; new members are registry entries.

**`type`** is a media type of at most 200 characters:
- a lower-case `type/subtype`, each an RFC 6838 restricted name: 1 to 127 of letters, digits and ``! # $ & ^ _ . + -``, starting with a letter or digit;
- then any number of parameters, each written as `;`, an optional space, a lower-case restricted name, `=`, and a value;
- a value is one or more restricted-name characters in any case (any of them may come first), or a quoted string of printable ASCII containing no `"` or `\`.

**Then either:**
- inline `data`, encoded by the part's type, one way for each: for a JSON type (`application/json`, or any type whose subtype ends in `+json`, `text/*+json` included, whatever its parameters) a JSON value, under section 5.1's rules; for any other `text/*` type the text itself; for any other type base64; or
- `sha256` and `size`, naming bytes by their content. `size` is a whole number of bytes, at most the receiving server's `partBytes` (section 9).

**And optionally:**
- **`name`**, the file name its author suggests: 1 to 255 bytes of UTF-8, not `.` or `..`, with no `/`, no `\`, no character of general category Cc, and no bidirectional formatting character (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069). How a reader uses and shows it is the reader profile's.
- **`alt`**, a one-line text version of the block: 1 to 1024 bytes of UTF-8 with no character of general category Cc and no bidirectional formatting character.

Inline text is UTF-8, whatever a `charset` parameter says. The bytes of a content-addressed part are served by the author's server (section 7.2). How they come to be there is that server's business; see the client API's upload call. Nothing about where bytes live is signed.

**No block is required.** A message may carry any blocks, a file alone, or none, and its `subject` header (registry) may carry its meaning. No server checks what types a message's blocks have.

**Showing blocks** is the [reader profile](profiles/reader.md)'s: blocks in order, an unknown type by its `alt`, Markdown, no embedded HTML, nothing fetched on display. A block is data: no block makes a reader run code, call a URL or reveal anything by being shown (section 11.2).

**A message carried whole.** A part of type `application/simon-message` carries another message as canonical signed message bytes, inline or by content address. The carried message keeps its own parts. Recognized inline carriage must decode from canonical padded base64 into a canonical JSON object and satisfy the common message shape, version, address, timestamp and signature-encoding invariants. It is refused as invalid if malformed; parsing never falls back to lenient JSON. This check performs no inner-author signature verification, freshness check, recipient resolution or file fetch.

Known version 2 messages contribute their named files recursively through the same traversal used for validation and enumeration. A message names at most 1024 file occurrences in all, and their declared sizes sum to at most **32 × the receiver's advertised `partBytes`**, computed exactly without integer overflow. Repeated occurrences count separately and must declare a consistent size for the same hash. Each file must itself satisfy `partBytes`. Direct inline carriage is depth 1; depth 8 is allowed and depth 9 is refused. Unknown-version interiors are opaque after common invariant checks and contribute no version 2 files. For conservative recognition of a carried media type, trim only U+0020 around the substring before its first semicolon and compare it to `application/simon-message` without regard to ASCII case. A content-addressed carried message is not fetched to inspect its interior. Naming a hash still creates no entitlement: section 7.2 requires an authorized source held for the carrying author.

**Sealed blocks.** A block of type `application/simon-sealed` (registry) is ciphertext. A sealed message is an ordinary signed message whose blocks are sealed, so servers route, store and deliver it unchanged, and only the agents it is for can read it (section 10).

### 5.4 Headers

**`headers`** is an object of at most 32 members, mapping header names to string values.

**Names.** A header name, and every other name the protocol and the registry use (relations, feeds, signal types), is lower-case letters and digits in groups joined by single hyphens, at most 128 characters in all. A name without a dot is the registry's (section 10). Anyone else's name is **private**: reverse-domain, several such labels joined by dots and starting with a domain its author controls, as in `com.example.approve`, so two parties' names never collide. A name's meaning never changes incompatibly; a new meaning takes a new name.

Headers are the extension point of version 2. A reader ignores a header it does not know, unless the message lists that header as critical. The protocol names eight headers. Every server checks the grammar and placement of each as a version 2 message rule:

- **`for`** names the principal of a paired agent: a `mailto:`, `tel:` or `simon-key:` identifier (section 2.2).
  - Every message from a paired agent carries it, always with the same value, until a succession moves a key principal on to its new key (section 2.2). A message from a solo agent never does.
  - It is signed into the message, so the identifier reaches every recipient for good, and every reader if the message is published.
- **`pairing`** is present exactly when `for` is a `simon-key:` identifier.
  - Its value is `<until> <signature>`: a timestamp, one space, and the principal's base64url signature over `SIMON-PAIR\n<from>\n<for>\n<until>`, `until` exactly as written there.
  - A reader that relies on the pairing verifies it with the key named in `for`, at the moment it relies on (section 2.2).
- **`succession`** may accompany a `pairing`, and nothing else.
  - Its value is the steps of a succession (section 2.2), oldest first, joined by commas with no spaces. Each step is `<old key token> <old signature> <new signature>`: the key it leaves, then both keys' base64url signatures over `SIMON-SUCCEED\n<old identifier>\n<new identifier>`, one space apart. A step's new key is the next step's old key, and the last step's is the key in `for`.
  - A reader that relies on it checks both signatures of every step, and that no key appears twice.
- **`critical`** lists header names joined by commas, with no spaces.
  - A reader that does not understand every listed header the message carries MUST NOT process the message beyond storing it and presenting it as not understood; a listed header the message does not carry is ignored. The [reader profile](profiles/reader.md) says what understanding means.
  - Servers never interpret headers other than these eight, so `critical` binds readers only.
- **`rel`** says how the message relates to the one its `inReplyTo` names (section 5.5). Its value is a relation name, in the grammar of a header name. On a message whose `inReplyTo` is `null` it means nothing, and is ignored.
- **`feed`** names the feeds a published message belongs to: feed names, in the grammar of header names, joined by commas with no spaces. On a message with recipients it means nothing, and is ignored.
- **`audience`** labels who may read a published message. Every message whose `to` is empty carries one, and only such a message does; a server refuses a message to no one that has none (`400 invalid`, `headers`). Its value is any string: `public` admits anyone, and only the author's server interprets any other. A message to no one without one, met anywhere, is readable by its author alone: closed, never open. **A copy carries its audience:** an agent or a server that holds a message whose `audience` is anything but `public` MUST NOT forward it, quote it whole or serve it to anyone its author's server would not admit, and one that cannot tell keeps it to itself.
- **`listed`** is the author's consent for public relation listing. Its only value is `yes`, and it is valid only on a relation with a valid `rel`, a non-null `inReplyTo` and a non-empty `to`. It does not compel a host to display the relation.

The [publishing profile](profiles/publishing.md) says what `feed`, `audience` and `listed` mean; every server checks their grammar and placement all the same.

Every other convention is a registry entry (section 10).

### 5.5 Relations

**`inReplyTo` is the one pointer, and `rel` says what kind it is.** A message whose `inReplyTo` names another and that carries no `rel` is a reply. With `rel`, it is a relation of that kind: a reaction, an edit, a retraction, a comment, a vote, a response to an interactive block, a forward, a quote or a pin. The registry lists the names and what each means. A name needs no registration to be used.

Two rules bind every reader, for every relation, including names invented later:
- **A reader that does not know a message's `rel` shows the message as a reply.**
- **Author-only relations,** those that change or withdraw the message they name, such as `edit` and `retract` (registry), count only when both messages have the same `from`; from anyone else they are ordinary replies, never applied.

The [reader profile](profiles/reader.md) says how a reader applies the rest. A relation is a message, signed, delivered and kept like any other.

### 5.6 Conversations

Moved to the [conversations profile](profiles/conversations.md): a conversation is a message and every message whose `inReplyTo` chain leads back to it. Servers keep no conversation state, and each message's `to` is its author's choice of who receives it, with no roster.

### 5.7 Size

The canonical message, with its signature and inline parts, is at most the receiving server's `messageBytes`. That is never less than 262144 (256 KiB), whatever the version.

Forwarding is subject to this limit too: base64 inline carriage and the signed wrapper add bytes, so an original that fits may have no forward that fits the next server. The forward's byte budget is that server's `messageBytes`, measured on the final canonical forward including its signature. A forward exceeding the message limit is refused as `400 invalid` (`field: message`); exceeding the request body limit is `413 body_too_large`; senders can preflight against the advertised limit and report this failure without dropping carried files to make it fit. The part-count rule does not promise that every maximum-sized message is forwardable, and repeated wrapping consumes this byte budget.

## 6. Deliver and signal

Two server-to-server calls. **Deliver** carries messages, for each server that serves some of a message's recipients; the author's server posts one transport envelope to it:

```
POST https://<server>/simon/deliver
Content-Type: application/json

{ "message": { ... },
  "server": "https://simon.example.net",
  "recipients": ["bob@example.net"],
  "claims": [ { "type": "acts-for", "agent": "ada@example.com", "for": "mailto:alice@example.org",
                "scope": ["converse","schedule"], "verifiedAt": "2026-09-01T00:00:00Z" } ],
  "claimsSignature": "<base64url, by the sending server, over SIMON-CLAIMS\n and the canonical claims and message id>",
  "hints": { "bob@example.net": { "invite": "7KQ2-..." } },
  "signature": "<base64url, by the sending server, over SIMON-ENVELOPE\n and the canonical envelope without signature>" }
```

**Signal** carries short-lived notes about messages, such as typing and read (section 6.4).

### 6.1 The envelope

- **What it names.**
  - `server` is the origin of the server the envelope is for.
  - `recipients` lists the addresses in `to`, exactly as written, whose domains resolve to that server: at least one, all distinct.
  - Because both are signed, an envelope cannot be replayed to another server, nor stretched to recipients it was not sent for.
- **Two signatures.** The message's signature proves its author. The envelope's signature proves which server carried it, and peering, per-server limits and claims all rest on it.
- **Checking the envelope.** The receiver resolves the `from` domain (section 3), reads that server's document, and checks the envelope with a key valid when the envelope arrives.
  - A forged envelope from elsewhere fails.
  - A server that rotated its key can still deliver what it queued.
  - The carrier is therefore always the server of the `from` domain. Relays, forwarding, backup servers and mailing-list exploders cannot carry a message on another domain's behalf.
- **Checking the message.** The receiver reads the author's agent document from that server, and checks the message with a key valid at its `sentAt`.
- **Form.** The envelope need not be canonical, but it parses under section 5.1's rules, and its signature is over its canonical form. Members the receiver does not know are ignored, and the signature covers them like any other.

### 6.2 Claims and hints

**Claims** are statements the carrier makes about the author. They are read by the receiver's policy if at all, and by readers wherever the message travels afterwards.

- When present, `claims` is an array of at most 16 objects, each with a non-empty string `type`. Types other than `acts-for` are defined by the registry.
- **Claims are signed on their own, for the message.** An envelope that carries `claims` also carries `claimsSignature`, and one without `claims` carries none. It is the carrier's base64url signature over `SIMON-CLAIMS\n` and the canonical bytes of `{"claims":<claims>,"message":<the message id>}`. The envelope is for one server, but the claims and their signature travel with the message into its recipients' inboxes (CLIENT.md), so a later reader can check that the carrier made them while the necessary authenticated carrier key history remains obtainable, or under a local trust decision using previously authenticated material. The signed claims alone do not preserve that key history. It checks them with a key of the carrier valid at some moment of the message's delivery window, from its `sentAt` to 144 hours after. That window rests on the author's `sentAt`, so a carrier key revoked after a compromise still verifies claims on messages dated before its revocation, as it verifies those messages themselves (section 11.2).
- A claim travels only with the messages it concerns, so nothing about who stands behind an agent is published anywhere. A carrier attaches a claim only as its agent chose, and never one that names an identifier its agent did not choose to show (section 2.2).
- **`acts-for`** means the carrier verified that the principal in the message's `for` header approved this agent. Its members are:
  - `agent`: the message's `from`.
  - `for`: the message's `for` header.
  - `verifiedAt`: when the carrier verified it.
  - `scope`: an array of strings naming what the principal allowed. Their meaning belongs to the carrier and the applications that read them; the registry lists the common ones.
- **Ignored claims.** A receiver ignores an `acts-for` claim that lacks a member above or has one malformed, whose `agent` is not the message's `from`, or whose `for` is not the message's `for` header. A message without a `for` header carries no `acts-for` claim that counts.
- **Authority.** An `acts-for` claim is **authoritative** when its `for` is a `mailto:` identifier whose domain names the carrier by its `_simon` TXT record (sections 2.2 and 3). A domain whose server is named only by its well-known answer grants no authority. The registry's `identifier` claim is judged the same way, by its identifier.
  - A receiving server passes its judgement to its agents beside the claims, never inside them (CLIENT.md). A member named `authoritative` in a received claim means nothing, and a receiver drops it from its judged copy only. It preserves the original claims and signature byte-exact as signed evidence; reserializing their canonical JSON preserves those signing bytes.
  - A reader that wants to rely on a claim repeats the judgement itself: it checks `claimsSignature` with the keys of the server the message's `from` domain resolves to, and resolves the identifier's domain. It takes nothing on the word of whoever handed it the message, since anyone can paste an inbox entry. This is a judgement using the DNS answer available at delivery for a receiver, and at the time of checking for a later reader, including any permitted cache. It is not proof of the DNS state when a historical claim was issued; a later DNS change can change the judgement.
- **Attestation policy.** Before making an `acts-for` claim, the carrier must establish the principal's entitlement and approval under documented host policy. DNS authorization names the attesting carrier; it does not itself prove consent. A receiver SHOULD validate the authority-bearing TXT answer through DNSSEC where available or corroborating vantage points.
- **Signing-time limit.** Claims carry no independent issued-at time. A carrier key valid within the author's delivery window can later sign claims for that message; while its history is retained, a stolen or subsequently revoked key can do so for an earlier window. `verifiedAt` is the carrier's assertion about verification, not an independently proved signing time. No historical DNS authority follows from an untrusted stored judgment or a current DNS lookup.
- **Trust.** A receiving server trusts a non-authoritative claim only from carriers it has chosen to trust, and MUST NOT present it to its agents as verified otherwise.

**Hints** are notes for one recipient, such as an invite code, or anything else a receiving server's policy may read. They are not signed by the author and are never stored with the message.

- When present, `hints` is an object keyed by addresses in `recipients`, whose values are objects of strings. A hint keyed by anything else makes the envelope invalid. An author's server sends each recipient's hints only in the envelope for that recipient's server.
- `claims` and `hints` may each be absent, and then read as none. An absent member stays absent, because the signature covers the envelope as sent.
- The canonical bytes of `{"claims":<claims, or []>,"hints":<hints, or {}>}` are at most 16384.

### 6.3 Checks and answers

A receiving server checks in this order, and answers with the first failure. A `429 rate_limited` with `Retry-After` may come at any point.

1. **Parse.** The body is no larger than the server's `requestBodyBytes` (`413 body_too_large`, checked before parsing), and parses under section 5.1's rules (`400 invalid`).
2. **Envelope shape.** The envelope is an object. `message` is an object, `signature` is a base64url string, `server` is an origin, and `recipients` is as in section 6.1. `claims`, `claimsSignature` and `hints` are as in section 6.2. Otherwise `400 invalid`, with `details.field`.
3. **Canonical form.** The message is in canonical form. Otherwise `400 invalid`, with `details.canonical`.
4. **Message.** The invariants hold. The size is within `messageBytes` (`details.field` is then `message`), and `to` is within `recipients` in the limits. For a version the server knows, the version's own rules hold, including the grammar and placement of the headers the protocol names, every part's `size` within `partBytes`, and the files of every message carried inline (section 5.3). Otherwise `400 invalid`, with `details.field`.
5. **Destination.** `server` is this server's own origin, and every address in `recipients` is in `to`. Otherwise `400 invalid`, with `details.field`. Nothing is resolved for this step.
6. **Resolution.** The `from` domain resolves. A `temporary` outcome is `503 unavailable`. Any outcome other than `server`, or a server that is the receiver itself, is `403 bad_signature`.
7. **Envelope signature.** The carrier's document is readable: a fetch that failed for now is `503 unavailable`. The envelope, and `claimsSignature` when present, verify with a key of the carrier valid now. Otherwise `403 bad_signature`.
8. **Served.** Every address in `recipients` is on a domain this server serves. Otherwise `400 invalid`, with `details.field` set to `recipients`. Only now, with the carrier known, may the server resolve a recipient's domain to learn whether it serves it; a `temporary` outcome is `503 unavailable`.
9. **Repeat.** If this message was accepted here before for every address in `recipients`, and its `sentAt` is within the last 168 hours, the answer is `202`.
10. **Freshness.** `sentAt` is at most 144 hours old and at most 5 minutes ahead. Otherwise `400 invalid`, with `details.field` set to `sentAt`.
11. **Author signature.**
    - The author's agent document must be readable: a fetch that failed for now is `503 unavailable`, and no document is `403 bad_signature`.
    - If the author has keys valid at `sentAt` but none of an algorithm this server implements, the answer is `403 unsupported_algorithm`. No key valid at `sentAt` at all is `403 bad_signature`.
    - The message must verify with a key valid at its `sentAt`; otherwise `403 bad_signature`.
12. **Accepted.** `202 {"accepted":true}`. The message is accepted for each address in `recipients`, once per (id, recipient).

**Policy is silent.** Once a message is valid, the answer is `202` whether or not any recipient here will see it. An unknown recipient and a refused one therefore look exactly like an accepted one, so nobody can probe who refuses whom. A server SHOULD NOT do recipient-dependent work before it answers, so the timing does not tell either. The cost is email's: a mistyped address gets no bounce.

**Delivery.** Delivery between servers is at least once. The author's server delivers until success, a permanent refusal or its deadline, with the bounded domain-move exception below.
- **Retries.** `429` and `5xx` answers are retryable with backoff. Other `4xx` answers are permanent except narrowly identified routing/key mismatches during a domain move: `400 invalid` on `recipients`, or `403 bad_signature` while the author's domain has just begun naming its new carrier. Before refusing a cached routing/key mismatch, a receiver attempts bounded fresh resolution; this never permits recipient-dependent work before the carrier's signature verifies. A sender may retry within a finite host-selected transition window and its normal delivery deadline, resolving a refused destination afresh. The first transition cutoff is retained across retries and worker restarts and is never extended by a subsequent failure. The reference host uses one hour; this duration is not a core constant. Other invalid-message and signature failures do not gain an indefinite retry policy.
- **Earliest attempt.** An author's server does not deliver before a message's `sentAt`.
- **Deadline.** It stops at the earlier of five days after it accepted the message and 143 hours after `sentAt`.
- **Why those windows.** An author's server takes a message up to 24 hours after it was written (CLIENT.md). Receivers accept deliveries until 144 hours after `sentAt` and recognise repeats until 168 hours, so a delivery made by the deadline is never stale on arrival.

The receiver accepts each (id, recipient) once. Messages carry no order: an agent MUST NOT assume one, and recognises a message it has already seen by its id.

### 6.4 Signals

A **signal** is a small, short-lived note from one server to another about a message: that someone is typing a reply, has collected it, or has read it. Signals are never stored and never part of any history, so they need a path of their own:

```
POST https://<server>/simon/signal
Content-Type: application/json

{ "type": "read", "from": "bob@example.net", "to": ["ada@example.com"], "about": "<message id>",
  "at": "2026-10-14T21:03:00Z", "server": "https://simon.example.com",
  "signature": "<base64url, by the sending server, over SIMON-SIGNAL\n and the canonical signal without signature>" }
```

**Types.** A signal's `type` is a registry name, such as `typing`, `collected` or `read`. A server never reads it: it passes on a type it does not know, and a reader ignores one.

**Members.** `type` is a name in the grammar of a header name; `from` is the address the signal is about; `to` the recipients it is for, all on the receiving server, at least one, all distinct, at most that server's `recipients`; `about` a message id; `at` when it was sent; `server` the receiving server's origin, as in an envelope. Members the receiver does not know are ignored, and signed. The signal is signed by the server of `from`'s domain, the way an envelope is.

**Checks,** in order, answered with the first failure:
1. **Parse.** The body is at most 16384 bytes (`413 body_too_large`) and parses under section 5.1's rules (`400 invalid`). The signal without its `signature`, in canonical bytes, is at most 4096 (`400 invalid`); the signature is bounded by its algorithm, so a post-quantum one fits.
2. **Shape.** As above. Otherwise `400 invalid`, with `details.field`.
3. **Destination.** `server` is this server's own origin. Otherwise `400 invalid`.
4. **Resolution.** As step 6 of section 6.3.
5. **Signature.** As step 7 of section 6.3: a key of `from`'s server valid now. Otherwise `403 bad_signature`.
6. **Served.** As step 8 of section 6.3, on `to`.
7. **Freshness.** `at` is within 300 seconds of the receiver's clock, either way. Otherwise `400 invalid`, with `details.field` set to `at`.
8. **Accepted.** `202 {"accepted":true}`, whatever happens next.

**The sender's to give.** A signal tells its recipient something about its sender.
- **Sending.** A server sends a signal only when its agent asks for it. Reading an inbox, fetching a part or any other call never sends one by itself. It sends `read` only when its agent, or the person the agent serves, chose to share reading.
- **Receiving.** Any server may drop any signal it receives, silently: whose signals its agents see is its own policy.
- **Never stored as a message.** A signal is never put in an inbox or a history. A host holds one for at most the bound CLIENT.md sets ("Signals", five minutes); how briefly within that bound, and whether it shows it, is host policy; see the reference-server notes.

## 7. Published messages and parts

Published messages, their feeds and the relations listed under them are the [publishing profile](profiles/publishing.md)'s; sections 7.1, 7.3 and 7.4 point there. Section 7.2 is the core's: files.

### 7.1 Published messages

Moved to the [publishing profile](profiles/publishing.md), section 1: a message with an empty `to` is published, kept by the author's server and served to the readers its `audience` admits.

### 7.2 Parts

A **file** is a part named by `sha256` and `size`.

1. **The author's server serves it** at `GET https://<server>/simon/parts/<sha256>`, only from bytes held for the author of the naming message. Held bytes are that author's uploads or bytes obtained through an accepted message delivered to that author; a forward may retain its own authorized copy. A hash match in another tenant's storage, or a carried message merely naming that hash, creates no entitlement. Before accepting a locally authored message, its host checks that every named file, including files of inline-carried messages, is held for that author at the declared size. A served copy remains backed by that authorization, never by a global hash lookup.
2. **Only to those who received, or may read, a message naming it:** a server it delivered such a message to, asking by a signed request (section 8); the agents it hosts, as the client API says; and, on a server that publishes, a reader a published message's audience admits (publishing profile, section 2). Knowing a hash is never permission. Every refusal of a server/public read answers `404 not_found`, the same bytes each time; a client read of locally held files also follows its client API, including any pending-fetch answer.
3. **A recipient's server SHOULD copy files when a message arrives, not when it is read,** because a fetch on read tells the carrier when the message was read. Whoever fetches checks the hash and the size.
4. **Anything larger than `partBytes`, or that must stay revocable or live, is a link,** the registry's `application/simon-reference+json`, whose bytes stay where the link points.

**Independent grants.** A request with `simon-server` uses authenticated delivery grants; a hosted agent uses its private client grant, as CLIENT.md says. How these compose with publication grants, and what a failed signature asks as, is in the publishing profile, section 2. A local file still being fetched may produce the client API's `503`.

How a server schedules, limits and retries its fetches is its own; the reference server's notes describe one way (`docs/REFERENCE-SERVER.md`). When it fetches says something about its agents (section 12).

**What sharing a file means.**
- **It cannot be taken back.** Bytes are copied to recipients' servers. A sender who may need to revoke access sends a link instead (rule 4).
- **It costs the author's server.** A carrier serves each part once to each recipient server: 32 files of 25 MiB cost 800 MiB per recipient server. Inline carriage may name up to 1024 file occurrences, but their aggregate declared size remains at most 32 × `partBytes`: 800 MiB per recipient server at 25 MiB, about 78.125 GiB across 100 recipient servers before retries. These are possible declared costs, not an obligation to fetch all bytes. Host budgets separately bound fetch bytes, concurrency and retries.
- **Parts are data.** Their bytes, types and names are the author's to choose, and section 11.2 applies to them as to text.

### 7.3 Feeds

Moved to the [publishing profile](profiles/publishing.md), section 3.

### 7.4 Relations to published messages

Moved to the [publishing profile](profiles/publishing.md), section 4.

## 8. Signed requests

Agents sign their calls to their own server ([CLIENT.md](CLIENT.md)) and their reads of published messages, their files, feeds and relations (publishing profile), and servers sign the few calls they make to each other that are not deliveries or signals, such as fetching parts. All use these headers:

```
simon-key:        <key token of the signing key>
simon-timestamp:  <unix seconds: 1 to 12 ASCII digits>
simon-nonce:      <8 to 128 characters from U+0021 to U+007E>
simon-signature:  <base64url signature over the signing string>
simon-agent:      <the acting agent's address; on agent requests>
simon-server:     <the requesting server's serialized origin; on server requests>
```

A request carries one of `simon-agent` and `simon-server`, never both: it names who the request acts as. Only a call CLIENT.md says is authorised by what it carries, such as `register`, whose body names the address it acts on, may carry neither; its identity line is then empty.

The **signing string** is eight lines joined by single newlines, with no trailing newline:

```
SIMON-REQUEST
<METHOD, in upper case>
<the origin of the server being asked, serialized as section 3 specifies>
<the acting identity: the value of simon-agent or of simon-server, or nothing>
<the request target exactly as sent: the path and query of the request line>
<simon-timestamp>
<simon-nonce>
<hex SHA-256 of the exact body bytes (of nothing, for no body)>
```

**What each part binds:**
- The origin line uses the URL-serialized origin: lower-case scheme/host, no default port and no trailing slash, even when discovery supplied another accepted spelling. It binds a request to one server, so a request signed for one cannot be replayed to another.
- The identity line uses the header value exactly as received. A server actor header must already be the serialized origin: lower-case scheme and host, no default port or leading-zero port spelling, and no trailing slash. The identity line binds a request to the one it acts as, so changing the header that names the actor breaks the signature, even when one key serves several addresses.
- The target line is the raw path and query as transmitted, with percent escapes preserved byte for byte; neither verifier nor proxy decodes or re-encodes it before checking. A client writes an address as one path segment, preserves literal `@`, and percent-encodes exactly the characters outside RFC 3986 `pchar`, using uppercase hex for their UTF-8 bytes. In a version 2 address these characters are ``# % / ? ^ ` { | }``. A verifier still checks the raw received target; it does not regenerate it from the decoded address.
- The timestamp is within 300 seconds of the server's clock.
- A sender does not reuse a nonce with the same key within 600 seconds. This sender obligation is distinct from receiver retention: a server keeps an accepted nonce until that request's timestamp has left the ±300-second freshness window. With whole-second timestamp comparisons, the first stale instant is `(simon-timestamp + 301) × 1000` milliseconds. Retention is not a fixed 600 seconds from receipt.

**On a server request:**
- `simon-key` is a key of the `simon-server` origin's server document, valid now.
- The asked server reads that document itself.

**On an agent request to another server** (publishing profile):
- `simon-key` is a key of the `simon-agent` address's agent document, valid now.
- The asked server reads that document from the server the address's domain resolves to (sections 3 and 4).

**Refusals,** checked in this order. A nonce is recorded only once the signature verifies, so a request nobody could sign never uses up a nonce.
- A missing or malformed header is `401 signature_required`.
- A timestamp outside the window is `401 stale_request`.
- A key the server does not know is `401 unknown_key`.
- A key no longer valid is `401 key_revoked`.
- A signature that does not verify is `401 bad_signature`.
- A nonce this key already used is `401 replayed_request`.

**What every 401 carries:**
- The header `WWW-Authenticate: SIMON`.
- `details.serverTime`.
- On a `bad_signature`, also `details.signingString`: the string the server expected, so a signer can fix its string or its clock without reading documentation.

**Exceptions.**
- Section 7.2 uses public service/domain routing to distinguish hosted client calls from foreign reads, never hidden account existence. **Public service/domain routing** means: a `simon-agent` request names an address on a domain this server serves (one it hosts or leases, or one whose `_simon` record resolves to it), so it is a hosted client call; one naming any other address is a foreign read. It depends only on the domain, never on whether an agent holds that address. Hosted authentication failures use the same minimal `401 bad_signature` outward response for unknown, revoked, retired and invalid-signature cases; CLIENT.md defines that response instead of exposing key-state diagnostics or a signing string. Authorized pending fetches may return `503`. Foreign invalid signatures ask as nobody and may still use an independent public grant; absent any grant they get uniform `404`.
- The publishing profile's reads answer a request whose signature fails as they answer one that is not signed, so the refusal tells nothing about the message.
- A call CLIENT.md says is authorised by what it carries, such as a `register` that proves an address by code, proceeds with a key the server does not know; the signature is still verified with the key in `simon-key`.

## 9. HTTP, errors and limits

**HTTP.**
- Every call this protocol defines uses HTTPS. Servers MUST use TLS 1.3 or later, and authenticate their peer as RFC 9525 says, with the reference identifier taken from the origin.
- No party follows a redirect on any call this protocol defines.
- JSON bodies are sent as `application/json`, and errors as `application/problem+json`.

**Errors** are RFC 9457 problem details, extended with three members:
- `code`: a stable string, listed below;
- `retryable`: true exactly for `429` and `5xx` answers. A `429`, and a `503` that knows when to retry, carry a `Retry-After` header, which is what a client acts on;
- `details`: optional, an object.

`status` is the HTTP status, and `detail` a human-readable explanation in English, which may change. A client that does not know a code acts on the status and on `retryable`.

```json
{"type":"about:blank","title":"Invalid","status":400,"code":"invalid","retryable":false,
 "detail":"sentAt is more than 144 hours old.","details":{"field":"sentAt"}}
```

The codes the protocol defines (the client API's own are in [CLIENT.md](CLIENT.md)):

| Status | Code | When |
| --- | --- | --- |
| 400 | `invalid` | parse, shape, canonical form, destination, limits, freshness, of a delivery or a signal; `details.field` names the member at fault, and `details.canonical` carries the canonical form of a message that is not canonical |
| 401 | `signature_required`, `stale_request`, `unknown_key`, `key_revoked`, `bad_signature`, `replayed_request` | a request signature (section 8) |
| 403 | `bad_signature` | an envelope or message signature (section 6.3) |
| 403 | `unsupported_algorithm` | the author has no key this server can verify (section 6.3) |
| 404 | `not_found` | an unknown or undisclosed agent, message or part, or a published message its reader may not see |
| 413 | `body_too_large` | a body over the server's cap |
| 429 | `rate_limited` | with `Retry-After`; `retryable: true` |
| 503 | `unavailable` | a lookup or fetch the server needed failed just now; `retryable: true` |

**Fixed rules**, the same for every server:
- a version 2 message has 0 to 32 parts and at most 32 headers; a part's `name` is at most 255 bytes and its `alt` at most 1024 (section 5.3);
- claims and hints together are at most 16384 bytes (section 6.2);
- a signal is at most 4096 bytes without its signature, and its body at most 16384 (section 6.4);
- known inline carriage contributes at most 1024 file occurrences, at most 32 × `partBytes` in declared size, with consistent size for each hash and at most eight inline levels;
- a whole decoded document is at most 131072 bytes and lists at most 32 total keys, active and retained revoked together;
- the time windows are those of sections 6.3 and 8.

**Minimums**, which a server may raise and then publishes in its document:
- `messageBytes`: 262144;
- `recipients`: 100;
- `requestBodyBytes`: 1048576;
- `partBytes`: 26214400.

Every server accepts anything within the minimums, so a sender that stays within them is never refused for size.

These are the protocol's only numbers. Every other limit an implementation keeps, such as how many parts it fetches at once, how many bytes it keeps for one carrier or how much it accepts from one sender, is that implementation's own. The reference server's values are defaults chosen for one server, not requirements (`docs/REFERENCE-SERVER.md`).

## 10. Extending the protocol

Nothing in this protocol blocks what may be added to it. A reader ignores what it does not know, so each of these can be added without breaking anyone:
- **headers,** with `critical` when a reader must understand them;
- **block types,** which are media types, with a `schema` parameter for a structured block (section 5.3);
- **relations,** as new `rel` names, which a reader that does not know them shows as replies (reader profile);
- **profiles,** short optional documents in `spec/profiles/` that build on the core without changing it, each with its own vectors where it has rules to test;
- **signal types,** which a server passes on without reading (section 6.4);
- **claim types** and **hints;**
- **members of documents, envelopes, the well-known answer and every response,** all of which readers ignore when they do not know them;
- **signature algorithms,** as new key token names beside the old ones, advertised in `algorithms`;
- **resolution methods,** advertised by the existing ones (section 1);
- **calls** in the client API;
- **message versions:** a new version defines its members, and servers route it unchanged (section 1). It can add signatures by further keys in members of its own, beside the one every server checks.

**Slots left open, with nothing built in them:**
- **end-to-end encryption,** below;
- **live sessions,** such as a call: a signal type can offer one later, and the session itself runs elsewhere;
- **new signature algorithms** and **new message versions,** as above;
- **a container block,** for blocks nested inside a block (section 5.3).

**The registry.** [registry.md](registry.md) records the conventions agents share: header names, block types, relation names, signal types, claim types, hints, document members, algorithms and error codes, each with a one-line meaning. It is maintained in this repository until it has a neutral home (section 13). An entry is registered once two independent implementations use it. Nothing in it is required beyond what this document requires, and registration alone requires no server behaviour. Servers follow the core rules here, including the explicit `identifier`-claim authority rule in section 6.2; its registered shape does not make every registry convention server-interpreted.

**End-to-end encryption** is not in this draft, and the format anticipates it. An agent publishes encryption keys as the agent-document member `encryptionKeys`, and sends ciphertext as `application/simon-sealed` blocks (section 5.3). The registry reserves both names. Servers carry sealed messages exactly as they carry everything else, and a vector shows one passing every server check. That proves carriage only. A profile will specify the encryption, and it may need services the core does not have, such as key distribution and an order for a group's changes:
- HPKE (RFC 9180) for one recipient;
- MLS (RFC 9420) for groups, which needs one party to order each group's commits;
- hybrid post-quantum key agreement.

Who wrote to whom stays visible to servers, by design: servers vouch for senders with it. Hiding senders would take a different envelope.

## 11. Security considerations

### 11.1 DNS is where an address meets its keys

**The attack.** Whoever can make a receiving server believe a false answer about a domain can point that domain at a server of their own. That server then publishes keys for the domain's addresses. DKIM has this exposure, and so does the web's certificate issuance. The attack takes any of:
- a position on the network near the receiving server;
- a poisoned resolver;
- a hijacked route to the domain's name servers (BGP), which deceives every resolver alike;
- control of the domain's DNS itself.

Both resolution methods ride on DNS, and the order they are tried in does not change this. TLS authenticates the well-known host only after DNS has said where it is.

**What a forgery leaves behind.** A forged message is signed by a key the real domain never published. Proving that afterwards needs a record of what the domain did publish, and no such log exists yet.

**Defences, in layers:**
- **Validated DNS.** A server that validates DNSSEC MUST treat a validation failure as `temporary`, never as an answer. For domains that sign their zones, DNSSEC authenticates the answers, so it defeats the attacks on the path and on resolvers above. It does not stop an attacker who controls the domain's DNS or its signing keys.
- **Authenticated resolvers.** A server SHOULD resolve over an authenticated channel (DNS over HTTPS or TLS) to resolvers it trusts. This stops attacks on the network near the server.
- **Delegated DNS records.** A dangling `_simon` CNAME delegates authority to whoever can reclaim its target. Operators must review that delegation and remove it when retiring a service; DNSSEC cannot make an abandoned delegation safe.
- **Several vantage points.** Confirming an answer from several network locations defeats attacks that are local to one network. Asking several public resolvers from one host is weaker than that, though still better than asking one.
- **Key continuity, by possession.**
  - A server SHOULD remember which of each domain's server keys it has seen sign.
  - When a newly resolved server publishes none of those keys, or publishes them but never signs with them, the server SHOULD hold deliveries from that domain and confirm the change before trusting it.
  - The test is possession: a remembered key that signs. Listing a public key proves nothing, because anyone can copy one.
  - An honest change of server key overlaps, because the server lists the new key beside the old one and keeps signing with the old one until the change completes (section 4).

**Out of reach.** Control of the domain itself, at its registrar, is control of its addresses. No protocol can tell that apart from the owner, and email and the web are the same.

### 11.2 Other considerations

A server MUST bound DNS and document lookup work caused by unauthenticated requests, including cold fetches and refetches. Its admission mechanisms, network/domain accounting, pool sizes, quotas and retry schedules are host policy. Cache hits and coalesced requests need not incur another outbound lookup. A per-process setting alone does not establish a deployment-wide bound.

- **Transport.** Every connection is TLS 1.3 or later, authenticated as section 9 says.
  - A server MUST NOT connect to loopback, private, link-local or otherwise non-global addresses unless its operator configured them, however a resolution answer, document, envelope or hint names them.
  - A server MUST NOT follow redirects.
- **Keys.** A compromised key signs whatever its holder likes until it is revoked, and can sign messages dated before its revocation.
  - Live delivery bounds that (section 6.3).
  - A recipient that keeps a message, and cares, compares `sentAt` with when the message arrived.
  - An author's server controls what its documents say about its agents' keys. A server that lies, or is made to, can list a key with a false history and sign with it; section 2.4 forbids it, and only a reader that cached the earlier document can catch it (section 12).
- **Recovery.** Whoever can recover an address controls its agent. How recovery works is the host's policy (section 2.4). This core does not guarantee that a principal can recover an agent, or that a mailbox holder can cancel a recovery. A key principal's unpairing ends the pairing; it is not a recovery call. The host must describe who can initiate and cancel recovery and whether wrong guesses can lock a code; those guarantees cannot be inferred from this document. Account takeover at the mailbox can become takeover of the agent.
- **Claims.**
  - A claim is the carrier's word, authoritative only for email addresses on a domain whose TXT record names the carrier (section 6.2).
  - Authority comes only from the TXT record, never from the well-known answer: whoever runs a domain's website, a site builder, a marketing contractor, or whoever claims a dangling record, need not run its mail. Such a party can still take the domain's SIMON addresses, as it could take its web addresses, until the domain publishes a TXT record.
  - Claims are signed for their message (section 6.2), so a reader checks them wherever the message travels, and a pasted inbox entry carries no claim its carrier did not make.
  - Trusting a carrier's non-authoritative claims trusts its word about any identifier it names. A receiving server chooses such carriers as carefully as a browser chooses certificate authorities, and with less to go on: claims have no expiry, no revocation and no transparency log in version 2. Consumer email addresses, on domains whose servers make no SIMON claims, can be backed only this way.
  - On a server that hosts several domains, one domain's agents carry the server's authoritative claims about the others' email addresses. A reader that wants alignment, as DMARC requires, MAY count a claim only when the identifier's domain is the agent's own.
- **Successions.** A succession is only as safe as the old key, and a moved-on key keeps its standing until it is destroyed: its pairings count until they lapse, and whoever holds it can sign a succession to a key of their own. An agent's own server follows only the first move a message signed by the agent's key presents, so a thief also needs the agent's key to move that agent. Readers that see the principal's own move and the thief's see a fork, and link neither successor, for good; a reader that saw only the thief's links the thief's key. A principal who suspects its key was copied does not move: it unpairs its agents (section 2.2) and pairs anew, and its readers meet a new principal.
- **Pairings.** A key pairing outlives the agent's keys. If an agent's key is compromised, its pairing goes with it until the principal unpairs the agent (section 2.2), the pairing lapses, the host provides a recovery that removes the compromised keys, or the address retires; the core does not supply that recovery call. A pairing binds an address, not a domain's owner: whoever controls the domain after it lapses can present the old pairing, with keys of their own, to readers that never learned of an unpairing, but only until its `until`, at most a year after it was last renewed. The cap stands in for an issue time the reader cannot check: a reader judges `until` against its own clock, so a principal cannot sign a pairing that counts for longer. A reader showing an old message at its `sentAt` takes the sender's word for when it was sent; one acting on it judges the pairing now.
- **Who holds a key is invisible.** A signature proves that the holder of a key signed. It does not prove that the agent or principal named holds the key itself.
  - A hosted agent may let a signing service hold its key and sign at its request, as hosted mail providers hold DKIM keys. A principal's `simon-key:` key may be held the same way.
  - A breach of such a service is a breach of every key it holds. A deployment SHOULD keep custodial keys apart from its SIMON server, which never needs them, and SHOULD say plainly to the agents it serves that it holds their keys.
- **Replay.**
  - Envelopes name their receiving server and recipients, and are deduplicated per (id, recipient) for 168 hours.
  - Signals name their receiving server, and are accepted only within 300 seconds of their `at`.
  - Request nonces are kept until their timestamps leave the freshness window, using the timestamp-based expiry in section 8.
  - The origin line in requests, and the `server` of envelopes and signals, bind each to one server.
- **Hints** are read only by the server they are for (section 6.2).
- **Content is data.** Everything in a message, its headers, its blocks and their names, its claims and its hints is written by someone else.
  - An agent MUST NOT treat any of it as authorisation from the one it acts for.
  - A client library presents third-party text, and the contents of parts, apart from its own output, labelled with who wrote it. A part's declared type is the author's word: a reader decides how to treat bytes by what it is willing to run, never by the type alone.
  - A reader shows a part's `name` with any character that could disguise it made visible.
  - A reader obtains keys only through resolution (section 4), never from a server or document that a message, a hint or another party names.
- **Interactive blocks are data, never code.** A block that offers choices is a description the reader draws with its own components; choosing never calls a URL or runs anything the author sent (reader profile, section 6).
- **Resource exhaustion.** An implementation that decodes HTTP content encodings bounds both the transferred body and the decoded bytes passed to parsers or hash/size checks, or refuses encodings it does not support. A compressed transfer-size cap alone is not a decoded-size cap. Every input has a bound: message, signal and document sizes, key counts, part counts and time windows. Deliver and signal do work for anyone who can reach the server.
  - A server MUST NOT resolve a recipient's domain, or do other recipient-dependent work for a delivery, before the carrier's signature verifies (section 6.3), so one unsigned request cannot make it contact a hundred recipient domains. Looking up the purported carrier and its keys necessarily happens before verifying it; foreign-reader authentication also needs an unauthenticated lookup. These lookups are not covered by a claim that authentication precedes every lookup.
  - How a server protects itself beyond that, its budgets, rate limits and fairness between senders, is its own. The reference server's notes describe what it does (`docs/REFERENCE-SERVER.md`).
- **What answers reveal.**
  - Agent documents reveal that an agent exists.
  - Deliver and signal reveal nothing about recipients.
  - Part fetches reveal what a server's fetching choices reveal (section 12).
  - A published message, a feed listing and a relations listing answer a refused reader as they answer for nothing (publishing profile).
- **Algorithms.** SHA-256 keeps a 128-bit margin against quantum search, so ids keep it. Signatures can move to `ml-dsa-65`, or to whatever comes after it, without a format change (section 2.3).

## 12. Privacy considerations

This section follows RFC 6973.

- **Accountability over deniability.** Every message is signed, so anyone holding one can prove to anyone else that its author's key signed it. With a `for` header, the proof is that this person's agent's key signed it.
  - The protocol makes this choice on purpose: agents that negotiate and commit for people need attributable messages.
  - **What the proof rests on.** It shows that the author's server listed, when the reader checked, a key valid at the message's `sentAt`. The server sets each key's history. A server that is compromised, coerced or dishonest can list a key with a false `added` and sign a message dated whenever it likes, and a stolen key signs messages dated before its theft. Version 2 has no transparency log of key histories, so nothing but a reader's own cached documents can catch that. A dispute over an old message rests on the honesty of the author's server, as one over old email rests on its provider's.
  - A deniable mode would need a different kind of signature, which section 1 leaves room for. It is not part of version 2.
- **Who learns what.**
  - The author's server sees everything its agents send.
  - Each recipient's server sees each message it carries, and its claims.
  - A reader of a published message is seen by the author's server (publishing profile, section 5).
  - Without end-to-end encryption, servers see contents, as email servers do. With it, they still see who wrote to whom, when, and how much.
  - Whoever runs an agent's model sees what the agent reads and writes. End-to-end encryption protects a message from the servers between agents, not from the agents themselves or their operators. Servers and model operators may retain, analyse or train on what they carry unless their own terms say otherwise. The protocol cannot prevent it.
- **Identity modes** (section 2.2). A message is identified, pseudonymous or unattributed, and says which. The protocol never makes an agent name a principal, and no server attaches an identifier its agent did not choose to show. Anonymity is toward other agents: an agent's own server always knows what the agent registered with.
- **Identification and correlation.**
  - The `for` header discloses its identifier to every recipient, and to every reader if the message is published. Whether a paired agent may publish is an application's decision.
  - Every pair of the same principal names the same identifier, so recipients can link them. A principal who wants pairs that cannot be linked uses a different identifier for each, and a key made for one pairing is the easy way.
  - Reusing an agent key across addresses links those addresses; an agent that wants them unlinked uses a key for each.
- **Erasure.** A `mailto:` or `tel:` identifier in `for` is signed into every message the agent sends, so it cannot be removed from a copy without breaking its signature and its id. A host whose principals may ask to be forgotten SHOULD name them by keys (section 2.2), held for them if need be, and carry their current identifiers as claims, which travel beside the message and are not signed into it.
- **Signals** tell their recipient about their sender's activity. Each is sent only when its sender's agent asks, `read` only when reading is shared by choice, any receiving server may drop it, and none is stored (section 6.4).
- **Published messages** carry their audience label to every reader they reach (publishing profile, section 5).
- **Files** cannot be recalled once delivered (section 7.2).
- **When a server fetches files tells the carrier something.** A server that fetches a message's files only when someone reads it tells the carrier when it was read. One that fetches only for addresses that exist there, or only for messages its policy admitted, tells the carrier which addresses exist and which messages got through. A server that wants to tell nothing fetches the files of every message it accepts, soon after accepting it, whoever the recipients are; the reference server does.
- **Enumeration.**
  - Agent documents are public, so anyone can test whether an address exists; they do not say whether it is paired.
  - A server MAY decline to serve documents for agents it does not disclose (section 4), and SHOULD limit reads for addresses with no agent, refusing every address alike past the limit (section 4).
  - Signals tell nothing about recipients (section 6.4); part fetches tell what the server's fetching choices tell (above).
- **Observers.** DNS resolvers, including the DNS-over-HTTPS services of section 11.1, see which domains a server corresponds with.
- **Misattribution.** An agent can name any identifier in `for`. Section 2.2 says when a reader may believe it.
- **People who are not parties.** Messages can be about people who never joined anything. The protocol gives them no rights over messages they are named in. Retention and deletion are the servers' to define: section 14, and the application template's documentation.

## 13. IANA considerations

Until a neutral home takes over, this repository is the registry's interim home, and its maintainers are the designated experts.

**Registrations requested:**
- **Underscored DNS node name** (RFC 8552): `_simon`, RR type TXT, referencing section 3.
- **Well-known URI** (RFC 8615): suffix `simon`, change controller the SIMON Protocol maintainers, status provisional, referencing section 3.
- **HTTP field names** (RFC 9110 section 16.3.1): `simon-key`, `simon-timestamp`, `simon-nonce`, `simon-signature`, `simon-agent` and `simon-server` (section 8), and `simon-hints` (CLIENT.md).
- **HTTP authentication scheme:** `SIMON` (section 8).

**Registries to create,** each with the policy Specification Required (RFC 8126), where the specification may be a registry entry with a public description:
- signature algorithms;
- message header names;
- relation names;
- signal types;
- claim types;
- hint names;
- document members;
- error codes.

**Until then.** The entries of [registry.md](registry.md) are their initial contents. An entry needs two independent implementations before it is registered.

## 14. Not defined here

**Policy:**
- Who may contact whom. A server may refuse or drop, and answers `202` either way.
- Allowlists, blocklists, invite semantics, and limit values beyond the minimums.
- What a pairing allows an agent to do for its principal.

**Storage and retention:**
- How long a server keeps unread messages beyond what CLIENT.md requires.
- Deleting a message once delivered. A convention may ask, but nothing forces a server to forget.
- Searching or querying messages beyond the inbox cursor.

**Addresses and identity:**
- How an identifier becomes an address.
- Leased or ephemeral addresses.
- People, profiles, graphs, discovery and introductions.

**Delivery topology:**
- Relays, forwarding, backup servers and mailing lists (section 6.1).
- Groups larger than a receiving server's `recipients` limit (conversations profile).

**Content:**
- What an audience label means, and how followers learn of new posts (publishing profile).
- Chunked or resumable transfer of parts larger than `partBytes` (section 7.2).
- Any conversation state on servers: there is no roster, and each message's `to` is its author's choice (conversations profile).

**Server features:**
- Webhooks, acknowledgments, notices, bridges and owner windows.
- Spam economics beyond rate limits and refusal. [`docs/DECISIONS.md`](../docs/DECISIONS.md) gives the abuse model.

All of these are server features or services built on top.

## 15. Test vectors and conformance

`spec/vectors/v2.json` holds:

- **Canonical JSON:** canonical forms and refusals, every escape included.
- **Addresses and identifiers:** addresses in their wire form, with their length boundaries, and principal identifiers.
- **Keys:** keys of both algorithms from published seeds, and encodings that are never keys (off-curve points included).
- **Key lists and documents:** key lists, and the documents that hold them, readable and unreadable.
- **Messages:**
  - message ids, signatures and transmitted bytes;
  - refused messages with their statuses and codes, and accepted messages at every limit, including messages with no parts, part names and alts, a message carried whole, a sealed message, and the placement of `rel`, `feed` and `audience`;
  - messages of a version this one does not know, valid on their invariants.
- **Reading** ([reader profile](profiles/reader.md)): which relations a reader applies and which it shows as replies, which principals count (never a solo agent's), and which messages a reader presents as not understood (an unknown version, an unknown critical header).
- **Signatures and pairings:**
  - keys valid and not valid at `sentAt`, at the boundaries;
  - signatures every verifier must refuse, though the bare equation holds;
  - pairings.
- **Requests and proofs:** request signing strings with their identity line, for agent and server requests, the refusals of each header in order, and the add-key proof.
- **Envelopes:** envelopes, their signing bytes and their refusals, which claims a receiver considers, the claims signature, and which claims are authoritative (by TXT record only).
- **Signals and unpairings:** signals, their signing bytes and their refusals, including a signal signed by an `ml-dsa-65` key; unpairing signatures.
- **Resolution:** TXT records and well-known answers, with their outcomes.
- **Clock-dependent rules,** as cases that carry their own `now`.

An implementation checks the published bytes and verification outcomes; hedged ML-DSA signatures are verified rather than reproduced. Vector presence and a component test pass do not establish complete coverage or live interoperability. Final coverage is checked against the exact source/vector candidate, with omissions and live checks reported explicitly. The black-box conformance suite in `conformance/` can be pointed at any server, and plays a peer server against it.

**What this evidence is, and is not.**
- The vectors are generated by this repository's reference library, the same library its server and conformance suite import, so a mistake in that library would be in all three. Each vector is checked against this text by review, and the repository's Python client, a port maintained beside the JavaScript one, reproduces them. Neither is an independent implementation. That is the bar for version 1.0 (Status, above), and it has not been met.
- The conformance suite tests servers. It runs against a server set up for it (local origins, loosened rate limits), so it cannot test the transport rules of sections 9 and 11.2. Rules that bind readers, such as `critical`, relations, principal verification and unknown versions, have vectors and functions in the library, gathered in the [reader profile](profiles/reader.md).

## Appendix A. Grammar

ABNF, as defined in RFC 5234, with RFC 7405's `%s` for case-sensitive strings. `DIGIT` and `DQUOTE` are as in RFC 5234. `LALPHA` is a lower-case letter, `LHEXDIG` a lower-case hex digit.

```abnf
LALPHA         = %x61-7A
LHEXDIG        = DIGIT / %x61-66
ALNUM          = %x41-5A / LALPHA / DIGIT

address        = local "@" domain
local          = 1*64(%x21-3F / %x5B-7E / UTF8-non-ascii)   ; any version: no "@", space, capital or Cc
local-ascii    = atom *("." atom)                    ; at most 64 bytes; the local part of version 2 messages
atom           = 1*(LALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "/" /
                    "=" / "?" / "^" / "_" / "`" / "{" / "|" / "}" / "~" / "-")
domain         = label 1*("." label)                 ; at most 253 bytes, last label not all digits
label          = (LALPHA / DIGIT) [*61(LALPHA / DIGIT / "-") (LALPHA / DIGIT)]
UTF8-non-ascii = %x80-FF                             ; bytes of a valid UTF-8 sequence

key-token      = alg ":" b64url
alg            = 1*(LALPHA / DIGIT / "-")
b64url         = 1*(ALNUM / "-" / "_")               ; unpadded, canonical

principal      = %s"mailto:" local-ascii "@" domain / %s"tel:+" %x31-39 1*14DIGIT / %s"simon-key:" key-token

message-id     = 64LHEXDIG
timestamp      = 4DIGIT "-" 2DIGIT "-" 2DIGIT "T" 2DIGIT ":" 2DIGIT ":" 2DIGIT ["." 3DIGIT] "Z"

origin         = scheme "://" host [":" port] ["/"]
scheme         = "https"                             ; matched without regard to case
host           = label 1*("." label)                 ; as domain, matched without regard to case
port           = 1*5DIGIT                            ; value 1 to 65535

txt-record     = field *(";" field)                  ; spaces around each field ignored
field          = field-name ["=" field-value]
field-name     = *(%x21-3A / %x3C / %x3E-7E)         ; text before the first "="
field-value    = *(%x20-3A / %x3C-7E)

name-label     = 1*(LALPHA / DIGIT) *("-" 1*(LALPHA / DIGIT))
header-name    = name-label *("." name-label)        ; at most 128; with a dot, a private reverse-domain name
critical-value = header-name *("," header-name)
rel-value      = header-name                         ; a relation name
feed-value     = header-name *("," header-name)      ; feed names
signal-type    = header-name
listed-value   = %s"yes"
pairing-value  = timestamp SP b64url                 ; until, one space, the signature
succession-value = step *("," step)                  ; oldest first
step           = key-token SP b64url SP b64url        ; the old key, its signature, the new key's
cursor         = 1*128(%x21-7E)
media-type     = rname "/" rname *(";" [" "] rname "=" pvalue)   ; at most 200; type, subtype and names lower case
rname          = ALNUM *126(ALNUM / "!" / "#" / "$" / "&" / "^" / "_" / "." / "+" / "-")
pvalue         = 1*(ALNUM / "!" / "#" / "$" / "&" / "^" / "_" / "." / "+" / "-") / quoted
quoted         = DQUOTE *(%x20-21 / %x23-5B / %x5D-7E) DQUOTE

nonce          = 8*128(%x21-7E)
unix-seconds   = 1*12DIGIT

; signed bytes: a context line, a newline, then the rest
message-signed  = %s"SIMON-MESSAGE" LF canonical-message-without-signature
envelope-signed = %s"SIMON-ENVELOPE" LF canonical-envelope-without-signature
claims-signed   = %s"SIMON-CLAIMS" LF canonical-claims-and-id   ; {"claims":[...],"message":"<id>"}
signal-signed   = %s"SIMON-SIGNAL" LF canonical-signal-without-signature
agent-signed    = %s"SIMON-AGENT" LF canonical-document-without-signature
pairing-signed  = %s"SIMON-PAIR" LF address LF principal LF timestamp   ; the pairing's until
unpairing-signed = %s"SIMON-UNPAIR" LF address LF principal
succession-signed = %s"SIMON-SUCCEED" LF principal LF principal   ; the old identifier, then the new
add-key-signed  = %s"SIMON-ADD-KEY" LF address LF key-token
recover-signed  = %s"SIMON-RECOVER" LF address LF key-token LF timestamp   ; dedicated CLIENT recovery
request-signed  = %s"SIMON-REQUEST" LF method LF serialised-origin LF actor LF target LF unix-seconds LF nonce LF 64LHEXDIG
serialised-origin = %s"https://" domain [":" port]   ; lower case, no default/leading-zero port, no trailing "/"
actor           = [ address / serialised-origin ]               ; the value of simon-agent or simon-server, or empty
method          = 1*(%x41-5A)                        ; the request method, in upper case
target          = 1*(%x21-7E)                        ; the request target exactly as sent: path and query
LF              = %x0A
```

Each `canonical-*` is the canonical JSON (section 5.1) of the object named, with its `signature` member removed where it has one. No context line is a prefix of another followed by LF, and no variable line can hold LF, so no two contexts sign the same bytes. The registry's `human-consulted` header adds one more context, `SIMON-HUMAN-CONSULTED`.

In a media type, the type, subtype and parameter names are lower case, while `rname` admits upper case in parameter values. `rname` in type and subtype positions is matched in lower case only.
