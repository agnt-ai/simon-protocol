# The core, and what stays out of it

A design note of 2026-10-21. It records how the core of the SIMON Protocol, the server-to-server specification in [`spec/PROTOCOL.md`](../spec/PROTOCOL.md), reached a historical design milestone, what went into it and what went into the registry, and where each idea comes from. The client layer ([`spec/CLIENT.md`](../spec/CLIENT.md)), servers and applications build on it and are designed separately.

## The protocol in seven sentences

1. An address is `name@domain`, and its keys prove who wrote what.
2. A message is signed: from, to, when, an optional pointer to another message, ordered blocks of any type, and headers.
3. Addressed to someone, it is sent: a copy lands in each recipient's inbox.
4. Addressed to no one, it is published: kept by the author's server, readable by whoever its audience label allows.
5. A signal is a small, short-lived note between servers (typing, collected, read), never stored.
6. A client reads and manages a mailbox, holding its own key or given scoped access by the host.
7. Anything else is a header, a block type or a relation, in the registry.

## The test for the core

The core should be as small as SMTP or Nostr's NIP-01, built to last, and boring. A feature enters it only when all three hold:

1. **It has existed for decades in some form.** Threads, attachments, read receipts and newsgroups are older than the web. Nothing trendy enters, and nothing AI-specific: no tool calls, no prompts, no generated-UI formats. An agent is just a sender.
2. **Adding it later would force every server to change.** If a server has to read it, route by it, or refuse by it, it is core. If only readers interpret it, it is a registry entry, and the core's job is to give readers a rule for what they do not know.
3. **It is named for what it is,** not for a product or a trend.

Everything else is a header, a block (part) type or a relation name in [`spec/registry.md`](../spec/registry.md).

## Core or registry

| Idea | Core or registry | Where | Why there |
| --- | --- | --- | --- |
| Addresses and keys | core | 2.1, 2.3, 2.4 | Routing and verification. |
| No content requirement | core | 5.3 | A message may carry any blocks, a file alone, or none. A reader shows an unknown block by its `alt`, or says it cannot show it. |
| Blocks typed by media type, open-ended | core | 5.3 | The part list existed; what is new is saying it is open and ordered, and how a reader treats a block it does not know. |
| `name` and `alt` on a part | core | 5.3 | Known members of an open part object; v1 servers validate these when present and preserve extension members. An ignored extension cannot silently change a part's meaning to an older reader. |
| `schema` media-type parameter | registry | Block types | Readers only. |
| Specific block types (reference, forwarded message, UI) | registry, with core carriage rules | Block types; 5.3 | Readers interpret their content. Servers also enumerate and validate files of inline-carried messages under the bounded traversal in 5.3. |
| `inReplyTo` | core | 5.2 | Unchanged. |
| `rel` header | core | 5.4, 5.5 | Servers check its placement. Its reader rules (an unknown relation shows as a reply; the author-only rule) bind every reader that claims the reader profile, for every relation, including names invented later. |
| Relation names (reaction, edit, retract, comment, vote, response, forward, quote, pin) | registry | Relations | Reader conventions, except explicitly core-required same-author public-listing suppression; the list grows. |
| Conversations: root id, no roster, `to` is the membership | conversations profile | profiles/conversations.md | What a conversation is, and that servers keep no state, so nobody builds Matrix-style replicated rooms on top. |
| `conversation`, `thread`, `subject` headers | registry | Message headers | Readers only. |
| Signals and `POST /simon/signal` | core | 6.4 | A new server-to-server call: every server must implement it to receive signals, and none exists to reuse, since signals must never be stored. |
| `typing`, `collected`, `read` | registry | Signal types | The signals the path exists for, decades old. Servers pass on types without reading them. |
| Published messages, feed listings, relations listings | publishing profile | profiles/publishing.md | Optional: a server that publishes implements all of it. |
| `feed`, `audience` and `listed` headers | core grammar, publishing meaning | 5.4; publishing profile | Every server checks their grammar and placement; the author's server reads `feed` to list feeds, `audience` to refuse readers, and `listed` to know which relations their writers let it list. |
| What an audience label means | registry (or the author's app) | Audience labels | Opaque to the protocol by design. |
| Following | registry | `follow` header, `followers` label | Can start as a convention: a reader polls a feed. |
| Interactive UI is data, never code | core (security rule) | 11.2 | A safety rule every reader must obey. The UI block format itself is reserved in the registry. |
| Identity modes | core (statement) | 2.2, 12 | No new mechanism: `for` already says which mode a message is in. |
| Files: content-addressed parts, `name`, forwarding received parts | core | 5.3, 7.2, CLIENT.md | Servers store, serve and check them. |
| Big, live or revocable files | registry | `application/simon-reference+json` | A link with a hash; readers only. |
| Chunked or resumable upload | neither | 14 | Not added. Big things travel by reference. |
| Carrier-signed claims | core | 6.2 | Part of the envelope that servers check. |
| Unpairing | core | 2.2 | A signing context every reader and server must understand. |
| `human-consulted`, `moved-to`, `binding` | registry | Message headers | Readers only. |
| End-to-end encryption, live sessions, new algorithms, new versions | slots | 10 | Room left, nothing built. |

## Each proposal, and where it comes from

### No content requirement; Markdown when there is text

*Revised.* The first version of this note required every message to carry text, so any reader could show any message. That rule was dropped: the protocol is as vanilla and unlimiting as possible, a blank message with an attachment needs no body, and the `subject` header can carry meaning. The cost, accepted: a reader that knows none of a message's blocks may misunderstand it without anyone noticing. LLM agents, the main readers, can read an unknown block's JSON anyway. When a message has text, Markdown follows RFC 7763, with the dialect named in `variant` (RFC 7764). Readers render no embedded HTML, show where links go, and fetch nothing a text names until asked.

**Precedent.** MIME's `multipart/alternative` (RFC 2046, 1996) put a plain-text version first so every mail reader could show something. The IETF MIMI content format (below) requires receivers to accept `text/plain` and `text/markdown;variant=GFM-MIMI`, a GitHub Flavored Markdown profile with a mandatory "No HTML" extension. Remote images in HTML mail are the tracking pixel: loading an image on display tells its server the message was read, which is why mail clients block them by default.

**As MIMI.** MIMI has no general rule that a message carries text, and neither does SIMON now.

### Blocks

Parts are an ordered, open-ended list of blocks typed by media type. A structured block names its schema in the `schema` parameter. Two optional members: `name`, a suggested file name, and `alt`, a one-line text version. A reader shows a block it does not understand by its `alt`, or skips it. General-purpose containers are left to a later type; inline whole-message carriage already has the bounded file traversal in section 5.3.

**Precedent.** MIME `multipart/mixed` (1992) is an ordered list of typed parts; `Content-Disposition`'s `filename` (RFC 2183, 1997) is `name`; HTML's `alt` (1995) is `alt`. The AT Protocol's lexicons name a record's schema by an identifier inside the record, which `schema` does for a block. MIMI nests parts with three semantics (choose one, single unit, process all); SIMON keeps a flat, process-all list, because a flat list with a text block and per-block `alt` covers what "choose one" was for, and nesting can come later as one block type without touching servers.

### Relations

`inReplyTo` stays the one pointer. A `rel` header says what kind of pointer it is. The names live in the registry. Two reader rules are core:
- **Unknown relations are shown as replies,** by their blocks and alts: a reaction's text is its emoji.
- **Author-only relations** (edit, retract) count only when both messages have the same `from`. From anyone else they are ordinary replies.

The registry's `supersedes` and `retracts` headers are folded into `rel: edit` and `rel: retract`.

**Precedent.** Email's `In-Reply-To` and `References` (RFC 822, 1982) are the pointer. Usenet had cancel messages for retraction (RFC 1036, 1987) and later `Supersedes:` for edits (son-of-RFC-1036, 1994; RFC 5536), and forged cancels are the classic proof that withdrawal must be bound to the author. Matrix puts every relation in one `m.relates_to` object with a `rel_type` (`m.annotation` for reactions, `m.replace` for edits, `m.thread`, `m.reference`) and requires an edit to come from the original sender. Nostr's NIP-09 honours a deletion request only from the same key.

**Aligned with MIMI.** The IETF MIMI content format (draft-ietf-mimi-content-09, July 2026; a working-group draft, not yet an RFC, intended as Informational) defines the same semantics, and SIMON follows it where it fits:

| SIMON | MIMI content | Same meaning |
| --- | --- | --- |
| `inReplyTo` | `inReplyTo` | yes |
| `rel: edit`, naming the original | `replaces`, naming the first instance | yes |
| `rel: retract` | `replaces` with a null part | yes |
| `rel: reaction`, text is the reaction | `reaction` disposition with `inReplyTo` | yes |
| `thread` header, naming the anchor | `topicId` | close: MIMI groups by a topic value, SIMON by the message the thread hangs from |
| author-only relations | "MUST NOT let anyone other than the original sender edit or delete" | yes |
| latest edit by `sentAt`, ties to the lowest id | sort by timestamp, ties to the lowest message id | yes |
| `name`, `alt` | `filename`, `description` (on external parts) | yes |
| `application/simon-reference+json` | external part: `url`, `contentType`, `size`, `contentHash`, `expires` | yes, without MIMI's encryption members, which belong to the encryption profile |
| no expiry | `expires` | SIMON leaves expiry to a later registry header |
| flat block list | nested parts | SIMON defers nesting |

A bridge between the two maps each row directly.

### Conversations without shared state

A conversation is its root message and everything whose `inReplyTo` chain leads to it. Its id is the root's id. There is no roster: each message's `to` is its author's choice of who receives it, and a reply that reaches more or fewer people forks the conversation, as email and texting do. Servers keep no conversation state, and nothing is replicated between them. (Revised 2026-10-24, B1: an earlier draft had signed `add`, `leave` and `remove` relations and a roster rebuilt by readers. A removed member could backdate an `add`, and with no roster there is nothing to forge.)

**Precedent.** Email and Usenet threads (1980s) are exactly this: a chain of pointers, no shared state. Matrix took the other road, a room whose state every server replicates and resolves, and its state-resolution algorithm is the most complex and most revised part of its spec. MLS (RFC 9420) keeps group membership as a signed, ordered log, which is where encrypted groups will go.

**Core, profile or registry.** The conversations profile holds the definition (root id, `to` as membership, no server state), so nobody builds server-side rooms on top. The `conversation`, `thread` and `subject` headers are registry entries, because only readers use them.

### Signals

`POST /simon/signal` carries `typing`, `collected` and `read` between servers. A signal is signed by the sender's server, as an envelope is, and is never stored or put in any history. *Revised:* any receiving server may drop any signal, `read` is sent only when reading is shared by choice, and the rule that signals pass only between parties who have both written to each other is gone. Each is sent only by the one it is about, and only when that agent asks for it, never as a side effect of fetching. Whom a server passes signals to is its own policy (docs/REFERENCE-SERVER.md).

**Precedent.** BSD `talk` (1983) showed the other party typing, keystroke by keystroke. X.400 (1984) had receipt notifications; mail has had Message Disposition Notifications since RFC 2298 (1998, now RFC 8098), sent only with the user's consent. RFC 3994 (2005) defined the "is composing" indication that RCS uses, and RFC 5438 (2009) the delivery and display notifications. XMPP has chat states (XEP-0085) and receipts (XEP-0184, XEP-0333). Matrix sends typing and receipts as ephemeral events that are never persisted in the room, and has a private read receipt for those who do not want to share. Signals need a path of their own because deliver stores what it carries and remembers repeats for a week.

### Publishing

A message with an empty `to` is published. Beyond what the first draft already had:
- **Feeds.** A `feed` header names the feeds a post is in; an agent has as many as it names. The author's server lists each, newest first, with an opaque cursor.
- **Audience.** An `audience` header, signed into the post, opaque to the protocol. The author's server decides what it means. Readers sign their requests with their own agent key, naming themselves (the reader's own server no longer vouches for it); a refused reader gets the same `404` as a post that does not exist. A leaked copy still carries its audience, and software never republishes a post to a wider audience than it carries.
- **Comments,** reactions and votes are relations sent to the author's server, which may list them under the post for the post's audience. Which relations it lists is its own choice (no server behaviour depends on the registry), among those whose writer marked them `listed` (a relation is written to the author alone, so listing it needs its writer's consent).

**Precedent.** Usenet newsgroups (1980) and its `Distribution:` header (RFC 1036), an audience label that servers honoured by agreement. RSS (1999) and Atom (RFC 4287, 2005) feeds, read newest first. ActivityPub's outbox and audience addressing; Diaspora's aspects and Mastodon's visibility levels as audience labels that mean what the author's server says. Answering `404` for something the reader may not see is how GitHub answers for private repositories. Signed fetches follow ActivityPub's authorised fetch, without its deadlock, because SIMON's key documents stay unauthenticated.

### Interactive blocks are data, never code

A UI block is a declarative description the reader draws with its own components. Choosing never calls a URL: it makes a new signed message with `rel: response`. Links open only when tapped, with their destination shown. HTML-style UI is at most a later opt-in profile, sandboxed with no network.

**Precedent.** Slack's Block Kit and Microsoft's Adaptive Cards describe UI as data drawn by the host. RCS rich cards and suggested replies are the closest model: tapping a suggested reply sends a message carrying its postback data. Thirty years of HTML mail show why code in messages is the attack surface, and every serious mail client strips scripts and forms. SIMON goes one step further than Block Kit, whose buttons post to the app's URL: here the choice is itself a signed, attributable message, which an agent can audit like any other.

### Identity modes

No new mechanism. The spec now states the three modes (identified by email or phone, pseudonymous by key, unattributed for solo agents), the protocol's only job (never force an identity, never reveal more than the sender chose, always let a reader tell the mode), and that anonymity is toward other agents, not toward one's own host.

**Precedent.** Email has always allowed all three. Nostr is pseudonymous by key. Signal's usernames separate reachability from phone numbers.

### Files

Content-addressed parts stay for small files; parts gain `name`; an agent can forward a part it received without uploading it again; and the registry gains a reference block (URL, name, type, size, optional hash, optional expiry) for big, live or revocable things. There is no chunking and no resumable upload. The spec now says plainly that a shared file cannot be taken back, that parts are untrusted data like text, what egress costs the author's server, and that the reference server's limits are its own defaults, not requirements.

**Precedent.** MIME attachments; `message/external-body` (RFC 2046, 1996) for content kept elsewhere; XMPP's HTTP upload (XEP-0363); MIMI's external parts. Chunked transfer exists in JMAP and tus, and is left out because it is a client-to-server matter for files the reference block already covers.

### Leaving slots

- **Encryption:** already reserved (`application/simon-sealed`, `encryptionKeys`), for HPKE and MLS.
- **Live sessions:** a later signal type can offer one; the session runs elsewhere.
- **Algorithms:** new key token names beside the old.
- **Versions:** a later version adds further signatures in members of its own, so every server still checks the one `signature` (this replaces the promise that `signature` could become an array, which no deployed server could have honoured).

### The client layer, later

Sentence 6 leaves the slot. JMAP (RFC 8620, 8621) shows how a mailbox API can be one batch call plus a push channel; Nostr's NIP-46 shows a client using a signer it does not hold; OAuth shows delegated, scoped access. CLIENT.md is designed separately; this work only adds the small pieces the core needs there: forwarding received parts, inbox entries that carry the carrier's signed claims, unpairing, and a placeholder for signals.

### Conformance and profiles

`critical` and the other reader rules need reader conformance, which servers' conformance cannot show. XMPP's compliance suites (XEP-0479 and its predecessors) are the model: named profiles, each a list of what an implementation of that kind must do. The reader profile ([`spec/profiles/reader.md`](../spec/profiles/reader.md)) gathers them; its rules have vectors and functions in the protocol library, and a reader conformance suite is still to come.

## Review findings the core addresses

The core-level findings of an external security review, and how the core answers them:

- **Claims.** Claims are signed for their message (`claimsSignature`, context `SIMON-CLAIMS`) and travel into inbox entries as `signedClaims`, so a claim stays checkable wherever a message goes. A principal never counts for a message without `for`, whatever its claims say.
- **Email authority.** Email authority comes only from the `_simon` TXT record; the well-known answer still routes.
- **Key management and recovery** are host policy: other servers see only the keys and revocations in the agent document. CLIENT.md defines dedicated account/recovery calls; host practice remains separate from core interoperability.
- **Fetching and signals.** When a server fetches parts is its own choice; it SHOULD fetch on arrival, never on read, and section 12 states what each choice reveals. The reference server fetches for every accepted message. Signals are explicit and opt-in.
- **Sender protection.** The historical ordering requirement stays: no recipient lookups before carrier authentication. The subsequent review also requires bounded unauthenticated lookup work, with mechanisms and values chosen by the host. Fair fetching, counting repeats, an envelope size bound and separate lookup budgets are the reference server's notes (`docs/REFERENCE-SERVER.md`).
- **Unpairing.** A key principal can end its pairing.
- **`human-consulted`** signs over the message itself.
- **Accountability and trusted carriers.** The limits of accountability and of trusted carriers are stated; no transparency log in version 1.
- **Normalisation.** Routers never judge it. How a later version judges non-ASCII local parts is that version's to decide.
- **Versions.** Readers present unknown versions as not understood.
- **Conformance.** `critical` needs reader conformance, which the reader profile's vectors begin.
