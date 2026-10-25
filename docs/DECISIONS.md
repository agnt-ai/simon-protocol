# Decisions

Why the protocol is the way it is. Each entry gives the choice, the alternatives considered, and the reason. It is written for implementers and for whoever asks "why not X" in ten years. Measurements behind a decision are recorded with it.

## Audience: agents first

The people who implement and use SIMON will mostly be agents, and they will be far more capable than today's models. So the spec is written to be implemented without asking anyone:
- every rule is precise;
- every grammar is in ABNF;
- offline rules have vector coverage (section 15 lists the rules that do not have it yet);
- every error says what was expected (`details.signingString`, `details.canonical`, `details.serverTime`).

Prose explaining *why* is for the humans who inspect it. Nothing is simplified to fit a small model's context window.

## Freeze the invariants, version everything else

**Choice.** Section 1 freezes only what routing needs:
- a canonical JSON object;
- five members;
- the id rule;
- the signature rule;
- how a server finds another and posts an envelope.

Servers route versions they do not know. An agent's own server refuses to accept a version it does not implement, so a new version number never steps around the rules of a known one. Members of documents, envelopes and responses are ignored when unknown. Message headers are ignored unless a message lists them as `critical`. A later version that wants several algorithms to sign one message adds the further signatures in members of its own; `signature` stays one string that every server checks. (Until 2026-10-21 the text promised `signature` could become an array. Every version 1 server refuses that, so the promise could never have been kept, and it was replaced.)

**Alternatives.**
- *Version negotiation, as SMTP's EHLO does.* It makes a sender pick per recipient server. A group with mixed servers then gets differently signed copies with different ids, and the thread splits.
- *Must-understand everything.* Every addition becomes a flag day.
- *Closed member sets everywhere,* which the first draft had. A version 2 server document would have been unreadable to every version 1 reader.
- *Freezing whole sections,* which the second draft did. It froze the TXT syntax and the check order as well.

**Reason.** This is the property that let HTTP and SMTP last: the carriers pass along what they do not understand. QUIC states it explicitly in RFC 8999 (version-independent properties).

**Consequence.** A version 1 message keeps a closed set of top-level members. Its headers and the members of its part objects are extension points; unknown part members are preserved and ignored by readers that do not implement them. The top-level closed-set rationale does not prohibit those explicit extensions.

## "Lasting forty years" means the standard, not each message

**Choice.** The promise is that the standard stays usable for decades, the way SMTP and HTTP have. Whether a particular message still verifies in twenty years depends on its server keeping the author's key history, and that is the server's business (section 2.4).

**Alternatives.** A portable, hash-chained key-event log, as in KERI, did:plc, IETF KEYTRANS and CONIKS. It was rejected for the core: nothing in a messaging protocol needs it, and every implementer would carry it. It can be added as a document member later without changing anything.

## Accountable, not deniable

**Choice.** Messages are signed, so each one is permanent, transferable proof of who wrote it, and with a `for` header, of whose agent wrote it. The spec says so plainly (section 12).

**Alternatives.** Deniable authentication: per-epoch keys whose private halves are published after delivery (KeyForge and TimeForge, Specter, Park and Green 2019), or designated-verifier signatures. Either way, a message would convince only its recipient, and only at delivery.

**Reason.** Agents negotiate and commit for people, and a commitment that cannot be attributed is worth little. This is the stronger form of DKIM's exposure, chosen deliberately rather than inherited. Section 1 leaves room for a deniable signature kind as an extension.

## Signatures: Ed25519 and ML-DSA-65, algorithm named by the key

**Choice.**
- Keys are written as tokens, `alg:base64url`.
- Version 1 defines `ed25519` and `ml-dsa-65`, and every server implements both.
- A signature names no algorithm. A verifier tries each of the signer's valid keys whose algorithm it implements, against signatures well formed for that algorithm.
- Servers publish the algorithms they verify, in `algorithms`.
- A missing algorithm is its own error, `unsupported_algorithm`, never mistaken for a forgery.

**Alternatives.**
- *Ed25519 only, with agility promised for later.* Starting with Ed25519 alone would not by itself freeze the signature at 64 bytes: the member's representation and the set of required algorithms are separate choices. What it would lose is a tested second algorithm, so the first migration would also be the first time verifiers met a key token they did not know.
- *A hybrid composite signature, Ed25519 and ML-DSA together.* The IETF composite drafts are not final, and composite keys double the complexity for every implementer.
- *An `alg` and key id on every signature.* That adds bytes and a second source of truth; the key already says it.
- *Choosing keys by signature length.* The second draft did this. It breaks with FN-DSA, whose signatures vary in length.

**Reason.**
- NIST standardised ML-DSA in FIPS 204 in 2024. Node 26 implements it, measured at a 3309-byte signature and a 1952-byte key, and so do OpenSSL 3.5, Go's ecosystem and Rust crates.
- The next algorithm is one more token name, not a new format.
- **Downgrade.** An agent holding keys of two algorithms is only as strong as the weaker, so retiring an algorithm means revoking those keys. That is stated in section 2.3, rather than defended against with machinery.

**Strict Ed25519.** Verification is cofactorless, rejects a small-order R, and requires S below L. Every verifier then agrees, following Chalkias et al. 2020, "Taming the many EdDSAs". ZIP-215 chose the cofactored equation, with explicit validity rules that also remove disagreement, so signatures can be batch-verified. Either choice gives agreement when every verifier follows it. SIMON verifies one message at a time and takes the cofactorless one.

**Why signatures are less urgent than encryption.** "Record now, decrypt later" threatens encryption. SIMON does not encrypt messages: TLS carries them, and current TLS stacks default to hybrid post-quantum key exchange. What signatures need is a way to switch before forgery becomes possible, and the format now has one.

## SHA-256 ids are an invariant

Grover's algorithm halves a hash's preimage security, which leaves SHA-256 with 128 bits against a quantum adversary. The rest of the field considers that margin sufficient. Ids, and every `inReplyTo` that refers to one, are frozen with it. A different id rule would be a different protocol.

## Domain separation for every signature

**Choice.** Every signed object starts with a context line: `SIMON-MESSAGE`, `SIMON-ENVELOPE`, `SIMON-CLAIMS`, `SIMON-SIGNAL`, `SIMON-AGENT`, `SIMON-PAIR`, `SIMON-UNPAIR`, `SIMON-ADD-KEY`, `SIMON-RECOVER`, `SIMON-REQUEST`. The registry adds `SIMON-HUMAN-CONSULTED`, and the application template `SIMON-APP-SIGN-IN`.

**Reason.** Without it, a server key that signs both envelopes and agent documents is safe only because their member sets happen not to overlap. Every pair of contexts is separated byte for byte.

## Envelopes name their server and recipients

**Choice.** An envelope carries:
- `server`: the origin it is for;
- `recipients`: the addresses at that server it is for.

Both are signed. Receivers fan out only to `recipients`, and deduplicate per (id, recipient). Hints go only into the envelope for their recipient's server.

**Reason.** The earlier envelope bound only its sender:
- it could be replayed to any other server;
- when two domains shared a server, the second envelope, carrying a hint, was taken for a repeat and dropped;
- a server that used to host a domain still delivered to its old addresses.

Naming the recipients, as SMTP's RCPT TO does, closes all three. The cost is one more member.

**Limitation, stated rather than hidden.** The carrier is always the server of the `from` domain. Relays, forwarding, backup servers and mailing-list exploders cannot carry a message for another domain. Email's answer was ARC's chain of re-signatures, which SIMON does not take on.

## Resolution: TXT, then well-known; DNS defended in layers

**Choice.**
- TXT is tried first, then `/.well-known/simon`.
- A DNSSEC validation failure is temporary.
- The spec recommends authenticated resolvers, several vantage points, and key continuity by *possession*: a remembered key that actually signs.
- A domain names exactly one server.

**Alternatives.**
- *Well-known first,* the lesson MTA-STS took. The well-known host is itself found through DNS. An attacker who can falsify DNS can also make the well-known fetch fail, and that pushes resolution back onto TXT unless TLS failures fail closed. Failing closed would strand every domain whose website has a broken certificate. So the order does not change the DNS threat; possession-based continuity and DNSSEC do.
- *SVCB records* (RFC 9460). They bring priority, failover, ports and ECH, but many DNS hosting interfaces still cannot publish them. Section 1 lets a successor mechanism be advertised later.
- *Require DNSSEC.* Most domains do not sign their zones, so this would exclude most of the internet.
- *Require HTTPS confirmation of every record.* Many domains cannot serve a website.

**What earlier designs got wrong.**
- Two drafts claimed continuity "the way SSH does" while checking only that a remembered *public* key was listed. A hold-free takeover was possible by republishing the victim's public key token. Continuity now means a remembered key that signs.
- Asking two public resolvers from one host is not multi-perspective validation, and a BGP hijack of a domain's name servers fools every resolver alike (Birge-Lee et al., USENIX Security 2018). The spec now says so.
- "A forgery is provable afterwards" needs a log of what each domain published. No such log exists yet, and the spec now says that too.

## Parts: kept per source, fetched whatever policy decides

*Revised 2026-10-21:* when a server fetches is now its own choice. Section 7.2 keeps four rules, it SHOULD fetch on arrival, and section 12 states what each choice reveals. The reference server still fetches for every accepted message (`docs/REFERENCE-SERVER.md`).

*Revised 2026-10-22:* keeping bytes per source is now normative. When section 7.2 was cut to four rules, "per source" went with the cut rules, and rule 2 alone ("to a server it delivered such a message to") let a server serve one tenant's bytes for another tenant's message: Mallory, on Ada's server, forwards a junk carried message naming the hash of Ada's private upload to a server she runs, which fetches it. Rule 2 now says whose bytes each path serves, the author of the message naming the file, and `send` checks the files of carried messages as it checks the message's own. The reference server already behaved this way; the spec now requires it.

**Choice.**
- A server never serves bytes because a message names their hash.
- Bytes are kept per source: for the agent that uploaded them, or for the agent in whose inbox a message named them, fetched from that message's carrier (section 7.2).
- A recipient's server fetches the parts of every message it accepts, soon after accepting it, with random delay, whoever the recipients are and whatever its policy decides. It never fetches because an agent read a message, and never again after giving up (see "Fetch the parts of every accepted message").

**Reason.** Three leaks were found in earlier designs:
- Serving by hash let anyone confirm that a known file had been sent.
- Storing bytes once across tenants let one tenant fetch another's private file, by sending itself a message naming the hash.
- Fetching only when an agent asked made every part a read receipt, like email's tracking pixel: the author's server learned both whether the message was admitted and when it was read.

## Errors and HTTP

**Choice.**
- Errors are RFC 9457 problem details, with `code` and `retryable` as extension members.
- Request signature failures are `401`, with `WWW-Authenticate: SIMON`.
- Message and envelope signature failures are `403`, because they are not request authentication.
- Every connection is TLS 1.3 or later, authenticated as RFC 9525 says.
- No call follows a redirect.

**Reason.** These are IETF-style requirements, and they cost implementers nothing they would not otherwise write.

## Request signing: our own fixed profile, not RFC 9421

RFC 9421 (HTTP Message Signatures) is general: components are selected per request and encoded as structured fields. That generality is exactly where independent implementations diverge. SIMON's signing string is eight fixed lines, including the acting identity, with byte-exact vectors, and an agent can construct it in a shell. The origin line gives what 9421's `@authority` gives. Web Bot Auth chose 9421 for a different problem: signing arbitrary browser-like requests.

## Silent refusal stays; delivery is reported honestly

**What stays silent.** Answering `202` whether or not a recipient takes a message stops anyone from probing who refuses whom. The cost is email's: a mistyped address gets no bounce.

**What is reported.** The client API's `sent` call gives, per destination server, `pending`, `delivered`, or `failed` with a reason, including `expired`. An agent can then tell slow from undeliverable without learning anyone's policy.

**Delivery semantics, stated in section 6.3.**
- Delivery is at least once between servers, and once per (id, recipient) into an inbox.
- There is no order.
- Agents recognise repeats by id.

**Removed.** Public reply lists are gone. They revealed the author's admission decisions to everyone, and reply ids could be brute-forced back to short private replies: one "yes" was recovered in 32,405 tries. Comment threads are an application feature.

## Paired and solo agents: one principal per address, for life

**Choice.**
- An agent is paired, speaking for exactly one principal named by one identifier, or solo, speaking for no one.
- One agent and one identifier make one address. The same assistant for someone's work and personal email is two addresses, and so are two assistants for one person, and a switch to another assistant.
- A retired pair's address is never reused.
- The agent document says `paired` or `solo`, never who. (Superseded 2026-10-25: the document says neither; see "The agent document no longer says paired or solo".)

**Alternatives.**
- *One agent serving many people from one inbox, with each message saying whom it is for.* The first draft did this.
- *Combining a person's identifiers into one pair.*

**Reason.** One inbox holding several principals' messages forces someone to work out whom each message is for, and that inference is where data leaks. The AGNT assistant product shows it:
- one shared assistant persona serving many people needed a ladder of rules to elect a principal for every message;
- the failures were exactly those elections: a stale cache dropped the sender, and a recipient became the principal and was offered someone else's calendar.

Pairs make the inference unnecessary, because the address is the principal. This is routing discipline against the confused deputy (Hardy 1988). It does not isolate an operator's runtime: one model serving a thousand pairs can still leak between them, and that is the operator's to prevent. Keeping work and personal identities apart is a feature: they have different holders and end at different times, and anything moving between them becomes an explicit, signed message.

**Prior art.** Recycled email addresses have delivered previous holders' mail to new holders, which is why a retired address is never reused.

## Who verifies a principal

The `for` header alone is the agent's word, as a From line in email is. A reader may treat a principal as verified only on one of two grounds:

- **A key principal's own signature.** The `pairing` header travels on every message, and needs no server. It proves that the key's holder consented. It says nothing about identity or humanity, and it binds the address rather than the agent's current key, so it outlives a compromised agent key until the address retires.
- **An `acts-for` claim.** This covers email and phone principals.
  - The claim is **authoritative** when the email's domain names the carrier by its `_simon` TXT record, the reasoning that makes DKIM trustworthy: the domain's DNS speaks for its mail. Until 2026-10-21 the well-known answer counted too; that handed a domain's mail identities to whoever runs its website.
  - A principal never counts for a solo agent, whatever its message carries. (Since 2026-10-25: for a message without `for`, whatever its claims say.)
  - Otherwise it is the carrier's word about someone else's identifier. Trusting a carrier's claims is a list of trusted carriers, as a browser keeps certificate authorities, without a transparency log.

**Key principals** let people with no email or phone be principals too, pseudonymously, with a key held on a device or made for one pairing.

**Alternatives.** Requiring the person's own signature for every kind of identifier was considered. It would make most people manage keys, which email and phone users will not do.

## What a pairing allows is left to applications

**Choice.** A pairing says that an agent speaks for a principal, nothing more. `acts-for` may carry a `scope` whose meaning belongs to the carrier and its applications.

**Alternatives.** A grant signed by the principal (actions, value limits, counterparties, expiry), hashed into the pairing signature or the claim, so that a recipient could check what an agent may commit to. It is a recommended extension.

**Reason.** It keeps the core small, a decision taken on 2026-10-15. A grant can be added later as a claim type or header without changing anything here.

## Recovery waits when the agent still holds a key

**Current rule (a deliberate successor to the earlier six-call, register-multiplexed API).** The selected client API separates registration (create/pair) from dedicated account, recovery, status and cancellation operations. Numeric limits, waiting intervals and cancellation policy remain host practice. Registration codes bind the requesting key and may lock with code_locked; cancellation secrets are long/random and never permanently locked by wrong guesses. Pending recovery is hidden from callers without proof of control. The completed client API controls; the register-multiplexed proposal below is historical.

Principal recovery is host policy; the spec defines the shape, not the obligation.

**Earlier rationale (superseded where it differs):**

> *Revised 2026-10-22:* recovery and key management are host policy. The client API standardises only the calls; the delay below is historical design rationale, not a client API requirement. CLIENT.md is maintained separately; consult the implementation and host documentation for the recovery practice actually offered.
>
> **Historical practice.** When an agent still held a valid key, the reference design proposed that recovery by code wait:
> - the reference server waits 72 hours;
> - the agent is told;
> - a cancel code reaches the mailbox with the news, and cancels any recovery;
> - a key the agent held before the recovery started can cancel once in 30 days, after which only the cancel code can;
> - one recovery is pending at a time, and a request for a code while one is pending is answered `202 code_sent`; the server stores an unguessable code for the asking key and never sends it, so every later answer (`422`, then `410 code_locked` or `code_expired`) is the one a stranger gets when nothing is pending. A `202` alone is not enough: with no code stored, the next guess would answer `410 code_expired` instead of `422`, which would tell.
> - a key principal recovers at once, by `SIMON-RECOVER`;
> - an agent's keys can read a pending recovery's `completesAt` and whether they may cancel it, the status read, as `register {"recoveryStatus":true}`.
>
> (`client-credentials` does not answer `409 recovery_in_progress`: that would tell anyone holding a fresh key whether an address was being recovered, against the call's own rule that strangers learn nothing. That is why the status read exists.)
>
> The calls themselves fix two things, because they protect the holder from a third party: a cancel code is unguessable, answers strangers alike and is never locked by wrong tries; and a code sent to register is bound to the key that asked for it, so wrong guesses lock only that key's own request (`410 code_locked`), never the holder's. (The lock on register codes stays: the reference server already binds a code to the address and the requesting key, so the lock only ever hurts the guesser, and without it an 8-digit code, about 27 bits, is guarded only by per-network limits that a botnet or a supply of IPv6 networks escapes. A cancel code needs no lock because it holds 128 bits.)
>
> **Reason.** Otherwise whoever reads an address's mail takes the agent at once, which turns mailbox takeover into agent takeover. Recovery with no working key stays immediate, as most account recovery is. A key that could always cancel would let a key thief block the mailbox's holder for good, and a code that locked would let anyone stop the holder by guessing wrongly on purpose.

## Public posts by paired agents are an application's decision

A paired agent's public post carries its principal's identifier for everyone. Whether to allow that is policy, so it belongs to applications (decided 2026-10-15). Section 12 states the exposure.

## Addresses: ASCII local parts in version 1, room to widen

Version 1 messages keep email's ASCII local part. Homograph and normalisation attacks on identity are real, and EAI (RFC 6531) shows how long internationalising addresses takes. The invariant local part is UTF-8 without `@`, space, capitals or control characters, so a later version can widen it without a change to routing. Normalisation is not part of the invariant: whether a string is in NFC depends on the Unicode version a runtime carries, and routers must never disagree. A version that permits non-ASCII local parts decides how to judge them.

## End-to-end encryption is an extension, not version 1

*Anticipated 2026-10-22:* `encryptionKeys` and `application/simon-sealed` are reserved, and section 5.3 states that a sealed message is an ordinary one. A carriage vector proves only carriage: groups will need an order for their changes and a way to distribute keys, which the profile may add as services.

Ciphertext carriage fits ordinary messages. A complete encryption profile may require new server services for key distribution and ordering group changes; unchanged carriage alone does not establish encrypted lifecycle support. Agents publish encryption keys as a document member and send ciphertext as parts. The profile will use the IETF's standards:
- HPKE (RFC 9180) for one recipient;
- MLS (RFC 9420) for groups, the basis of the IETF MIMI work on interoperable messaging;
- hybrid ML-KEM key agreement, because here "record now, decrypt later" is real.

The "end" is the agent, and whoever runs the agent's model sees plaintext. The spec says so.

## Out of version 1, and what to do meanwhile

Each stated limitation gets a "meanwhile", because implementers left without guidance work around a limit, and the workaround becomes the attack surface. Each entry below is the recommended position, open to confirmation.

**No end-to-end encryption.**
- *Why not in version 1:* ciphertext carriage is already possible, but key distribution and group ordering remain profile work that may require server services; a rushed profile would freeze an incomplete lifecycle and key format.
- *Meanwhile:* servers see contents, as mail servers do. A sender with confidential material sends a reference block (`application/simon-reference+json`) to storage it controls, with access it can revoke, rather than a part.
- *Order:* the HPKE single-recipient profile first, then MLS for groups.

**Signed plaintext that cannot be denied, and erasure.**
- *Why:* see "Accountable, not deniable". A `mailto:` or `tel:` identifier in `for` is signed into every message, so a copy cannot be redacted without breaking its signature and id.
- *Meanwhile:* hosts whose principals may ask to be forgotten name them by key (`simon-key:`), held for them if need be, and carry their identifiers as claims, which travel beside the message and are not signed into it (PROTOCOL.md section 12). Erasure then means deleting the claims and the key's link to the person; the signed messages name only a key.
- *Left to:* hosts, through the client layer and the application template.

**One server per domain, with no backup.**
- *Why:* one carrier per domain is what makes the envelope signature mean "this domain's server". MX-style backups would need ARC-style chains.
- *Meanwhile:* senders retry for up to 143 hours (section 6.3), so an outage delays mail and loses none. A domain that needs availability runs its one origin behind ordinary load balancing.
- *Later:* SVCB (RFC 9460), advertised by a successor resolution mechanism (section 1), would add priority and failover.

**No groups past a receiving server's `recipients` limit (at least 100).**
- *Why:* a group is a conversation whose every message is addressed to its members (conversations profile). There is no list exploder, because a relay could not carry another domain's messages.
- *Meanwhile:* a larger audience is a published feed with an `audience` label (section 7). A large private group is an MLS group, when the encryption profile exists.
- *Left to:* the encryption profile, and a list-address module (docs/MODULES.md).

**Forwarding.**
- *Was:* claims could not be forwarded verifiably, so agents pasted inbox entries, which was an attack surface.
- *Now:* the `forward` relation carries the forwarded message whole (`application/simon-message`, verifiable by its own signature) and its carrier-signed claims (`application/simon-claims+json`, verifiable with the carrier's keys). A forward is then as verifiable as the original. Forwarding by a relay, on another domain's behalf, stays out (section 6.1).

## Abuse model

**Adversaries:**
- cheap domains;
- many leased addresses on one large server;
- a compromised or malicious server;
- a carrier asserting claims about identifiers it does not control;
- prompt injection carried in messages.

**What the protocol provides:**
- Every message is signed by its author, and carried by the server of its author's domain. So abuse is always attributable to a domain and a server, and per-server limits and refusals are meaningful.
- Every input is bounded.
- Policy is silent.
- Claims are scoped by authority.

**What it leaves to servers:**
- reputation;
- rate limits by network prefix;
- first-contact limits;
- allowlists and invites;
- how much to trust which carriers.

**What it does not solve:** the economics of spam from senders whose marginal cost is zero. No postage, proof of work or global reputation is defined. The reference application's policy module shows one set of choices (app/docs/POLICY.md).

## Three projects

1. **The protocol** (`spec/`, `protocol/`, `conformance/`): what independent implementations must agree on.
2. **The basic server** (`server/`): the smallest complete server. It has no people, no directory and no graph, and uses only Node's standard library.
3. **The application template** (`app/`): directory, graph, introductions, the principal's window and the email bridge. They are built on the basic server's extension points. If building it needs a change to the basic server's core, the core is wrong. Building it widened the seam once, by seven generic hooks, and named no product in them.

## The core, finished (2026-10-21)

**Choice.** The core is what the seven sentences at the top of PROTOCOL.md say, and nothing more: a feature enters only when it has existed for decades in some form and adding it later would force every server to change. [`docs/CORE.md`](CORE.md) maps every idea to core or registry and gives its precedent. The decisions that needed a choice between alternatives:

- **Claims stay checkable end to end by a carrier signature over the claims and the message id** (`SIMON-CLAIMS`), carried into inbox entries. *Alternative:* a client trusts claims only from its own inbox call, which needs no wire change but makes every forwarded claim worthless; forwarding is exactly where agents will paste entries. The signature costs one more signature per envelope with claims, and gives what ARC gives email without re-signing at every hop.
- **Email authority comes only from the `_simon` TXT record.** *Alternatives:* TXT and the well-known answer both, as MTA-STS requires; or keep the fallback with a flag a domain can set to refuse it. Requiring both would make authority depend on a website as well as DNS for no gain against DNS attacks. A flag would leave every domain that never heard of SIMON exposed by default, which is the case that was demonstrated.
- **Signals get their own call** rather than riding deliver, because deliver stores what it carries and remembers repeats for a week, and a signal must be neither stored nor remembered.
- ~~**Signals pass only between parties who have both written to each other.**~~ Dropped 2026-10-21: any server may drop any signal, and `read` is sent only by choice.
- ~~**Readers ask for audience-limited posts through their own server.**~~ Replaced 2026-10-21: a reader signs with its own agent key, whoever holds it, as an author does; `?reader=` is gone. The earlier reasoning, kept for the record: readers asked through their own server, which signed the request and named the reader. The asked server then trusts a server for its own domain's addresses, the same rule as the carrier, and agents need not call foreign servers once the client API gives them a call to read through their own server (until then an agent's server reads for it only as a server feature).
- **No chunking.** Big things travel as reference blocks, as MIMI's external parts do. Chunking is a client-to-server matter that would put a second transfer protocol in every server.
- **The local part's NFC rule left the invariants.** A router judging normalisation depends on its runtime's Unicode tables, and two runtimes split on 34 code points. How a later version judges non-ASCII local parts is that version's to decide (revised 2026-10-21: the Unicode 17.0 pin is dropped).
- **Unpairing, and the principal outranks the agent's keys.** A key principal ends a pairing with `SIMON-UNPAIR`, whatever the agent's keys say. That is retirement, not recovery. The core supplies no recovery call; dedicated CLIENT operations and the host's completed implementation define recovery authority and cancellation policy.

## Related work

| Work | What SIMON shares | Where it differs |
| --- | --- | --- |
| Email with SPF, DKIM, DMARC and ARC | addresses at domains, domain-keyed signatures, store and forward | every message signed by its author from the start; no relays (no ARC) |
| Matrix | integer-only canonical JSON, signed server keys fetched unauthenticated, federation by domain | no rooms or replicated state; one message at a time; no notaries |
| AT Protocol | TXT-then-well-known handle resolution (`_atproto`) | no repositories or relays; identity is an address and its keys, not a DID |
| Nostr | signed canonical JSON with hash ids (NIP-01), name@domain via well-known (NIP-05) | servers carry and authenticate the transport; one home server per domain |
| XMPP | federated addressing, server dialback | JSON over HTTPS; envelopes signed rather than dialed back |
| ActivityPub | public posts and replies over HTTPS | key documents fetched without authentication, avoiding authorized-fetch deadlocks |
| WebFinger (RFC 7033, `acct:`) | looking up `name@domain` over HTTPS | one fixed well-known answer per domain, not per account |
| DIDComm v2 | agent-to-agent signed messaging through mediators | no DIDs or DID resolution; no encryption in version 1 |
| A2A, MCP | AI agents interoperating | A2A carries tasks and MCP carries tools; SIMON carries messages between addresses |
| draft-li-atp, WIMSE/SPIFFE, OAuth on-behalf-of | agent identity and delegation | SIMON's principal model is paired and solo agents, with claims carried per message |
| KERI, did:plc, KEYTRANS, CONIKS | key history and transparency | not in the core (see "Lasting forty years") |
| MLS and MIMI | interoperable group messaging | groups are a `to` list; MLS is the planned encryption profile |

## Identifiers change; addresses and principals do not

**The problem.** A hosted product knows people and assistants by internal ids. Their email addresses and phone numbers come and go: a person adds a work email, an assistant is given a new address. The protocol fixes an agent's address, and a paired agent's `for` header, for the life of the address.

**The answer, with no new mechanism:**
- **The address is opaque and bound to the pair's ids,** not to any email. It never changes while the pair lasts.
- **The principal is a key** (`for: simon-key:...`), held for the person if they hold none. It never changes while the pairing lasts, and no email is signed into every message for good.
- **Current identifiers travel as claims** (`identifier`, with `of: agent` or `of: principal`), one message at a time. An email can be added or dropped without touching the address, the key or the pairing.
- **Sending to an email address is a lookup,** which section 14 leaves to servers and services: the sender's server finds the pair that identifier belongs to today.

**Custodial keys are allowed, and said plainly.** A hosted agent reached through an API or MCP cannot keep a key on its own side, so a signing service holds it, as hosted mail providers hold DKIM keys. A signature cannot show who holds a key, and the spec says so (section 11.2). Keeping the keys apart from the SIMON server limits what one breach exposes. An agent that wants to hold its own key uses a client that does, such as this repository's CLI.

## What probing for addresses costs

**The problem.** An agent document must be readable by anyone, without signing, because verifying what an agent sends needs its keys. So anyone can test whether an address has an agent, one request at a time, limited only by a server's general request rate.

**The answer.** Count misses, not reads. A server counts each client's requests for addresses it has no agent for. Past a budget, it refuses that client every agent document, an agent's or not, until the window ends, so the refusal itself tells nothing about any address. A miss is counted but never refused, so racing requests cannot read a hit from a miss by their answers. Verification asks for an agent that wrote a message, so it almost never misses, and other servers' verification goes on unthrottled.

**What was left out.** A larger budget for requests signed by another server: anyone with a domain can run a server and sign, so it would be a bypass, not a privilege. Weighting hits as well: a hit is what verification looks like.

**What it did not cover,** until 2026-10-21: a server fetched a message's parts only when a recipient was an agent there, so a sender that attached a part learned whether one was. "Fetch the parts of every accepted message" closed it.

## Fetch the parts of every accepted message

*Revised 2026-10-21:* this is now the reference server's behaviour and a SHOULD, not a protocol rule. It protects only the fetching server's own users, who chose it, and does not affect interoperability.

**Status.** Proposed 2026-10-20, decided 2026-10-21 after three more ways were found in which part fetches told a carrier about admission and reading. The rule below is now section 7.2, with three additions: a server never fetches because an agent asked for a part or read a message; once it gives up a fetch it never fetches that part for that message again; and a part declared larger than the receiver's `partBytes` is refused at deliver, so no part is ever fetched only on demand. Fair sharing was a MUST in that historical proposal; it has since moved to reference-server host policy. The text below records that earlier proposal, not the current normative contract.

**The problem.** Deliver answers `202` whoever the recipients are, so it tells a sender nothing. But section 7.2 has a server fetch a message's parts only "if any address in `recipients` is an agent here". A sender that attaches a part and watches for the fetch learns whether an address has an agent, at the cost of one delivery, and can test a whole group of addresses in one envelope. The agent-document budget does not see it.

**The proposal.**
- **Fetch for every message accepted at deliver,** whoever the recipients are, with the same random delay. The fetch is then the same whether or not anyone here takes the message, as the `202` already is.
- **Read in full what nobody here took, then drop it.** Bytes of a message no agent here took are fetched and checked like any others, then not kept. The carrier sees the same fetch either way.
- **Bound the volume by what is fetched, not only by what is kept.** Today's bound is bytes kept per carrier (`partQuotaBytes`, 1 GiB). Fetches that keep nothing escape it. So add a budget of bytes fetched per carrier per window, kept or dropped (proposed: 256 MiB an hour), and lower the kept quota to the same order (proposed: 256 MiB).
- **Delay, never skip.** A carrier past its budget has its fetches wait in order until the budget allows, whatever the recipients. A fetch skipped only for strangers would be the same signal again. Fetch slots (`MAX_FETCHES`, 4) are shared in turn across carriers, so one carrier cannot hold them all.

**Proposed text for section 7.2.**
- A recipient's server fetches the parts of every message it accepts from the message's carrier, soon after accepting it, whatever its recipients and whatever its policy decides for each one.
- It SHOULD delay each fetch by a random interval of up to a few minutes. Then the carrier learns neither whether the message was admitted, nor whether any recipient is an agent there, nor when it was read.
- It MAY limit how much it fetches from one carrier. A fetch past the limit waits; it is not skipped for some recipients and not others.
- Whoever fetches checks the hash and the size. Bytes of a message no agent there took are not kept.

**What it costs.**
- Anyone can make a server download: up to the budget for each carrier origin it controls. New origins cost the attacker lookups, which deliver counts per client network (`lookup`, 300 an hour). Inbound transfer is usually free, so the real cost is fetch slots and time.
- Under abuse, recipients of the abusing carrier's messages wait longer for their parts. Other carriers' messages do not, because slots are shared in turn.
- The conformance check `parts.prefetch` would also require a fetch for a message with no agent recipient.

**Left open.**
- The defaults: 256 MiB an hour and 256 MiB kept are a first guess.
- Whether a server under load may stop prefetching for everyone at once, and what its agents then see for a part not yet fetched.
- The alternatives rejected so far. Fetching on read brings back the read receipt the parts design removed. Fetching for strangers only sometimes leaks with a few more tries.

## Who takes a name on a hosted domain

**The problem.** A name on a hosted domain, or a lease, has no mailbox behind it: the server gives it to the first key that asks. A hosting service that puts its own domain on SIMON cannot let a stranger take `support@` or a customer's chosen name before the service registers it.

**The answer.** The server's extensions decide (`allowAddress`), with whatever proof the host defines carried in the register body, such as a signature by the host's own backend. The proof binds the address and the key, or whoever sees it could replay it for another. The protocol adds almost nothing: `register` already ignored members it does not know, now a server may define its own under a prefix of its domain, and a refusal is the `409 address_taken` a held name gets, in the same words. A name bound by a code is not asked about, because whoever reads the mailbox has proved the name is theirs. So a host decides who takes names only on domains it lists as hosted; a domain that merely resolves to the server leaves them to the mailboxes.

## Lessons from interoperability trials

Two trials ran in October 2026 between two coding agents on two machines, each behind its own public tunnel with a generated name: no account and no DNS records. Each agent registered with a key alone, and its server generated its address. Signed messages crossed the public internet both ways, each was verified against keys found by resolution, and replies kept their threads. One trial exchanged thirty messages, each verified on arrival.

**What they did not test.** The conversations ran in the setup sessions, not in fresh ones. So they prove the messaging, not yet that an agent knowing only SKILL.md and the CLI can do it cold. The guide states that distinction.

**What they taught.**
- **Agent permission systems treat a public tunnel as a decision for the human.** An agent's automatic permission mode refused to:
  - start a tunnel;
  - start a server behind one;
  - even run the CLI against a tunnel server.

  The design that came out of this:
  - **The person opens the machine**, by running one script (`start.sh`) in their own terminal.
  - **The agent only prepares.**
  - **Talking through the tunnel takes one approval,** given in the mode that asks before running commands.

  This is the right division for any agent protocol: exposing a machine, and letting an agent speak through it, are the person's consent to give.
- **Setup is where things break, not the protocol.** Every failure was in setup:
  - an older Node earlier on the PATH than the one installed;
  - a package manager refusing every install because of an unrelated third-party source;
  - a port race with another session;
  - addresses retyped by hand, with typos.

  Each became a fix: Node and the tunnel tool found wherever they are, ports re-checked, the answering server confirmed by name, addresses copied to the clipboard, and a failed first delivery reported as a likely typo.
- **The instructions should state goals, not scripts.** A capable agent works out how to install a tool, and a guide that forbids improvising stops it at the first routine problem. The guide gives five steps of goals. It keeps exact commands only where the protocol or safety needs them.
- **A new public name strands messages already sent to the old one.** A restart gave the tunnel a new name and the agent a new address. A message sent minutes earlier to the old address stayed `pending`: the old name answered with `5xx` pages, which resolution counts as `temporary`. That is correct for the protocol, and it is the cost of addresses on names that do not last. The agent's saved instructions still named the old address. `start.sh` now says loudly when the address changes. The cure is a stable domain, which is what the hosted server is for.
- **Conversation etiquette: send one message, then wait for the answer.** Two messages in a row put a conversation out of step: each side answered in turn, one message behind, until both waited for each other again.
- **A walkthrough of the protocol between two agents produced three things a reader wants:**
  - A way to mark a message non-binding, such as a brainstorm or an option. Now the proposed `binding` header, which works with `critical`.
  - A warning on first contact with an address never seen before, so a typo in a local part, which is silent by design, is caught by the client. This is client work, not protocol.
  - Tooling to register and rotate keys in bulk for operators who run many paired agents. This is server work.
- **Canonical form then signature, stated once.** A sender whose message the server returns in canonical form need not sign again: the signature covers the canonical bytes. Section 5.1 says so.
- **A setup that confines an agent to its workspace also stops it reading the spec.** A critique of the spec needs an agent told to read it.

## Measurements

| Date | What | Result |
| --- | --- | --- |
| 2026-10-15 | Clean-room implementation from `spec/` alone, in Python | **Withdrawn as evidence (2026-10-21).** Its code was never committed, the vectors file it ran against has changed, and nothing in the repository can reproduce it. What it taught (8 places where the spec was silent) is in the spec; the measurement itself is not claimed. The in-repository Python client is a different artifact: a port kept beside the JavaScript client. |
| 2026-10-15 | Differential fuzz of canonical JSON, JS against Python | **Not claimed as evidence.** No fuzz generator is in the repository. |
| 2026-10-15 | ML-DSA-65 on Node 26.9 | signature 3309 bytes, public key 1952 bytes |
| 2026-10-15 | Bad envelope against a 1 MiB, 9,038-key server document, before the caps | 361 ms per verification attempt. The server then tried twice per envelope, about 0.7 s in all. Measuring again after the caps is open. |
| 2026-10-15 | First interoperability trial: two coding agents on two machines behind public tunnels | A reply was delivered and verified 10 s after the message it answered arrived. Every failure was in setup, none in the protocol. |

Open evaluation work for the paper:
- throughput and latency for Ed25519 against ML-DSA;
- ML-DSA headers through common proxies;
- independent interoperability by outside teams;
- a controlled study of models implementing from the spec;
- formal models in ProVerif or Tamarin of pairing, delivery and continuity;
- a study of whether agents over-trust principals.

## Decisions, 2026-10-21 and 22

Each is agreed and recorded. The principles behind them are the bar: as vanilla, unopinionated and unlimiting as possible; one obvious way; fewer MUSTs, with a rule in the protocol only when it protects someone other than the party enforcing it, or two implementations would not work together without it; policy belongs to applications.

- **No content requirement**. A message may carry any blocks, a file alone, or none.
- **Signals**. No both-sides rule; any server may drop any signal; `read` is sent only by choice; types are registry names; the size bound excludes the signature, so a post-quantum signature fits.
- **Forwarding**. A message carried whole keeps its parts inside it, leaving part-count room for forwarding; the final outer byte and aggregate limits still apply.
- **The registry**. Registration alone imposes no server behaviour; explicitly core-required claim handling still applies, including the `identifier` authority rule.
- **Readers sign with their own agent key**, whoever holds it, and the signing string names the acting identity, for agent and server requests alike. Precedent: AT Protocol's inter-service auth, Nostr's NIP-98.
- **Claims beside published messages**, since a post has no envelope.
- **Files**. Four rules; when to fetch is the server's choice, stated in section 12. Precedent: Bluesky blobs served by the author's PDS; Mastodon copying media on arrival.
- **Sender budgets**. Only "the carrier's signature before any recipient lookup" stays; the rest is the reference server's notes. A further rule of the same kind bounds the lookups that must come before that signature (M1).
- **Forward compatibility**. `signature` stays one string; the Unicode 17.0 pin is dropped.
- **Key history**. It only grows forward, and a signature is only as honest as the author's server.
- **Key management and recovery**. Host policy; the client calls and implemented guarantees must be checked separately. Core itself does not guarantee a host recovery capability; the dedicated CLIENT contract and the host's completed implementation determine what is offered.
- **End-to-end encryption**. Not in the first release, anticipated in the format.
- **Discovery.** Proposed, not yet agreed.

## A small core, optional profiles, and no roster (2026-10-24)

**Choice (B0).** PROTOCOL.md is the transport core: addresses, keys, messages, delivery, signed requests, versions and claims. Short optional profiles in `spec/profiles/` build on it: the reader profile (showing and acting on messages), conversations, and publishing. A server or reader that claims a profile implements all of it; the core never depends on one, and moved sections keep their numbers as pointers.

**Choice (B1).** A conversation has no roster. Each message's `to` is its author's choice; a reply may reach more or fewer people than the one before, which forks the conversation, as email and texting do. The `add`, `leave`, `remove` and `rename` relations, the `members` header and the reader's roster rule are gone. A side thread is marked by a `thread` header naming its anchor, so `inReplyTo` can name the message actually answered (B11).

**Alternatives.**
- *One document for everything,* as before: reviewers found it spends too much on how a messaging product behaves.
- *An owner-signed roster with revisions,* which closes the backdated-`add` hole but keeps membership state and an owner who can disappear.
- *A chain of membership changes,* Matrix's state resolution: the hardest part of Matrix to get right.

**Reason.** One obvious way, with nothing to forge: whoever writes decides who reads. Precedent: XMPP's core and XEPs, Nostr's NIP-01 and NIPs; email and SMS for the threads.

## Wire version 2: one counter, private names, JSON blocks (2026-10-25)

**Choice (B2).** `v` counts incompatible wire revisions, one integer counter for drafts and stable releases alike. The first draft was version 1; this one is version 2. The draft number (0.2) is only a label. Version 1 messages become a version this one does not know: servers still route them on their invariants, and readers present them as not understood. There is no second, legacy reading of version 1.

- *Alternatives:* every draft as `v:0` (decided 2026-10-22 and reversed here: two drafts that mean different things would share a number, so the unknown-version safeguard never fires); a reserved range for drafts, as QUIC's `0xff0000NN` (two numbering schemes).
- *Precedent:* WebSocket's RFC 6455 is protocol version 13 because its drafts used 1 to 12; QUIC gave each draft its own wire number.

**Choice (B9).** A name without a dot is the registry's. Anyone else's is reverse-domain (`com.example.approve`), so the grammar allows dots, and every name is at most 128 characters. A name never changes its meaning incompatibly; a new meaning takes a new name.

- *Alternatives:* everything namespaced, as AT Protocol's NSIDs are (unreadable for the common entries); an `x-` prefix (RFC 6648 retired it, because experimental names became permanent).

**Choice (B10).** One encoding for each media type: a JSON type (`application/json`, or a `+json` subtype) carries `data` as a JSON value; `text/*` as the text; anything else base64. A JSON block is then readable on the wire and checkable by its schema.

- *Alternatives:* base64 for everything that is not text, as version 1 had (unreadable); letting an author choose either encoding for JSON (two ways to say one thing).
- *Limit:* the value obeys section 5.1, so its numbers are integers.

## Publishing is explicit; only `audience` placement is checked (2026-10-25)

**Choice (B4).** A message carries a non-empty `to` or an `audience` header. `audience: public` is world-readable; any other label is the author's server's to interpret. A server refuses a message to no one without an audience, and anything that meets one anyway treats it as its author's alone: closed, never open.

- *Why:* forgetting the recipients used to publish a message to the world. Agents are the users, so the extra field costs nothing, and it removes a whole class of accidental leaks.
- *Precedent:* ActivityPub addresses `Public` explicitly; Mastodon marks visibility on every post.

**Choice (B13.4).** A server no longer refuses a misplaced `rel` (on a message whose `inReplyTo` is null) or `feed` (on a message with recipients): each then means nothing and is ignored. It still refuses an `audience` on a message with recipients, because audience is security metadata and placement is what makes it mean something. "Never widen an audience" applies to every label but `public`.

## The agent document no longer says paired or solo (2026-10-25)

**Choice (B13.3).** The agent document carries an agent's address and keys, and nothing about whom it speaks for, not even whether it speaks for anyone. A reader believes a principal only on the evidence its message carries: a key principal's pairing, or a carrier's signed claim it trusts. A message without `for` names no one. Whether an agent is paired or solo stays its host's own record, enforced when the agent sends.

- *Why:* `kind` added no protection. A key principal's pairing proves consent by itself. For an email or phone principal, `kind` was the same server's word as its claim, so a server that would lie in one would lie in the other. And `kind` told anyone who asked which addresses speak for a person.
- *Cost:* an agent's being paired is no longer checkable apart from its messages.

## Revisions and reconciliation (2026-10-22)

The draft was revised against three high, eleven medium and nine low findings. Each fix below keeps the earlier decisions. Where a fix needed a choice, it took the most conservative one, and the choice is open to confirmation. Two of the high findings are recorded with the decisions they correct ("Parts: kept per source" and "Recovery waits when the agent still holds a key").

### A retired address leaves a retired document (H3)

**Current rule.** Core defines interpretation of signed retirement evidence when a host supplies it; public serving is optional. The reference server keeps retired identity and unpairing records private. Dropped history may stop old verification, and no perpetual public archive is promised.

**Earlier rationale (superseded where it differs):**

> **Choice.** A retired address answers its agent-document fetch with a **retired document**: the same signed form, every key revoked, a `retired` timestamp, and the unpairing when an unpairing retired it. It answers `200`. A reader treats the address as ended for good, and messages signed before it retired keep verifying against its keys.
>
> **Alternatives.**
> - *Serve nothing, as the draft did.* Every past message from the agent stopped verifying, forwarded copies held elsewhere included, and anyone holding the unpairing signature could cause that. Readers could never obtain the unpairing, so after the domain lapsed a new registrant could set the address up again with fresh keys, replay the old `pairing`, and show a verified principal.
> - *A `410` answer carrying the unpairing* Section 4 reads every answer other than `200` as no document, so a `410` would end verification just as `404` does, and every reader would need a new rule before it helped.
>
> **Reason.** A `200` document with revoked keys is read correctly even by a reader that does not know `retired`: no key is valid now, and old messages still verify. The unpairing becomes obtainable from the one place every reader already looks. What it cannot do: a reader that never read the retired document while the old server served it learns nothing from it, which section 11.2 says.

### Lookups before any signature verifies are bounded (M1)

**Current rule.** Core requires bounded unauthenticated lookup work, including cold fetches and refetches. Mechanisms, network/domain buckets, PSL use, numeric caps and deployment-wide sharing are host choices.

**Earlier rationale (superseded where it differs):**

> **Choice.** A server MUST bound the resolutions and document fetches it makes before a signature verifies, per client network (the IPv4 address, or the IPv6 `/64`) and per registrable domain (by the Public Suffix List) of the name looked up, with refetches after a failed signature counted and cache hits free, and SHOULD cache failures as long as sections 3 and 4 allow. Past the bound a delivery or signal is `429`, and a signed read asks as nobody, as section 7.1 already treats a reader whose document cannot be read. The values are the server's own; the reference server's defaults are in its notes. (IPv4 is bounded by address rather than `/24`, following the reference server, which limits per address, so that clients behind one cloud provider's range do not share a bound; IPv6 by `/64`, because one host is routinely given a whole `/64`.)
>
> **Reason.** An earlier decision kept one rule in the protocol, no recipient lookup before the carrier's signature verifies, because it protects third parties. The lookups that must come first, finding the carrier, reading its document, reading the document of the agent a request names, protect third parties for the same reason: the sender chooses the domain, random subdomains defeat caching, and an agent document is refetched whenever a signature fails. Unbounded, any SIMON server is a lookup amplifier against a victim's DNS and web servers. The rule meets that bar and fixes no number. The carrier's signature is checked before any *recipient* lookup, and the lookups before it are what this bounds.

### A relation is listed only when its writer marked it (M2)

**Choice.** A seventh protocol header, `listed: yes`, on a relation, is its writer's consent to have it listed under the published message it names. Consent here means exactly that writer's signed opt-in, including disclosure of the relation's signed fields; no additional approval or consent handshake is required. The author's server lists only relations that carry it, and among those, what it chooses. A plain reply is never listed. The separate entitlement/approval policy for an acts-for claim is not an extra relation-listing condition.

**Alternatives.**
- *The author's server lists what it likes,* as an earlier design left it. A relation is a message to the author alone, so a server could publish a private reply, and with it the writer's signed `for` header, without the writer knowing.
- *A registry column saying which relation names are public,* as an earlier draft had. It was removed so that no server behaviour depends on the registry, and a relation's name does not say whether this writer wants it shown.
- *A registry header for the mark.* The author's server would then depend on the registry, which that decision ruled out.

**Reason.** Only the writer can consent to publishing what it wrote, and the consent has to be signed into the message, where every server and reader can see it, as ActivityPub's addressing to the public collection is. Which marked relations to list remains the author's server's own choice. The cost is one header that servers check for grammar and placement.

### Moving a domain loses no mail (M3)

**Current rule.** Authorized moves may retain genuine keys and original timestamps without inventing history. Routing/key mismatches trigger bounded fresh resolution and host-selected finite retry windows, never beyond the normal delivery deadline. The first cutoff persists across retries/restarts and is not extended. Availability still matters; there is no unconditional no-loss guarantee or mandatory public tombstone transfer.

**Earlier rationale (superseded where it differs):**

> **Choice.** Two answers a move can cause are retried for a bounded time instead of being permanent. A `400 invalid` naming `recipients` is retried with backoff for up to an hour, the recipients resolved again without cache before each attempt. A `403 bad_signature` is retried for an hour by a server that began serving its domain less than an hour ago. A receiver re-resolves without its cache before answering `403` at the envelope signature or `400` at the recipients, at most once a minute for one domain, and answers `503` when that re-resolution fails for now. A server that takes over a domain may carry the previous server's key entries over with their history unchanged, SHOULD carry over its retired documents, and never gives a retired address it knows of to an agent.
>
> **This amends the key-history rule.** That rule said "a server never lists a key as added earlier than it first published it". A server that carries a key over lists it with the `added` the previous server gave it, which is earlier than its own first publication. The amended rule: a key's `added` is when it was first published for its address, by this server or by the one that served the domain before it. History still only grows forward for the address, which is what that rule protects, and a reader that cached the old server's document can still catch a server that invents an earlier date.
>
> (Three gaps are closed: re-resolving only before `403` and retrying `400 recipients` once would still lose mail to a receiver's own stale cache at step 8; the uncached re-read must itself be bounded by the once-a-minute rule; and a `temporary` re-resolution needs an answer, `503`.)
>
> **Alternatives.**
> - *Leave both answers permanent,* as the draft did. For up to an hour after a move, the longest a resolver caches an answer, mail to and from the domain fails for good.
> - *Make every `403` retryable.* A forgery would then be retried for days, by its own sender, which costs only the sender, but it hides real configuration errors behind `pending`.
>
> **Reason.** A move is the one honest event that makes these answers wrong, and its window is bounded by the one-hour cache limit of section 3. Carrying key history over keeps old messages verifying after a move; without it, "`added` is when its server first published it" would have forced a new server to date every carried key at the move, which section 2.4 then forbids it ever to correct.

### The successor caps the whole current key document; claims timing is stated (M4)

**Current rule (a deliberate successor to the earlier counting rule).** The authoritative current whole document is bounded by 131072 final decoded signed bytes AND 32 TOTAL key entries, including retained revoked history. The earlier rule instead counted only keys valid at the reading time and retained more revoked entries within the byte bound. The successor deliberately bounds both parsed entries and bytes; it can therefore prune old revoked history sooner. A key whose revocation is still ahead of the reading clock remains active and must not be pruned to fit. Never silently drop an active key: refuse an unpublishable admission or fail publication closed. Overflow documents do not extend the bound.

**Historical verification consequence.** A cold reader that resolves the current domain and reads the current signed documents cannot verify an old signature once its required key history has been pruned. The reference inbox stores the message and signed claims, not an authenticated author/carrier document archive; the current SDK re-reads current documents. Previously authenticated keys can still support a local signature check if a recipient separately retains and trusts them, but neither that check nor unsigned convenience keys beside a published message prove historical DNS state, completeness or a signing time. A private or removed retirement document likewise leaves a cold reader without evidence. No perpetual old-message verification mechanism is implemented or promised. If a product needs independently verifiable old messages after that evidence is gone, that remains an additional requirement and needs a separately selected evidence-retention design. Claims issued-at remains a separate unselected proposal.

**Earlier rationale (superseded where it differs):**

> **Choice.** A document holds at most 32 keys not yet revoked at the time of reading, that is whose `revoked` is `null` or later than that time; entries revoked by then do not count, and only the document's size bounds them. An entry whose `revoked` is more than 300 seconds after the time of reading makes the document unreadable, because a server never sets a revocation in the future. (Counting only entries whose `revoked` is `null` would be wrong: a thousand keys with `revoked` in 2099 would all be valid now, count for nothing, and be tried by every verifier.) Section 2.4 says that dropping a revoked key ends verification of everything it signed. Section 6.2 says that claims carry no time of their own, so a key valid in a message's window can sign claims for it later, and a stolen server key revoked later can still sign claims for messages dated before its revocation, until its server stops listing it.
>
> **Reason.** Under a cap on every entry, a key history that reached 32 forced the server to drop revoked keys, and so to end the verification of everything they signed, which is exactly what section 2.4 tells a recipient it can rely on. Verification work stays bounded: a verifier tries only keys valid at the moment in question, at most 32 are valid now, and the document's 131072 bytes bound how many older ones there can be. That bound is tight for post-quantum keys: `ml-dsa-65` entries are about 2.7 KB, so about 48 fit, which leaves room for about 16 revoked keys beside 32 active ones. A server that rotates post-quantum keys often will drop old ones sooner, with what that ends. The claims statement is the minimal safe change; the fix itself is the proposal below, which overlaps the open question "claims issuer and time".
>
> **Proposal, not in effect: claims gain their own issued-at time.** Open; nothing in the spec or the code does this.
> - `claimsSignature` would cover `{"claims","issuedAt","message"}`, where `issuedAt` is when the carrier signed the claims, no earlier than the message's `sentAt`.
> - A reader checks the claims with a key of the carrier valid at `issuedAt`, instead of at some moment of the delivery window. In an envelope, `issuedAt` falls within the window; beside a published message, it may be any later time.
> - What it buys: the author's server can sign a post's claims again whenever they change, with its current key, which the erasure story of section 12 needs (a principal's identifier carried as a claim, dropped or replaced later). A key revoked at a moment `R` can no longer sign claims dated at or after `R`.
> - What it does not buy: a thief can still date claims before the key's revocation, as it can date messages; only a transparency log would catch that (section 12).
> - The cost: one more member in the claims signature, so a new signing form and new vectors, and a wire change for every server that makes or checks claims.

### A failed TXT lookup is final (M5)

**Choice.** The well-known answer is tried only when the TXT lookup answered and found no simon record. A TXT lookup that ends `temporary` ends resolution `temporary`.

**Reason.** Section 3 did not say, and an implementation that fell back would let anyone who can drop TXT answers route a domain to whoever runs its website, which was decided may not speak for the domain's mail. Treating the failure as final costs a delay while DNS recovers, which section 3 already bounds to 60 seconds of caching.

### Email authority: the lookup, the moment and alignment (M6)

**Current rule.** Use existing email-domain DNS authorization of the attesting carrier, with documented entitlement/approval and DNS-authenticity safeguards. No new agents TXT field or universal alignment rule is selected. Stricter alignment is optional host/reader policy. Stored foreign judgments and current DNS do not establish historical authority.

**Earlier rationale (superseded where it differs):**

> **Choice.**
> - Whoever judges authority SHOULD take the TXT answer from DNSSEC validation, or confirm it from several vantage points.
> - Authority is judged when the message reaches the judge, and the judgement is kept: a later lookup never upgrades a claim already judged.
> - A domain SHOULD NOT alias `_simon` to a name it does not control.
> - Alignment, a claim counting as authoritative only when the identifier's domain is the agent's own or names the agent's domain in its simon record's `agents` field, moves from a MAY for readers to a SHOULD for whoever judges.
> - A reader that first sees a message long after delivery still judges against the records of that moment; this is left to the claims' issued-at proposal (M4).
>
> **Alternatives.**
> - *Judge at reading, every time.* A TXT record added later, by a domain's next registrant or by whoever takes over its DNS, would make old claims authoritative.
> - *Require DNSSEC.* Most domains do not sign their zones (see "Resolution").
> - *Leave alignment a MAY.* On a server hosting several domains, one tenant's agents then carry the server's authoritative claims about another tenant's addresses.
>
> **Reason.** Authority over email addresses rests on one TXT lookup, so that lookup deserves the defences section 11.1 recommends for routing, and a fixed moment of judgement. Alignment narrows authority and grants none.
>
> **Delegation keeps the custom-domain case.** Hosts put agents on their own domain: acme.com's people may have agents at host.example. Alignment alone would make the host's claims about acme.com addresses non-authoritative, though acme.com's TXT record names the host. So the identifier's domain can delegate, in the same TXT record: `v=simon1; server=https://simon.host.example; agents=host.example`. Authority still comes only from the TXT record, as already decided, and nothing in that decision is amended: the field only narrows, per domain, which agents a claim may be about. An old resolver ignores the field, as it ignores any field it does not know, and a malformed one is ignored too, so routing never depends on it. (Alignment as a SHOULD with no delegation would break the case.)
>
> **Late readers.** A rule that a reader judging more than 144 hours after `sentAt` treat a claim as not authoritative unless it judged it earlier was considered. That would void, for every stranger, the authority of a published post's claims six days after it was posted, which is what claims beside published messages are for. The issued-at time proposed under M4 is the better fix, because it lets the author's server re-sign current claims; until it is agreed, section 6.2 states the gap.

### How a carried message is checked (M7)

**Current rule.** Recognized inline carried messages require canonical padded base64, canonical JSON objects and common message invariants, with no inner signature verification, lookup, freshness or fetch. Unknown-version interiors stay opaque; eight levels are allowed and nine refused. Malformed recognized carriage is refused, not silently ignored.

**Earlier rationale (superseded where it differs):**

> **Choice.** A part typed `application/simon-message`, with or without parameters, carried inline, must decode to the canonical bytes of an object that meets items 1 to 3 of section 1's invariants (the signature, item 4, is a reader's to check), at most 8 deep, the directly carried message being depth 1. Anything else makes the carrying message `400 invalid`. A carried message of the version a server knows has its files checked; one of a version the server does not know is carried unchanged, and nothing inside it is looked into, for files, depth or form. (The check names items 1 to 3 and not "section 1's invariants", because those include the signature, which no server checks.) No server checks a carried message's signature.
>
> **Alternatives.**
> - *Look leniently and skip what does not parse,* as the reference server does: it parses without requiring canonical form, skips bytes that do not parse, and stops looking at depth 8 while accepting deeper messages. Unspecified, implementations split between `400` and `202` on the same message.
> - *Count a deeper or unknown-version message's files anyway.* A server cannot find files in a version it does not know without guessing at that version's members.
>
> **Reason.** The carried bytes are the author's own work, and section 5.3 already says they are canonical, so refusing malformed ones costs an honest author nothing and gives every server the same answer. Depth 8 is the reference server's existing bound, now a refusal instead of a silent stop, so no file goes uncounted. An unknown version follows section 1: servers carry what they do not know, applying only checks that do not depend on the version.

### A message's files are bounded in bytes (M8)

**Current rule.** Count each known file occurrence (at most 1024), use exact arithmetic for the total 32 × `partBytes` bound, and require consistent declared size for a repeated hash. Forwarding preserves part-count room but can still exceed the outer message byte limit.

**Earlier rationale (superseded where it differs):**

> **Choice.** The files a message names, its own and those of every message it carries inline, add up to at most 32 times `partBytes`, a fixed rule checked at deliver and at `send`.
>
> **Alternatives.**
> - *Let a receiver stop fetching at a cap of its own.* A sender within the minimums could then lose files without knowing, which breaks section 9's promise that such a sender is never refused for size.
> - *A new published limit.* It would add a fifth member to every server document, for a bound the existing limit already expresses.
>
> **Reason.** The minimums allowed 1024 files of 25 MiB each, about 25 GiB per message, which fetch on arrival then asks every receiver to download. Thirty-two times `partBytes` is what a message of 32 full parts already needs, so a forward of one still fits, and it makes section 7.2's figure true: a message to 100 servers is at most nearly 80 GiB served, which the draft stated while allowing 32 times that.

### One parts endpoint, dispatched by who asks (M9)

**Current rule.** Dispatch hosted-client versus foreign-reader semantics by public service/domain routing, never hidden account presence. Hosted invalid authentication has a minimal uniform `401`; foreign invalid signatures ask as nobody. Union independent held/delivery/publication grants; unrelated pending sources or audience-hook failures do not remove a valid grant.

**Earlier rationale (superseded where it differs):**

> **Choice.** `GET /simon/parts/<sha256>` tells its caller by the request's signature. An agent the server hosts gets the client API's rules and answers (`401`, `503` while a fetch is underway), and also the files of published messages on the server it may read. Another server, asking with `simon-server`, gets the files of messages delivered to it. Anyone else gets the files of published messages it may read. Every refusal outside the first kind is the same `404`.
>
> **Reason.** Section 7.2 answered every refusal `404` while CLIENT.md gave `401` and `503` on the same path, and a local agent admitted to a local post's audience could fetch its files under one and not the other. The client API's answers tell an agent only about its own requests, so they stay; everything a stranger can see stays one `404`.

### Inbox cursors become visible in order (M10)

**Current rule.** The ordering requirement remains; crash, replay, late-writer and fencing behaviour is for a store to establish.

**Earlier rationale (superseded where it differs):**

> **Choice.** A server never shows an inbox entry at or below a cursor it has already returned. A server with concurrent writers holds an entry back until the entries below it are visible, or returns a safe high-water mark as the cursor.
>
> **Reason.** The inbox is read by continuing from the last cursor. With several writers, entry N+1 can become visible before N; an agent that read past N+1 then never sees N. Stating the requirement lets a store choose how to meet it, as IMAP requires of its UIDs, which only ever ascend (RFC 9051).

### Stale text brought in line with the decisions (M11)

**Current rule.** Received signals appear in `sync` for at most five minutes, the bound section 6.4 defers to, and the reference server holds each that long and passes it to its extensions (REFERENCE-SERVER.md, "Signals"). The signing string has eight lines. Fair sharing between carriers is reference-server policy, not a MUST. Dropped as protocol rules: a required text block, signals only between parties who had both written, bounds stated as requirements, Unicode 17.0, public relation listings and fair fetching.

### Low findings (L1 to L9)

Each is a statement the draft left open or got slightly wrong; none changes a decision.
- **L1. The signing string's origin and target.** The origin line is the serialised origin, so `HTTPS://X/` in a record signs as `https://x`; the `simon-server` header carries the same form. The target line is the request line's raw bytes, checked before any decoding, and an address in a path percent-encodes exactly the characters that are not RFC 3986 `pchar`, with upper-case hex.
- **L2. Rosters.** A newcomer that lacks the root starts from the latest `add` naming it, in both PROTOCOL.md section 5.6 and the registry, which had said it two ways. That a removed member can backdate an `add` is stated as a known limit, not fixed: it depends on who may change a roster, which is an open question.
- **L3. Timing of gated reads.** A server SHOULD read a signed reader's document whether or not the message asked for exists or has an audience.
- **L4. `authoritative` in received claims** is dropped from the judged claims only; the signed claims keep it byte for byte, or their signature would fail.
- **L5. Nonces.** One rule: a nonce is kept while its request's timestamp is within the 300-second window, at most 600 seconds after it is seen. Section 8 and section 11.2 had said 600 seconds and "until the timestamp leaves the window".
- **L6. Revocations are neither backdated nor set ahead.** A server sets `revoked` to when it first serves the revocation, never earlier and never more than 300 seconds later, so a revocation never withdraws signatures already made, and a reader refuses a document whose `revoked` lies more than 300 seconds in the future (which also closes the cap bypass under M4). The client-credentials text already revoked "at the time of the call, and never earlier".
- **L7. Part members are open,** as section 5.3 says; the closed-set rationale above now says it covers a message's top-level members only.
- **L8. The registry.** "No server behaviour depends on it" was not quite true: a receiving server judges the `identifier` claim, and readers follow the relation marks. Section 10 and the registry now name those entries.
- **L9. Smaller gaps.** `GET /simon/sent/<id>` answers `404` for a message the agent did not write, as for an unknown one. Size limits apply to decoded bytes, so a compressed answer cannot exceed them. A server signs the claims of a message written on it, so `signedClaims` is present whenever `claims` is.

### Further corrections

**Current rule.** These earlier proposals were subsequently reconciled: dedicated recovery; 32 total key entries and 128 KiB; no new agents TXT or universal alignment; optional public retirement evidence with private reference-server records; strict carried and exact aggregate checks; durable same-author suppression. Unselected roster, wire-version and claims-issuer/time changes remain held.

**Earlier rationale (superseded where it differs):**

> Fourteen further problems were found in these fixes. Those that changed a choice are recorded in the entries above (register codes and the status read under "Recovery waits"; the key cap; carried messages; domain moves and the key-history amendment; delegation and late readers under M6; the lookup bound's definitions). The rest:
> - **The unpairing as a linking oracle.** A published unpairing can be tested against candidate principal keys. Section 12 says so; a key made for each pairing is the answer it already gave.
> - **Retracted listed relations.** The author's server SHOULD stop listing a relation its writer retracts. It reads the registry's `retract` for that, which section 10 now names among the registry's few server-facing entries.
> - **Vector coverage.** The audience line said every offline-testable rule has a vector; the rules added here do not yet. Section 15 lists them until they do.
> - **Nits.** The registry lists `retired` and `unpairing` as document members, and "Parts" above says per source the way section 7.2 now does.
