# SIMON: Signed Messages Between Agents at Addresses

The SIMON Protocol maintainers

First cut, 27 October 2026. Describes SIMON 1 (wire `v:1`), a public draft, as specified in `spec/protocol.md` [1]. Where this paper and the specification differ, the specification governs.

## Abstract

Software agents that act for different people and organizations need to exchange messages without sharing an operator. SIMON is a protocol for this. An agent has an address `name@domain`; the domain names its server in DNS; servers carry messages for one another by store and forward, so neither agent need be online when the other writes. A message is one canonical JSON object whose identifier is the SHA-256 hash of its content and which carries its author's signature, checked by every receiving server against keys that the author's domain publishes. A thread is the chain of replies. An agent speaks for no one or for exactly one principal, and the message itself carries whatever evidence supports that principal. We state the security properties the design provides, the adversaries each holds against, and what lies outside them, including confidentiality, which version 1 does not provide.

## 1. The problem

Agents increasingly act for the people and organizations that run them: they schedule, negotiate, buy and answer. Two such agents rarely share an operator. An assistant run by one company for one person must reach an assistant run by another company for someone else, and the exchange must work as correspondence works. One side writes when it is ready, the other reads when it is able, and afterwards each can show what the other said.

We take the requirements to be these, in order of priority, in the manner of the goals that shaped the Internet protocols [2]:

1. **Stable addresses.** An agent is reached at a name that outlives its process, its machine and its keys, and that its correspondents can keep.
2. **No common operator.** Anyone may run a server for addresses at a domain they control. No registry, relay or directory stands between two servers.
3. **Asynchrony.** Neither agent need be online when the other writes. Delivery completes or fails within a stated time.
4. **Attribution.** Any reader of a message, including a third party who obtains a copy later, can check which key signed exactly these bytes, and can tell what evidence, if any, supports the statement that the agent speaks for a particular person or organization.
5. **Indifference to content.** A server routes, stores, delivers and verifies a message without understanding it.

Internet mail meets the first three and has met them at the scale of the Internet for four decades [3]. It does not meet the fourth: a DKIM signature is optional, attests to a domain rather than an author, and breaks when a message is modified in transit [4]. Protocols built for agents meet the fourth in part and the first three not at all. In A2A one agent calls another's endpoint, so the callee must be reachable when called [5]; MCP connects a model to tools and data rather than to another party [6].

SIMON keeps the architecture of mail and adds one thing to it: every message carries its author's signature, and every receiving server checks that signature before it accepts the message. The rest of the design follows from keeping that addition, and little else, in the core. A feature enters the core only when it has existed for decades in some form and adding it later would force every server to change. Everything else is a header, a block type or a relation name in a registry that only readers interpret. Nothing in the core concerns artificial intelligence. An agent is a sender.

## 2. Design

### 2.1 Notation

`C(x)` is the canonical JSON encoding of `x` (section 2.4). `H` is SHA-256, written as 64 lower-case hexadecimal digits where it names something. `m∖s` is a message `m` without its `signature` member. `Sign_k(c, b)` is a signature by key `k` over the ASCII context string `c`, one newline, and the bytes `b`. Each kind of signed object has its own context (`SIMON-MESSAGE`, `SIMON-ENVELOPE`, `SIMON-CLAIMS`, `SIMON-AGENT`, `SIMON-PAIR` and others). No context followed by a newline is a prefix of another, and no variable line can contain a newline, so no signature made for one purpose verifies for another [1, Appendix A].

### 2.2 Addresses

An address is `local@domain`, the only thing the protocol routes to. The domain is an ASCII DNS name; an internationalized domain is written as its A-labels. In version 1 messages the local part is ASCII, with the atom characters of Internet mail and dots between atoms, and inside a message an address is written in lower case, so that one message has one form and one identifier.

The invariant that binds every version is wider: a local part is 1 to 64 bytes of UTF-8 with no `@`, space, ASCII capital or control character. A later version may admit non-ASCII local parts without any change to routing. Unicode normalization is deliberately not part of the invariant, because whether a string is normalized depends on the Unicode tables a runtime carries, and two routers must never disagree about an address.

### 2.3 Servers and keys

A domain names its server in one of two ways, tried in this order:

```
_simon.<domain>  TXT  "v=simon1; server=https://<host>"
GET https://<domain>/.well-known/simon            {"server":"https://<host>"}
```

Resolution ends in one of three outcomes: a server, no server, or try again. A temporary failure of the TXT lookup ends resolution as *try again* without consulting the well-known answer, and *try again* is never cached or read as *no server*; otherwise whoever can drop DNS answers could route a domain to whoever runs its website. The outcome records which method named the server, because only the TXT record grants authority over the domain's email addresses (section 3.3). A domain names exactly one server, with no priority list and no backup.

A server publishes two kinds of document, without authentication, cacheable for at most ten minutes. The *server document* lists the server's keys, the algorithms it verifies, and its limits. The *agent document* lists one agent's keys and is signed by a server key. Each key entry carries `added` and `revoked`; a key is *valid at* a moment `t` when `added` is at most 300 seconds after `t` and `revoked` is empty or later than `t`. History grows only forward: a revocation takes effect when first published, and is never backdated, scheduled ahead or withdrawn. Documents are unauthenticated on purpose, since requiring a signed request to fetch the key that verifies signed requests is a deadlock. A reader obtains an agent's document only from the server the agent's domain resolves to. The document says that an agent exists and what its keys are, and nothing about whom it speaks for.

A key is a token, an algorithm name and the raw public key: `ed25519:11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo`. Every implementation implements `ed25519` [7], verified strictly (the cofactorless equation, `S` below the group order, neither the key nor `R` of small order) so that every verifier accepts exactly the same signatures [8]. An implementation may implement `ml-dsa-65` [9], and then advertises it. A signature does not name its algorithm: a verifier tries each of the signer's valid keys whose algorithm it implements and skips the rest. A signer whose every valid key is of an algorithm the verifier lacks cannot be verified by it, and the verifier fails explicitly rather than accept weaker evidence. Servers sign what they send one another with `ed25519` keys.

### 2.4 The message

The message is the protocol's only object:

```json
{"from":"ada@example.com","headers":{"for":"mailto:alice@example.org","subject":"Thursday"},
 "inReplyTo":null,"parts":[{"data":"Does **3pm** work?","type":"text/markdown; variant=GFM"}],
 "sentAt":"2026-10-14T21:00:00Z","to":["bob@example.net"],"v":1,"signature":"<base64url>"}
```

Version 1 defines exactly eight members, all required: `v`, `from`, `to`, `inReplyTo`, `parts`, `headers`, `sentAt` and `signature`. A message is transmitted and stored as canonical JSON: RFC 8785 [10] restricted to integers within ±(2^53 − 1), so that nothing needs floating point, with keys sorted by UTF-16 code units, nesting at most 64 deep, no whitespace, and one escape for each character that needs one. (The example is broken into lines for the page.) A server refuses a message that is not already canonical and returns its canonical form, so a difference in encoding is caught at the first hop. Then

```
id(m) = H( C(m∖s) )
s     = Sign_k( "SIMON-MESSAGE", C(m∖s) )
```

where `k` is a key of `from` valid at `sentAt`. The identifier commits to every member but the signature, `inReplyTo` among them, so a reply names the exact content it answers.

`parts` is an ordered list of 0 to 32 *blocks*, each typed by a media type, carrying data inline or naming bytes by `sha256` and `size`. No block is required. `headers` maps at most 32 names to strings. A reader ignores a header it does not know unless the message lists it in `critical`, in which case the reader presents the message as not understood. The protocol names eight headers (`for`, `pairing`, `succession`, `critical`, `rel`, `feed`, `audience`, `listed`) and every server checks their grammar. Any other name without a dot belongs to the registry; anyone else names a header under a domain it controls, in reversed label order, as `com.example.approve`.

Five things are frozen for every version: the message is canonical JSON; it has `v`, `from`, `to`, `sentAt` and `signature`; the identifier rule; the signature rule; and how a server finds another and posts an envelope to it. A server routes a message of a version it does not know, applying only the checks that do not depend on the version. An agent's own server refuses to accept from its agent a version it does not implement, and a reader presents such a message as not understood. Carriers pass along what they do not understand; this is what let SMTP and HTTP last, and what QUIC states as its version-independent invariants [11].

### 2.5 Delivery

An agent submits a signed message to its own server through the client interface [12], which checks the version, the signature, the agent's principal (section 3) and a `sentAt` at most 24 hours old. The author's server resolves each recipient's domain and posts one *envelope* to each server that serves some of the recipients:

```
  agent A              server of a.example                   server of b.example          agent B
  signs m --submit-->  signs envelope E    --POST deliver-->  resolves a.example;           reads its
                       (m, server,                            checks E with a key of        inbox when
                        recipients,                           a.example's server;           it is able
                        claims, hints)                        checks m with A's key
                       retries until                          valid at m.sentAt;
                       the deadline                           answers 202; stores m
                                                              once per (id, recipient)
```

The envelope holds the message; `server`, the origin of the receiving server; `recipients`, the addresses in `to` that server serves; optional *claims* about the author (section 3.3); and optional per-recipient *hints*. The sending server signs it under `SIMON-ENVELOPE`. Because the receiving server and recipients are signed, an envelope cannot be replayed to another server or stretched to other recipients. The receiver checks the envelope with a key of the server that the `from` domain resolves to, so the carrier of a message is always the server of its author's domain. Relays, forwarders, backup servers and list exploders cannot carry a message on another domain's behalf.

A receiving server checks, in a recommended order: the body's size, the envelope's shape, the message's canonical form and version rules, that the envelope is addressed to itself, the resolution of the author's domain, the carrier's signature, that it serves the recipients, whether the message is a repeat, its freshness, and the author's signature. Four dependencies are requirements: the body is bounded before it is parsed; the carrier's signature is verified before any work that depends on a recipient or a third party; a repeat is recognized before freshness is judged; and nothing is changed or accepted until every check passes. A valid message is answered `202` whether or not any recipient will see it. Policy is silent.

Delivery between servers is at least once, and into each recipient's inbox at most once per (id, recipient). Three constants set the windows: a send window of 24 hours, a delivery horizon of 144 hours after `sentAt`, and a clock skew of 300 seconds. A receiver accepts a message whose `sentAt` is at most 144 hours old and at most five minutes ahead, and recognizes repeats for 168 hours. The author's server never delivers before `sentAt`, retries `429` and `5xx` answers with backoff, does not retry other refusals (except two narrow cases that arise while a domain moves between servers), and stops at the earlier of five days after accepting the message and 143 hours after `sentAt`, so that no delivery is stale on arrival. Messages carry no order; agents recognize a message already seen by its identifier.

A file is a part named by `sha256` and `size`. The author's server serves it only from bytes held for the author of a message that names it, and only to those who received or may read such a message; knowing a hash is never permission. A recipient's server should copy files when a message arrives, not when it is read, since a fetch on reading tells the carrier when the message was read. Anything larger than the receiver's `partBytes` travels as a link. A separate call carries *signals* (typing, collected, read), sent only when an agent asks, droppable by any receiver, and never stored.

### 2.6 Threads

`inReplyTo` is the single pointer between messages: `null`, or the identifier of the message this one answers. A `rel` header says what kind of pointer it is, such as a reaction, an edit or a retraction, with names kept in the registry. Two rules bind every reader. A relation a reader does not know is shown as a reply. A relation that changes or withdraws a message, such as `edit` or `retract`, takes effect only when both messages have the same `from`; from anyone else it is an ordinary reply.

A conversation is a root message and every message whose chain of `inReplyTo` leads back to it, through replies and through relations that stay in their conversation; a forward, a quote or a comment points at a message without joining it [13]. Its identifier is the root's. There is no roster. Each message's `to` is its author's choice, a reply that reaches more or fewer people forks the conversation, as in mail and text messaging, and servers keep no conversation state. Since no message changes who is in a conversation, there is no membership to forge and nothing for servers to reconcile.

### 2.7 Extension

A reader ignores what it does not know, so the protocol grows without coordination: by headers (with `critical` where a reader must understand them), block types, relation names, signal types, claim types, signature algorithms as new key-token names, resolution methods advertised by the existing ones, and message versions routed on the invariants. A name enters the registry once two independent implementations use it. Optional *profiles* build on the core without changing it: a reader profile, conversations, publishing (messages with an empty `to` and an `audience` header, served by the author's server), and discovery. The core depends on none of them.

## 3. Principals

### 3.1 Solo and paired agents

An agent is one of two kinds, fixed for the life of its address. A *solo* agent speaks for no one, and its messages carry no `for` header. A *paired* agent speaks for exactly one *principal*, a person or an organization, named by one identifier that every message it sends carries as `for`: `mailto:` and an email address, `tel:` and an E.164 number, or `simon-key:` and a key token, for a principal who holds a key.

One agent and one identifier make one address. The same assistant working for someone's work email and for their personal email is two agents, with two addresses, two sets of keys and two inboxes. One inbox never holds two principals' messages, so no server or agent has to work out whom a message is for. That inference, made on every message by a system that serves many people from one place, is where data leaks between them. It is the confused deputy [14], removed by routing rather than by care. A retired address is never paired again.

### 3.2 What verifying a message proves

Verifying a message proves its author in a precise and limited sense: a key, which the server named by the author's domain lists for that address as valid at `sentAt`, signed exactly these bytes. It does not prove who holds the key; a hosted agent may have a signing service hold it, as mail providers hold DKIM keys. It does not prove that a human wrote the message. And by itself it proves nothing about the principal: a `for` header alone is the agent's word, as the From line of an email is.

### 3.3 Evidence for a principal

A reader treats a principal as verified only on one of two kinds of evidence, both carried with the message.

**A key principal's pairing.** The principal signs `SIMON-PAIR`, the agent's address, the identifier and a time `until`, and every message the agent sends carries `until` and that signature as its `pairing` header. Any reader can check it with the key named in `for`, trusting no server. A pairing counts before its `until` and at most 366 days before it, so no signature binds an address to a principal for more than about a year; the principal renews by signing a later `until`. A reader judges the pairing at `sentAt`, which the agent's own server also checked against its own clock. The principal ends a pairing by signing `SIMON-UNPAIR`, and the agent's server must then retire the address, whatever the agent's keys say. A principal moves to a new key by a *succession*: old and new keys both sign `SIMON-SUCCEED` with both identifiers, messages carry the chain, and a reader that knew any key in it may treat the new key as the same principal. Two successions from one key are a fork, and a reader that holds both links neither successor to that key. An unpairing signed by any key in the chain ends the agent.

A pairing proves that the key's holder consented to this address speaking for that key. It binds the address, not the agent's current key, so it survives rotation of the agent's keys, and survives their compromise until the principal unpairs, the pairing lapses or the address retires. It does not say who holds the principal's key, and it carries no scope; what an agent may do for its principal is left to applications.

**A carrier's claim.** An email or telephone principal signs nothing. The carrier, having verified the identifier under documented policy, typically by sending a code to it, attaches an `acts-for` claim and signs the claims for this message: `Sign("SIMON-CLAIMS", C({claims, message: id(m)}))`. The signed claims travel with the message into its recipients' inboxes, so a later reader can check them wherever the message goes. A claim is *authoritative* when its identifier is an email address whose domain names the carrier by its `_simon` TXT record: the domain's DNS speaks for the domain's mail, as with DKIM. The well-known answer grants no such authority, because whoever runs a domain's website need not run its mail. Every other claim, every claim about a telephone number among them, is the carrier's word about someone else's identifier; a receiving server presents it as verified only from carriers it chose to trust. A reader that relies on a claim repeats the judgement itself.

### 3.4 Identity modes

A message is therefore *identified* (`for` names an email address or telephone number), *pseudonymous* (`for` names a key), or *unattributed* (no `for`), and a reader can tell which from the message alone. The protocol never makes an agent pair, and a server never attaches a claim naming an identifier its agent did not choose to show. Anonymity is toward other agents, never toward the agent's own server.

## 4. Threat model and security properties

### 4.1 Adversaries and assumptions

The parties are agents, their principals, the servers that host them, and readers: any party that interprets a message, including a recipient's server and anyone who later holds a copy. We consider seven adversaries.

- **N**, the network: any party on the path between servers, or between a reader and a server.
- **D**, a DNS adversary: one who can make a server or reader believe a false answer about a domain, by position on its network, a poisoned resolver, or a hijacked route to the domain's name servers.
- **S**, a malicious, compromised or coerced server: the author's, a recipient's, or a third.
- **A**, a malicious agent, including one on its victim's own server, and a sender who writes to probe rather than to communicate.
- **K**, a thief of an agent's, a server's or a principal's key.
- **R**, the next registrant of a domain, or whoever later controls its DNS.
- **I**, an author of hostile content meant to steer the agent that reads it.

We assume that SHA-256 is collision and second-preimage resistant; that Ed25519 with strict verification and ML-DSA-65 are existentially unforgeable under chosen-message attack; that TLS 1.3, authenticated against the peer's origin, protects each connection; and that honest clocks agree within 300 seconds.

### 4.2 Properties

Each property is stated with whom it holds against, what it rests on, and where it stops. None has been proved in a formal model (section 4.5).

**P1. Authorship.** If a reader accepts `m` as verified, then a key `k`, listed for `from(m)` as valid at `sentAt(m)` in an agent document signed by the server that `from(m)`'s domain resolved to, signed exactly `C(m∖s)` under `SIMON-MESSAGE`, a context that signs nothing else.
*Holds against* N; against recipient servers and later holders, who cannot change a byte without breaking the signature and the identifier; against other agents, including those on the author's server, who do not hold `k`; and against every server but the author's, since keys are read only from the server the author's domain names. Strict verification means no two honest verifiers disagree about any signature [8].
*Rests on* the author's server's honesty about its agents' key histories, and on the DNS answer.
*Stops at* the author's server, which can list a key of its choosing with a false `added` and sign with it; at D (section 4.3); and at K, since a stolen key signs anything until revoked and can date messages before its revocation. Live delivery bounds the last, because a receiver refuses a message more than 144 hours old. Version 1 keeps no log of key histories, so only a reader that cached an earlier document can catch a server that rewrites one. A signature is transferable proof to anyone who can still obtain the authenticated key history; once a server stops listing a revoked key, a new reader cannot verify what it signed.

**P2. Content identity.** Any two parties holding the same message compute the same identifier, and a change to any member but the signature changes it. Because `inReplyTo` is signed content, a reply commits to the exact message it answers, and a conversation is linked by hashes of content.
*Holds against* every adversary, given SHA-256, which keeps a 128-bit margin against quantum search. Canonical form is unique and enforced at the first hop, so encodings do not drift between servers.
*Stops at* what an identifier names: content, not a signing event. It does not distinguish two valid signatures over the same content, which only a holder of the author's key can make. A reply proves only that its author knew an identifier, not that the earlier message exists or was received. No reader can know that it holds all of a conversation.

**P3. Carrier binding.** Every delivery is signed by the server of the author's domain, over an envelope naming the receiving server and the recipients. An envelope cannot be replayed to another server or used for other recipients; a replay to the same server is a repeat for 168 hours, storing nothing, and stale after 144. Claims are signed over the claims and the message identifier, so they stay bound to that message. Signed requests bind the method, the origin asked, the acting identity, the exact request target, a timestamp within 300 seconds, a nonce and the hash of the body.
*Holds against* N, A and every server but the carrier. Since only a domain's server can carry its messages, abuse is attributable to a domain and a server, and limits and refusals attach to an accountable party.
*Stops at* what an envelope says: which server carried a message, not that its agent wrote it, which is P1. By construction it excludes relays (section 6).

**P4. Delivery.** If the two servers can reach each other at some time before the deadline and the recipient's server admits the message, it enters each recipient's inbox once, with neither agent online. Otherwise the author's server stops at the deadline, and its agent sees, per destination server, whether delivery is pending, delivered or failed.
*Holds against* N, which can delay but not alter a delivery, and transient failure, which retries absorb.
*Stops at* the recipient's server, which may drop any message silently; at a domain whose single server is down past the deadline; and at order, which the protocol does not provide. A mistyped address receives no bounce.

**P5. Silence toward senders.** A receiving server answers every valid delivery `202`, whether a recipient accepted it, refused it or does not exist, and should do no recipient-dependent work before answering. A sender learns from delivery neither whether an address exists nor whether its holder refuses the sender. Signals likewise reveal nothing about recipients.
*Holds against* A.
*Stops at* agent documents, which are public and reveal that an address has an agent, though a server may decline to disclose agents and may limit lookups of absent addresses, refusing every address alike past the limit; at timing, where a server ignores the recommendation; and at file fetches, which reveal admission or reading unless a server fetches the files of every message it accepts soon after accepting it, as the reference server does.

**P6. Principal evidence.** A reader treats a principal as verified only with a pairing that verifies under the key in `for` and counts at `sentAt`, or with a carrier's claims signature that the reader judges authoritative or trusts.
*Holds against* A naming any identifier in `for`; against S, which cannot forge a key principal's consent; against anyone pasting a message or inbox entry, since claims are bound to the message identifier and re-judged by the reader; and against old consent outliving its purpose, which the 366-day limit bounds.
*Stops at* five things. A server that lies about its agent's keys can attach the agent's genuine pairing to messages it signs itself, because a pairing binds an address, not a key. R can present an old pairing with keys of its own, to readers that never learned of an unpairing, until its `until`. A stolen principal key can sign a rival succession, which readers that see both treat as a fork, and can unpair the agents; the safe end of a stolen principal key is the end of its agents. Claims carry no expiry, revocation or independent time of issue, so a carrier key valid at any moment of the delivery window can sign claims for that window later, and authority is judged against DNS when the judgement is made, not when the claim was issued. On a server hosting several domains, one domain's agents carry authoritative claims about another's addresses unless the reader requires, as DMARC does [15], that the identifier's domain be the agent's own. Nothing shows who holds a key, or whether a human is involved.

**P7. Safety of versions, algorithms and relations.** A new version number cannot step around a known version's rules: the agent's own server refuses a version it does not implement, and a reader presents one as not understood, saying nothing of its content or principal. A missing algorithm is an explicit failure, never a downgrade. An unknown header listed in `critical` stops a reader from acting. An edit or retraction by anyone but the author is shown as a reply and never applied, which is the lesson of forged Usenet cancels.
*Stops at* algorithm strength: an agent holding keys of two algorithms is as strong as the weaker, so retiring an algorithm means revoking its keys.

**P8. Bounded work.** Every input is bounded: sizes of messages, requests, signals and documents, counts of keys and parts, file aggregates, nesting depth and time windows. No recipient-dependent work precedes the carrier's signature, so one unsigned request cannot make a server contact a hundred domains. A server bounds the lookups that unauthenticated requests cause, follows no redirect, and connects to no private or link-local address unless configured to.
*Stops at* the lookups that verifying a carrier necessarily requires, which the protocol bounds without fixing a number, and at unsolicited messages from senders whose marginal cost is near zero. No postage, proof of work or global reputation is defined.

**P9. Content is data.** Everything in a message is written by someone else. An agent must not treat any of it as authorization from the one it acts for; a client library labels third-party text and parts with who wrote them; an interactive block is drawn by the reader, and choosing an option sends a new signed message rather than calling a URL or running code; keys come only from resolution, never from a party a message names.
*Holds against* I insofar as implementations follow these rules.
*Stops at* the model. Whether a model obeys a label is outside the protocol, which bounds what a message can cause structurally but does not prevent persuasion.

### 4.3 DNS

Every address meets its keys in DNS, whichever resolution method is tried first, since TLS authenticates the well-known host only after DNS has said where it is. Whoever can make a server believe a false answer can point a domain at a server of their own, which then publishes keys for its addresses. DKIM and web certificate issuance share this exposure [16]. The defences are layered. A server that validates DNSSEC treats a validation failure as *try again*, never as an answer, which for signed zones defeats attacks on the path and on resolvers. A server should resolve over an authenticated channel to resolvers it trusts. Confirming answers from several network locations defeats attacks local to one network; asking several resolvers from one host does not. A server should remember which of each domain's server keys it has seen sign, and hold deliveries when a newly resolved server publishes none of them or never signs with them. The test is possession: a remembered key that signs, not a listed public key, which anyone can copy. Control of a domain at its registrar is control of its addresses, and no protocol can tell it apart from ownership.

### 4.4 Out of scope

Version 1 provides no confidentiality from servers. The author's server sees everything its agents send, and each recipient's server sees what it carries, as mail servers do. Under end-to-end encryption servers would still see who wrote to whom, when and how much, and whoever runs an agent's model sees what the agent reads and writes, whatever any protocol does.

It provides no deniability. Every message is permanent, transferable proof that its author's key signed it. This is deliberate: agents that commit for people need attributable messages, and a deniable signature kind would be an extension.

It does not make key history trustworthy beyond the author's server (P1); make recovery safe, since recovery is the host's policy and whoever can recover an address controls its agent; isolate the pairs one operator's runtime serves; decide whom an agent may contact; or give rights to people a message mentions who are not party to it.

### 4.5 What has not been shown

These properties are argued informally from the specification's rules. No formal model of SIMON exists. Models in ProVerif or Tamarin of pairing, delivery, key continuity, recovery and grants are on the roadmap [17], and an external security review named them as what matters most before version 1 is declared stable. No independent cryptographic review has been made. The properties are claims to be checked, not results.

## 5. Related work

SIMON keeps the model of Internet mail, borrows mechanisms from federated systems, and sits beside, not on top of, the protocols built for agents.

| System | What SIMON shares | Where SIMON differs |
| --- | --- | --- |
| SMTP with SPF, DKIM, DMARC, ARC [3, 4, 15, 18, 19] | addresses at domains; servers found by DNS; store and forward; a domain's DNS authorizing keys; alignment | every message signed by its author, not optionally by a domain, and checked by every receiving server; messages never modified in transit; no relays, so no ARC |
| Matrix [20] | integer-only canonical JSON; server keys fetched unauthenticated; federation by domain | no rooms and no replicated state; Matrix events are signed by servers, SIMON messages by authors; no notaries |
| ActivityPub [21] | server-to-server delivery over HTTPS, signed in common deployments; addressing public posts | the agent, not its server, holds the signing key; key documents always unauthenticated; no vocabulary of activities |
| AT Protocol [22] | name resolution by a TXT record under an underscore label, then an HTTPS well-known path | no public repositories or relays; messages go to named recipients; identity is an address and its keys, not a DID |
| Nostr [23] | signed JSON events identified by a SHA-256 hash; `name@domain` through a well-known path (NIP-05) | a domain names one server that carries and authenticates delivery, retried to a deadline, rather than relays |
| XMPP [24, 25] | `local@domain`; federation between domain servers; domain authentication between servers | JSON over HTTPS; envelopes signed rather than dialled back; every message signed by its author |
| WebFinger [26] | looking up `name@domain` over HTTPS | one well-known answer per domain names the server; keys come from that server's agent document |
| DIDComm v2.1 [27] | signed messages between agents; delivery while the recipient is offline | no DIDs; the carrier is the author's domain's server, not a chosen mediator; no encryption in version 1 |
| A2A v1.0 [5] | independently operated agents; discovery at a well-known HTTPS path | A2A asks a reachable agent to run a task; SIMON stores and forwards signed messages between addresses |
| MCP [6] | the agent ecosystem | MCP connects a model to tools and data; an MCP server is one way for an agent to use SIMON |
| WIMSE, SPIFFE [28, 29] | cryptographic identity for software that acts | workload identity for service calls within and across trust domains; SIMON names agents at public addresses and carries principal evidence per message |
| MLS, MIMI [30, 31] | interoperable messaging; semantics of replies, reactions, edits, retractions | SIMON 1 is unencrypted; groups are a `to` list; MLS is the planned basis for encrypted groups |
| KEYTRANS, CONIKS [32, 33] | auditable key histories | SIMON 1 has no transparency log |

SIMON differs from mail chiefly in where the signature lives. SPF authorizes the hosts that send for a domain [18], DKIM lets a domain sign a message [4], and DMARC, now on the standards track [15], asks that the signing domain align with the visible author. Each binds a domain, not an author, and none is required. Lists that modify messages break DKIM, and ARC [19] adds intermediaries' signatures to carry results across them. SIMON makes the opposite trade: messages are never modified, so the author's signature always survives, and no intermediary can carry a message for another domain. Its rule for email authority is DKIM's.

Among federated systems, Matrix [20] replicates each room's state across servers and resolves conflicts by an algorithm revised more than once; SIMON keeps no shared state and has nothing to resolve. Nostr [23] makes the key the identity and treats relays as untrusted stores; SIMON makes the address the identity, so a correspondent has a stable name and delivery has a responsible party. The AT Protocol [22], now before an IETF working group [34], publishes signed public repositories; SIMON carries messages to named recipients. XMPP [24] established domain-federated addressing; SIMON adds a signature by the author.

A2A [5] and MCP [6] are maintained under the Linux Foundation's Agentic AI Foundation. A2A's unit is a task performed by a reachable agent over a live connection; SIMON's is a signed message to an address that may be offline. They compose: a task can run over a connection that a SIMON exchange arranged, and its outcome can be recorded as a message. DIDComm [27] is the nearest predecessor in purpose, resolving keys through DIDs where SIMON resolves them through the author's domain. WIMSE [28] and SPIFFE [29] identify workloads for authenticated service calls; SIMON's principal model is narrower and travels with each message. SIMON follows MIMI's content semantics [31] for replies, reactions, edits and retractions where they fit, so a bridge between the two maps them directly.

## 6. Limitations and future work

**No end-to-end encryption.** Servers read what they carry. The format anticipates encryption: an agent-document member `encryptionKeys` and a block type `application/simon-sealed` are reserved, servers carry a sealed message like any other, and a test vector shows one passing every server check. That shows carriage only. The planned profile uses HPKE [35] for one recipient, MLS [30] for groups, and hybrid post-quantum key agreement, because ciphertext kept for years is exposed to later decryption. Groups need an order for their changes and a way to distribute keys, which may need services the core lacks. The signature stays outside the ciphertext so servers still verify the author. The profile is to be written with outside implementers and cryptographers. Meanwhile a sender with confidential material sends a link to storage it controls.

**No key transparency.** A signature is as honest as the author's server's account of its keys (P1). A portable key log was considered for the core and rejected, since delivery does not need it and every implementer would carry it; it can be added as a document member. An open proposal would give claims their own time of issue, so a revoked carrier key could not sign claims dated after its revocation.

**Live sessions.** Store and forward is slow for negotiation in real time. The direction is an opt-in upgrade in which a signed message offers a live channel for one conversation and a signed reply accepts it, as SIP's offer and answer and XMPP's Jingle do. The message network stays the source of truth: anything that matters, such as an agreement, is sent as a message afterwards. This waits for cases where a round trip of seconds is too slow.

**Privacy and erasure.** A `mailto:` or `tel:` identifier in `for` is signed into every message the agent sends and cannot be removed from a copy without breaking its signature, its identifier and every reply after it. The remedy within version 1 is to name principals by keys, held for them by their host if need be, and to carry email addresses and telephone numbers as claims, which travel beside the message and are not signed into it. Erasing a person then erases the claims a host keeps, and nothing signed names them. Copies on other servers are theirs, and no erasure request reaches them.

**Topology.** A domain names one server with no backup, and an outage longer than the deadline loses what is undelivered. SVCB records [36], advertised by a successor resolution method, would add priority and failover. With no relays there are no list exploders, and each receiving server bounds how many addresses a message's `to` may hold, at least 100; larger audiences are published feeds, and large private groups await MLS.

**Verification over time.** Whether an old message still verifies depends on its author's server keeping the key history. The protocol promises the standard's longevity, not each message's, and defines no archival evidence format.

**Analysis.** Formal models, an independent cryptographic review, a conformance suite for readers, and a study of whether agents over-trust the principals messages claim all remain to be done (section 4.5).

## 7. Status

SIMON 1 is a public draft; its messages carry `"v":1`. Until it is declared stable any rule may change, except the invariants of section 2.4, which change only for an overwhelming reason.

There is one implementation: this repository's, in two forms, a basic server built on Node's standard library and SQLite, and an application template built on its extension points. The reference packages are in the 0.3 series. A Python client reproduces every test vector; it is a port maintained beside the JavaScript client by the same authors, not an independent implementation. The vectors are generated by this repository's reference library, which its server and conformance suite also import, so a mistake in that library would appear in all three; each vector is checked against the specification by review. The conformance suite tests servers configured for it, so it cannot test the transport rules on TLS, redirects and private addresses. Reader rules have vectors but no conformance suite yet. Trials between agents on separate machines across the public Internet exercised the reference implementation against itself, which shows that it works, not that the specification interoperates.

SIMON 1 will be declared stable when two independent implementations reproduce every test vector and pass the conformance suite against each other. Independent means written from the specification alone, by people outside the team that wrote the reference, in another language, with its own cryptographic bindings, and with a public log of every question the text did not answer. That criterion has not been met. No benchmarks or adoption figures are reported, because none have been measured in a form that can be reproduced.

## References

1. The SIMON Protocol: SIMON 1 (wire `v:1`). `spec/protocol.md`. https://github.com/agnt-ai/simon-protocol/blob/main/spec/protocol.md
2. D. D. Clark. The Design Philosophy of the DARPA Internet Protocols. ACM SIGCOMM, 1988. https://groups.csail.mit.edu/ana/Publications/PubPDFs/The%20design%20philosophy%20of%20the%20DARPA%20internet%20protocols.pdf
3. J. Klensin. Simple Mail Transfer Protocol. RFC 5321, 2008. https://www.rfc-editor.org/rfc/rfc5321
4. D. Crocker, T. Hansen, M. Kucherawy. DomainKeys Identified Mail (DKIM) Signatures. RFC 6376, 2011. https://www.rfc-editor.org/rfc/rfc6376
5. Agent2Agent (A2A) Protocol Specification, version 1.0, March 2026. https://a2a-protocol.org/latest/specification/ (summary: https://aaif.io/blog/a2a-v1-0-a-builder-s-guide-part-1-discovery-tasks-and-clients)
6. Model Context Protocol Specification, revision 2026-07-28. https://modelcontextprotocol.io/specification/2026-07-28
7. S. Josefsson, I. Liusvaara. Edwards-Curve Digital Signature Algorithm (EdDSA). RFC 8032, 2017. https://www.rfc-editor.org/rfc/rfc8032
8. K. Chalkias, F. Garillot, V. Nikolaenko. Taming the Many EdDSAs. Security Standardisation Research, 2020. https://eprint.iacr.org/2020/1244
9. NIST. Module-Lattice-Based Digital Signature Standard. FIPS 204, 2024. https://csrc.nist.gov/pubs/fips/204/final
10. A. Rundgren, B. Jordan, S. Erdtman. JSON Canonicalization Scheme (JCS). RFC 8785, 2020. https://www.rfc-editor.org/rfc/rfc8785
11. M. Thomson. Version-Independent Properties of QUIC. RFC 8999, 2021. https://www.rfc-editor.org/rfc/rfc8999
12. The SIMON client API. `spec/client.md`. https://github.com/agnt-ai/simon-protocol/blob/main/spec/client.md
13. SIMON conversations profile. `spec/profiles/conversations.md`. https://github.com/agnt-ai/simon-protocol/blob/main/spec/profiles/conversations.md
14. N. Hardy. The Confused Deputy (or why capabilities might have been invented). ACM SIGOPS Operating Systems Review 22(4), 1988. https://css.csail.mit.edu/6.566/2011/readings/confused-deputy.html
15. Domain-based Message Authentication, Reporting, and Conformance (DMARC). RFC 9989, May 2026. https://www.rfc-editor.org/rfc/rfc9989.html
16. H. Birge-Lee, Y. Sun, A. Edmundson, J. Rexford, P. Mittal. Bamboozling Certificate Authorities with BGP. USENIX Security, 2018. https://www.usenix.org/conference/usenixsecurity18/presentation/birge-lee
17. SIMON roadmap. `docs/roadmap.md`. https://github.com/agnt-ai/simon-protocol/blob/main/docs/roadmap.md
18. S. Kitterman. Sender Policy Framework (SPF). RFC 7208, 2014. https://www.rfc-editor.org/rfc/rfc7208
19. K. Andersen et al. The Authenticated Received Chain (ARC) Protocol. RFC 8617 (Experimental), 2019. https://www.rfc-editor.org/rfc/rfc8617
20. Matrix Specification. https://spec.matrix.org/latest/
21. C. Lemmer Webber, J. Tallon et al. ActivityPub. W3C Recommendation, 2018. https://www.w3.org/TR/activitypub/
22. AT Protocol specifications. https://atproto.com/specs/atp
23. Nostr Implementation Possibilities, NIP-01 (basic protocol) and NIP-05 (DNS-based identifiers). https://github.com/nostr-protocol/nips/blob/master/01.md ; https://github.com/nostr-protocol/nips/blob/master/05.md
24. P. Saint-Andre. Extensible Messaging and Presence Protocol (XMPP): Core. RFC 6120, 2011. https://www.rfc-editor.org/rfc/rfc6120
25. XEP-0220: Server Dialback. XMPP Standards Foundation. https://xmpp.org/extensions/xep-0220.html
26. P. Jones, G. Salgueiro, M. Jones, J. Smarr. WebFinger. RFC 7033, 2013. https://www.rfc-editor.org/rfc/rfc7033
27. Decentralized Identity Foundation. DIDComm Messaging v2.1. https://identity.foundation/didcomm-messaging/spec/v2.1/
28. IETF WIMSE Working Group. WIMSE Architecture, draft-ietf-wimse-arch-08, July 2026. https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/
29. SPIFFE: Secure Production Identity Framework for Everyone. https://github.com/spiffe/spiffe
30. R. Barnes et al. The Messaging Layer Security (MLS) Protocol. RFC 9420, 2023. https://www.rfc-editor.org/rfc/rfc9420
31. IETF MIMI Working Group. MIMI message content, draft-ietf-mimi-content-09, July 2026. https://datatracker.ietf.org/doc/draft-ietf-mimi-content/
32. IETF KEYTRANS Working Group. Key Transparency Protocol, draft-ietf-keytrans-protocol-05, July 2026. https://datatracker.ietf.org/doc/draft-ietf-keytrans-protocol/
33. M. S. Melara, A. Blankstein, J. Bonneau, E. W. Felten, M. J. Freedman. CONIKS: Bringing Key Transparency to End Users. USENIX Security, 2015. https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/melara
34. Bluesky. Kicking off the ATP Working Group at the IETF, April 2026. https://atproto.com/blog/kicking-off-the-atp-working-group
35. R. Barnes, K. Bhargavan, B. Lipp, C. Wood. Hybrid Public Key Encryption. RFC 9180, 2022. https://www.rfc-editor.org/rfc/rfc9180
36. B. Schwartz, M. Bishop, E. Nygren. Service Binding and Parameter Specification via the DNS (SVCB and HTTPS Resource Records). RFC 9460, 2023. https://www.rfc-editor.org/rfc/rfc9460
