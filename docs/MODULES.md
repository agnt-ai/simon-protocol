# Optional server modules (draft)

Things a server may do beyond the protocol, specified so that two servers that do them do them the same way. None is required, none is in a profile ([CORE.md](CORE.md#conformance-and-profiles)), and none changes the core: a module is built on a server's extension seam, and a server without it still federates with every other. Each section says what the module does, the rules it keeps, and how it is tested.

| Module | In short | Precedent |
| --- | --- | --- |
| [Bridges](#1-bridges) | Reach people and agents outside SIMON: email, A2A, later SMS. | Matrix application services |
| [Custom domains](#2-custom-domains) | A host serves a customer's own domain. | Google Workspace, ACME DNS-01 |
| [Lists, relays and backups](#3-lists-relays-and-backups) | One address that reaches many; more than one server per domain. | Mailing lists, MX, SVCB |
| [Mobile push](#4-mobile-push) | Wake a phone app without giving the push service any content. | Matrix push gateways, Web Push |
| [Abuse](#5-abuse) | Limits that scale with reputation, shared lists, invites. | Email reputation, DNSBLs |
| [Key transparency](#6-key-transparency) | A public log of every agent's keys, so backdating shows. | Certificate Transparency, IETF KEYTRANS |

## 1. Bridges

A bridge carries messages between SIMON and another network, the way a Matrix application service bridges a homeserver to IRC or Slack: it registers the addresses it is responsible for, the server hands it what is addressed to them, and it acts as those addresses. The outside world gets **puppets**: SIMON addresses that stand for someone outside.

**What every bridge does.**
- **It owns a namespace.** A bridge is configured with a domain, or a pattern of local parts on one, whose addresses are its puppets (`e-7f3k2q@bridge.example.net`). The server routes to the bridge every message for an address in it, and every recipient it cannot route because no server serves its domain (the basic server's `on.unroutable` hook).
- **A puppet is a solo agent** with its own key, which the bridge holds. Its messages are signed by that key, so readers verify them as they verify any message. A puppet never carries a `for` header: the outside person never paired with it.
- **It says who it stands for, as its word.** A puppet's messages carry the outside identity in a registry header (`email-from` for email; `a2a-agent` for A2A) and, when the bridge verified it, an `identifier` claim. Any agent can write those headers, so a reader shows the outside identity as *who the author says it relays for*, and as an identity only when an `identifier` claim backs it from a carrier the reader trusts for that identifier. That claim is never authoritative, since the outside identity's domain does not name the bridge (PROTOCOL.md 6.2).
- **One puppet per outside identity,** per bridge, for good: `bob@example.org` is always the same puppet address there, so a conversation with Bob keeps one counterpart.
- **Replies route by themselves.** A reply to a puppet goes to the bridge, which sends it on outside. No reply tokens are needed for messages written in SIMON; tokens remain only where the outside network needs them.
- **It sends nothing anonymous.** A bridge relays outward only for an agent whose principal the host verified by email or phone, or approved some other way. A key principal is not enough on its own, since anyone can make a key. It limits outward relays per principal and per day.
- **It never changes the core.** A bridged message is an ordinary message, signed by an ordinary key.

**The email bridge.**
- **Outward:** a message to `bob@example.org`, whose domain names no SIMON server, is sent as email from the host's domain. The text part is the body, content-addressed parts become attachments, and `subject` is the subject. The email's `From` names the author, and its `Reply-To` is an address on the bridge's domain that maps to the author and the conversation, so Bob's answer reaches the author's agent and no one else. The email carries `SIMON-Agent` (registry) naming the sender.
- **Back:** Bob's reply arrives at the author as a message from Bob's puppet, with `email-from: bob@example.org`, in reply to the original (`inReplyTo` from the email's `In-Reply-To`). The bridge checks the reply's DMARC alignment as it does inward mail: it adds the `identifier` claim only when the reply aligns, so a forged reply reaches the author as unverified. The conversation's roster still names `bob@example.org`, as the author wrote it (PROTOCOL.md 5.6); a reader treats the puppet that carries `email-from: bob@example.org` as that member's voice, and a reply to the conversation reaches Bob through the bridge either way.
- **Inward:** email to a SIMON address on a host that runs the bridge arrives the same way, from the sender's puppet. A host checks DMARC alignment before it claims the sender's address (`identifier`), and passes mail that fails as unverified.
- **Abuse:** outward mail counts against the host's sending reputation, so the bridge applies the host's limits per principal, per destination and in total, and refuses premium or unknown destinations by default.

**The A2A bridge.** A2A agents are reached by calling their HTTP endpoint, found from an agent card. The bridge:
- gives each A2A agent it reaches a puppet, and sends a SIMON message to it as an A2A `message/send`, with text and file parts carried over and the SIMON message id kept as context;
- returns the A2A agent's answers, and its task's status updates, as messages from the puppet in reply;
- offers each SIMON agent that opts in as an A2A agent: an agent card served by the bridge, whose calls become messages to that agent.

A2A answers are not signed by their author, so a puppet's message says only that the bridge received it from that endpoint, over TLS.

**SMS** follows the email bridge's shape when it comes, with per-session, per-person and global budgets from the first day, and no premium-rate destinations.

**Tested by:** the bridge's own suite (outward, back, inward, refusal of key-only principals, limits), and the conformance suite run against the host with the bridge on, which must pass unchanged.

## 2. Custom domains

A host serves `acme.com` for a customer, as Google Workspace serves a company's mail. The protocol side already works: the customer publishes `_simon.acme.com TXT "v=simon1; server=https://simon.host.example"` and agents at `@acme.com` live on the host. This module specifies the host's side.

1. **Verify control.** The host gives the customer a token, and the customer puts it in the domain's own record, as a field the protocol ignores (PROTOCOL.md 3): `_simon.acme.com TXT "v=simon1; server=https://simon.host.example; tenant=<token>"`. One record then routes the domain and names its customer, as ACME's DNS-01 challenge proves control. The host provisions the domain only when it sees the token, so no customer can claim another's domain on a shared host.
2. **Route by TXT, never by the website.** The host asks the customer to publish the `_simon` TXT record, not a well-known file, because only the TXT record grants authority over the domain's email addresses (PROTOCOL.md 6.2).
3. **Names belong to the customer.** On a provisioned domain, only the customer's administrators may create addresses. The host's default for any domain it serves but did not verify is to refuse new names.
4. **Claims stay aligned.** The host makes `acts-for` and `identifier` claims about identifiers on `acme.com` only for agents of the customer that verified `acme.com`. Another tenant's agents never get them, though the server is the same.
5. **Leaving.** When the customer leaves, or the record has named another server or no tenant for 30 days in a row, the host stops serving the domain: its agents' documents, published messages and parts go, and its addresses are retired, never handed to anyone else. Until then a missing or changed record is treated as an outage and the customer is told, so a DNS mistake never retires anyone.

**Tested by:** a suite with two tenants on one host, checking that neither can provision, name or claim on the other's domain.

## 3. Lists, relays and backups

**Lists.** A list is an agent, solo or paired with the organisation that runs it, at an address such as `team@lists.example.com`. A member writes to the list; the list sends each message on to the members from its own address, as a `forward` (registry): the original travels whole as an `application/simon-message` part, and its carried claims as `application/simon-claims+json`. Readers verify the original author's signature against that author's own keys, so the list cannot forge what a member wrote, and the list's own signature says who carried it. This is forwarding that stays verifiable, as encapsulating the original (`message/rfc822`) is for email, where ARC (RFC 8617) can only carry the forwarder's word about it. Membership, moderation and archives are the list's own business.

**Backups and relays.** A domain names exactly one server today, and the carrier of a message is always the server of its author's domain (PROTOCOL.md 6.1). A backup server, such as an MX record of lower priority, therefore needs a change in the core:
- an SVCB record (RFC 9460), advertised as a successor resolution mechanism (PROTOCOL.md section 1), naming several servers with priorities;
- a way for a backup to queue envelopes for its primary without becoming their carrier.

This module will specify both once the core reserves the mechanism. Until then a host gets availability inside its one origin: load balancers, several regions, one name.

## 4. Mobile push

A phone app cannot hold a connection open, so the server wakes it through the platform's push service (Apple's APNs, Google's FCM), as a Matrix homeserver does through a push gateway.

- **The app's maker runs a push gateway,** a small service that holds the app's platform credentials.
- **The app subscribes the gateway** with the agent's webhooks (CLIENT.md, "sync"), through its own grant or key. The gateway passes the server's verification code to the app over the platform's push, and the app returns it with `POST /simon/webhooks/<id>/verify`; the gateway holds no grant. It checks each signed post against the server's document and turns it into a platform notification.
- **No content leaves the server.** The post says only that something changed, and the notification carries only "new mail". The app wakes, connects to the server, and syncs. Apple and Google learn that something arrived, never what or from whom.
- An app that wants to show a sender's name before it is opened fetches it itself when woken, on the device, never through the gateway or the push service.

**Tested by:** the webhooks' checks, and a gateway test that nothing but that change reaches the push service.

## 5. Abuse

The protocol gives attribution: every message is signed by its author and carried by the author's domain's server, so refusals and limits can be aimed. What servers do with that is policy (PROTOCOL.md section 14). This section is guidance, so that servers keep what works and drop what doesn't, rather than copying the reference server's defaults.

- **Key reputation on the right unit.** Count by carrier origin and by **organisational domain** (the registered domain under the Public Suffix List, as DMARC does), never by the full domain, which costs nothing to multiply. Count lookups per `/64` of IPv6 and, with a larger allowance, per `/48`, since one `/48` holds 65,536 `/64`s.
- **Limits that grow with trust.** A new carrier gets small budgets for lookups, deliveries and fetched bytes. A carrier that has delivered accepted mail for weeks gets more. The reference defaults are for a server under attack, and throttle a large, honest carrier if copied as they are.
- **Fair shares.** Shared work, such as part fetches and resolution, is shared per carrier in turn, so one slow carrier never starves the others.
- **Trusted carriers** (whose non-authoritative claims a server shows) are chosen per identifier domain, not wholesale: "trust X for claims about `@corp.com`", not "trust X". A server publishes its list, so its agents know whose word they are given.
- **Shared lists.** A blocklist or allowlist that several servers use is a document a list operator publishes and signs, entries naming carrier origins or organisational domains with a reason and an expiry. Servers choose their lists; no list is built in.
- **Invites.** An invite is a one-time code a recipient's server issues and a sender passes as the `invite` hint (registry). It admits one message and its repeats, and is checked only by the server that issued it.
- **Blocks hold everywhere.** A block applies to every path a message can take: direct, released after a hold, or through an introduction.

## 6. Key transparency

Every signature is only as good as the author's server's record of when each key was valid. A server can backdate a key it adds, and a forgery made with it verifies for good. The core forbids it (PROTOCOL.md 2.4, "History only grows forward"), but only a reader that cached the old document can tell. A transparency log lets anyone tell.

- **The log** is append-only and public, as Certificate Transparency's logs are (RFC 9162): each entry is an agent document as a server served it, with the time the log saw it. Servers submit a document within an hour of serving it, and monitors check that no key's `added` is more than that hour earlier than the first time any log saw it, and that no revocation moves back. A new key still works at once (PROTOCOL.md 4); the log catches backdating, not use.
- **Servers submit** each new version of each agent document, and receive a signed timestamp they may serve in the document (a registry member, `transparency`).
- **Readers may require it** for messages that matter: a commitment is accepted only when the key that signed it was logged before the message's `sentAt`.
- **No vendor runs it alone.** Logs, like CT logs, are run by several independent operators, and a neutral home coordinates them (ROADMAP.md, "Governance"). IETF KEYTRANS is the work to follow.

Until logs exist, the core's monotonic history and readers' caches are the defence, and section 12 of the protocol says plainly what a signature does not prove.
