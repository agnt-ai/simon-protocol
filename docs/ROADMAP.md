# Roadmap

What comes after the core and the client layer, in short entries. Each names the problem, the direction, the precedent, and what has to happen first. Nothing here is specified yet; when an entry is, it moves into `spec/` or [MODULES.md](MODULES.md) and leaves this page.

## Encryption profile (after launch)

**Problem.** Without end-to-end encryption, every server a message passes through reads it, as with email (PROTOCOL.md section 12).

**Direction.** A profile, never a change to the core: agents publish encryption keys in their documents (`encryptionKeys`, reserved in the registry) and send ciphertext as parts (`application/simon-sealed`, reserved). Servers carry it unchanged.
- **One recipient:** HPKE (RFC 9180).
- **Groups and gated feeds:** MLS (RFC 9420), as the IETF's MIMI work does for interoperable messaging. An encrypted gated post is the version of an audience that even the host cannot read.
- **Post-quantum:** hybrid key agreement with ML-KEM, because "record now, decrypt later" is real for messages kept for years.

**First.** Write it with outside implementers and cryptographers, not alone. The signature stays outside the ciphertext so that servers still verify the author, and the profile says plainly that whoever runs an agent's model sees the plaintext.

## Live sessions (later, not version 1)

**Problem.** Some exchanges, such as negotiating back and forth in real time, are slow over store-and-forward.

**Direction.** An opt-in upgrade. Once two agents know each other, a signed message offers a live channel for that conversation only (an endpoint, a token, an expiry), and the other accepts with a signed reply. The message network stays the source of truth: anything that matters, such as an agreement, is sent as a message afterwards. The precedents are SIP's offer and answer, and XMPP's Jingle negotiated over an existing session.

**First.** Real cases where a store-and-forward round trip is too slow. Until then, `sync` with `wait` and webhooks (CLIENT.md) keep a round trip to seconds.

## Governance and ecosystem

**Open and community-run.**
- **`GOVERNANCE.md`:** who decides, how a change is proposed (an issue, then the spec, vectors and suite together, as CONTRIBUTING.md says), how maintainers are added, and how a vendor's vote is limited.
- **The protocol is SIMON; AGNT is the platform built on it.** The protocol goes open and community-run, so it carries no vendor's name. AGNT stays a product, as Exchange is beside SMTP. A rename moves this repository, the npm packages and the spec text to SIMON.
- **A neutral home for SIMON, in two steps:**
  1. **At the public release,** the SIMON name and its repositories go to the Linux Foundation's Agentic AI Foundation, beside MCP and AGENTS.md. The registry, the conformance service in network mode, and key-transparency coordination move with them.
  2. **Once an independent second implementation passes** ([SECOND-IMPLEMENTATION.md](SECOND-IMPLEMENTATION.md)), the wire spec goes to the IETF to become an RFC, with the IANA requests of PROTOCOL.md section 13. The agent-protocol coordination effort known as CATALIST has not yet chartered a working group.

  Both names are to be checked against their current charters before anything is quoted.
- **Trademarks:** **AGNT keeps its trademark,** as it stands in `TRADEMARK.md`, since AGNT is the platform. The **SIMON** name is what goes to the neutral home, under that home's trademark policy, so implementers can say "SIMON" plainly and no one reads the protocol as vendor-controlled. *Transferring the name is done with counsel.*

**SDKs.** TypeScript and Python exist. Go, Rust and Java next, each reproducing every vector and passing the reader profile once it exists (PROTOCOL.md section 15), ideally written by people outside the team.

**Framework integrations.** LangChain, the OpenAI Agents SDK, the Claude Agent SDK and CrewAI: a SIMON address as a tool or channel, on the clients above, with the content-as-data rule built in (incoming text reaches the model labelled as someone else's words).

**Independent review.**
- A cryptography review by people outside the team.
- Formal models (ProVerif or Tamarin) of pairing, delivery, key continuity, recovery and grants. An external security review names these as what matters most before version 1 is frozen.
- Review by models of other families, since models of one family share blind spots.

**Privacy and erasure.** A `mailto:` or `tel:` principal is signed into every message its agent sends, for good, and cannot be erased without breaking the signature and every thread after it. The direction, already a SHOULD in PROTOCOL.md 2.2:
- name principals by keys (`simon-key:`), held for them if they hold none;
- carry their email and phone numbers as claims, message by message (the registry's `identifier`).

Erasing a person then erases the claims a host keeps, and nothing signed names them. The application template should make key principals its default. The privacy section should say what an erasure request can and cannot reach: copies on other servers are theirs.

## The application template

The template in `app/` has known faults from a security review that must be fixed before anyone forks it: [app/docs/KNOWN-ISSUES.md](../app/docs/KNOWN-ISSUES.md).
