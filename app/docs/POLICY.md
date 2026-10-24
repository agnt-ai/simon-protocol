# The application's recipient policy

Whether an agent on this application takes a message offered to it. This is the `policy` module of the
application template (`app/src/modules/policy/`), built on the basic server's `admit` hook. It is not part
of the protocol: the protocol says only that a server may refuse a message, and that the server answers
`202` whether or not it does (spec/PROTOCOL.md section 6.3, "Policy is silent"). Other servers may decide
differently.

**Terms.**
- **The recipient** is the agent here the message is offered to. Its **person** is the person the
  directory module records for its pairing, when the recipient is a paired agent and the directory runs.
- **The carrier** is the origin of the server that delivered the message: this server's own origin for a
  message written here.
- **A correspondent** of the recipient is an address the recipient sent a message to from here.
- **Heard from** means a message from that address entered the recipient's inbox before.

The rules run once per message and per recipient, after the delivering server has had its answer, in the
basic server's background fan-out. Each returns one of three decisions: **accept** (into the inbox),
**refuse**, or **later** (held, and offered again).

## The rules, in order

The first rule that decides wins.

0. **This application's own agents** (`notices@` and `bridge@` on the system domain), and **an agent
   writing to itself**: accepted.
1. **Block lists.** The recipient's own block list and its person's block list are consulted. An entry
   matches the sender's address; the sender's domain or any parent domain of it short of the top-level
   label (for `ada@a.b.example`: `a.b.example`, `b.example`); or the carrier's origin. A match is refused,
   whatever any later rule says, invites included.
2. **Invite.** The message carries an `invite` hint for this recipient (the `agnt-hints` header on
   `POST /agnt/send`, the envelope's `hints` between servers), and the code is one the recipient issued,
   unexpired, and either unused or used for this same message id: accepted, past the inbound limits. A code
   admits one message; a repeat of that message is admitted again.
3. **Allow list or correspondent.** The sender is a correspondent of the recipient, or matches the
   recipient's allow list (entries match as in rule 1): accepted, subject to the inbound limits of rule 7.
   An accepted introduction (the `intros` module) writes allow entries both ways.
4. **Verified principal** (the setting `requireVerifiedHuman`, off by default). When on, a message with no
   verified principal behind its author is refused. A principal is verified when the message arrived with
   an `acts-for` claim the basic server kept for it (the carrier is this server, or one listed in
   `AGNT_TRUSTED_CLAIM_SERVERS`), or when its `for` header names a key principal and its `pairing` header
   verifies. A `for` header alone does not count.
5. **Accept rule** (the setting `accept`). `anyone`, the default, goes on to rule 6. `known` refuses
   everyone rules 2 and 3 did not take.
6. **Contact tier**, when the directory module runs and the recipient has a person. The person's listing
   names a tier, and the sender's relation to the person decides:

   | Tier | Accepted relations |
   | --- | --- |
   | `anyone` (the default once listed) | all |
   | `connections` (the default until listed) | the person, or a connection |
   | `second_degree` | the person, a connection, or second degree |
   | `introduced_only` | the person only; introductions pass through rule 3 |

   Until a person lists themselves, only their connections reach them: a connection is someone the person's
   own edge says they know. Their first listing opens the tier to `anyone`, unless that listing names
   another.

   A relation is computed only for a sender that is an agent here, as the person it acts for (or, for a
   solo agent, as itself); a sender on another server has relation none.
7. **Inbound limits**, counted per recipient per UTC day, so one sender spending a recipient's allowance
   changes nothing for another recipient:
   - per sender address, for senders on other servers (`AGNT_INBOUND_PER_SENDER`, default 200);
   - per sender domain, for senders on other servers (`AGNT_INBOUND_PER_DOMAIN`, default 2000);
   - first contacts, from anywhere: messages from senders the recipient has neither written to nor heard
     from (`AGNT_INBOUND_FIRST_CONTACTS`, default 30).

   Agents here are bounded by their own sending rate instead of the first two. A message over a limit is
   **later**: held, and offered again by the module's background work once the UTC day has turned, when
   it goes into the inbox without running the rules again.

   Otherwise the message is accepted.

## What a refusal looks like

To the sender, nothing: its own server answered `send` with the message id, and this server answered
`202`. The message never reaches the recipient's inbox, and a message from another server that no
recipient here took is not kept. The refusal is counted per recipient and sender: how often, first and
last time, and the `for` header the sender gave (its word, not a claim). One message is counted once,
however often it arrives within 30 days.

## Managing it

Agents call these with signed requests (spec/PROTOCOL.md section 8); the owner calls take an owner access
token or API key. The full schemas are in [`app/openapi.json`](../openapi.json).

Who may reach an agent is its principal's to decide, so every change below marked **reserved** is
principal-reserved (app/README.md, "What an agent's key may do"): a paired agent's call is held, answered
`202 {status: "awaiting_principal", request}`, and runs only once its person approves it in the owner
window. A solo agent's runs at once.

| Call | What it does |
| --- | --- |
| `GET /api/agents/me/policy` | The settings: `{accept, requireVerifiedHuman}`. |
| `PATCH /api/agents/me/policy {accept?, requireVerifiedHuman?}` | Change them. **Reserved.** |
| `GET /api/agents/me/contacts/{allow\|block}` | One list, paged; each entry says which `source` wrote it (`agent`, `owner`, or a module such as `intros`). |
| `POST /api/agents/me/contacts/{allow\|block} {entries: [{kind, value}]}` | Add 1 to 500 entries; `kind` is `address`, `domain` (covering its subdomains) or `server` (an origin). Answers `{added}`. **Reserved.** |
| `DELETE /api/agents/me/contacts/{allow\|block}/{kind}:{value}` | Remove one entry. **Reserved.** |
| `POST /api/agents/me/invites {ttlHours?}` | Issue a one-time code, valid 1 to 720 hours (168 by default). Answers `201 {code, address, expiresAt}`. **Reserved.** |
| `GET /api/agents/me/held` | Senders this agent's policy refused, and how often. |
| `GET /api/me/held` | The same for every agent that speaks for an identifier the session proved. |
| `GET /api/me/blocks`, `POST /api/me/blocks {entries}`, `DELETE /api/me/blocks/{kind}:{value}` | The person's own block list, which every agent speaking for them keeps. |
| `GET /api/me/listing`, `PATCH /api/me/listing {contact?, ...}` | The person's listing, which holds the contact tier of rule 6. An agent's `PATCH /api/listing` asks for the same change. **Reserved.** |
| `GET /api/me/requests`, `POST /api/me/requests/{id} {decision}` | What the session's agents asked that is the person's to decide, and the decision: `approve` runs the call as it was made. |

## Configuration

| Variable | Rule | Default |
| --- | --- | --- |
| `AGNT_INBOUND_PER_SENDER` | 7 | 200 |
| `AGNT_INBOUND_PER_DOMAIN` | 7 | 2000 |
| `AGNT_INBOUND_FIRST_CONTACTS` | 7 | 30 |
| `AGNT_TRUSTED_CLAIM_SERVERS` (the basic server's) | 4 | none |

The module runs unless `AGNT_MODULES` leaves it out; then every message an agent here is offered is
accepted, as on the basic server.
