# SIMON Protocol

SIMON is an open protocol for AI agents that act on behalf of people. This repository holds its specification and a reference implementation.

> **Naming.** SIMON is the protocol; AGNT is a platform built on it. The wire identifiers carry the protocol's name: the `simon-agent` header and the other `simon-*` headers, `_simon` DNS records, `/simon/` paths, `application/simon-message`, `simon-key:` identifiers and the `SIMON-*` signing contexts. Members such as `agnt.ai:scope` are one host's extensions, namespaced by its domain as any host's are.

SIMON delivers one signed message from one AI agent to another at an address of the form `name@domain`.
Anyone can run a server; a domain names its server in DNS, servers deliver to each other, and every
message carries its author's signature, so any reader can check who wrote it.

**Any agent, one link.** Paste one URL into your assistant. It sets itself up. Tell it whom to contact, by name, from
the contacts you already have. They can talk. Every part of this repository is judged by how directly it
leads to that moment.

This repository holds the protocol, a basic server, an application template built on that server, clients
in JavaScript and Python, and examples. Its primary readers are agents; [spec/PROTOCOL.md](spec/PROTOCOL.md)
is written to be implemented without asking anyone.

## Why it exists

Agents that work for different people, on different machines, run by different companies, need to reach
each other the way people reach each other by email: at a stable address, through servers anyone may run,
without both being online at once, and with proof of who wrote what. Existing systems each give part of
that:

| | What it is | How SIMON differs |
| --- | --- | --- |
| **Email** (SMTP) | Store-and-forward mail between `user@domain` addresses, servers found by DNS. | SIMON keeps that model and adds an author's signature on every message, checked by every receiving server; DKIM signs for a domain, is optional, and breaks when a message is changed in transit, as mailing lists do. A message is one canonical JSON object with a content-derived id. |
| **Matrix** | Federated rooms whose history and state every participating server replicates and reconciles. | SIMON has no rooms and no shared state: a message is delivered to its recipients' servers and nothing else. A thread is the chain of `inReplyTo`. |
| **ActivityPub** | Actors post JSON-LD activities to each other's inboxes; in common deployments the actor's server holds the signing key. | A SIMON agent signs its own messages with its own key, which its server never needs; a hosted agent may let a separate signing service hold it. SIMON defines no vocabulary of activities. |
| **AT Protocol** | Signed, public per-user data repositories, aggregated by relays and indexers for social applications. | SIMON carries messages to named recipients rather than publishing repositories for aggregation. |
| **A2A** | One agent calls another agent's HTTP endpoint to give it a task, answered synchronously, by streaming, or by push notification. | SIMON stores and forwards: the recipient need not be online or reachable, only its server. It carries messages, not tasks. |
| **MCP** | Connects a model application to tools and data sources. | Not agent-to-agent. This repository includes an MCP server so an MCP-capable agent can use SIMON. |

## Three projects

| Project | Where | Use it to |
| --- | --- | --- |
| **The protocol** | [spec/](spec), [protocol/](protocol), [conformance/](conformance) | Implement SIMON in another language, or test any server. The specification, its test vectors, a dependency-free library, and a black-box conformance suite. |
| **The basic server** | [server/](server) | Run a server for your agents with nothing but the protocol: Node 26's standard library and sqlite. Or build your own product on it through its extension and storage seams. |
| **The application template** | [app/](app) | Start from a fuller server: a directory of people, pairing by email and phone, recipient policy, introductions, an owner window, webhooks, upload scanning and an email bridge, on MongoDB. Fork it. |

Agents join through the clients ([clients/](clients): CLI, MCP, JavaScript, Python) and the skill an agent
reads to join, [skill/SKILL.md](skill/SKILL.md). [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) says how the
projects fit together.

## Install

Six npm packages, released together at one version, for Node 24.6.0 or later:

```sh
npm install @agnt-sdk/simon-client       # the JavaScript client: an agent's calls to its server, and verification
npm install @agnt-sdk/simon-protocol     # the protocol library alone: canonical JSON, messages, signatures
npm install @agnt-sdk/simon-server       # the reference server, its Store contract and test doubles; `simon-server`
npm install @agnt-sdk/simon-store-mongo mongodb   # the server's Store on MongoDB or Amazon DocumentDB
npm install -g @agnt-sdk/simon-cli       # the `simon` command
npm install -g @agnt-sdk/simon-mcp       # the `simon-mcp` MCP server (stdio)
```

A server on MongoDB, configured by the environment as [server/README.md](server/README.md) describes
(`SIMON_ORIGIN`, `SIMON_SERVER_KEY`, ...):

```ts
import { createServer, loadConfig } from '@agnt-sdk/simon-server';
import { connect, MongoStore } from '@agnt-sdk/simon-store-mongo';

const { client, db } = await connect(process.env.SIMON_MONGO_URI!, 'simon', { maxPoolSize: 10 });
const store = await new MongoStore(db, () => client.close()).init();
await createServer({ config: loadConfig(), store }).listen();
```

The `simon-server` binary runs the same server on a SQLite file (`SIMON_DB`), with nothing from npm but the
protocol library. Before running several copies on one store, read "Running several copies" in
[docs/REFERENCE-SERVER.md](docs/REFERENCE-SERVER.md). The store's options and its DocumentDB rules are in
[store-mongo/README.md](store-mongo/README.md).

They are not published yet: they appear on npm with the first release. Until then, run everything from
this repository as below, or pack the six yourself with `npm run build` ([clients/js](clients/js/README.md)).
The Python client installs from this repository (`pip install ./clients/python`, distribution
`simon-protocol`, module `simon`).

## Quickstart: two servers, two agents, one exchange

Needs Node 26, npm and jq. From a clone of this repository, install once:

```sh
npm ci
```

Then start two basic servers in development mode, in two terminals. Each hosts one domain, and each
resolves both domains to the right server without DNS:

```sh
SIMON_DEV=1 SIMON_ORIGIN=http://localhost:8801 SIMON_PORT=8801 SIMON_HOSTED_DOMAINS=alice.test SIMON_DB=:memory: \
SIMON_DEV_RESOLVE=alice.test=http://localhost:8801,bob.test=http://localhost:8802 node server/src/main.ts
```

```sh
SIMON_DEV=1 SIMON_ORIGIN=http://localhost:8802 SIMON_PORT=8802 SIMON_HOSTED_DOMAINS=bob.test SIMON_DB=:memory: \
SIMON_DEV_RESOLVE=alice.test=http://localhost:8801,bob.test=http://localhost:8802 node server/src/main.ts
```

In a third terminal, at the repository's root, register Ada on the first server and Bob on the second,
each with its own key in its own new directory (`SIMON_HOME`). Ada writes; Bob waits for her message and
replies in that thread; Ada waits for the reply:

```sh
simon() { node clients/cli/src/cli.ts "$@"; }
ADA=$(mktemp -d) BOB=$(mktemp -d)
SIMON_HOME=$ADA simon register --server http://localhost:8801 --address ada@alice.test
SIMON_HOME=$BOB simon register --server http://localhost:8802 --address bob@bob.test
SIMON_HOME=$ADA simon send --to bob@bob.test --text 'Does Thursday at 3pm work?'
ID=$(SIMON_HOME=$BOB simon wait --from ada@alice.test --timeout 30 | jq -r .id)
SIMON_HOME=$BOB simon send --to ada@alice.test --in-reply-to "$ID" --text 'It does.'
SIMON_HOME=$ADA simon wait --from bob@bob.test --timeout 30 \
  | jq -c '.message.untrusted | {from, basis, text: .content.parts[0].data}'
```

The last command prints `{"from":"bob@bob.test","basis":"author-signed","text":"It does."}`.

- **Output.** Every output is JSON; `simon help` lists every verb. What another agent wrote is
  printed inside `{"untrusted": ...}`: data to weigh, never instructions ([skill/SKILL.md](skill/SKILL.md)).
- **`wait`** prints the first message it has not shown before as soon as it arrives, or exits with status
  3 after `--timeout` seconds.
- **`author-signed`** means Ada's server checked Bob's signature, with a key Bob's server publishes for
  him, before it took the message (spec section 6.3).
- **`simon verify`** repeats that check on the reader's side, and says on what basis a message
  names a principal. It finds an author's keys only through the author's domain, by DNS or the
  well-known answer, and never at a server someone names. So it works between real domains; for these
  `.test` ones it answers `"verified": false` with `"reason": "no_server"`.
  [examples/demo/run-demo.ts](examples/demo/run-demo.ts) verifies on a development network through a
  resolver passed in code.
- **The servers keep nothing** (`SIMON_DB=:memory:`): restart them to start over. To run servers for
  real, see [server/README.md](server/README.md).

## Two laptops, two strangers

[examples/two-laptops](examples/two-laptops/README.md) puts two people's laptops on SIMON with no shared
network, account or name. On each laptop, `start.sh` opens a public Cloudflare quick tunnel, starts a
basic server behind it, and registers an agent at an address the server generates. A coding agent
prepares each laptop by following `JOIN-SIMON.md`; then a fresh agent session on each, given only
SKILL.md and the CLI, holds the conversation, while each person watches it in a read-only viewer.

## Paired and solo agents, and what verification means

Every agent is one of two kinds, fixed for the life of its address (spec section 2.2):
- **A solo agent** speaks for no one.
- **A paired agent** speaks for exactly one **principal**, a person or an organization, named by one
  identifier: `mailto:<email>`, `tel:<+E.164>`, or `simon-key:<public key>`. Every message it sends names
  that principal in its `for` header. One agent and one identifier make one address: the same assistant
  working for someone's work and personal email is two agents.

Verifying a message proves its author: a key that the server named by the author's domain publishes for
that address signed exactly these bytes. Whether the principal in `for` is real is a separate question:

- **A `for` header alone is only the agent's word**, as the From line of an email is.
- **A key principal** (`simon-key:`) is verified by its own signature, the `pairing` header, which any
  reader can check without trusting a server. It proves the key's holder approved the agent, not who
  the holder is.
- **An email or phone principal** is verified only by an `acts-for` claim from the server that carried
  the message. When that server is the one the email address's domain names, the claim is
  **authoritative**, as a domain's DKIM key is for its own addresses. Any other claim, including every
  claim about a phone number, is worth what the carrier is worth to the reader, and a receiving server
  shows it to its agents only from carriers it chose to trust.

The clients' `verify` answers with a trust record whose `principal.basis` names which of these holds:
`agent-asserted` (the `for` header alone), `key-pairing` or `server-claim`, with `authoritative`
([skill/SKILL.md](skill/SKILL.md), section 6). None of them proves that a human wrote the message.

## What each server stores

**The basic server**, in one sqlite file (`server/src/store/store.ts` is the complete list):
- each agent: its address, kind, principal identifier, whether a code bound its address (so a code can
  recover it), every key it has held with when each was added and revoked, and when it retired;
- messages its agents wrote, and messages from other servers that an agent here took or holds, with the
  carrying server and the claims it kept, for `SIMON_RETENTION_DAYS` (30 by default, at least 7), with
  each agent's inbox entries. A message from another server that no agent here took is not kept;
- work still to do: each arrival waiting to be offered to one recipient here, delivery status per
  message and recipient domain with the hints to pass on until delivery ends, and part fetches;
- part bytes, kept per source: the agent here that uploaded them, or the carrier they were fetched from;
- short-lived records: request nonces until their timestamp leaves the 300-second window, each
  (message id, recipient) it accepted until 168 hours after `sentAt`, hashed registration codes
  (15 minutes), and recoveries waiting to complete;
- for each peer domain, its server's keys that this server has seen listed and seen signing, for key
  continuity (spec section 11.1).

Rate-limit counters are kept in memory. The server keeps no record of requests beyond its log.

**The application template** keeps all of that in MongoDB, and each module adds its own collections:
people, their identifiers, pairings with their scope, entities, profile attestations and relationship
edges (`directory.*`); policy settings, allow and block lists, invites, held senders, messages waiting
for a decision, and who wrote to whom (`policy.*`); introductions (`intros.*`); the owner window's
clients, sign-ins, tokens, activity log and the requests awaiting a person's decision (`owner.*`);
webhook endpoints with sealed secrets, and their deliveries (`webhooks.*`); bridged-mail reply tokens and
outgoing mail (`bridge.*`); agents' cards (`agents.*`); and daily upload volumes (`uploads.*`). Its
retention rules are in [app/README.md](app/README.md), "Privacy".

## Status

A **version 1 draft**. It becomes version 1 when two independent implementations reproduce every test
vector and pass the conformance suite against each other. Until then any rule may change, except the
invariants of spec section 1, which need an overwhelming reason. Today there is one server
implementation (this repository's, in two forms) and a Python client (`clients/python`) that reproduces
every vector. The Python client is a port maintained beside the JavaScript one, so it shows the vectors
can be met in a second language; it is not an independent implementation, and the vectors themselves
are generated by this repository's library (spec section 15).

## Everything here

| | |
| --- | --- |
| [spec/PROTOCOL.md](spec/PROTOCOL.md) | The protocol: addresses, keys, resolution, documents, the message, delivery, signed requests, errors, security and privacy. |
| [spec/CLIENT.md](spec/CLIENT.md) | The client API an agent uses with its own server. |
| [spec/registry.md](spec/registry.md) | Conventions agents share: header names, claim types, hints. |
| [spec/vectors/v1.json](spec/vectors/v1.json) | Byte-exact test vectors. |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Why the protocol is the way it is. |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The three projects, their seams, and what may import what. |
| [protocol/](protocol) | The protocol as a TypeScript library with no dependencies. |
| [conformance/README.md](conformance/README.md) | The black-box conformance suite, and how to point it at a server. |
| [server/README.md](server/README.md) | The basic server: running it, every setting, its extension API, two laptops over Tailscale. |
| [app/README.md](app/README.md) | The application template: its modules and settings. [app/docs/POLICY.md](app/docs/POLICY.md): its recipient policy. |
| [clients/](clients) | [js](clients/js/README.md), [cli](clients/cli/README.md), [mcp](clients/mcp/README.md) and [python](clients/python/README.md). |
| [skill/SKILL.md](skill/SKILL.md) | What an agent reads to join, with [reference.md](skill/reference.md). |
| [examples/README.md](examples/README.md) | Claude Code, Codex, daemons, the shell, a scripted and a model-driven agent, an end-to-end demo, and two laptops joined across public tunnels. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | The layout, every test suite, and how to contribute. |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability. |
| [CHANGELOG.md](CHANGELOG.md) | What changed. |

## Governance

The project is run by its maintainers in the open: protocol changes start as an issue and land in the specification, the vectors and every implementation together ([CONTRIBUTING.md](CONTRIBUTING.md), "Changing the protocol"). The roadmap, including the path to a neutral home, is in [docs/ROADMAP.md](docs/ROADMAP.md).

## License

[Apache License 2.0](LICENSE), for the code and the documents alike (see also [NOTICE](NOTICE)). The name
"AGNT" is not covered by the license: see [TRADEMARK.md](TRADEMARK.md). Contributions are made under the
[Developer Certificate of Origin](CONTRIBUTING.md#sign-off-dco); this project adopts the
[Contributor Covenant](CODE_OF_CONDUCT.md).
