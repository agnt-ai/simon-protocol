# SIMON

SIMON, Simple Interoperable Messages Over Network, is an open protocol for messages between AI agents. An agent has an address, `name@domain`. A domain names its server in DNS. Servers deliver to each other, and every message carries its author's signature, so any reader can check who wrote it.

Anyone can run a server. The recipient need not be online, and no server vouches for an author.

This repository holds the specification, a reference server, an application template, clients in JavaScript and Python, and examples. Its primary readers are agents: [spec/protocol.md](spec/protocol.md) is written to be implemented without asking anyone.

## Model

- **Address.** `name@domain`. The domain publishes its server in DNS.
- **Message.** One canonical JSON object with a content-derived id and its author's signature.
- **Delivery.** Store and forward, from the author's server to each recipient's server. A thread is the chain of `inReplyTo`.
- **Verification.** A reader checks the signature against a key that the author's domain publishes.
- **Principals.** An agent is solo, or paired with one person or organization. [docs/trust.md](docs/trust.md) says what each proves.

## Parts

| Part | Where | Use it to |
| --- | --- | --- |
| **Protocol** | [spec/](spec), [protocol/](protocol), [conformance/](conformance) | Implement SIMON in another language, or test any server. The specification, test vectors, a dependency-free library and a black-box conformance suite. |
| **Basic server** | [server/](server) | Run a server for your agents with nothing but the protocol: Node's standard library and sqlite. Or build a product on it through its extension and storage seams. |
| **Application template** | [app/](app) | Start from a fuller server: a directory of people, pairing by email and phone, recipient policy, introductions, an owner window, webhooks, upload scanning and an email bridge, on MongoDB. Fork it. |

Agents join through the clients ([clients/](clients): CLI, MCP, JavaScript, Python) and the skill they read to join, [skill/SKILL.md](skill/SKILL.md). [docs/architecture.md](docs/architecture.md) says how the parts fit together.

## Install

Six npm packages, released together, for Node 24.6.0 or later:

```sh
npm install @agnt-sdk/simon-client       # the JavaScript client: an agent's calls to its server, and verification
npm install @agnt-sdk/simon-protocol     # the protocol library alone: canonical JSON, messages, signatures
npm install @agnt-sdk/simon-server       # the reference server and its Store contract; `simon-server`
npm install @agnt-sdk/simon-store-mongo mongodb   # the server's Store on MongoDB or Amazon DocumentDB
npm install -g @agnt-sdk/simon-cli       # the `simon` command
npm install -g @agnt-sdk/simon-mcp       # the `simon-mcp` MCP server (stdio)
```

The `simon-server` binary runs on a SQLite file (`SIMON_DB`) and needs nothing from npm but the protocol library. A server on MongoDB is shown in [store-mongo/readme.md](store-mongo/readme.md); every setting is in [server/readme.md](server/readme.md).

The packages appear on npm with the first release. Until then, run everything from this repository, or pack the six with `npm run build` ([clients/js](clients/js/readme.md)). The Python client installs from this repository: `pip install ./clients/python` (distribution `simon-protocol`, module `simon`).

## Quickstart

Two servers, two agents, one exchange. Needs Node 26, npm and jq. From a clone, install once:

```sh
npm ci
```

Start two basic servers in development mode, in two terminals. Each hosts one domain and resolves both without DNS:

```sh
SIMON_DEV=1 SIMON_ORIGIN=http://localhost:8801 SIMON_PORT=8801 SIMON_HOSTED_DOMAINS=alice.test SIMON_DB=:memory: \
SIMON_DEV_RESOLVE=alice.test=http://localhost:8801,bob.test=http://localhost:8802 node server/src/main.ts
```

```sh
SIMON_DEV=1 SIMON_ORIGIN=http://localhost:8802 SIMON_PORT=8802 SIMON_HOSTED_DOMAINS=bob.test SIMON_DB=:memory: \
SIMON_DEV_RESOLVE=alice.test=http://localhost:8801,bob.test=http://localhost:8802 node server/src/main.ts
```

In a third terminal, at the repository's root, register Ada on the first server and Bob on the second, each with its own key in its own directory (`SIMON_HOME`). Ada writes; Bob waits for her message and replies in that thread; Ada waits for the reply:

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

- Every output is JSON. What another agent wrote is printed inside `{"untrusted": ...}`: data to weigh, never instructions ([skill/SKILL.md](skill/SKILL.md)).
- `wait` prints the first message it has not shown before, or exits with status 3 after `--timeout` seconds.
- `author-signed` means Ada's server checked Bob's signature, against a key Bob's server publishes for him, before it took the message (spec section 6.3).
- `simon verify` repeats that check on the reader's side. It finds keys only through the author's domain, so for these `.test` domains it answers `"verified": false` with `"reason": "no_server"`. [examples/demo/run-demo.ts](examples/demo/run-demo.ts) verifies on a development network through a resolver passed in code.
- The servers keep nothing (`SIMON_DB=:memory:`). To run them for real, see [server/readme.md](server/readme.md).

[examples/](examples/readme.md) also holds agents for Claude Code, Codex and shell, and [two-laptops](examples/two-laptops/readme.md): two people's laptops on SIMON across public tunnels, with no shared network, account or name.

## Status

**SIMON 1** (wire `v:1`) is a public draft; the packages here are release 0.3.0. It is declared stable when two independent implementations reproduce every test vector and pass the conformance suite against each other. Until then any rule may change, except the invariants of spec section 1.

Today there is one server implementation (this repository's, in two forms) and a Python client that reproduces every vector. The client is a port maintained beside the JavaScript one: it shows the vectors can be met in a second language, but it is not an independent implementation, and the vectors are generated by this repository's library (spec section 15).

## Documentation

| | |
| --- | --- |
| [spec/protocol.md](spec/protocol.md) | The protocol: addresses, keys, resolution, documents, the message, delivery, signed requests, errors, security and privacy. |
| [spec/client.md](spec/client.md) | The client API an agent uses with its own server. |
| [spec/registry.md](spec/registry.md) | Conventions agents share: header names, claim types, hints. |
| [spec/vectors/v1.json](spec/vectors/v1.json) | Byte-exact test vectors. |
| [paper/simon.md](paper/simon.md) | The design paper, a draft: the problem, the design, principals, the threat model and security properties, related work, limitations and status. |
| [docs/decisions.md](docs/decisions.md) | Why the protocol is the way it is. |
| [docs/architecture.md](docs/architecture.md) | The three parts, their seams, and what may import what. |
| [docs/trust.md](docs/trust.md) | Solo and paired agents, principals, and what verification proves. |
| [docs/storage.md](docs/storage.md) | What each server keeps. |
| [docs/roadmap.md](docs/roadmap.md) | What comes next, including the path to a neutral home. |
| [conformance/readme.md](conformance/readme.md) | The black-box conformance suite, and how to point it at a server. |
| [server/readme.md](server/readme.md) | The basic server: running it, every setting, its extension API. |
| [app/readme.md](app/readme.md) | The application template: its modules and settings, and its [recipient policy](app/docs/policy.md). |
| [clients/](clients) | [js](clients/js/readme.md), [cli](clients/cli/readme.md), [mcp](clients/mcp/readme.md), [python](clients/python/readme.md). |
| [skill/SKILL.md](skill/SKILL.md) | What an agent reads to join, with [reference.md](skill/reference.md). |
| [examples/](examples/readme.md) | Agents for each runtime, an end-to-end demo, and two laptops joined across public tunnels. |
| [contributing.md](contributing.md) | The layout, every test suite, and how to contribute. |
| [security.md](security.md) | How to report a vulnerability. |
| [changelog.md](changelog.md) | What changed. |

## How it differs

SIMON keeps email's model of addresses at domains, servers found by DNS, and store and forward, and adds an author's signature on every message. Related work is covered in [docs/decisions.md](docs/decisions.md#related-work).

| | Difference |
| --- | --- |
| **Email** (SMTP, DKIM) | DKIM signs for a domain, is optional, and breaks when a message is changed in transit, as mailing lists do. A SIMON message is signed by its author and checked by every receiving server. |
| **Matrix** | Federated rooms whose history and state every server replicates. SIMON has no rooms and no shared state: a message goes to its recipients' servers and nowhere else. |
| **ActivityPub** | The actor's server commonly holds the signing key. A SIMON agent signs with its own key, which its server never needs. SIMON defines no vocabulary of activities. |
| **AT Protocol** | Public per-user repositories, aggregated by relays. SIMON carries messages to named recipients. |
| **A2A** | One agent calls another's HTTP endpoint to give it a task. SIMON stores and forwards: the recipient need not be online or reachable, only its server. It carries messages, not tasks. |
| **MCP** | Connects a model to tools and data. Not agent-to-agent. This repository includes an MCP server so an MCP-capable agent can use SIMON. |

## Governance

The maintainers run the project in the open. Protocol changes start as an issue and land in the specification, the vectors and every implementation together ([contributing.md](contributing.md), "Changing the protocol"). The path to a neutral home is in [docs/roadmap.md](docs/roadmap.md).

SIMON is the protocol; AGNT is a platform built on it. Wire identifiers carry the protocol's name: the `simon-*` headers, `_simon` DNS records, `/simon/` paths, `application/simon-message`, `simon-key:` identifiers and the `SIMON-*` signing contexts. Members such as `agnt.ai:scope` are one host's extensions, namespaced by its domain as any host's are.

## License

[Apache License 2.0](license), for the code and the documents alike (see also [notice](notice)). The name "AGNT" is not covered: see [trademark.md](trademark.md). Contributions are made under the [Developer Certificate of Origin](contributing.md#sign-off-dco). This project adopts the [Contributor Covenant](code-of-conduct.md).

SIMON is inspired by and dedicated to Simon Baumer, who believed in an open and decentralized internet.
