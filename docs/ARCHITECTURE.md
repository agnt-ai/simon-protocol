# Architecture

How this repository is divided, and what may depend on what. The protocol itself is
[`spec/PROTOCOL.md`](../spec/PROTOCOL.md) and the agent-to-server API is [`spec/CLIENT.md`](../spec/CLIENT.md);
the reasons behind the division are in [DECISIONS.md](DECISIONS.md), "Three projects".

## Requirements

1. Two independently operated servers exchange messages with no SIMON account and no SIMON-operated
   service in the path.
2. A minimal implementation communicates fully without any optional feature.
3. Resolving an address to its server is protocol. Finding a person worth writing to is a feature.
4. Everything a server does is deterministic: no model in the request path.

## Three projects

| Project | Directories | What it is | Depends on |
| --- | --- | --- | --- |
| **The protocol** | `spec/`, `protocol/`, `conformance/` | What independent implementations must agree on: the specification, its test vectors, a library that implements every offline rule, and a black-box suite that tests any server over HTTP. | Node only |
| **The basic server** | `server/` | The smallest complete server: the protocol and the client API, hardened, and nothing else. No people, directory or policy. Storage is sqlite. | Node and `@agnt-sdk/simon-protocol` |
| **The application template** | `app/` | The basic server with modules for a directory, pairing by email and phone, recipient policy, introductions, an owner window, webhooks, upload checks and an email bridge. Storage is MongoDB. | The basic server's published entry points, MongoDB's driver, zod, nodemailer |

Beside them:
- **Clients** (`clients/`): `js` (the client API and verification, Node and `@agnt-sdk/simon-protocol` only), `cli`
  and `mcp` (both on `js`), and `python` (a port maintained beside the JavaScript client, standard library only,
  `cryptography` optional).
- **Examples** (`examples/`): agents and per-runtime guides, on the clients.

Each layer is complete without the one above it. The protocol runs without a server; the basic server
federates with any conforming server; the application adds behaviour without editing the basic server.
If the application needs a change to the basic server's core, the core is wrong, and the change is made
there as a general extension point.

Repository integration tests (`test/integration/`) exercise handoffs between these packages. They run
through the root `npm test` command and root typecheck, outside each package's independent test suite.
Package boundary checks still apply to each package and its own tests.

## The protocol package

`protocol/src/` has one file per concern: `canonical` (canonical JSON), `address`, `keys` (key tokens,
Ed25519 and ML-DSA-65, validity at a time), `principal` (identifiers and pairing signatures), `message`,
`envelope` (envelopes naming their server and recipients, claims and their authority), `documents`
(server and agent documents, with `algorithms`), `resolve` (TXT records, well-known answers, server
origins, how long an outcome may be cached), `request` (signed requests and the add-key proof), `limits`
(sizes and time windows), `time` and `errors` (RFC 9457 problem details, sent as
`application/problem+json`). It opens no connection of its own: resolution takes its DNS and HTTP lookups
as an argument, and the document readers take the fetched bytes.

`protocol/test/vectors.ts` builds the test vectors from this code, and `npm run vectors` writes them to
`spec/vectors/v2.json`; a test fails when the committed file differs. The Python client reproduces every
vector without reading this code.

## The basic server

`createServer({config, store, extensions, dns, http, now, log, mailbox, worker})` assembles the core
from its parts. Everything outside the process is passed in: DNS, outbound HTTP, the clock and what sends
codes, and the news of a recovery, to an address's mailbox. The defaults are c-ares DNS (`net/dns.ts`: the system's DNS servers or `SIMON_DNS_SERVERS`,
confirmed by DNS-over-HTTPS resolvers when `SIMON_DOH_RESOLVERS` names them), an SSRF-guarded HTTP client
(`net/fetch.ts`: outside development, https with TLS 1.3 or later and public addresses only, unless
`SIMON_TRUSTED_NETWORKS` names private ones; no redirects), the system clock, and codes logged in
development only. `server/README.md` lists the files and every setting.

**Work after the answer.** `send` and `deliver` answer once a message is stored, together with the rows
that carry it on: one delivery row per recipient domain for a message sent here, one arrival per
recipient for a message accepted from another server. Everything else happens afterwards in the worker
loop (`worker.ts`), so no answer and no timing depends on a recipient's decision (spec section 6.3,
"Policy is silent"):
- **Arrivals** (`fanout.ts`): each is offered to its recipient through the admit chain on its own, and
  retried with backoff if the offer fails. The parts of a message for an agent here are queued for
  fetching from its carrier first, whatever the chain decides. A message from another server that no
  recipient here took is not kept.
- **Inbox events** are written with the inbox entry and told to listeners afterwards, at least once.
- **Part fetches** (`parts.ts`) wait a random delay, are bounded in number and bytes, and are checked
  against hash and size.
- **Deliveries** (`outbox.ts`): due rows are claimed under a lease, so two workers never take the same
  one. Recipient domains that name the same server share one envelope, which names that server and its
  recipients. POSTs are capped in total and per destination; a destination that does not answer is
  skipped for a while, and a `429` throttles its server. Retries back off to the deadline, the earlier of
  five days after acceptance and 143 hours after `sentAt`, and no attempt starts before `sentAt`.

**Behind a proxy.** Rate limits count clients by address, so behind a tunnel or a load balancer the server
reads the client's address from the header the proxy sets (`SIMON_CLIENT_IP_HEADER`). It believes that
header only from this machine and from the networks in `SIMON_TRUSTED_PROXIES`, and reads it from the
right, past every trusted hop: a client may write anything at the left of `X-Forwarded-For`, but never
past the proxy that heard from it. A hosting service's own networks (`SIMON_RATE_EXEMPT_NETWORKS`) skip
the per-client rates by that same address, and its agents' rates still apply. `GET /health` answers
while the server and its store do, for the balancer's checks, and says nothing else. `server/README.md`
describes a deployment on one.

### The extension seam

An application changes behaviour only by passing extensions (`server/src/extensions.ts`). An extension is
a plain object with a name and any of these hooks. Every hook is the list of all extensions' hooks, run
in the order given; none is a single slot.

| Hook | When the core calls it | What it decides |
| --- | --- | --- |
| `routes` | A request to one of its paths | The answer. Core paths cannot be replaced. |
| `admit(arrival, api)` | Per recipient here, after the answer | `accept`, `refuse` or `later` ends the chain; `undefined` passes it on. With no decision, the message is accepted. |
| `claimsFor(message, agent, api)` | On `send` | Claims for the envelope, such as `acts-for`. |
| `allowAddress(request, api)` | `register` for a new name on a hosted domain, or a lease: an address no agent holds or ever held, with no mailbox to prove | `allow` or `refuse` ends the chain; `undefined` passes it on. With no decision, the key takes the address. A refusal is `409 address_taken`. |
| `verifyPrincipal(request, api)` | `register` with a `mailto:` or `tel:` principal, for an address no agent holds or ever held | `verified`, `pending` with a 202 body, or `undefined` for a kind it does not verify. A refusal throws. |
| `upload(upload, api)` | `PUT /simon/parts/<sha256>`, before the bytes are kept | Nothing, or a thrown error that refuses the upload. |
| `on.stored`, `on.inbox`, `on.delivered`, `on.deliveryFailed`, `on.recovered` | After the event; `inbox` at least once, so a listener dedupes by (address, message id) if it must | Nothing; a failing listener is logged and never fails the core. |
| `on.unroutable` | Recipients whose domain names no SIMON server | `true` when it took them: their delivery then counts as delivered, and later listeners are not told. |

An `arrival` is one message offered to one recipient here: the message and its id, the recipient, the
carrier's origin, that recipient's hints, and the claims agents here are shown. Those are the
authoritative claims always and the others only from carriers in `SIMON_TRUSTED_CLAIM_SERVERS`; each
`acts-for` and `identifier` claim carries `authoritative` (spec section 6.2, the registry). Only a claim
about an email address on the carrier's own domain is authoritative, so with the default settings
another server's `operator` claims, and its claims about addresses elsewhere, reach no agent here: the
operator decides whose word to pass on.

Hooks receive `api` (`ServerApi`): the configuration, the store, the clock and the log, and five
operations: `authenticate` a signed request, `admit` a message an extension held, `offer` a stored
message to an agent through the admit chain, `send` as an agent here (checked as `POST /simon/send`
checks it), and `retire` an address.

### The storage seam

`server/src/store/store.ts` is everything the core keeps, as one interface (`Store`):
- **agents** and every key each has held; an address and a key each belong to one agent, forever;
- **messages**, each stored once by id together with its delivery rows or its arrivals;
- **arrivals**, one per (id, recipient), each retried and settled on its own;
- **inboxes**, one entry per (address, id), with cursors that increase across the store, and the inbox
  events not yet told;
- **deliveries**, one row per (id, domain), claimed under a lease and settled only by that lease;
- **parts**, bytes kept per (sha256, source), where a source is the uploading agent or the carrier, and
  `partSources`, which names the sources a viewer (anyone, a server, an agent) may read;
- **part fetches**, one per (sha256, carrier);
- **marks, counters and values**, scoped by name, each living until its expiry.

Its rules are written on the interface:
- the store has no clock, so every time is passed in;
- uniqueness is part of the contract and atomic, so two racing calls on one key never both win;
- a method is one change: what it writes is all there or none of it;
- queues are claimed, not read: work for later is a row settled explicitly, so a crash at worst repeats
  work and never loses it;
- nothing expires except through `sweep`;
- returned records are copies.

`server/src/store/contract.ts` states those rules as tests, published as
`@agnt-sdk/simon-server/contract`. Among them, a reader following the inbox cursor never skips an
entry that concurrent writers add. A store proves itself by running them:
`storeContract(name, () => freshStore())`. `SqliteStore` passes them in `server/test/store.test.ts`, and
`MongoStore` (`store-mongo/`, published as `@agnt-sdk/simon-store-mongo`) in `store-mongo/test/store.test.ts`.

### Testing seam

`@agnt-sdk/simon-server/testing` is the outside world as test doubles: a movable `Clock`, `FakeDns`, and
`FakeNet`, whose origins answer in-process. The server's tests and the application's run whole
federations of servers in one process on it.

## The application template

`createApp` (`app/src/app.ts`) builds each module from a shared context (`app/src/context.ts`) and the
modules before it, and turns each into one extension of the basic server: its routes, its hooks and its
background work. The modules, the hooks each uses, and every setting are in `app/README.md`; recipient
policy is in [`app/docs/POLICY.md`](../app/docs/POLICY.md). Each module keeps its own records in its own
collections behind a small store interface of its own.

The application's own API is under `/api/` and described by `app/openapi.json`. The protocol's paths
are under `/simon/`, served by the basic server unchanged.

## What may import what

| A file in | may import |
| --- | --- |
| `protocol/` | Node's built-in modules |
| `server/`, `conformance/`, `clients/js/` | Node, `@agnt-sdk/simon-protocol` |
| `clients/cli/`, `clients/mcp/` | Node, `@agnt-sdk/simon-protocol`, `@agnt-sdk/simon-client` and its `/credentials`, `/provenance`, `/wait` and `/workspace` entries |
| `store-mongo/` | Node, `@agnt-sdk/simon-protocol`, `@agnt-sdk/simon-server` and its `/contract` entry, `mongodb`, and `mongodb-memory-server` in its `/testing` entry |
| `app/` | Node, `@agnt-sdk/simon-protocol`, `@agnt-sdk/simon-client`, `@agnt-sdk/simon-server` and its `/contract` and `/testing` entries, `@agnt-sdk/simon-store-mongo` and its `/testing` entry, its npm dependencies, `skill/grade.js`; never a file inside `server/` or `store-mongo/` |
| `examples/` | Node, the published packages, and an example's own dependencies |

A relative import stays inside its own project, with two exceptions:
- the CLI's and the MCP server's tests share `clients/js/test/fake-server.ts`;
- the application imports `skill/grade.js`, the published grading rubric.

Nothing outside `app/` imports the application.

Two tests enforce this: `protocol/test/boundary.test.ts` for the protocol, the basic server, the
conformance suite and the JavaScript clients, and `app/test/boundary.test.ts` for the application. No
test checks `examples/` beyond the application's. One example reaches past the published packages on
purpose: the two-laptops viewer reads the basic server's sqlite file directly, read-only, against
schema version 2 of `server/src/store/sqlite.ts`, and its test imports that file to write a database.

## Evidence of interoperability

1. **Test vectors** (`spec/vectors/v2.json`), written from the protocol code and checked by a test.
2. **The conformance suite** (`conformance/`), black-box over HTTP against any origin; the application's
   tests run it against the application with every module on.
3. **Federation** in the test harnesses: basic servers and application servers delivering to each other
   on the fake network.
4. **A second-language client** in Python (`clients/python/`), a port of the JavaScript client that
   reproduces every vector. It is not independent: the vectors are generated by the library it was
   ported beside, and the same people wrote both.
