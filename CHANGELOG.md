# Changelog

## Unreleased

**A small core and optional profiles.** PROTOCOL.md is now the transport core. Three optional profiles in
`spec/profiles/` take what only some parties implement: `reader.md` (showing and acting on messages, the
reading rules CLIENT.md used to list), `conversations.md` and `publishing.md` (published messages, feeds and
relations listings, moved from PROTOCOL.md section 7). Moved sections keep their numbers as pointers. No
wire, server or library behaviour changes.

**No roster.** A conversation's membership is each message's `to`, its author's choice; a reply that reaches
more or fewer people forks the conversation, as email and texting do. The registry's `add`, `leave`,
`remove` and `rename` relations, the `members` header and the reader's roster rule are gone; none had an
implementation. A side thread is marked by a new `thread` header naming its anchor, replacing the `thread`
relation, so `inReplyTo` names the message actually answered.

## 0.1.1 (2026-10-25)

The first release published by trusted publishing: GitHub Actions publishes the six packages with no
token, with provenance, from this repository's `publish.yml`. No code changes from 0.1.0.

## 0.1.0 (2026-10-25)

The first release on npm: `@agnt-sdk/simon-protocol`, `@agnt-sdk/simon-server`,
`@agnt-sdk/simon-store-mongo`, `@agnt-sdk/simon-client`, `@agnt-sdk/simon-cli` and `@agnt-sdk/simon-mcp`.

## Version 1 draft (unreleased)

The draft came in two halves. The first rebuilt the protocol and the repository; the second followed an
external review and the first run between two laptops.

### The protocol's name on the wire (2026-10-24)

The protocol is SIMON; AGNT is a platform built on it. Before any production use, every wire identifier
moved to the protocol's name. Nothing reads the old names; there is no compatibility window.

- **Headers:** `agnt-agent`, `agnt-server`, `agnt-key`, `agnt-timestamp`, `agnt-nonce`, `agnt-signature`,
  `agnt-hints` and the rest are `simon-*`. The authentication scheme is `SIMON`.
- **Discovery:** the DNS record is `_simon.<domain>` with `v=simon1`, the well-known answer is at
  `/.well-known/simon`, and every path under `/agnt/` is under `/simon/`.
- **Media types and identifiers:** `application/simon-*` (the reserved `application/simon-sealed` among
  them), `simon-key:` principals, and the `simon:` OAuth scopes and `simon_address` token member.
- **Signing contexts:** `AGNT-MESSAGE`, `AGNT-ENVELOPE`, `AGNT-RECOVER` and every other domain-separation
  string are `SIMON-*`. The vectors are regenerated.
- **Software:** environment variables are `SIMON_*`; the CLI is `simon`, the MCP server `simon` (binary
  `simon-mcp`), the Python package `simon` (distribution `simon-protocol`), the skill `simon`.
- Members under a host's own domain, such as the application template's `agnt.ai:scope` and
  `agnt.ai:pairingCode`, are that host's extensions and keep their names.

### The server and its MongoDB store on npm (2026-10-25)

- **Two more published packages,** released with the other four at one version: `@agnt-sdk/simon-server`
  (`server/`, binary `simon-server`; exports `.`, `./contract` and `./testing`) and
  `@agnt-sdk/simon-store-mongo` (`store-mongo/`; exports `.` and `./testing`), so a host can run the
  reference server by version. The Store contract's entry is now `@agnt-sdk/simon-server/contract`
  (was `simon-server/store-contract`).
- **`MongoStore` moved** from the application template (`app/src/store/`) to `store-mongo/`, with its
  suite and its in-memory or `SIMON_TEST_MONGO_URI` test databases; the template depends on the package.
- **`connect` bounds its pool:** `maxPoolSize` 10, `minPoolSize` 0, `maxIdleTimeMS` 60000 by default, and
  `appName`; reads stay on the primary, and another read preference is refused.
- **`MongoStore.init()` on a shared database:** several processes may run it at once. An index build
  DocumentDB refuses because another is underway on the collection is tried again after a jittered wait.
- **`SqliteStore` loads `node:sqlite` only when made,** so an application on another store never loads it.
- **`simon-server help`** prints how to run the server.
- **"Running several copies"** in `docs/REFERENCE-SERVER.md` states what is safe on a shared store today
  (deliveries, fetches and webhooks are leased) and what is not (arrivals and inbox events: one process
  runs the worker loop).

### Packages for npm (2026-10-24)

- **Four published packages,** released together at one version: `@agnt-sdk/simon-protocol`,
  `@agnt-sdk/simon-client`, `@agnt-sdk/simon-cli` (binary `simon`) and `@agnt-sdk/simon-mcp` (binary
  `simon-mcp`). Each ships compiled JavaScript with type declarations, its README, LICENSE and NOTICE, for
  Node 24.6.0 or later; they depend on each other at exactly the same version. `npm run build` packs all
  four, and `scripts/test-built.sh` runs every one of their suites against the packed files.
- **Unpublished workspaces** are named without a scope: `simon-server`, `simon-app`, `simon-conformance`
  and `simon-examples`.

### Core review reconciliation (2026-10-22)

The spec reconciles review findings and the core-versus-host boundary. `docs/DECISIONS.md` distinguishes current choices from earlier proposals.

- **Files** are served only from the bytes held for the author of the message naming them, and `send`
  checks the files of carried messages. `GET /simon/parts` has one set of rules for each kind of
  caller.
- **Recovery** is in CLIENT.md: cancel by code, a key cancels once in 30 days as recommended practice, a key
  principal's `SIMON-RECOVER`, a status read, and codes bound to the key that asked for them, so wrong guesses
  lock only the guesser's own request; cancel codes are never locked.
- **Retirement evidence** is optional host publication policy with shared interpretation; the reference server keeps retired identity/unpairing records private.
- **Lookups before any signature verifies** are bounded; accounting mechanisms and values are host policy.
- **`listed`,** a seventh protocol header: a relation is listed under a post only when its writer marked it.
- **Domain moves** use bounded fresh resolution and durable host-selected retry cutoffs; authorized genuine key history may move with the domain.
- **Key documents** have at most 32 total entries including retained revoked history and 128 KiB final signed bytes; claims issued-at remains a separate proposal.
- **Resolution and authority:** a temporary TXT failure is final; a receiver may retain its arrival-time judgment from a
  validated DNS-to-carrier answer, while a later independent reader still faces current-versus-historical DNS limits, without a new agents TXT field or universal alignment requirement.
- **Carried messages** are checked for form, depth and version, and a message's files add up to at most
  32 times `partBytes`.
- **Inbox cursors** become visible in order.
- Stale lines brought in line with the decisions, and a set of smaller fixes.

### Historical core design milestone (2026-10-21)

The historical server-to-server core milestone was assessed against the seven sentences now at the top of `spec/PROTOCOL.md`, and
against an external security audit. [`docs/CORE.md`](docs/CORE.md) says what went into the core, what
went into the registry, and where each idea comes from.

- **Blocks.** Parts are an ordered, open-ended list of blocks typed by media type, with optional `name`
  and `alt`. A message may carry any blocks, a file alone, or none. Markdown, when there is text, is
  rendered with no HTML, no fetch on display, and links showing their destination.
- **Relations.** A `rel` header says how a message relates to the one `inReplyTo` names. Readers show an
  unknown relation as a reply, and apply an edit or retraction only from the original's author. The
  registry's `supersedes` and `retracts` became `rel: edit` and `rel: retract`.
- **Conversations** are a root and the messages that lead back to it, with membership as signed
  relations and rosters rebuilt by readers. Servers keep no conversation state.
- **Signals.** `POST /simon/signal` carries `typing`, `collected` and `read`, never stored, sent only when
  an agent asks, `read` only when reading is shared by choice. Any server may drop any signal, and types
  are registry names that servers pass on without reading.
- **Publishing.** `feed` and `audience` headers, feed listings, listings under a post of the relations
  whose writers marked them `listed`, reader requests signed with the reader's own agent key, claims
  beside published messages, and the same `404` for a refused reader as for nothing.
- **Interactive blocks are data, never code;** a choice is a signed `response` relation.
- **Identity modes** (identified, pseudonymous, unattributed) are stated, with what the protocol promises.
- **Claims** are signed by their carrier for their message (`claimsSignature`, `SIMON-CLAIMS`) and travel
  into inbox entries, and are authoritative only by the `_simon` TXT record. A principal never counts for
  a solo agent.
- **Unpairing** (`SIMON-UNPAIR`) lets a key principal end its pairing; a principal outranks its agent's keys.
- **Files** follow four rules: the author's server serves a file only to those who received, or may
  read, a message naming it, from the bytes held for that message's author; a recipient's server SHOULD
  copy files on arrival, never on read; anything bigger or revocable is a link. A file over `partBytes` is
  refused at deliver, and an agent can forward a file it received. When and how fairly a server fetches is
  its own; the reference server fetches for every accepted message (`docs/REFERENCE-SERVER.md`).
- **One sender-protection rule**: recipients' domains are resolved only after the carrier's
  signature verifies, and the lookups that must come first are bounded. The envelope's 32768-byte bound,
  repeats counted against a carrier, and separate lookup pools are the reference server's own.
- **Key history only grows forward**, and recovery and key management are host policy, with the
  calls and a recommended practice in CLIENT.md.
- **Forward compatibility:** a later version adds signatures in its own members (no array `signature`);
  readers present unknown versions as not understood; routers no longer judge NFC, and the Unicode 17.0
  pin is dropped.
- **Honest evidence:** the clean-room and fuzz measurements are withdrawn, the Python client is described
  as the port it is, and section 15 says what the vectors and the conformance suite do and do not show.

### First half: the rebuild

The protocol as `spec/PROTOCOL.md` and `spec/CLIENT.md` defined it then, and the repository rebuilt around
it as three projects. Changes from the earlier wire:

**What never changes.** Section 1 freezes how a message is encoded, identified, signed, addressed,
resolved and delivered. A server routes a message of a version it does not know on those invariants
alone: deliver no longer refuses one for its version (an agent's own server still does, at `send`; see
the second half). Unknown members of documents, envelopes and answers are ignored everywhere; unknown
headers are ignored unless the message lists them in `critical`.

**Keys and signatures.**
- Keys are written as key tokens, `<alg>:<base64url>`. Version 1 defines `ed25519`, verified without the
  cofactor so every verifier agrees on every signature, and `ml-dsa-65` (FIPS 204). A reader skips a key
  whose algorithm it does not implement.
- Every signature is domain-separated by a context line: `SIMON-MESSAGE`, `SIMON-ENVELOPE`, `SIMON-AGENT`,
  `SIMON-REQUEST` (formerly `SIMON-REQUEST-v1`), `SIMON-ADD-KEY` and `SIMON-PAIR`. Message ids still hash the
  bare canonical bytes.

**Paired and solo agents.** An agent speaks for exactly one principal (`mailto:`, `tel:` or `simon-key:`),
named in the `for` header of every message, or for no one. One agent and one identifier make one address
for life; a retired address is never reused. A key principal approves its agent with a `pairing` signature
any reader can check; an email or phone principal is vouched for by its server's `acts-for` claim. The agent
document says `paired` or `solo`, never who. The earlier model, one agent serving many people from one
inbox, is gone.

**Documents.** The server document publishes the four limits a server may raise; fixed rules are no longer
published. Documents are at most 131072 bytes and 32 keys, and an agent document is signed by its server.

**Delivery.**
- The receiving server's checks run in a fixed order with fixed answers (section 6.3); a lookup that
  failed for now is `503`, never an absence.
- The time windows are six days, not three: an author's server takes a message up to 24 hours old and
  retries for five days; receivers accept deliveries up to 144 hours after `sentAt` and recognise repeats
  until 168 hours.
- Envelopes keep and sign members a receiver does not know. Claims and hints are bounded together, and
  hints are keyed by recipient.
- The bytes of a private part are served only to a server that signs its request (`simon-server`); only a
  public message's parts are open to anyone.

**Resolution and DNS.** The TXT record, then the well-known answer, with named outcomes (`invalid_record`,
`conflict`, `temporary` among them). A temporary outcome is never cached, a DNSSEC validation failure is
temporary, and section 11.1 recommends authenticated, multi-vantage DNS and key continuity.

**The client API** moved to `spec/CLIENT.md`: six calls, `register` (leasing, hosted names, codes,
recovery, added keys, key-principal pairing through `pairing_required`), `send`, `inbox`, `sent` (delivery
status per recipient server) and part upload and fetch.

**The repository.**
- `protocol/`: the protocol as a dependency-free library, and `spec/vectors/v1.json`, which the Python
  client reproduces independently.
- `conformance/`: rebuilt as a black-box suite with a peer simulator, 158 checks by spec section, and a
  JSON report.
- `server/`: the basic server, the whole protocol on Node's standard library and sqlite, with an extension
  seam and a storage contract suite.
- `app/`: the application template (directory, pairing by email and phone, recipient policy,
  introductions, owner window, webhooks, upload checks, email bridge) rebuilt on the basic server's
  extension API, on MongoDB.
- `clients/`: the JavaScript client reduced to the six calls and verification, a CLI written by hand, an
  MCP server whose tools are fixed in its source, and a Python package following the draft.

### Second half: after external review and the first run between two laptops

**Wire** (`spec/PROTOCOL.md`, `spec/CLIENT.md`, the protocol library and the vectors).
- **Errors are RFC 9457 problem details,** sent as `application/problem+json`: `type`, `title`, `status`,
  `detail`, and the protocol's `code`, `retryable` (true exactly for `429` and `5xx`) and optional
  `details`. They replace the earlier error object. A `429`, and a `503` that knows when to retry, carry
  `Retry-After`.
- **Signature failures are told apart by status.** A request signature that fails is `401`, with
  `WWW-Authenticate: SIMON` and `details.serverTime`, and on `bad_signature` also `details.signingString`.
  An envelope or message signature that fails at deliver is `403 bad_signature`.
- **Two new codes.** `403 unsupported_algorithm` at deliver, when the author has keys valid at `sentAt`
  but none of an algorithm the receiver implements (no valid key at all stays `bad_signature`).
  `400 unsupported_version` at `send` only: an agent's own server takes no message of a version it does
  not implement, while deliver still routes one on the invariants.
- **Envelopes name `server` and `recipients`,** both signed: the origin the envelope is for, and the
  addresses in `to` that server serves. An envelope cannot be replayed to another server or stretched to
  other recipients. Deliver checks both (section 6.3, steps 2 and 5), accepts once per (id, recipient),
  and answers a repeat only when every listed recipient was accepted before. Hints are keyed by listed
  recipients and travel only to their server.
- **`algorithms` in the server document:** every signature algorithm the server verifies, both version 1
  algorithms included. Key lists keep entries of algorithms a reader does not implement, skipped, so
  `unsupported_algorithm` can be told apart from a bad signature.
- **`acts-for` claims carry `authoritative`.** A receiving server marks a claim authoritative when its
  `for` is a `mailto:` identifier and the carrier is the server that address's domain resolves to. It
  shows its agents authoritative claims always and others only from carriers it chose to trust, and
  ignores malformed claims. A client library should repeat the judgement itself.
- **Parts are kept per source,** the uploading agent or the carrier, and never served because a message
  names their hash. Bytes go to anyone only for a public message, to a server only for a message
  delivered to it, and to an agent for its own uploads and the messages in its inbox; every refusal is
  the same `404`. A recipient's server prefetches the parts of an accepted message from its carrier after
  a random delay, whatever its policy decides, so the carrier learns neither admission nor reading. An
  agent's fetch answers `503` with `Retry-After` until the bytes are there.
- **Public messages** answer `{"message","keys"}`. There is no public list of the messages that answer
  one: a reply is an ordinary message to the author. A retired agent's public messages and parts are no
  longer served.
- **Delivery timing.** No attempt before `sentAt`. The deadline is the earlier of five days after
  acceptance and 143 hours after `sentAt`, after which `sent` reports `expired`.
- **Recovery waits.** While the agent still holds a valid key, a recovery by code answers
  `202 recovery_pending` with `completesAt`, the server tells the agent with a message in its inbox, and
  any valid key of the agent cancels it with `register {"cancelRecovery":true}`. Repeating the code call
  after `completesAt` completes it. The reference server waits 72 hours.
- **Resolution.** A refused connection or a certificate not valid for the domain is `not_found`.
  `temporary` is cached at most 60 seconds; `server` for its TTL, or ten minutes when the answer states
  none, and at most an hour; `not_found` at most ten minutes; malformed and conflicting records not at
  all.
- **Key continuity by possession** (section 11.1): a server trusts a domain's new keys because a key it
  remembers signed for them, not because a document lists a remembered key.
- Local parts are in Normalization Form C. Nonces are kept until their timestamp leaves the window. The
  specification gained honest DNS, privacy and IANA sections, and the reasons are in `docs/DECISIONS.md`.

**Servers** (the basic server; the application's `MongoStore` follows its store).
- **Atomic, claimed work.** A message is stored together with its delivery rows or its arrivals, and a
  repeated `send` restores rows a store lost. Arrivals are one per (id, recipient), offered and retried
  each on its own. Deliveries are claimed under a lease and settled only by it, at most 32 POSTs at once
  and 4 to one server; a destination that does not answer is skipped for five minutes, and a `429`
  throttles its server. Inbox events are told at least once.
- **Bounded work for strangers.** Deliver counts each lookup against the client's network (IPv6 by /64)
  before making it, runs at most 32 at once, and counts failed signatures per (client network, claimed
  server) before verifying more. Part fetches run at most 4 at once and 64 MiB in flight, against a
  per-carrier quota. Connections have header, request and keep-alive timeouts and a cap.
- **Outbound calls** use TLS 1.3 or later and follow no redirects.
- **Notices** come from `postmaster@<the agent's domain>`, an ordinary signed message.
- **New settings:** `SIMON_RECOVERY_WAIT` (259200 seconds), `SIMON_MAX_CONNECTIONS` (1024),
  `SIMON_DNS_SERVERS` (DNS servers to ask instead of the system's, such as a tailnet's resolver),
  `SIMON_LISTEN_HOST` (`127.0.0.1` behind a tunnel) and `SIMON_CLIENT_IP_HEADER` (such as
  `cf-connecting-ip`, read only from connections from this machine, so rate limits see real clients).
- **Behind a load balancer.** `SIMON_TRUSTED_PROXIES` names the networks a balancer connects from, and
  `SIMON_CLIENT_IP_HEADER` (`x-forwarded-for` there) is believed from them as from this machine. The header
  is read from the right, past every trusted hop, so a client cannot choose the address its limits count.
  `SIMON_KEEP_ALIVE_TIMEOUT` (5 seconds) lets idle connections outlast the balancer's own timeout.
  `GET /health` answers `{"status":"ok"}` while the server and its store answer, `503` when the store does
  not, and nothing else. CI runs the image as a deployment does (`scripts/image-check.sh`).
  `SIMON_RATE_EXEMPT_NETWORKS` spares a hosting service's own networks the per-client `request` and
  `register` rates; its agents' rates still apply.
- **Changing address on one server** takes a new key, since a key belongs to one address there for good;
  CLIENT.md now says so, and how the old address shows the continuity before it retires.
- **Identifier claims are judged.** A registry `identifier` claim is considered only when well formed:
  about the author; `of: principal` only when the `for` header names a key; a `mailto:` or `tel:`
  identifier exactly as written; a timestamp `verifiedAt`. It is marked authoritative as an `acts-for`
  claim is, by its identifier. PROTOCOL section 12 now says that authority can come from a domain's web
  server, through its well-known answer, and that a reader acting on an email identity may require the
  TXT record. So a server now shows another
  server's claim about an email address on that server's own domain, and still drops its claims about
  addresses elsewhere unless it trusts that server. New vectors: identifier cases in `claimsConsidered`,
  and `claimsJudged`.
- **Reading agent documents to probe for addresses costs.** A new rate, `agentMiss` (100 an hour per
  client IP), counts agent documents asked for addresses with no agent served; past it, every agent
  document is `429` for that client, an agent's or not, so the refusal tells nothing. Documents served
  never count. PROTOCOL section 4 allows such a limit, and section 12 names the part prefetch as the
  other way a sender can tell whether a recipient is an agent.
- **Who takes hosted names.** A new extension hook, `allowAddress`, decides which keys may take a new
  name on a hosted domain or a lease, by a proof of the host's own in the register body, under a member
  name prefixed with its domain; a refusal is `409 address_taken`, in the words a held name gets. With no hook, names stay first come, first served. Addresses bound by a code to
  their mailbox are not asked about: the mailbox is the proof.
- **The `Store` interface changed:** `claimDeliveries` and `settleDelivery`, arrivals per recipient,
  inbox events, parts per source with `partSources`, and part fetches. Two rules joined the contract: a
  method is one change, and queues are claimed, not read. The contract suite also requires that a reader
  following the inbox cursor never skips an entry that concurrent writers add.

**Clients** (JavaScript, CLI, MCP and Python).
- **Keys only from resolution.** `verifyAuthor`, `fetchAgentDocument`, the CLI's `verify` and
  `document`, MCP's `verify_message` and Python's `verify_author` take no server: keys come only from
  the server the author's domain resolves to. `--server` and `--allow-http` left `verify`. A resolver
  stays as a seam that only code can pass, for tests and local development.
- **A trust record.** `verify` answers `authorSigned`, `authorServer`, `kind` and `principal`, with
  `id`, `basis` (`agent-asserted`, `key-pairing` or `server-claim`), and for a claim `claimant`,
  `authoritative` and `scope`, and `proves` in words. It replaces the earlier yes-or-no answer about the
  principal. An inbox or `wait` entry's claims count with their carrier.
- **Provenance-labelled output.** Messages, headers, parts and claims are printed inside
  `{"untrusted":{"from","basis","content","invisible"?}}`, apart from what the client and the agent's own
  server say; `invisible` lists tag characters, bidirectional controls and zero-width characters by path.
  MCP sends each in a content item of its own, marked untrusted, and has no `call`.
- **The workspace sandbox.** Every file the CLI and MCP server read or write is in `SIMON_WORKSPACE` (by
  default the working directory), links resolved, never under `SIMON_HOME`; anything else is
  `path_refused`. No output names where the key is kept, and `--add-key` names a file in `SIMON_HOME`.
- **`wait`.** It polls until a message not shown before arrives, prints it and exits 0, or exits 3 at
  `--timeout` (600 s), with `--from` and `--interval`. What it has shown is kept in
  `$SIMON_HOME/wait.json`, so each message is shown once, across sessions and across the CLI and the MCP
  server (`wait_for_message`, 1 to 300 s).
- **The revised wire:** problem details read and passed through, `unsupported_version`,
  `unsupported_algorithm` and `403 bad_signature`, `expired` in `sent`, and `recovery_pending` with
  `--cancel-recovery` (`cancelRecovery`).
- **Python** follows all of it, reproduces the revised vectors, has no default server, and keeps
  `address.json` and `wait.json` as the JavaScript CLI does.
- **Package names.** The packages moved off the `@agnt` scope, which is not this project's on npm. (They
  have since been renamed again; see "Packages for npm" above.)
- **Packed for Node 24.** `npm run build` compiles the protocol library and the JavaScript client to
  JavaScript with type declarations and packs them as tarballs for Node 24.6.0 or later; the sources stay
  the source of truth. CI installs them on Node 24.6.0 and runs both suites, the vectors among them,
  against the compiled files.
- **The skill** (`skill/SKILL.md`) gained the rules that hold everywhere and the conversation loop of
  wait, read, verify, reply.

**The application template.**
- **Privacy defaults.** People who have not listed themselves are found by nobody but their own
  connections. A session sees only what belongs to the identifiers proven in it; joining two people needs
  confirmation (`409 merge_required`); an identifier last proven more than a year ago grants nothing until
  proven again; `DELETE /api/me` erases a person. Others' attestations wait for their subject, and a fact
  is corroborated only by authors at three distinct verified domains. The graph tells nobody about anyone
  else's edges. Introductions reach only people who joined and listed themselves. Retention periods are
  fixed for each kind of record.
- **Principal-reserved routes.** What decides who may reach an agent, what is published about it, where
  it is woken, whether it lives, which introductions its person joins and what it writes into the graph
  is reserved to its principal. A paired agent's call is held as a request (`202 awaiting_principal`)
  until its person approves or declines it in the owner window, or it expires after 7 days; without the
  owner module it is `403 principal_required`.
- Key principals sign in to the owner window by signing a challenge. Notices state facts, with anything
  someone else wrote quoted in their JSON part. `human-consulted` resets the agent-only run only on
  evidence. Errors are problem details. `MongoStore`'s inbox never skips an entry written late.
- The application runs on Amazon DocumentDB (8.0) as well as MongoDB: plain update operators only, no update
  pipelines anywhere, reads from the primary whatever the connection string asks, and duplicate keys
  recognised by the index DocumentDB names. The store contract runs against a real deployment with
  `SIMON_TEST_MONGO_URI`.

**Conformance.**
- 182 checks (167 must, 15 should), up from 158: envelopes' `server` and `recipients` and their order,
  `403` at deliver, problem details and `WWW-Authenticate: SIMON`, `algorithms`, `authoritative` claims,
  identifier claims judged as acts-for claims are (`inbox.claims-identifier`), parts never served for
  naming a hash and prefetched, delivery timing, and recovery waits.
- Removed: `public.replies`, `public.replies-to-author-only`, `send.unknown-version` and
  `outbound.unknown-version`.
- New options: `--retire-command`, `--second-peer-domain` and `--second-peer-port`, `--prefetch-wait` and
  `--recovery-wait`.
- **Against a server elsewhere.** `--peer-origin` (and `--second-peer-origin`) puts the simulator behind a
  public tunnel: it announces the tunnel's origin, takes its name as the peer domain, and answers the
  well-known resolution for it, so the suite can run against a remote server such as a staging deployment.
- The toy server under test speaks the new wire, with more planted faults, each caught by its own check.

**Examples.**
- **`examples/two-laptops`** puts two people's laptops on SIMON across two public Cloudflare quick
  tunnels, with no shared network, account or name: `start.sh`, which the person runs; `JOIN-SIMON.md`,
  which a coding agent follows to prepare the laptop and hand a fresh session the conversation; and a
  read-only live viewer. It replaced an earlier version over Tailscale.
- The demo and the model-driven agent follow the revised clients.
