# @agnt-protocol/server

The basic SIMON server: everything in [`spec/PROTOCOL.md`](../spec/PROTOCOL.md) and [`spec/CLIENT.md`](../spec/CLIENT.md), and nothing else. No people, directory, graph, blocklists, webhooks or bridges; those are extensions. Runtime dependencies: `@agnt-protocol/protocol` and Node's standard library (`node:http`, `node:sqlite`, `node:crypto`, `node:dns`). Node 26.

## Run

```sh
SIMON_DEV=1 SIMON_ORIGIN=http://localhost:8080 SIMON_HOSTED_DOMAINS=example.test node server/src/main.ts
```

In production: an https origin (TLS in front of the server, or `SIMON_TLS_CERT_FILE` and `SIMON_TLS_KEY_FILE`), a server key, and the domains you serve pointed at it (`_simon.<domain> TXT "v=simon1; server=<origin>"`).

## Configuration

Every variable, read once at startup; an invalid value throws. Source: `src/config.ts`.

| Variable | Meaning | Default |
| --- | --- | --- |
| `SIMON_ORIGIN` | This server's origin, `https://host[:port]` | required |
| `SIMON_DEV` | `1`: development. http and local hosts allowed, register codes logged, a throwaway key when none is set | `0` |
| `SIMON_HOSTED_DOMAINS` | Domains whose names agents take at once, comma separated | none |
| `SIMON_LEASE_DOMAIN` | Domain for leased addresses (`register` with a key alone) | none |
| `SIMON_SERVER_KEY` / `_FILE` | Signing key: `<alg>:<base64url 32-byte seed>` (`scripts/server-keys.sh` makes one), or a PKCS #8 PEM file | required outside dev |
| `SIMON_NEXT_SERVER_KEY` / `_FILE` | Announced next key: listed, not used. List it 10 minutes before swapping it in | none |
| `SIMON_DB` | sqlite file; `:memory:` for none | `simon.sqlite` |
| `SIMON_PORT` | Port | `8080` |
| `SIMON_LISTEN_HOST` | The address to listen on; `127.0.0.1` behind a tunnel | every interface |
| `SIMON_CLIENT_IP_HEADER` | A header proxies set to the client's address: `x-forwarded-for` behind a load balancer, `cf-connecting-ip` behind Cloudflare. Believed only from this machine and from `SIMON_TRUSTED_PROXIES` | none: the connection's address |
| `SIMON_TRUSTED_PROXIES` | Networks a load balancer connects from, in CIDR notation, comma separated, each `/8` or narrower. Needs `SIMON_CLIENT_IP_HEADER` | none: this machine only |
| `SIMON_KEEP_ALIVE_TIMEOUT` | Seconds an idle connection stays open. Behind a load balancer, longer than its idle timeout | `5` |
| `SIMON_TRUSTED_CLAIM_SERVERS` | Origins whose claims agents here are shown, beyond the authoritative ones (below) | none |
| `SIMON_DOH_RESOLVERS` | Two or more DNS-over-HTTPS JSON endpoints; every TXT answer must agree with them | none |
| `SIMON_DNS_SERVERS` | DNS servers to ask instead of the system's, IP addresses (a tailnet's `100.100.100.100`, for one) | the system's |
| `SIMON_RATES` | Overrides, `name=count/seconds,...`; names in `DEFAULT_RATES` | see `config.ts` |
| `SIMON_PUBLIC_SUFFIX_LIST` | A newer copy of the Public Suffix List (`public_suffix_list.dat`) to judge registrable domains by; its ICANN section is read, and a file without its section markers or with fewer than 5000 rules there stops the server from starting | the snapshot of 2024-01-07 that ships in `src/net/public-suffixes.ts` |
| `SIMON_RETIRED_AGENT_DOCUMENTS` | `private`: a retired address answers its agent-document lookup with the same 404 as an unknown address. `public`: it answers its signed retired document, keys and unpairing included (see Storage). Any other value stops the server from starting | `private` |
| `SIMON_RATE_EXEMPT_NETWORKS` | Networks whose clients the per-client `request`, `register`, `codeClient` and `agentMiss` rates do not count, in CIDR notation, comma separated, each `/8` or narrower: a hosting service that registers and speaks for many agents from a few addresses. Its agents' own rates (`send`, `destinations`, `upload`, `code`) still apply | none |
| `SIMON_KEY_CHANGE_HOLD` | Seconds to hold a domain whose server signs with a key it was not seen to vouch for (spec 11.1) | `3600` |
| `SIMON_RECOVERY_WAIT` | Seconds a recovery by code waits while the agent still holds a valid key; the agent is told, and the address is sent a code that cancels it | `259200` (72 h) |
| `SIMON_MAX_CONNECTIONS` | Connections served at once | `1024` |
| `SIMON_RETENTION_DAYS` | Days messages are kept (at least 7) | `30` |
| `SIMON_DEV_RESOLVE` | Development only: `domain=origin,...` answered without DNS | none |
| `SIMON_TRUSTED_NETWORKS` | Private networks outbound calls may reach, in CIDR notation, comma separated. Each is `/8` or narrower; `0.0.0.0/0`, `::/0` and anything broader than `/8` stop the server at startup. Calls stay https only | none: public addresses only |
| `SIMON_TLS_CERT_FILE`, `SIMON_TLS_KEY_FILE` | Serve https directly with this PEM certificate chain and private key. Both or neither; the origin must then be https | plain http (put TLS in front) |

**Outbound calls** (deliveries, documents, well-known answers, part fetches) go through an SSRF guard:
https only, TLS 1.3 or later, no redirects, and only to public addresses, so a domain cannot point this
server at a private one. Lookups made before a delivery's signature verifies are counted against the
client's network (`lookup` in `DEFAULT_RATES`) and against the registrable domain of the name looked up
(`lookupDomain`, by the Public Suffix List's ICANN section, counted in the store so every process shares
it), only when made, and at most 24 run at once. Those a
delivery asks for once its carrier is known, its recipients' domains and its claims, are counted against
the carrier (`carrierLookup`) and run in a pool of their own, at most 8 for one carrier. An agent's send and
the outbox look up in a third pool, which nothing from outside can fill. `SIMON_TRUSTED_NETWORKS` is the one exception, for servers that federate over a private
network. A host with any address outside the public internet and outside every trusted network is
refused.

**Probing for addresses.** Anyone may read an agent document, which says an agent exists: verification
needs that. To make testing many addresses expensive, the server counts each client's requests for
addresses it has no agent for (`agentMiss` in `DEFAULT_RATES`, 100 an hour per client IP). Past that,
the client is answered `429` for every agent document, an agent's or not, until the hour ends, so the
refusal tells nothing about any address. Verifying a message asks for an agent that wrote it, so other
servers' verification seldom counts. A signed request from another server gets no larger budget:
anyone with a domain can sign as a server.

**Claims from other servers.** A carrier's claims about a message's author are its word, not proof.
Agents here are always shown a carrier's authoritative claims: an `acts-for` or an `identifier` for an
email address on the carrier's own domain. They are shown its other claims, `operator` and claims about
addresses elsewhere among them, only when the carrier's origin is in `SIMON_TRUSTED_CLAIM_SERVERS` (spec
section 6.2). So with the default settings, agents here see no `operator` claim from another server, and
no claim about an address that server does not speak for. To show a carrier's, list it:
`SIMON_TRUSTED_CLAIM_SERVERS=https://simon.partner.example`.

**The well-known answer.** When this server's origin host is itself a hosted domain or the lease domain,
the server answers `GET /.well-known/simon` with `{"server": <origin>}`. That domain then resolves to it
by the well-known method of spec section 3, with no TXT record.

## Behind a load balancer

The server can run as one container behind a load balancer that ends TLS, such as an AWS Application
Load Balancer in front of an ECS service. The image is the Dockerfile's default stage (`docker build -t
simon-server .`): it listens on 8080 with plain http and keeps its sqlite file in `/data`.
`scripts/image-check.sh` builds it and runs it this way.

```sh
SIMON_ORIGIN=https://simon.example.com            # the public origin, https at the balancer
SIMON_SERVER_KEY_FILE=/run/secrets/simon-server-key   # or SIMON_SERVER_KEY, from a secret store
SIMON_HOSTED_DOMAINS=example.com
SIMON_CLIENT_IP_HEADER=x-forwarded-for
SIMON_TRUSTED_PROXIES=10.0.0.0/24,10.0.1.0/24    # the balancer's own subnets, not the whole VPC
SIMON_KEEP_ALIVE_TIMEOUT=65                      # longer than the balancer's idle timeout (60 s on ALB)
```

- **The client's address.** Rate limits count clients by address. The balancer appends the address it
  heard from to `X-Forwarded-For`, and the server reads the list from the right, past every address in
  `SIMON_TRUSTED_PROXIES`: the first one outside is the client. Name only the balancer's own subnets; a
  network that holds anything else, a whole VPC for one, lets what runs there choose the address it is
  counted under. The balancer appends to the header without client ports (on ALB, the default `append`
  mode with `routing.http.xff_client_port.enabled` off): an entry with a port is no address, so every
  client would be counted as the balancer, and a balancer that does not append passes on what clients
  wrote.
- **A service of your own in front.** A service that registers and speaks for many agents reaches the
  server from a few addresses, which the per-client `request` and `register` rates would soon refuse.
  `SIMON_RATE_EXEMPT_NETWORKS` names its networks; they are judged by the client's address as read above,
  so nobody outside the trusted proxies' networks can claim one, and nobody inside them should be able
  to. Its agents' own rates (`send`, `destinations`, `upload`, `code`) still
  apply, and so do `lookup` and `badSignature`, which bound deliveries from other servers.
- **Health checks.** `GET /health` answers `200 {"status":"ok"}` while the server and its store answer,
  and `503` when the store does not. It says nothing else.
- **Keep-alive.** A balancer reuses idle connections to its targets. If the server closes one first, a
  request on it fails with `502`, so the server's timeout must be the longer. Raise it only when nothing
  but the balancer can reach the server: one client holding long-lived idle connections fills
  `SIMON_MAX_CONNECTIONS` within its request rate.
- **One task.** sqlite has one writer: run exactly one server on the data, and never start a replacement
  beside it (on ECS, a maximum of 100 percent and a minimum healthy of 0). `SIGTERM` stops it cleanly.
- **The volume.** `/data` is a block volume, not a network file system, whose sqlite locking cannot be
  relied on. It must be writable by the image's user, `node` (uid 1000). Snapshot it for backups.
- **DNS.** Each hosted domain points at the origin: `_simon.<domain> TXT "v=simon1; server=<origin>"`.

## Two laptops over Tailscale

Two people, each running a basic server on their own laptop, can federate over a
[Tailscale](https://tailscale.com) tailnet with no public DNS and no open ports. Each server hosts
addresses on its laptop's MagicDNS name, for example `ada-laptop.tail1234.ts.net`, and serves https on
port 443 with the certificate `tailscale cert` issues for that name. Each domain resolves by the
well-known answer its own server gives, because no TXT record can be added under `ts.net`.

In the tailnet's admin console, turn on MagicDNS and HTTPS certificates. Then, on each laptop, from
this repository:

```sh
NAME=$(tailscale status --json | jq -r '.Self.DNSName | rtrimstr(".")')     # ada-laptop.tail1234.ts.net
tailscale cert "$NAME"                                  # writes $NAME.crt and $NAME.key here
[ -f simon-keys.env ] || (umask 077; scripts/server-keys.sh > simon-keys.env)   # once: the server key
. ./simon-keys.env
SIMON_ORIGIN="https://$NAME" SIMON_PORT=443 SIMON_HOSTED_DOMAINS="$NAME" \
SIMON_TLS_CERT_FILE="$NAME.crt" SIMON_TLS_KEY_FILE="$NAME.key" \
SIMON_TRUSTED_NETWORKS=100.64.0.0/10,fd7a:115c:a1e0::/48 SIMON_DB=simon.sqlite \
node server/src/main.ts
```

- **The port.** Resolution fetches `https://<domain>/.well-known/simon`, so the server listens on 443. On
  Linux a process needs permission for that, for example `sudo sysctl net.ipv4.ip_unprivileged_port_start=443`.
- **The networks.** `100.64.0.0/10` and `fd7a:115c:a1e0::/48` are the IPv4 and IPv6 ranges Tailscale gives
  its devices. A MagicDNS name has addresses in both, and the guard refuses a host if any of its
  addresses is outside the trusted networks.
- **Name lookups.** The server asks the system's DNS servers through c-ares, not the operating system's
  resolver library, so the other laptop's name must resolve that way. This prints its tailnet addresses
  when it does: `node -e 'new (require("node:dns").promises.Resolver)().resolve4(process.argv[1]).then(console.log)' other-laptop.tail1234.ts.net`.
- **If the name does not resolve that way,** add `SIMON_DNS_SERVERS=100.100.100.100`, Tailscale's own resolver.
- **The key.** Keep `simon-keys.env` (mode 600) and reuse it: a server whose key changes wholesale is held
  by its peers for `SIMON_KEY_CHANGE_HOLD` seconds (spec section 11.1).

Agents then register on the laptop's own name, for example
`simon register --server "https://$NAME" --address "ada@$NAME"`, and write to agents on the other
laptop's name.

Two laptops with no tailnet in common can federate over public Cloudflare quick tunnels instead, with the
server behind the tunnel (`SIMON_LISTEN_HOST=127.0.0.1`, `SIMON_CLIENT_IP_HEADER=cf-connecting-ip`):
[examples/two-laptops](../examples/two-laptops/README.md) does it in one script.

## Layout

| File | Responsibility |
| --- | --- |
| `server.ts` | `createServer`: assembly, routing, the request pipeline |
| `http.ts` | Request/Reply, router, the `node:http` adapter with body caps |
| `deliver.ts` | `POST /simon/deliver`, spec 6.3 in order |
| `outbox.ts` | Delivery to other servers: claimed rows, caps on POSTs, backoff to the deadline, dead and throttled destinations |
| `fanout.ts` | Arrivals offered to recipients here through the admit chain, each on its own; inbox events told |
| `parts.ts` | Uploads, the per-source reading rules, and part fetches from carriers (prefetched, bounded) |
| `register.ts`, `account.ts` | The agent's address and keys: register and recovery; the account, keys, cancelling a recovery, unpairing |
| `send.ts`, `sync.ts`, `public.ts` | Sending, retained sync and public reads |
| `signal.ts`, `webhooks.ts` | Client signals and verified webhook wakeups |
| `notice.ts` | Messages from the server itself to an agent here, as `postmaster@<its domain>` |
| `resolver.ts`, `continuity.ts` | Resolution and documents, bounded and cached; key continuity by possession |
| `auth.ts` | Signed requests, nonces recorded after verification |
| `net/` | c-ares DNS with DoH confirmation, the SSRF-guarded client, IP rules |
| `store/` | The `Store` interface, sqlite, and the contract suite |
| `extensions.ts`, `config.ts`, `rate.ts`, `worker.ts`, `main.ts` | The seam, settings, limits, the loop, the process |
| `context.ts`, `errors.ts` | What the parts share; the protocol's problem-detail errors |
| `testing.ts` | A fake clock, DNS and network, for tests here and in applications |

## Extensions

An application adds behaviour by passing extensions; it never edits the core. Every hook is the list of all extensions' hooks, in order.

| Hook | Called | Returns |
| --- | --- | --- |
| `routes` | Requests to its paths (core paths cannot be replaced) | a `Reply` |
| `admit(arrival, api)` | Per recipient here, after the 202 | `'accept'` or `'refuse'` or `'later'` ends the chain; `undefined` passes. Default: accept |
| `claimsFor(message, agent, api)` | On `send` | claims for the envelope |
| `allowAddress(request, api)` | `register` for a new hosted name or lease, before any pairing | `'allow'` or `'refuse'` (`409 address_taken`) ends the chain; `undefined` passes. Default: allow |
| `verifyPrincipal(request, api)` | `register` with a `mailto:`/`tel:` `for` | `{status:'verified'}`, `{status:'pending', body}`, or `undefined` |
| `upload(upload, api)` | `PUT /simon/parts/<sha256>`, before the bytes are kept | nothing; a thrown WireError refuses the upload |
| `on.stored / inbox / delivered / deliveryFailed / recovered` | After the event (`inbox` at least once) | nothing; failures are logged |
| `on.unroutable` | Recipients whose domain names no SIMON server | `true` when it took them: they count as delivered, and later listeners are not told |

`api` (`ServerApi`) offers `config`, `store`, `now()`, `log`, `authenticate(req)`, `admit(address, id)` (release a `'later'`), `offer(address, id)` (a stored message to an agent here, through the admit chain), `send(message, hints?)` (as an agent here, checked as `send` checks it) and `retire(address)`.

```ts
import { createServer, json, loadConfig, SqliteStore, type Extension } from '@agnt-protocol/server';

const held = new Map<string, string>(); // message id -> recipient
const quiet: Extension = {
  name: 'quiet-hours',
  admit: ({ id, recipient }) => {
    const hour = new Date().getUTCHours();
    if (hour >= 6) return undefined; // no opinion: the next link decides
    held.set(id, recipient);
    return 'later';
  },
  routes: [
    {
      method: 'POST',
      path: '/app/release',
      handle: async (req, api) => {
        const agent = await api.authenticate(req);
        for (const [id, to] of held) if (to === agent.address && (await api.admit(to, id))) held.delete(id);
        return json({ released: true });
      },
    },
  ],
};
const config = loadConfig();
createServer({ config, store: new SqliteStore(config.database), extensions: [quiet] }).listen();
```

## Storage

The ordinary SQLite Store refuses legacy standalone schema2. The separate
[offline candidate conversion tool](SQLITE-V2-MIGRATION.md) preserves a WAL-aware core/app-outbox
cohort and validates a new current-schema copy under explicit maintenance prerequisites. Its output stays
blocked for activation, with no operational promotion/reset override; passing source, CLI and synthetic
tests says nothing about readiness of real data, hosts or runtimes.

A retired agent-document lookup answers the same 404 as an unknown address by default (`'private'`).
Publishing signed retirement evidence is an explicit opt-in: `SIMON_RETIRED_AGENT_DOCUMENTS=public` in
the environment (or `retiredAgentDocuments: 'public'` in `defineConfig`), or `retiredAgentDocuments: 'public'`
passed to `createServer`, which overrides the configuration. The setting is validated and captured at
construction, and applies to both `handle` and the HTTP listener. Invalid values fail before workers
start. It does not remove internal retired records or change retired-key authentication, unpairing
retries, or previously published signed messages.

`store/store.ts` is everything the core keeps, with its uniqueness and retention rules written on the interface. Another store proves itself with the contract suite:

```ts
import { storeContract } from '@agnt-protocol/server/store-contract';
storeContract('mongo', () => new MongoStore(/* a fresh database */));
```

## Testing

`@agnt-protocol/server/testing` is the fake outside world the tests use: a movable `Clock`, `FakeDns`, and `FakeNet`, whose origins answer in-process. An application runs whole federations of its own servers on it.

```sh
node --test server/test          # spec rules, federation on a fake network, hardening, the store contract
node server/scripts/smoke.ts     # two real server processes, a message each way over localhost
```

To run the conformance suite against it, start the server with its peer simulator's domain resolved
without DNS (`SIMON_DEV_RESOLVE` is honoured only with `SIMON_DEV=1`, and refused at startup otherwise) and
rate limits loose enough for one run:

```sh
SIMON_DEV=1 SIMON_ORIGIN=http://127.0.0.1:8080 SIMON_PORT=8080 SIMON_HOSTED_DOMAINS=sut.test \
SIMON_LEASE_DOMAIN=lease.sut.test SIMON_DB=:memory: \
SIMON_RATES=register=1000/3600,badSignature=100000/3600,code=100/3600,codeClient=1000/3600,deliver=100000/3600 \
SIMON_DEV_RESOLVE=sut.test=http://127.0.0.1:8080,lease.sut.test=http://127.0.0.1:8080,peer.test=http://127.0.0.1:47100 \
node server/src/main.ts
```

and, in another terminal, `node conformance/src/cli.ts --server http://127.0.0.1:8080 --hosted-domain sut.test --format text`.
[conformance/README.md](../conformance/README.md) explains every option, including the code-flow checks,
which read the register codes this server logs in development. How the server runs recovery and keys, and
its other choices, are in [docs/REFERENCE-SERVER.md](../docs/REFERENCE-SERVER.md).

### Client lifecycle and wakeups

Registration creates or pairs an address at `POST /simon/register`. Recovery uses `POST /simon/recovery`;
`GET /simon/recovery` reports pending state to an agent key. The old registration call does not recover a
held address. A pending mailbox proof can complete for seven days after its `completesAt`, including
legacy proofs that lack a nonce; it never grants old keys new cancellation authority.

`GET /simon/sync` includes received messages, newly accepted sends and transient signals. Its encrypted
account-bound tokens survive worker restarts through the shared Store secret. Unknown, tampered,
cross-account and expired tokens fail with `410 token_expired`. Schema 8 preserves historical received
positions; old stores have no trustworthy discriminator for historic local sends, so each affected device receives an explicit `410 token_expired` with `details.reason=history_migration`
and an account-bound `details.resumeToken`. Passing that token explicitly reads preserved received
history and newly tracked sends; starting without a token continues to report the old sent-history gap.
This never invents old sent history or acknowledges a gap for other devices.

`POST /simon/send-signal` carries registry signal types. Webhook creation, verification and deletion use
`/simon/webhooks`: at most five HTTPS URLs per account, verification before wakeups, signed posts,
one-second quiet time and lease-fenced retries. An unverified URL whose first verification post fails
must be deleted and recreated by its owner; it sends no changed notifications. Three days of failures
switch off a verified webhook.

Retraction admission is bounded by host policy: 4096 accepted IDs globally, 256 per author, and 4 MiB
of canonical receipt/journal state by default. Configure `retractions` on the SQLite/Mongo Store
constructor with `maxRecords`, `maxPerAuthor`, and `maxBytes` (at most 8 MiB). An exact repeat uses
its original receipt. Accepted suppression is never evicted to admit another entry, so a full store
returns a generic `503 unavailable` before acceptance. This conservative permanent allocation can
exhaust; it is an overload hold rather than permission to relist retracted content.
