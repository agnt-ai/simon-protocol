# Template servers

A template server is a plain, no-frills SIMON server in one language, written to be read: the shortest path from the spec to a server someone can run, fork and trust. It is a starting point, not a product. Every template lives in `templates/<language>/`. The first is the basic server in Node, now in [`server/`](../server), which moves to `templates/node/` when the repository splits for its public release. Python is next, and any language is welcome.

Templates beyond the basic server, such as client apps or social shapes (followers, forums, mutual connections), are not designed in advance. They are extracted from real apps built on SIMON once those apps work, the way Rails was extracted from Basecamp.

## What every template is

- **Complete for its profile.** It passes the conformance suite for *SIMON Core Server*, and, when it keeps people's history (CLIENT.md, "Which servers keep a history"), for *SIMON Hosting Server*. The profiles are still to be written ([CORE.md](CORE.md#conformance-and-profiles)). Its README carries the suite's latest report.
- **Nothing else.** No people, directory, graph, policy, bridges or billing. Those are modules ([MODULES.md](MODULES.md)) or products, built on the template's extension seam, never inside it.
- **Small dependencies.** The language's standard library, an embedded database (sqlite), and the protocol library for that language when one exists. Anything more is justified in the README.
- **The same shape in every language,** so a reader who knows one knows them all (below).
- **Safe by default.** Every MUST of PROTOCOL.md section 11 is on unless a development flag says otherwise, and that flag refuses to start on a public address.
- **Configured by environment variables** with the same names in every language (`SIMON_ORIGIN`, `SIMON_HOSTED_DOMAINS`, `SIMON_DB`, ...), as `server/README.md` lists them.

## The shape

One file per concern, named for the spec section it implements. The Node template's names are the reference:

| Concern | Spec | Node template | What it does |
| --- | --- | --- | --- |
| Configuration | | `config.ts` | Reads and checks every setting once, at startup. |
| HTTP | PROTOCOL 9 | `http.ts`, `errors.ts` | Routes, body limits, problem details. |
| Signed requests | PROTOCOL 8 | `auth.ts` | Checks section 8 signatures and nonces; finds the agent key or grant. |
| Resolution | PROTOCOL 3 | `resolver.ts`, `net/dns.ts` | TXT, then well-known; caching bounds; `temporary` kept apart. |
| Outbound HTTP | PROTOCOL 9, 11.2 | `net/fetch.ts`, `net/ip.ts` | TLS 1.3, no redirects, public addresses only. |
| Key continuity | PROTOCOL 11.1 | `continuity.ts` | Remembers which server keys signed, and holds a domain whose keys changed. |
| Documents | PROTOCOL 4 | `public.ts` | Serves the server and agent documents; the probing budget. |
| Deliver | PROTOCOL 6 | `deliver.ts` | The checks of section 6.3, in order, and nothing that depends on a recipient. |
| Fan-out | PROTOCOL 6.3 | `fanout.ts` | After the answer, offers each arrival to its recipient. |
| Outbox | PROTOCOL 6.3 | `outbox.ts` | Delivers with leases, retries and the deadline. |
| Signals | PROTOCOL 6.4 | `signal.ts` | Checks and sends signals; never stores them as messages. |
| Published messages | publishing profile, section 1 | `published.ts`, `readers.ts` | Serves published messages to whoever their audience admits. |
| Parts | PROTOCOL 7.2 | `parts.ts` | Bytes per source; fetching from carriers. |
| The client API | CLIENT | `register.ts`, `account.ts`, `send.ts` | Registration, recovery, keys, and sending. |
| Sync and webhooks | CLIENT | `sync.ts`, `webhooks.ts` | `sync` and `sent`; verified, signed webhooks. The history calls are to be written. |
| Grants | CLIENT | `grants.ts` | Delegated access (to be written). |
| Rates | PROTOCOL 11.2 | `rate.ts` | Limits by network prefix and per client. |
| Work after the answer | | `worker.ts` | Runs fan-out, outbox, fetches and sweeps. |
| Storage | | `store/store.ts`, `store/sqlite.ts`, `store/contract.ts` | One interface; one embedded implementation; its rules as tests. |
| Extensions | | `extensions.ts` | The seam modules plug into: routes, admit, claims, address rules, events. |
| Testing seam | | `server.ts` | DNS, HTTP and the clock are passed in, so tests run a whole federation in one process on a fake network and a movable clock. |

A template in another language keeps these concerns and these boundaries. It names its files in its own language's style (`resolver.py`), and says where it differs.

**The store contract travels.** The rules of `server/src/store/contract.ts` (uniqueness is atomic, a method is one change, queues are claimed, nothing expires except through `sweep`) are what make a server correct under concurrency. A template states them as tests in its own language, and every store it ships passes them.

## Starting a template in a new language

**Templates are built by agents.** Each one is built by an agent working from the spec alone, in a checkout that holds no other template's code. Each question the agent has to ask is a spec bug, fixed in the text before the template goes on, so every template also tests the spec.

1. **Read** PROTOCOL.md, CLIENT.md and the registry. Not the Node code: a template that copies another inherits its bugs (see [SECOND-IMPLEMENTATION.md](SECOND-IMPLEMENTATION.md)).
2. **Reproduce every vector** in `spec/vectors/` first, with a protocol library for the language. That library is half the work, and is useful alone.
3. **Build the concerns in the order above,** each with its tests, and run the conformance suite against the result from the first day it answers `/simon/server`.
4. **Federate** with the Node template: two servers, one message each way, as the README's quickstart does.
5. **Open a pull request** adding the template under `templates/<language>/`, with its conformance report. It is reviewed against this page.

## Python, next

The Python template follows the shape above on the standard library (`asyncio`, `sqlite3`, `ssl`), with the protocol rules of `clients/python/simon/` moved into a `protocol` package the template and the client share. The client verifies in pure Python, but a server signs, and must sign in constant time: the template signs Ed25519 with `cryptography`, and ML-DSA-65 with `cryptography` where the pinned version supports it, or else with one vetted ML-DSA library. Its README names the versions it pins, and verifying ML-DSA-65 in pure Python, which takes seconds, is never on its request path.
