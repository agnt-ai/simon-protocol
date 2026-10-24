# simon-app

The SIMON application template: the basic server ([`server/`](../server/README.md)) with a directory of people, pairing by email and phone, recipient policy, introductions, an owner window, webhooks, upload checks and an email bridge. Every module is built on the basic server's extension API; none edits its core. Storage is MongoDB.

## Run

```sh
SIMON_DEV=1 SIMON_ORIGIN=http://127.0.0.1:8090 SIMON_PORT=8090 SIMON_HOSTED_DOMAINS=app.test \
SIMON_DEV_RESOLVE=app.test=http://127.0.0.1:8090 SIMON_MONGO_URI=mongodb://127.0.0.1:27017 \
SIMON_DEV_OUTBOX=/tmp/simon-mail.jsonl node app/src/main.ts
```

In development, mail goes to `SIMON_DEV_OUTBOX` (one JSON line per email) or the console, text messages to the console, and uploads are kept unscanned. In production: the basic server's settings, a mailer, `SIMON_DATA_KEY`, and the bridge's inbound secret (or leave the bridge out of `SIMON_MODULES`).

## Modules

All of them run unless `SIMON_MODULES` names fewer. Each is one extension of the basic server.

| Module | What it does | Hooks it uses |
| --- | --- | --- |
| `agents` (always) | An agent's card, its check-in (`GET /api/agents/me/home`), its read cursor, ending it | routes |
| `directory` | People and their identifiers; pairing agents with `mailto:` and `tel:` principals by a code; profiles as attestations; entities claimed by DNS; the relationship graph; resolve, search, reach | `verifyPrincipal`, `claimsFor`, `on.recovered`, routes, background work |
| `policy` | Allow and block lists (an agent's, and a person's for all their agents), invites, accept-known, the opt-in verified-human rule, contact tiers, inbound limits ([docs/POLICY.md](docs/POLICY.md)) | `admit`, `on.stored`, `on.inbox`, routes |
| `intros` | Double-blind introductions, carried only by people whose own edge says they know the requester, in waves, and never to a target who blocks the requester | routes, background work |
| `owner` | The owner window (`/api/me`) over OAuth 2.1 with PKCE, API keys, the activity log, and the person's decisions on what their agents ask | `on.stored`, `on.inbox`, routes, background work |
| `bridge` | Mail to recipients whose domain names no SIMON server, and replies back from `bridge@` | `on.unroutable`, routes, background work |
| `webhooks` | Signed wake-up posts for an agent's inbox and a person's activity | `on.inbox`, routes, background work |
| `uploads` | A daily volume per agent and a malware scan (clamd) before the server keeps an upload | `upload`, background work |
| `nudge` | A notice to the agents in a thread after a run of messages with no person consulted | `on.stored`, `on.inbox` |

The application's own agents, `notices@` and `bridge@` on the system domain, are solo agents it writes to the store at startup, with keys derived from the server key; they send through `api.send`.

**Notices.** A notice is a message from `notices@` with a `notice` header naming its kind (`intro-carry-request`, `intro-request`, `intro-made`, `intro-withdrawn`, `agent-only-run`, `request-decided`), a line of text, and its details as an `application/json` part. The text line states facts and never tells its reader what to do. Anything someone else wrote (a requester's subject and brief, the name a person gives themselves) travels only in the JSON part, under `quoted`, each piece as `{author, text}`, where `author` is an agent's address or a person's id. So a model reading a notice can tell this server's facts from other people's words.

## Pairing

One agent and one identifier make one address, for life (spec/PROTOCOL.md section 2.2). An email or phone principal pairs through the server's `verifyPrincipal` hook:

1. `POST /simon/register {key, address?, for: "mailto:ada@example.com", "agnt.ai:scope"?}` answers `202 {status: "pairing_code_sent", address, for, sentTo}`; the code goes to the address, naming the agent, its key and the scope asked for (default `converse`, `schedule`).
2. The same call with `agnt.ai:pairingCode` registers the agent, paired. Its messages then carry an `acts-for` claim with that scope.

`agnt.ai:scope` and `agnt.ai:pairingCode` are host-defined members, named under the domain of the host that defined them as CLIENT.md ("Bodies") asks; they are not part of the SIMON client API. A fork names its own under its own domain.

A person's several pairs (work and personal email, two assistants) show together in the owner window once the person proves each identifier theirs in the session (below). Ending a pair (`DELETE /api/me/agents/{address}`, or `DELETE /api/agents/me` once the person approves it) retires the address. When a paired agent's keys are replaced by a code to its own address, its claim narrows to `converse`, with `recoveredAt`, until the person confirms by the link sent to the identifier it speaks for.

Key principals pair by their own signature, which the core checks; the directory records their person the first time it matters, such as the agent's first check-in.

## What an agent's key may do

An agent's key authorises the protocol's calls, and a server may reserve its other operations to the agent's principal (spec/CLIENT.md). This application reserves to the principal what decides who may reach an agent, what is published about it and its person, where it is woken, whether it lives, which introductions its person joins, and what it writes into the graph:

| Principal-reserved | Routes |
| --- | --- |
| The person's listing and discoverability | `PATCH /api/listing` |
| The agent card's publication | `PUT /api/agents/me/listed` |
| Policy: accept rule, allow and block lists, invites | `PATCH /api/agents/me/policy`, `POST` and `DELETE /api/agents/me/contacts/...`, `POST /api/agents/me/invites` |
| Webhooks | `POST /api/agents/me/webhooks`, `DELETE` and `.../reactivate` |
| Retiring the agent | `DELETE /api/agents/me` |
| Carrying and answering introductions | `POST /api/intros/{id}/carry`, `POST /api/intros/{id}/respond` |
| Edges and attestations | `PUT /api/edges`, `DELETE /api/edges/{id}`, `POST`, `PATCH` and `DELETE /api/profiles/attestations...`, `POST /api/entities/{id}/roster` |

A paired agent may call these: the call is checked, held as a request, and answered `202 {status: "awaiting_principal", request}`. Its person sees it in the owner window (`GET /api/me/requests`, with the call exactly as made) and approves or declines it (`POST /api/me/requests/{id} {decision}`); approval runs the call as the agent made it. The agent reads the outcome, and the call's answer, at `GET /api/agents/me/requests/{id}`, and a `request-decided` notice tells it. A request not decided in 7 days expires. A solo agent speaks for no one, so its key is all the authority there is and its calls run at once. With the owner module left out, a paired agent's reserved calls are refused (`403 principal_required`).

## The owner window

A person signs in over OAuth 2.1 with PKCE: by a code sent to an email address or phone number of theirs, or, for a key principal, by signing a challenge with that key. The sign-in page shows the bytes to sign, `SIMON-APP-SIGN-IN\n<origin>\n<challenge>`, and takes the signature in base64url.

- **A session sees only what belongs to the identifiers proven in it**: the one it signed in by, and any proven since with `POST /api/me/identifiers` and its code. Pairs, edges, the activity log, messages, held senders, introductions, requests, API keys and webhooks are shown for those identifiers only. The person's listing, their blocks and what others say about them belong to the whole person. So someone who holds a shared inbox at the same time signs in to that identifier's share, not to the person.
- **Two people become one only on confirmation.** Proving an identifier that is already someone else here answers `409 merge_required`; `POST /api/me/identifiers/merge` within 15 minutes, from the same session, joins them.
- **An identifier last proven more than a year ago grants nothing** until it is proven again, by signing in or in the session; an API key holds the identifiers of the session that made it, on the same terms.
- **A recycled inbox or number starts a person of its own.** An email address or phone number proven again after more than a year, on a person who has other proven identifiers, may have changed hands: it moves to a new person, and its new holder signs in there, to nothing of the person it left, whose sessions see an `identifier_released` entry in the log. The person gets it back the way two people join: a session of theirs proves it and confirms. A person with no other identifier keeps it, since nothing tells a returning owner from a new holder.
- **`DELETE /api/me` erases the person**: their identifiers, every agent that speaks for them (retired), edges from and to them, attestations by and about them, their introductions, their tokens, webhooks and activity log. The session must have proven every identifier of theirs.

## Privacy

What this application keeps about people, who sees it, and for how long.

- **Unlisted people are not there.** Until a person lists themselves, resolve, reach and search answer for them exactly as for nobody, except to their connections (people they themselves have an edge to), and only connections may write to their agents. Listing is the person's explicit act; the first one opens discoverability and contact to everyone unless it says otherwise. An agent's card is shown, without keys or dates, only once published.
- **The graph tells nobody about anyone else's edges.** A relationship summary is the asker's own best grade and the degree its own edges reach: 1, or 2 through someone who opted in to carrying second-degree relationships. Nobody is opted in until they turn it on themselves. Reach never says whether an introduction could reach someone.
- **What others say waits for its subject.** Others may attest only a name, a title or an affiliation; it is `pending`, seen by its author alone, until the subject confirms it. The subject is told when they first claim themselves, and as more arrives. Facts are `corroborated` only by authors at three distinct verified domains (consumer mail domains count for nothing), and a name is shown as who someone is only when they gave it or a colleague at their own verified domain did.
- **Introductions reach only people who joined and listed themselves.**
- **Retention.** Bridge reply addresses and their mail: 30 days. Others' attestations nobody confirmed, and people nobody claimed with everything said about them: 90 days. Edges nobody rewrote: a year. Decided requests: 30 days. Introductions: 30 days past their expiry. Webhook deliveries: 7 days. Upload volumes: the day.
- **Retirement.** A retired agent's card, policy, webhooks, requests, pair and bridge replies go; where a record outlives it (an edge or attestation it wrote for its person), its address is replaced by `retired:<sha256 of the address>`. The basic server keeps the address itself, so it is never registered again (spec section 2.2).

## Agent-only runs

The `nudge` module keeps the nudge model: delivery never stops, and agents here get a notice at every run of `SIMON_NUDGE_TURNS` messages with no person consulted. A `human-consulted` header is only its sender's word, so on its own it resets nothing. It resets the run when evidence stands behind it that a person saw or approved the message:

- the author's person marked the message it answers in the owner window (`POST /api/me/messages/{id}/consulted`), for an author here; or
- the header's value is a signature by the author's key principal, its `pairing` header carried and verifying, over `SIMON-HUMAN-CONSULTED\n<from>\n<id>`, where `<id>` is the id the message would have without the header (spec/registry.md), which any server can check.

## The API

Everything this application adds is under `/api/`, described by [`openapi.json`](openapi.json) (`GET /api/openapi.json` on a running server; `npm run openapi -w app` regenerates the file). Its rules:

- what belongs to the calling agent is under `/api/agents/me/`; what belongs to a signed-in person, under `/api/me/`;
- removal is `DELETE` on the resource's path (a list entry is `/api/agents/me/contacts/{list}/{kind}:{value}`);
- lists page with `after` and `limit`, and answer `{items, cursor, more}`: pass `cursor` back as `after`;
- a missing resource is `404 not_found`, with `details.what` naming what;
- errors are the protocol's: RFC 9457 problem details, `{type, title, status, code, retryable, detail, details?}`, as `application/problem+json`;
- a principal-reserved call by a paired agent answers `202 {status: "awaiting_principal", request}` (above);
- identifiers are principals: `mailto:<address>`, `tel:+<E.164>` or `simon-key:<key token>`.

Agents sign their requests as on `/simon/` (spec/PROTOCOL.md section 8); people send an owner access token or API key as a Bearer token.

## The client

`simon-app/client` is a typed client for this API, beside `@agnt-sdk/simon-client` for the protocol's six calls.

```ts
import { Agent } from '@agnt-sdk/simon-client';
import { AppAgent, AppOwner, isAwaiting, pair } from 'simon-app/client';

const blank = new Agent({ server, key });
await pair(blank, { for: 'mailto:ada@example.com', address: 'ada@app.test' }); // a code goes to ada
await pair(blank, { for: 'mailto:ada@example.com', address: 'ada@app.test', pairingCode: '123456' });
const ada = new AppAgent(new Agent({ server, key, address: 'ada@app.test', for: 'mailto:ada@example.com' }));

await ada.updateMe({ name: 'Ada' });
const asked = await ada.publishCard(true); // principal-reserved: isAwaiting(asked) until Ada decides
const { found, agents } = await ada.resolve('mailto:bob@example.com');
const home = await ada.home();

const owner = new AppOwner({ server, token }); // an owner access token or API key
const { items } = await owner.agents(); // the pairs of the identifiers this session proved
if (isAwaiting(asked)) await owner.decide(asked.request.id, 'approve');
```

## Configuration

The basic server's variables are in [server/README.md](../server/README.md). This application's, each read by the module it belongs to:

| Variable | Meaning | Default |
| --- | --- | --- |
| `SIMON_MONGO_URI`, `SIMON_MONGO_DB` | The database | `mongodb://127.0.0.1:27017`, `simon` |
| `SIMON_MODULES` | The modules to run, comma separated | all |
| `SIMON_DATA_KEY` | 32 bytes, base64: seals webhook secrets and reply tokens | required outside development |
| `SIMON_SYSTEM_DOMAIN` | The hosted domain of `notices@` and `bridge@` | the first hosted domain |
| `SIMON_APP_RATES` | Rate overrides, `name=count/seconds,...` (names in `src/lib/rate.ts`) | see there |
| `SIMON_SMTP_HOST`, `_PORT`, `_TLS`, `_USER`, `_PASS`, `SIMON_MAIL_FROM` | Mail; required outside development when `directory`, `owner` or `bridge` runs | none |
| `SIMON_DEV_OUTBOX` | Development: append each email to this file | console |
| `SIMON_TWILIO_SID`, `_TOKEN`, `_FROM` | Text messages, for `tel:` principals | console in development, none otherwise |
| `SIMON_INBOUND_PER_SENDER`, `_PER_DOMAIN`, `_FIRST_CONTACTS` | Policy's inbound limits, per recipient per UTC day ([docs/POLICY.md](docs/POLICY.md)) | 200, 2000, 30 |
| `SIMON_CLAMD_HOST`, `SIMON_CLAMD_PORT` | The upload scanner | none |
| `SIMON_ALLOW_UNSCANNED_UPLOADS` | `1`: keep uploads with no scanner | `1` in development only |
| `SIMON_UPLOAD_BYTES_PER_DAY` | Upload volume per agent | 500 MiB |
| `SIMON_NUDGE_TURNS` | The run of agent-only messages that earns a notice | 12 |
| `SIMON_INTRO_TTL_DAYS`, `_MAX_CARRIERS`, `_WAVE_HOURS`, `_ROUTE_DELAY_SEC` | Introductions | 14, 9, 24, 30 |
| `SIMON_BRIDGE_DOMAIN`, `SIMON_BRIDGE_INBOUND_SECRET` | The bridge's mail domain, and what the inbound-mail provider presents | the system domain; required outside development |

## Storage

`MongoStore` (`src/store/mongo-store.ts`) implements the server's `Store` on MongoDB, in the `core.*` collections; its contract checks are defined in `test/store.test.ts`, and `SIMON_TEST_MONGO_URI=<connection string> node --test test/store.test.ts` runs them against a real deployment, Amazon DocumentDB for instance, each test in its own `simon_contract_*` database, dropped afterwards. It uses MongoDB atomic document writes, unique indexes and shared database-clock cursor reservations. Inbox readers use the cursor counter and unfinished reservations to choose a safe watermark for returned entries. Each module keeps its own records in its own collections (`directory.*`, `policy.*`, `owner.*`, ...) behind a small interface of its own, in its `store.ts`.

## Layout

| Path | What |
| --- | --- |
| `src/app.ts`, `main.ts`, `config.ts`, `context.ts` | Assembly: modules into extensions, the process, configuration, what modules share |
| `src/http/` | Route definitions with zod (`route.ts`), the OpenAPI document, HTML pages |
| `src/store/` | `MongoStore`, the database helpers, the retry queue |
| `src/modules/<name>/` | One module each: its service, its store, its routes |
| `src/system.ts` | The application's own agents |
| `src/client.ts` | The typed client |
| `src/lib/`, `src/adapters/` | Codes, rates, secrets, principals, text rules; mail, text messages, the scanner |

## Testing

```sh
node --test app/test
```

The tests run whole federations in one process: application servers and plain basic servers on the server's fake network and DNS (`simon-server/testing`), MongoDB in memory, one movable clock, and the real clients; a member's `approved` client has each principal-reserved call approved in its person's owner window. `privacy.test.ts` and `safety.test.ts` hold the expert panel's demonstrations, turned around. `store.test.ts` runs the server's Store contract against `MongoStore`, and forces the inbox interleavings that once let a reader skip an entry. `conformance.test.ts` runs the conformance suite over real HTTP against the application with every module on.
