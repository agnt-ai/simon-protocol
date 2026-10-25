# SIMON Protocol conformance suite

A black-box test of any SIMON server, in any language. Point it at a server's origin; it plays a peer
server against it over HTTP and reports, check by check, which rule of the spec held and which did not.
Every failure names the spec section, the request it sent, the answer that came back, and what a
conforming server answers instead.

It needs Node 26 and nothing else but the protocol package in this repository (`@agnt-sdk/simon-protocol`).

## Run it

```sh
node conformance/src/cli.ts --server http://127.0.0.1:8080 > report.json
```

- **stdout** is the JSON report (or one line per check with `--format text`).
- **stderr** is a short summary: each failure and skip as it happens, then counts per area.
- **The exit code** is 1 when any `must` check failed, 2 when the suite could not run, 0 otherwise.

`--only deliver.,requests.nonce` runs a subset (ids or prefixes). `--list` prints the checks without
running them (`--format markdown` for the table below). `--help` lists every option. The run against the
basic server is in step 1 below.

## What the suite needs from you

1. **Resolve the simulator's domain to the simulator.** The suite runs its own SIMON server, the peer
   simulator, at `http://127.0.0.1:47100` and delivers from agents at `peer.test`. Configure your
   server to resolve `peer.test` to `http://127.0.0.1:47100`, and to accept `http:` origins on local
   hosts for development, as section 3 allows. Change either with `--peer-domain`, `--peer-host` and
   `--peer-port`; a server on another machine reaches the simulator through a tunnel (item 9). For the
   basic server in `server/`, with every optional check below turned on:

   ```sh
   SIMON_DEV=1 SIMON_ORIGIN=http://127.0.0.1:8080 SIMON_HOSTED_DOMAINS=sut.test SIMON_LEASE_DOMAIN=lease.sut.test \
   SIMON_DEV_RESOLVE=sut.test=http://127.0.0.1:8080,lease.sut.test=http://127.0.0.1:8080,mail.sut.test=http://127.0.0.1:8080,peer.test=http://127.0.0.1:47100,peer2.test=http://127.0.0.1:47101 \
   SIMON_RATES=register=1000/3600,badSignature=100000/3600,code=100/3600,deliver=100000/3600 \
   SIMON_RECOVERY_WAIT=5 SIMON_DB=conformance.sqlite node server/src/main.ts > server.log 2>&1
   ```

   and, from another terminal:

   ```sh
   node conformance/src/cli.ts --server http://127.0.0.1:8080 --hosted-domain sut.test \
     --second-peer-domain peer2.test \
     --code-address "c$(date +%s)@mail.sut.test" \
     --code-command 'sleep 0.5; grep "register code" server.log | grep "\"address\":\"$1\"" | tail -1 | sed -E "s/.*\"code\":\"([0-9]+)\".*/\1/"' \
     --cancel-code-command 'sleep 0.5; grep "recovery cancel code" server.log | grep "\"address\":\"$1\"" | tail -1 | sed -E "s/.*\"code\":\"([A-Za-z0-9_-]+)\".*/\1/"' \
     --retire-command "sqlite3 conformance.sqlite \"UPDATE agent_keys SET revoked=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE address='\$1' AND revoked IS NULL; UPDATE agents SET retired_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE address='\$1'\""
   ```

2. **A way to get agents.** The suite registers its own agents. A server that leases addresses (register
   with a key alone) needs nothing more. Otherwise pass `--hosted-domain <domain>`, a domain whose names
   agents take at once; it also turns on the hosted-name checks.

3. **Room under your rate limits.** One run registers about 40 agents, sends a few dozen bad signatures on
   purpose and delivers about 200 envelopes from one peer. The suite waits out a `429` whose
   `Retry-After` is at most 15 seconds (`--rate-limit-wait`), and skips a check otherwise. For the basic
   server: `SIMON_RATES=register=1000/3600,badSignature=100000/3600,code=100/3600,deliver=100000/3600`.

4. **A server that has not seen the simulator in the last ten minutes**, for one check:
   `deliver.server-document-unavailable` makes the simulator's server document answer `503`, which a
   server that cached the document cannot observe. The check skips, saying so, when the server did not
   fetch the document during it.

5. **Optional: the code flow.** To check binding an address by a code, recovery, its wait and its
   cancelling, and `key_revoked`, give `--code-command <command>` and `--code-address <address>`. The
   address is on a domain that resolves to your server and is neither hosted nor leased. The command is
   run with the address as `$1` and as `SIMON_ADDRESS`, and prints the code your server sent there. The
   basic server logs codes in development, which the command above reads. A recovery that waits (CLIENT
   Recovery, "By the address's mailbox") is waited out when its `completesAt` is within
   `--recovery-wait` (30 s); run the server with a short wait for that (the basic server:
   `SIMON_RECOVERY_WAIT=5`). `register.cancel-code` also needs `--cancel-code-command <command>`, which
   prints the cancel code your server sent to the address with the news of a recovery (CLIENT
   "Cancelling a recovery"); the basic server logs it in development as `recovery cancel code`.

6. **Optional: retiring an agent.** `public.retired` needs `--retire-command <command>`, run with an
   address as `$1` and `SIMON_ADDRESS`, that retires the agent there, as your server's principal-only
   operations would. For the basic server, run it on a database file and update it with `sqlite3`, as
   above.

7. **Optional: a second simulator.** `outbound.per-server` needs `--second-peer-domain <domain>`, a
   second domain your server resolves to a second simulator, on `--second-peer-port` (47101).

8. **A domain that names no server** is `example.invalid` by default, which DNS never answers. A server
   with no DNS at all reports it as `temporary`; give `--unresolvable-domain` a domain it can look up.

9. **A server on another machine,** such as a staging deployment, cannot reach `127.0.0.1` and takes only
   `https:` origins. Put the simulator behind a public tunnel to its port, and give the tunnel's origin as
   `--peer-origin`. Its name is then the peer domain, and the simulator answers `/.well-known/simon` for
   it, so the server resolves it by the well-known method of section 3, with no DNS record to add. (With
   a `--peer-domain` of your own, that domain needs a TXT record naming the tunnel's origin instead.) Before
   any check, the suite fetches the simulator's server document through the tunnel, for up to a minute,
   so that the server never tries a name that does not resolve yet. A Cloudflare quick tunnel needs no
   account:

   ```sh
   cloudflared tunnel --url http://127.0.0.1:47100      # prints https://<name>.trycloudflare.com
   ```

   and, from another terminal:

   ```sh
   node conformance/src/cli.ts --server https://simon.staging.example \
     --peer-origin https://<name>.trycloudflare.com --hosted-domain staging.example
   ```

   A second tunnel, to port 47101, gives the second simulator with `--second-peer-origin`. A quick tunnel
   gets a new name each time, so the server has never seen the simulator before a run (item 4). Every
   request then reaches the server from this machine's address, so item 3's rate limits apply to it, and
   `--code-command` and `--retire-command` (items 5 and 6) must reach the server where it runs.

Time: a run takes three to five minutes. Most of it is waiting, while the other checks run: for the
server to fetch the parts of a received message, which it may delay by a few minutes (up to
`--prefetch-wait`, 240 s); to retry a delivery the simulator answered `503` (up to `--retry-wait`, 180 s);
and for the 144-hour freshness window to close on messages delivered just inside it (twice, each twice
`--clock-margin` plus two seconds).

## The report

```json
{
  "suite": "simon-conformance 0.2.0",
  "target": { "server": "http://127.0.0.1:8080", "origin": "http://127.0.0.1:8080" },
  "peer": { "domain": "peer.test", "origin": "http://127.0.0.1:47100" },
  "summary": { "total": 181, "pass": 179, "fail": 1, "skip": 1, "mustFailed": 1, "shouldFailed": 0 },
  "setup": { "notes": ["..."], "exchanges": ["..."] },
  "checks": [
    {
      "id": "deliver.order-envelope-before-freshness",
      "section": "PROTOCOL 6.3 steps 7, 9",
      "level": "must",
      "title": "The envelope signature is checked before freshness",
      "expected": "403 bad_signature, not 400, for a stale message in an envelope signed by an unlisted key",
      "status": "fail",
      "observed": "expected 403 bad_signature, got 400 invalid (details.field \"sentAt\")",
      "exchanges": [
        {
          "direction": "to-target",
          "request": { "method": "POST", "url": "http://127.0.0.1:8080/simon/deliver", "headers": {}, "body": "{...}" },
          "response": { "status": 400, "headers": { "content-type": "application/problem+json" }, "body": "{...}" }
        }
      ]
    }
  ]
}
```

`direction` is `to-target` for a request the suite (or its simulator) sent to your server, and
`from-target` for one your server sent to the simulator. Bodies over 4 KiB are shown as their size,
SHA-256 and first characters. `skip` means the check could not run here, and `observed` says why (no
hosted domain given, a policy holding mail from the simulator, a prerequisite that failed elsewhere).

## How it works

- **The simulator** (`src/peer.ts`) serves a server document, agent documents for the agents it
  controls, `/simon/deliver` and part bytes. Each simulated agent's document can be made to fail in a
  chosen way (404, 503, the wrong address, a bad signature, a malformed or unknown key, 33 keys, too
  large) or list chosen keys (one of an algorithm nobody implements, say), and its server document can
  answer 503. Its envelopes name your server and, by default, the recipients on the domains the suite
  knows your server serves. Its `/simon/deliver` records every envelope and answers 202, or 503 once for
  a recipient named `x503-...`, or 400 for `x400-...`. It serves part bytes only to a server request
  signed by a server it delivered them to, and checks that signature.
- **Its server keys come from fixed seeds**, so a server that cached its document from an earlier run
  still verifies its envelopes. Its agents get new addresses every run.
- **The suite's agents** on your server are built on `@agnt-sdk/simon-protocol` alone: no product client sits
  between the suite and the wire.
- **Clock.** The suite reads your server's clock from the `details.serverTime` of a 401, and puts time
  boundaries on that clock, `--clock-margin` seconds inside or outside each bound.
- **Background scenarios.** What takes your server minutes (a retry, a message dated ahead of the clock,
  parts it may wait to fetch) starts early in the run, and its checks read what it saw later.
- **The error checks** run last, over every error answer of the run.

## Tests of the suite

`node --test conformance/test` runs the whole suite in process against a toy server
(`test/toy-server.ts`) with planted faults: limits below the minimum, a nonce used up by a bad
signature, freshness checked before the envelope and before the repeat, an unknown recipient answered 404, no `algorithms` in
the server document, errors sent as `application/json`, 401s without `WWW-Authenticate`, an envelope
taken whatever server it names, repeats recognised by message id alone, and `bad_signature` where
`unsupported_algorithm` is due. The test requires each fault to be caught by the check aimed at it, and
what the toy does right to pass. It also requires the list below to match the code; regenerate it with
`node conformance/scripts/write-readme.ts`.

## Readings of the spec

Where the spec leaves a choice, the suite takes the reading most consistent with section 1 and
`docs/DECISIONS.md`, and says so here.

- **`claims: null` is refused.** Only an absent member reads as none (section 6.2).
- **The pairing signature is not a server's to check on deliver** (`should`): section 5.4 makes presence a
  rule every server checks, and verification a reader's.
- **A message dated 24 hours back is refused for its signature.** CLIENT's `send` checks the signature
  before `sentAt`, and a key registered during the run was not valid a day earlier, so the 24-hour bound
  is `401 bad_signature` here; only the 5-minute bound reaches the `sentAt` check.
- **Repeats are told by freshness, not by documents.** Whether a delivery is a repeat for its recipients
  (step 8) shows in whether a message past the 144-hour window is still taken; a server may cache an
  author's document for ten minutes, so a document that stops being served shows nothing.
- **A held leased or hosted address is `409 address_taken`** (`should`); the `must` is that the new key is
  refused and not listed.
- **A claim that is not authoritative must never be shown as authoritative**; hiding it altogether is a
  `should`, since the suite cannot know which carriers your server's operator chose to trust.
- **A recovery may wait** (`should`); cancelling one that waits is a `must`, and so is completing it once
  `completesAt` has passed.
- **Delivery timing is checked through the simulator, best effort.** A message dated ahead must not
  arrive before its `sentAt`, and must arrive within the retry wait after it, since a first attempt may
  meet a failure that passes. `sent` reporting `expired` cannot be observed without moving your server's
  clock by days, so `sent.expired` always skips.

Recovery uses `POST /simon/recovery`, `GET /simon/recovery` and `POST /simon/recovery/cancel`.
Registration creates or pairs an address; account and key operations return `{address, keys, grants, recovery}`.
The client stream uses `GET /simon/sync` and opaque server-issued tokens; tokens are stored and returned unchanged.
A core reference host may keep retired agent documents private or serve a valid signed retirement record.

## The checks

Generated from the declarations in `src/checks/`, in the order they run.

<!-- checks:start -->

235 checks: 217 must, 18 should.

### Documents (PROTOCOL 4)

| Check | Level | Section | Expected |
| --- | --- | --- | --- |
| `documents.server.readable` | must | PROTOCOL 4 | GET /simon/server without any signature answers 200 with a JSON object under section 5.1's rules, at most 131072 bytes, whose keys are well-formed entries, at most 32 of them not yet revoked |
| `documents.server.origin` | must | PROTOCOL 4 | `server` equals the origin of the URL it was fetched from, compared as the URL standard serialises origins |
| `documents.server.limits` | must | PROTOCOL 4, 9 | limits has messageBytes >= 262144, recipients >= 100, requestBodyBytes >= 1048576 and partBytes >= 26214400, each a safe integer |
| `documents.server.algorithms` | must | PROTOCOL 2.3, 4 | algorithms is an array of algorithm names (lower-case letters, digits and hyphens) that includes ed25519 and ml-dsa-65 |
| `documents.server.key-valid-now` | must | PROTOCOL 2.4, 4 | at least one entry of an implemented algorithm is valid at the time of reading, or nothing the server signs can verify |
| `documents.agent.served` | must | PROTOCOL 4 | GET /simon/agents/<address> (unsigned, `@` literal) answers 200 with the address asked for, and a signature over SIMON-AGENT that verifies with a server key valid now |
| `documents.agent.address-segment` | must | PROTOCOL 2.1, 4, 8 | for an agent whose hosted name holds every version 2 character that is not an RFC 3986 pchar (# % / ? ^ ` { \| }), GET /simon/agents/<the address, those characters percent-encoded with upper-case hex, @ literal> answers 200 with that address, and the agent's own signed request naming its address in the path is answered as any other |
| `documents.agent.no-kind` | must | PROTOCOL 2.2, 4 | no kind member in the document of an agent registered without `for` |
| `documents.agent.lists-key` | must | PROTOCOL 4 | the key the agent registered appears in keys, with added and revoked making it valid now |
| `documents.agent.unknown` | must | PROTOCOL 4, 9 | GET /simon/agents/<an address nobody holds> answers 404 not_found in the error shape |

### Signed requests (PROTOCOL 8)

| Check | Level | Section | Expected |
| --- | --- | --- | --- |
| `requests.key-revoked` | must | PROTOCOL 8 | 401 key_revoked (with details.serverTime) for a request signed by a key that recovery replaced |
| `requests.unsigned` | must | PROTOCOL 8 | 401 signature_required with details.serverTime, for a client API call carrying no signature headers |
| `requests.missing-header` | must | PROTOCOL 8 | dropping any one of simon-key, simon-timestamp, simon-nonce or simon-signature gives 401 signature_required |
| `requests.malformed-header` | must | PROTOCOL 8, Appendix A | a timestamp that is not 1 to 12 digits, a nonce outside 8 to 128 characters of U+0021 to U+007E, a key that is not a key token, or a signature that is not canonical base64url gives 401 signature_required |
| `requests.nonce-bounds` | must | PROTOCOL 8, Appendix A | a request whose nonce is exactly 8, or exactly 128, characters from U+0021 to U+007E (including ! and ~) answers 200 |
| `requests.timestamp-window` | must | PROTOCOL 8 | a timestamp 300 s minus the clock margin from the server clock (either way) answers 200; 300 s plus the margin answers 401 stale_request |
| `requests.unknown-key` | must | PROTOCOL 8 | 401 unknown_key for a well-formed request naming an agent there in simon-agent, signed by a key that agent does not hold |
| `requests.bad-signature` | must | PROTOCOL 8 | 401 bad_signature with details.serverTime and details.signingString exactly the eight lines the server expected: SIMON-REQUEST, the method, its origin, the actor, the request target as sent, the timestamp, the nonce, the body hash |
| `requests.binds-origin` | must | PROTOCOL 8 | 401 bad_signature, the signing string naming this server's own origin |
| `requests.binds-target` | must | PROTOCOL 8 | 401 bad_signature for a request signed over another query, the signing string naming the target exactly as sent |
| `requests.binds-actor` | must | PROTOCOL 8 | 401 bad_signature for a request signed as one address and sent naming another in simon-agent, the signing string naming the address sent |
| `requests.binds-method` | must | PROTOCOL 8 | 401 bad_signature for a GET signed as a POST, the signing string naming GET |
| `requests.binds-body` | must | PROTOCOL 8 | 401 bad_signature for a POST whose body differs from the one signed, the signing string ending in the hash of the body as sent |
| `requests.replayed` | must | PROTOCOL 8 | the same signed request twice: 200, then 401 replayed_request |
| `requests.nonce-after-bad-signature` | must | PROTOCOL 8 | nonce N with a signature that does not verify: 401 bad_signature; then a good request with N: 200; then N again: 401 replayed_request |
| `requests.nonce-after-unsigned` | must | PROTOCOL 8 | nonce N with no simon-signature: 401 signature_required; then a good request with N: 200 |
| `requests.nonce-after-stale` | must | PROTOCOL 8 | nonce N with a timestamp outside the window: 401 stale_request; then a good request with N: 200 |
| `requests.refusal-order` | must | PROTOCOL 8 | malformed header before stale timestamp; stale timestamp before unknown key; unknown key before bad signature; bad signature before replayed nonce |
| `requests.nonce-per-key` | should | PROTOCOL 8 | two agents using the same nonce, each once, both answer 200 |
| `requests.server-time` | should | PROTOCOL 8 | a 401's details.serverTime is within 300 s of the time the suite read it |

### Deliver, received from the simulator (PROTOCOL 6)

| Check | Level | Section | Expected |
| --- | --- | --- | --- |
| `deliver.server-document-unavailable` | must | PROTOCOL 6.3 steps 6-7, PROTOCOL 9 | 503 unavailable with retryable: true when the from-domain's server answers its server document with 503; never a permanent refusal |
| `deliver.accepted` | must | PROTOCOL 6.3 step 12 | 202 with the body {"accepted":true} for a valid envelope from a server whose domain resolves, carrying a message its author signed |
| `deliver.body-too-large` | must | PROTOCOL 6.3 step 1 | 413 body_too_large for a body one byte over the published requestBodyBytes, even when it is not JSON |
| `deliver.body-at-limit` | must | PROTOCOL 6.3 step 1, PROTOCOL 9 | 202 for a valid envelope padded with whitespace to exactly the published requestBodyBytes |
| `deliver.parse` | must | PROTOCOL 6.3 step 1, PROTOCOL 5.1 | 400 invalid for: truncated JSON, a repeated key, a fraction, an exponent, -0, a leading zero, an integer beyond 2^53-1, a lone surrogate escape, a byte order mark, invalid UTF-8, and 65 levels of nesting |
| `deliver.shape-envelope` | must | PROTOCOL 6.3 step 2 | 400 invalid with a details.field for an array or a string as the envelope; details.field "message" when message is missing, a string or an array |
| `deliver.shape-signature` | must | PROTOCOL 6.3 step 2 | 400 invalid with details.field "signature" when it is missing, a number, padded, or empty |
| `deliver.shape-server` | must | PROTOCOL 6.3 step 2, PROTOCOL 6.1 | 400 invalid with details.field "server" when it is missing, a number, a URL with a path, or not a URL, the envelope signed as sent |
| `deliver.shape-recipients` | must | PROTOCOL 6.3 step 2, PROTOCOL 6.1 | 400 invalid with details.field "recipients" when it is missing, empty, a string, holds a number or an address in upper case, or names one address twice |
| `deliver.shape-claims` | must | PROTOCOL 6.3 step 2, PROTOCOL 6.2 | 400 invalid with details.field "claims" for an object, a number in the array, a claim with no type, an empty type, a numeric type, and 17 claims |
| `deliver.claims-null` | must | PROTOCOL 6.3 step 2, PROTOCOL 6.2 | 400 invalid with details.field "claims" for an envelope whose claims is null (only an absent member reads as none) |
| `deliver.shape-hints` | must | PROTOCOL 6.3 step 2, PROTOCOL 6.2 | 400 invalid with details.field "hints" for hints that are an array, null, keyed by an address not in to, keyed by an address in to but not in recipients, keyed by a recipient in another case, holding a string, or holding a number |
| `deliver.hints-valid` | must | PROTOCOL 6.3 step 2, PROTOCOL 6.2 | 202 for an envelope whose hints name one of its recipients exactly as written, with string values |
| `deliver.extras-limit` | must | PROTOCOL 6.3 step 2, PROTOCOL 6.2, 9 | 202 when canonical {"claims":..,"hints":..} is exactly 16384 bytes; 400 invalid (details.field "claims" or "hints") at 16385 |
| `deliver.claims-signed` | must | PROTOCOL 6.3 steps 2, 7, PROTOCOL 6.2 | 400 invalid with details.field "claimsSignature" for claims without a claimsSignature, and for a claimsSignature without claims; 403 bad_signature for a claimsSignature made over other claims, though the envelope itself verifies |
| `deliver.unknown-members` | must | PROTOCOL 6.1, 10 | 202 for an envelope carrying members this version does not define, covered by its signature |
| `deliver.order-shape-before-canonical` | must | PROTOCOL 6.3 steps 2-3 | 400 invalid with details.field "claims" and no details.canonical, for claims that are a string and a message that is not canonical |
| `deliver.canonical` | must | PROTOCOL 6.3 step 3, PROTOCOL 5.1 | 400 invalid with details.canonical exactly the canonical form, for whitespace, keys out of order, an escaped solidus, and a needless \u escape |
| `deliver.envelope-need-not-be-canonical` | must | PROTOCOL 6.1 | 202 for an envelope with whitespace and its members out of order, whose message member is canonical and whose signature is over the canonical envelope |
| `deliver.order-canonical-before-message` | must | PROTOCOL 6.3 steps 3-4 | 400 invalid with details.canonical for a non-canonical message that also has a field version 2 does not define |
| `deliver.order-canonical-before-signature` | must | PROTOCOL 6.3 steps 3, 7 | 400 invalid with details.canonical (not 403) for a non-canonical message in an envelope signed by a key the sender's server does not list |
| `deliver.invariants` | must | PROTOCOL 6.3 step 4, PROTOCOL 1 | 400 invalid with details.field naming v, from, to, sentAt or signature when it is missing or malformed: v absent, 0 or "1"; from in upper case or without @; to in upper case, not an array, or holding a non-address; sentAt with an offset or naming 30 February; signature missing or padded |
| `deliver.version-rules` | must | PROTOCOL 6.3 step 4, PROTOCOL 5.2-5.4 | 400 invalid with details.field naming the field at fault: an undefined field, inReplyTo missing or not an id, a repeated recipient, a non-ASCII local part, 33 parts, a part with an upper-case type or both data and sha256, non-base64 data in a binary part, 33 headers, a header name in upper case, a header that is not a string, a for that is no principal, pairing without a simon-key for, a simon-key for without pairing, and critical with spaces |
| `deliver.any-parts` | must | PROTOCOL 6.3 step 4, PROTOCOL 5.3 | 202 for a message with no parts, one with only a file, one whose only text is HTML, one whose text is content-addressed, a sealed message, and one of 32 parts; 400 invalid with details.field "parts" for one of 33 parts |
| `deliver.part-labels` | must | PROTOCOL 6.3 step 4, PROTOCOL 5.3 | 202 for a part with a name and an alt, and for one with a member the server does not know; 400 invalid with details.field "parts" for a name with a slash, a name that is .., a name with a right-to-left override, a name of 256 bytes, an alt of two lines, an alt with a right-to-left override, and an empty alt |
| `deliver.part-size` | must | PROTOCOL 6.3 step 4, PROTOCOL 5.3, 7.2 | 400 invalid with details.field "parts" for a message naming a part one byte over partBytes, so no part is ever fetched only on demand |
| `deliver.carried-files` | must | PROTOCOL 6.3 step 4, PROTOCOL 5.3, 7.2 | 400 invalid with details.field "parts" for a message carrying inline a message that names a file one byte over partBytes, and for one naming more than 1024 files in all, counting those of the messages it carries inline: so no carrier can make a recipient fetch unbounded bytes |
| `deliver.header-placement` | must | PROTOCOL 6.3 step 4, PROTOCOL 5.4 | 202 for a message with inReplyTo and a rel the registry does not list, for a relation marked listed: yes, for rel without inReplyTo and for feed on a message with recipients (each ignored); 400 invalid with details.field "headers" for rel in upper case, audience on a message with recipients, listed on a plain reply, and listed: Yes |
| `deliver.pairing-signature-not-checked-by-servers` | should | PROTOCOL 2.2, 5.4 | 202 for a message with a simon-key: for and a well-formed pairing, valid or not: verifying it is for readers who rely on it |
| `deliver.recipients-limit` | must | PROTOCOL 6.3 step 4, PROTOCOL 9 | 202 for exactly `recipients` recipients; 400 invalid with details.field "to" for one more |
| `deliver.message-size` | must | PROTOCOL 6.3 step 4, PROTOCOL 5.5 | 202 for a message of exactly the published messageBytes; 400 invalid with details.field "message" for one byte more |
| `deliver.unknown-version` | must | PROTOCOL 1, 6.3 step 4 | 202 for a version 7 message with fields version 2 does not define (and a headers member version 2 would refuse), signed by its author; and for one whose to also names a non-ASCII local part, which only version 2 forbids |
| `deliver.unknown-version-stored` | must | PROTOCOL 1 | the version 7 message appears in the recipient's inbox with its id, byte for byte (given that a plain version 2 message from the same sender does) |
| `deliver.unknown-version-invariants` | must | PROTOCOL 1, 6.3 step 4 | 400 invalid naming from for a version 7 message whose from is in upper case, and naming to for one without to |
| `deliver.order-message-before-resolution` | must | PROTOCOL 6.3 steps 4, 6 | 400 invalid naming the field, not 403 or 503, for a message with an undefined field from a domain that names no server |
| `deliver.destination-server` | must | PROTOCOL 6.3 step 5, PROTOCOL 6.1 | 400 invalid with details.field "server" for an envelope signed for the simulator's own origin, and for another port of the server's host, delivered here |
| `deliver.destination-recipients` | must | PROTOCOL 6.3 step 5, PROTOCOL 6.1 | 400 invalid with details.field "recipients" for a recipient that is not in to |
| `deliver.served-recipients` | must | PROTOCOL 6.3 step 8, PROTOCOL 6.1 | 400 invalid with details.field "recipients" for a recipient in to on a domain the server does not serve |
| `deliver.order-signature-before-served` | must | PROTOCOL 6.3 steps 7-8, PROTOCOL 11.2 | 403 bad_signature, not 400 on recipients, for an envelope signed by an unlisted key naming a recipient on a domain the server does not serve: no recipient is looked up for an unauthenticated caller |
| `deliver.no-lookup-before-signature` | must | PROTOCOL 6.3 steps 5-8, PROTOCOL 11.2 | no request to the second simulator's /.well-known/simon while the server refuses a forged envelope naming a recipient on the second simulator's domain (needs a second simulator reached by its well-known answer, as behind a tunnel) |
| `deliver.order-message-before-destination` | must | PROTOCOL 6.3 steps 4-5 | 400 invalid naming the undefined field (not server) for a message with a field version 2 does not define, in an envelope for another server |
| `deliver.order-destination-before-resolution` | must | PROTOCOL 6.3 steps 5-6 | 400 invalid on server, not 403 or 503, for an envelope for another server carrying a message from a domain that names no server |
| `deliver.from-unresolvable` | must | PROTOCOL 6.3 step 6, PROTOCOL 3 | 403 bad_signature for a message from a domain whose resolution is not_found (the default, example.invalid, has no DNS at all) |
| `deliver.from-own-domain` | must | PROTOCOL 6.3 step 6 | 403 bad_signature for a message from an address on the server's own domain, carried by the simulator |
| `deliver.order-resolution-before-freshness` | must | PROTOCOL 6.3 steps 6, 10 | 403 bad_signature, not 400, for a stale message from a domain that names no server |
| `deliver.envelope-signature` | must | PROTOCOL 6.3 step 7, PROTOCOL 6.1 | 403 bad_signature for an envelope signed by a key the sender's server does not list, by a listed key revoked in the past, and by a listed key added in the future |
| `deliver.envelope-covers-everything` | must | PROTOCOL 6.1, 6.2 | 403 bad_signature for an unknown member added after signing, hints changed after signing, claims: [] with its claimsSignature added to an envelope signed without claims, claims and their claimsSignature removed from one signed with claims: [], and a recipient added after signing (one the message names) |
| `deliver.order-envelope-before-repeat` | must | PROTOCOL 6.3 steps 7, 9 | 202 for a message, then 403 bad_signature for the same message in an envelope signed by an unlisted key |
| `deliver.order-envelope-before-freshness` | must | PROTOCOL 6.3 steps 7, 10 | 403 bad_signature, not 400, for a stale message in an envelope signed by an unlisted key |
| `deliver.repeat` | must | PROTOCOL 6.3 step 9, PROTOCOL 11.2 | 202 for the same message delivered twice, and the recipient's inbox holds it once |
| `deliver.repeat-other-envelope` | should | PROTOCOL 6.3 step 9 | 202 for a message delivered again to the same recipients with different hints and claims |
| `deliver.order-repeat-before-author` | must | PROTOCOL 6.3 steps 9, 11 | 202 for a message accepted before, delivered again after its author's document stopped being served (404) |
| `deliver.repeat-per-recipient` | must | PROTOCOL 6.3 steps 9-10, 12 | for a message to a and b first delivered to a just inside the 144-hour window: once the window closed, 202 for a again (a repeat), but 400 on sentAt for a and b, and for b alone, which are not repeats |
| `deliver.repeat-new-recipient` | must | PROTOCOL 6.3 step 12, PROTOCOL 11.2 | for a message to a and b: 202 for an envelope to a, then 202 for one to b; b's inbox then holds the message, and a's holds it once |
| `deliver.fan-out-recipients` | must | PROTOCOL 6.3 step 12, PROTOCOL 6.1 | for a message to a and b in an envelope listing only a: a's inbox holds it, and b's does not (read after a's has it, and again a second later) |
| `deliver.order-repeat-before-freshness` | must | PROTOCOL 6.3 steps 9-10 | 202 for a message first delivered just inside the 144-hour window and delivered again just after it closed; 400 on sentAt for a new message with the same sentAt |
| `deliver.freshness` | must | PROTOCOL 6.3 step 10 | 202 just inside each bound (by the clock margin); 400 invalid with details.field "sentAt" just outside each |
| `deliver.order-freshness-before-author` | must | PROTOCOL 6.3 steps 10-11 | 400 invalid on sentAt, not 403, for a stale message whose signature does not verify |
| `deliver.author-signature` | must | PROTOCOL 6.3 step 11 | 403 bad_signature for a message signed by a key its author's document does not list, and for one altered after signing |
| `deliver.author-strict-ed25519` | must | PROTOCOL 6.3 step 11, PROTOCOL 2.3 | 403 bad_signature for a valid signature with L added to S, which the bare verification equation still accepts |
| `deliver.author-document-unavailable` | must | PROTOCOL 6.3 step 11, PROTOCOL 4 | 503 unavailable with retryable: true when the author's server answers the agent document with 503, 500 or 429: those are temporary |
| `deliver.author-document-unreadable` | must | PROTOCOL 6.3 step 11, PROTOCOL 4 | 403 bad_signature when the agent document is answered 404 or 403 (no document), names another address, is signed by a key the server does not list, lists a malformed Ed25519 key, lists 33 keys, or is over 131072 bytes |
| `deliver.author-document-extensible` | must | PROTOCOL 2.3, 4 | 202 when the author's document also lists a key of an algorithm nobody implements, when it still says kind, a member of draft 0.1, and when it has members no reader knows (the simulator's server document always has one too) |
| `deliver.author-key-valid-at-sentAt` | must | PROTOCOL 6.3 step 11, PROTOCOL 2.4 | 202 when the key was added 299 s after sentAt or revoked 1 s after it; 403 bad_signature when added 301 s after sentAt or revoked exactly at it |
| `deliver.author-ml-dsa` | must | PROTOCOL 6.3 step 11, PROTOCOL 2.3 | 202 for a message signed by an author whose key is ml-dsa-65 |
| `deliver.author-unsupported-algorithm` | must | PROTOCOL 6.3 step 11, PROTOCOL 2.3, 9 | 403 unsupported_algorithm when the author document lists only a key of an algorithm nobody implements, and when it also lists an Ed25519 key revoked before sentAt; 403 bad_signature, not unsupported_algorithm, when an Ed25519 key valid at sentAt is listed beside it and the signature does not verify |
| `deliver.silence` | must | PROTOCOL 6.3 "Policy is silent" | byte-identical 202 answers for a valid message to a known agent, to an unknown name on the server's domain, and to an unknown name whose message also names an address elsewhere |

### register (CLIENT)

| Check | Level | Section | Expected |
| --- | --- | --- | --- |
| `register.lease` | must | CLIENT register | 200 {"address","keys","grants","recovery"} with a new address and the key listed, or 400 address_required on a server that leases none |
| `register.repeat` | must | CLIENT register | the same call again answers 200 account with the same address |
| `register.member-types` | must | CLIENT register | 400 invalid, for a call signed by an agent the server knows, when key is a number, address is a number, code is true, or pairing is an object |
| `register.unknown-members` | must | CLIENT register | 200 account for a key alone with an extra member, on a server that leases |
| `register.hosted` | must | CLIENT register | 200 account with exactly the address asked for, the key listed; the same call again gives the same result |
| `register.not-recoverable-without-mailbox` | must | CLIENT register | registering a new key with an address another agent holds, where the address has no mailbox, is refused (409 address_taken is the natural answer), and the holder's document does not list the new key |
| `register.address-taken-code` | should | CLIENT register | 409 address_taken for a new key registering an address another agent holds |
| `register.homed-elsewhere` | must | CLIENT register | 409 address_homed_elsewhere with details.server the simulator's origin, for an address on the simulator's domain |
| `register.no-server` | must | CLIENT register | 409 address_homed_elsewhere with details.server null, for an address on a domain that resolves to no SIMON server |
| `register.ml-dsa` | must | CLIENT register, PROTOCOL 2.3 | registering with an ml-dsa-65 key succeeds, its document lists the key, and requests it signs answer 200 |
| `register.pairing-required` | must | CLIENT register | register {"key","for"} with a simon-key: principal answers 202 {"status":"pairing_required","address"}; the same call with "pairing", the principal's signature over SIMON-PAIR\n<address>\n<for>, answers 200 account at that address |
| `register.paired-document` | must | CLIENT register, PROTOCOL 4 | the document is readable, has no kind member, and nothing in it names the principal's key |
| `register.pairing-bad-proof` | must | CLIENT register, CLIENT errors | 401 bad_proof for register with for and a pairing signed for another address |
| `register.pairing-hosted` | must | CLIENT register | register {"key","address","for","pairing"} on a hosted domain answers 200 account, and the agent document is readable |
| `register.code` | must | CLIENT register | register {"key","address"} answers 202 {"status":"code_sent","address"}; the same call with a wrong code answers 422 wrong_code; with the code the operator's command printed, 200 account |
| `register.recovery-pending` | should | CLIENT Recovery | 202 {"status":"recovery_pending","address","completesAt"} for POST /simon/recovery with a new key handing back the code while the agent holds a valid key; its document is unchanged meanwhile, and its inbox gets a message from the server itself |
| `register.recovery-status` | must | CLIENT Recovery | GET /simon/recovery signed by the key the agent holds answers 200 {"recovery":{"completesAt","cancellable"}}, completesAt a timestamp and cancellable a boolean; signed by a key the server does not know, 401 unknown_key |
| `register.recovery-cancellable` | should | CLIENT Recovery, CLIENT recommended host practice | GET /simon/recovery signed by the key the agent held before the recovery started says cancellable true, as the recommended practice lets such a key cancel (who may cancel is host policy) |
| `register.recovery-hidden` | must | CLIENT Recovery | while a recovery waits, POST /simon/recovery from a new key asking for a code answers 202 code_sent and a wrong code then 422 wrong_code, as when none waits; a wrong cancel code for the address answers 422 wrong_code with the same body as one for an address with no recovery waiting |
| `register.cancel-recovery` | must | CLIENT Cancelling a recovery | POST /simon/recovery/cancel {} signed by a key the account permits answers 200 {"status":"cancelled","address"}; the waiting key then cannot complete the recovery with its code, and the document lists only the old key |
| `register.recovery` | must | CLIENT Recovery | POST /simon/recovery with the new key and code gets 200 account {address,keys,grants,recovery} without a status member, or 202 recovery_pending and then 200 account when it repeats the recovery call after completesAt (waited for when within the recovery wait); the old key is then marked revoked in the document |
| `register.cancel-once` | should | CLIENT Cancelling a recovery, CLIENT recommended host practice | a recovery started after register.cancel-recovery cancelled one by key answers 409 recovery_not_cancellable to a cancel by the key now holding the agent, and GET /simon/recovery says cancellable false |
| `register.cancel-code` | must | CLIENT Cancelling a recovery | POST /simon/recovery/cancel {"address","cancelCode"} with the cancel code the operator's command printed, signed by a key the server never saw, answers 200 {"status":"cancelled","address"}; the same call again answers 422 wrong_code; the waiting key cannot complete the recovery after it |
| `register.principal-recovery` | must | CLIENT Recovery | POST /simon/recovery {"address","key","at","recover"} signed by the new key, recover the principal's signature over SIMON-RECOVER\n<address>\n<key>\n<at>, answers 200 account {address,keys,grants,recovery} without a status member, listing the new key, the old key revoked; the old key is then 401 key_revoked, and the same call again answers alike |
| `register.principal-recovery-refused` | must | CLIENT Recovery | 400 invalid with details.field "at" for an at 25 hours old and one 10 minutes ahead; 401 bad_proof for a recovery signed by another key; 409 key_in_use for a recovery to a key the agent held and that is now revoked |
| `register.unpair` | must | PROTOCOL 2.2, CLIENT Unpairing | POST /simon/unpair {"address","unpairing"} signed by a key the server never saw, unpair the principal's signature over SIMON-UNPAIR\n<address>\n<for>, answers 200 {"status":"retired","address"}; the agent document is then 404 or a valid retired document, a request signed by the agent's key is 401 key_revoked, and the same call again answers 200 retired |
| `register.unpair-bad-proof` | must | PROTOCOL 2.2, CLIENT Unpairing, CLIENT errors | 401 bad_proof for POST /simon/unpair with an unpairing signed by another key, and for a pairing signature offered as an unpairing; the agent document is still served |

### send (CLIENT)

| Check | Level | Section | Expected |
| --- | --- | --- | --- |
| `send.accepted` | must | CLIENT send | 200 {"id","receivedAt"} where id is the hex SHA-256 of the canonical message without signature, and receivedAt a timestamp |
| `send.repeat` | must | CLIENT send "Idempotence" | the same message sent twice answers 200 both times with the same id and receivedAt |
| `send.body-too-large` | must | CLIENT, PROTOCOL 6.3 step 1 | 413 body_too_large for a correctly signed body one byte over requestBodyBytes |
| `send.canonical` | must | CLIENT send, PROTOCOL 5.1 | 400 invalid with details.canonical exactly the canonical form |
| `send.message-rules` | must | CLIENT send, PROTOCOL 6.3 step 4 | 400 invalid naming the field for a field version 2 does not define, naming to for one recipient over the published limit, and naming headers for a message to no one with no audience |
| `send.order` | must | CLIENT send | 400 invalid with details.canonical, not 409, for a non-canonical message from another agent; 400 naming the field, not 409, for another agent's message with an undefined field |
| `send.from` | must | CLIENT send | 400 invalid with details.field "from" for a message whose from is another agent's address, sent by this agent |
| `send.solo` | must | CLIENT send, PROTOCOL 2.2 | 400 invalid with details.field "headers" for a solo agent's message with a for header |
| `send.paired` | must | CLIENT send, PROTOCOL 2.2, 5.4 | 200 with the principal as for and its pairing; 400 invalid with details.field "headers" with no for, with another principal (and that principal's valid pairing), and with a pairing signed for another address |
| `send.sent-at` | must | CLIENT send | 200 for sentAt 5 minutes ahead less the clock margin; 400 invalid with details.field "sentAt" 5 minutes ahead plus the margin; 401 bad_signature for 24 hours old plus the margin, since the signature is checked first and a key registered during the run was not valid 24 hours earlier |
| `send.part-not-uploaded` | must | CLIENT send | 400 part_not_uploaded with details.sha256 for a part nobody uploaded, and for a part another agent uploaded |
| `send.unsupported-version` | must | CLIENT send, CLIENT errors, PROTOCOL 1 | 400 unsupported_version for a version 7 message, signed by the agent, that keeps the invariants (a server routes such a message on deliver, but takes none from its own agents) |
| `send.bad-signature` | must | CLIENT send | 401 bad_signature for a message altered after signing, and for one signed by a key the agent does not hold |
| `send.order-version` | must | CLIENT send | 400 invalid with details.canonical for a non-canonical version 7 message; 400 invalid naming to for a version 7 message without to; 400 unsupported_version, not 400 on from, for another agent's version 7 message |
| `send.order-after-message` | must | CLIENT send | 400 on from (not 401) for another agent's message with a bad signature; 401 bad_signature (not 400 on headers) for a solo agent's message with a for header and a bad signature; 400 on headers (not on sentAt) for a solo agent's message with a for header, 5 minutes ahead plus the margin; 400 on sentAt (not part_not_uploaded) for a message that far ahead naming a part never uploaded; 401 bad_signature (not part_not_uploaded) for a bad signature naming a part never uploaded |
| `send.hints` | must | CLIENT send "Hints" | 200 with a valid simon-hints header added after signing; 400 invalid for simon-hints that is not JSON, an array, or names an address not in to |
| `send.ml-dsa` | must | CLIENT send, PROTOCOL 2.3 | 200 for a message signed with ml-dsa-65 by an agent registered with that key |

### Account and recovery (CLIENT)

| Check | Level | Section | Expected |
| --- | --- | --- | --- |
| `account.shape` | must | CLIENT account | 200 with the signed-in address, readable keys including its key, a grants array and recovery null on a fresh account |
| `account.unknown-grant` | must | CLIENT ending a grant | 404 not_found for a grant that never existed |
| `account.no-recovery` | must | CLIENT cancelling a recovery | 404 not_found for an agent-key cancellation on a fresh account |
| `account.cancel-code-silence` | must | CLIENT cancelling a recovery | byte-identical 422 wrong_code for a wrong code at an existing address and an address nobody holds, signed by an unknown key |

### Keys (CLIENT)

| Check | Level | Section | Expected |
| --- | --- | --- | --- |
| `keys.add-key` | must | CLIENT keys | 200 account listing the new key, for POST /simon/keys {"key","proof"} signed by an existing key, proof over SIMON-ADD-KEY\n<address>\n<key>; the same call again gives the same result; the new key then signs requests |
| `keys.add-key-bad-proof` | must | CLIENT keys, CLIENT errors | 401 bad_proof for a proof over another address, and for a proof signed by a different key |
| `keys.add-key-no-proof` | must | CLIENT keys, CLIENT errors | 401 bad_proof for POST /simon/keys {"key"} signed by an existing key of an agent, with no proof |
| `keys.too-many-keys` | must | CLIENT keys, PROTOCOL 4 | adding keys one by one is refused with 400 too_many_keys before the agent holds 33 (a document lists at most 32 keys) |
| `keys.labels` | must | CLIENT adding a key | a 64-character label appears in the account but not the public document; 65 characters is 400 invalid |
| `keys.unknown` | must | CLIENT revoking a key | 404 not_found for a key the agent never held |
| `keys.revoke` | must | CLIENT revoking a key | 200 account marking a second key revoked now, 401 key_revoked when it signs, 404 on repeated revocation and 409 key_in_use on re-adding; host policy may refuse revocation |

### sync (CLIENT)

| Check | Level | Section | Expected |
| --- | --- | --- | --- |
| `sync.shape` | must | CLIENT sync | 200 {"messages","marks","removed","signals","token","more"} with token a string and more a boolean; each entry has id (the id of its message), message, carrier, claims (an array, each acts-for claim with a boolean authoritative) and receivedAt |
| `sync.self` | should | CLIENT sync | the message appears in the sync within the delivery wait |
| `sync.carrier-local` | must | CLIENT sync | carrier is the server's own origin, and the message is the one sent, byte for byte |
| `sync.carrier-peer` | must | CLIENT sync | carrier is the simulator's origin for a message it delivered, and the message is unchanged |
| `sync.claims-considered` | must | CLIENT sync, PROTOCOL 6.2, 11.2 | no acts-for claim in the entry for a message without a for header delivered with acts-for claims naming another agent and naming its author; nor for a message whose for is the carrier's own domain, with acts-for claims lacking scope, with a malformed verifiedAt, or naming another for |
| `sync.claims-authoritative` | must | CLIENT sync, PROTOCOL 2.2, 6.2 | the entry shows the acts-for claim, as sent, with authoritative: true, for a message whose for is mailto: an address on the simulator's own domain, carried by the simulator (whose word the server need not otherwise trust); the same when the author's document also says kind: solo, a member of draft 0.1 that no longer decides anything |
| `sync.claims-not-authoritative` | must | CLIENT sync, PROTOCOL 6.2 | for a message whose for is mailto: an address on a domain naming no server (its claim sent with authoritative: true), and one whose for is tel:, the acts-for claim is absent or shown with authoritative: false |
| `sync.claims-elsewhere-not-authoritative` | must | CLIENT sync, PROTOCOL 2.2, 6.2 | for a message carried by the simulator whose for is mailto: an address on the server's own domain, and one whose for is an address on the second simulator's domain (with --second-peer-domain), the acts-for claim is absent or shown with authoritative: false |
| `sync.claims-no-for` | must | CLIENT sync, PROTOCOL 2.2, 6.2 | no acts-for claim in the entry for a message without a for header, though the claim names an address on the carrier's own domain |
| `sync.claims-own-judgement` | must | CLIENT sync, PROTOCOL 6.2 | no claim of a type the server does not judge (an operator claim sent with authoritative: true) carries an authoritative member in the entry: the member is dropped, or the claim not shown |
| `sync.signed-claims` | must | CLIENT sync, PROTOCOL 6.2 | signedClaims is {"claims","signature"}: every claim exactly as the simulator sent it, with the envelope's claimsSignature, which verifies with the simulator's key for the message |
| `sync.claims-identifier` | should | CLIENT sync, PROTOCOL 6.2, registry identifier | for a message without a for header, the entry shows the identifier claim of: agent naming mailto: an address on the simulator's own domain, as sent, with authoritative: true; and no identifier claim naming an address on a domain naming no server, naming another agent, or of: principal |
| `sync.claims-untrusted-hidden` | should | CLIENT sync, PROTOCOL 6.2 | the entries of sync.claims-not-authoritative show no acts-for claim at all (a server trusts no carrier unless its operator chose it, and the simulator is no such carrier) |
| `sync.parameters` | must | CLIENT sync | 200 for no parameters, limit=1, limit=200 and wait=0; 400 invalid for out-of-range or non-integer limit and wait |
| `sync.unknown-token` | must | CLIENT sync | 410 token_expired for a token the server never issued |
| `sync.paging` | must | CLIENT sync | passing each token as since with limit=1 gives the same messages in the same order as reading with limit=200, without losing entries |
| `sync.sent` | must | CLIENT sync | sync includes an accepted outgoing message with this server as carrier and exactly the message sent |

### Signals, received from the simulator (PROTOCOL 6.4)

| Check | Level | Section | Expected |
| --- | --- | --- | --- |
| `signal.accepted` | must | PROTOCOL 6.4 | 202 with the body {"accepted":true} for typing, collected and read signals, and for a type the registry may add, each signed by the simulator's server key and naming this server |
| `signal.shape` | must | PROTOCOL 6.4 | 400 invalid with details.field "type" for a type in upper case, "to" for an empty to, "about" for an about that is not a message id, "at" for an at that is not a timestamp, and "signal" for a signal over 4096 canonical bytes without its signature; 413 body_too_large for a body over 16384 bytes |
| `signal.destination` | must | PROTOCOL 6.4 | 400 invalid with details.field "server" for a signal naming the simulator's own origin as its server |
| `signal.signature` | must | PROTOCOL 6.4 | 403 bad_signature for a signal signed by a key the simulator's server document does not list, and for one changed after signing |
| `signal.served` | must | PROTOCOL 6.4 | 400 invalid with details.field "to" for a signal also naming an address on a domain the server does not serve |
| `signal.order-signature-before-served` | must | PROTOCOL 6.4 steps 5-6, PROTOCOL 11.2 | 403 bad_signature, not 400 on to, for a signal signed by a key the simulator's server document does not list and naming an address on a domain the server does not serve: no recipient is looked up for an unauthenticated caller |
| `signal.freshness` | must | PROTOCOL 6.4 | 202 for an at 300 s old less the clock margin; 400 invalid with details.field "at" for one 300 s old plus the margin, and one 300 s ahead plus the margin |
| `signal.silence` | must | PROTOCOL 6.4, 6.3 "Policy is silent" | byte-identical 202 answers for a signal to the agent the message went to, to an unknown name on the server's domain, and about a message nobody here holds |
| `signal.not-stored` | must | PROTOCOL 6.4 | the recipient's inbox holds exactly the entries it held before, a second after valid signals to it |

### Deliver, sent to the simulator (PROTOCOL 6)

| Check | Level | Section | Expected |
| --- | --- | --- | --- |
| `outbound.delivered` | must | PROTOCOL 6 (the server delivering) | a message sent to agents on the simulator's domain arrives at the simulator's /simon/deliver within the delivery wait |
| `outbound.envelope` | must | PROTOCOL 6 (the server delivering), 6.2-6.3 | the body parses under section 5.1's rules, has the envelope's shape, carries the message in canonical form, the message keeps version 2's rules, and the envelope is for the simulator and recipients on its domain |
| `outbound.destination` | must | PROTOCOL 6 (the server delivering).1 | server is the simulator's origin, and recipients are exactly the addresses of to on the simulator's domain, as written (not the recipient on the server itself) |
| `outbound.envelope-signature` | must | PROTOCOL 6 (the server delivering).1 | the envelope's signature, over SIMON-ENVELOPE\n and the canonical envelope without signature, verifies with a key the server's document lists valid at arrival |
| `outbound.message-intact` | must | PROTOCOL 6 (the server delivering), PROTOCOL 1 | the envelope's message member is the canonical bytes the agent sent, so its id is unchanged |
| `outbound.author-verifiable` | must | PROTOCOL 6 (the server delivering).1, PROTOCOL 4 | the author's agent document, fetched from the server, lists a key that verifies the delivered message at its sentAt |
| `outbound.one-envelope` | must | PROTOCOL 6 (the server delivering) | a message to two agents at the simulator arrives in exactly one envelope (the simulator answered 202) |
| `outbound.hints` | must | PROTOCOL 6 (the server delivering).2, CLIENT send "Hints" | the envelope's hints hold exactly the hints the simon-hints header gave for recipients at the simulator (a non-ASCII value, escaped in the header, arrives as itself), and none for the recipient on the server itself |
| `outbound.per-server` | must | PROTOCOL 6 (the server delivering), 6.1-6.2, CLIENT send "Hints" | for a message to agents at both simulators (given --second-peer-domain) and one local agent: each simulator receives exactly one envelope, naming its own origin, exactly its own recipients, and only their hints |
| `outbound.claims` | must | PROTOCOL 6 (the server delivering).2 | claims, when present, are at most 16 objects with a non-empty string type; an acts-for claim names the author as agent and the message's for header as for |
| `outbound.not-before-sent-at` | must | PROTOCOL 6 (the server delivering).3 "Delivery" | a message dated 45 s ahead of the server's clock reaches the simulator no earlier than its sentAt (less the clock margin), and within the retry wait after it |
| `outbound.no-retry-on-4xx` | should | PROTOCOL 6 (the server delivering).3 "Delivery" | after the simulator answers 400, the server does not deliver the same message again (watched for 10 s) |
| `outbound.retry` | must | PROTOCOL 6 (the server delivering).3 "Delivery", PROTOCOL 9 | after the simulator answers 503 (Retry-After: 1), the server delivers the same message again, byte for byte, within the retry wait |

### sent (CLIENT)

| Check | Level | Section | Expected |
| --- | --- | --- | --- |
| `sent.shape` | must | CLIENT sent | 200 {"id","servers":[{"server","recipients","status"}]}, each recipient in exactly one entry, the simulator's two agents together under its origin, status pending, delivered or failed |
| `sent.delivered` | must | CLIENT sent | the entry for the simulator becomes "delivered" after the simulator answered 202 |
| `sent.local` | should | CLIENT sent | the recipient on the server itself is in an entry under the server's own origin that becomes delivered |
| `sent.failed-not-found` | must | CLIENT sent | {"server":null,"recipients":[...],"status":"failed","reason":"not_found"} for a recipient on a domain with no SIMON server |
| `sent.failed-code` | must | CLIENT sent, PROTOCOL 6.3 "Delivery" | status "failed" with reason "invalid" once the simulator answered 400 invalid |
| `sent.pending-while-retrying` | should | CLIENT sent | between the simulator's 503 and the retry, the entry says "pending" |
| `sent.after-retry` | must | CLIENT sent | once the retry was answered 202, the entry says "delivered" |
| `sent.expired` | should | CLIENT sent, PROTOCOL 6.3 "Delivery" | status "failed" with reason "expired" once the deadline passed (the earlier of five days after acceptance and 143 hours after sentAt); not observable black-box, so always skipped |
| `sent.not-found` | must | CLIENT sent, PROTOCOL 9 | 404 not_found for an id the agent never sent |
| `sent.not-yours` | must | CLIENT sent | 404 not_found when an agent asks for the id of a message another agent sent |

### Parts (CLIENT parts, PROTOCOL 7.2)

| Check | Level | Section | Expected |
| --- | --- | --- | --- |
| `parts.upload` | must | CLIENT parts | 200 {"sha256","size"} for PUT /simon/parts/<sha256> with those bytes; the agent then fetches them back unchanged |
| `parts.upload-mismatch` | must | CLIENT parts | 400 invalid for an upload whose body does not hash to the path |
| `parts.upload-too-large` | should | CLIENT parts | 413 body_too_large for an upload one byte over the published partBytes (skipped above 64 MiB) |
| `parts.private-unsigned` | must | PROTOCOL 7.2 | 404 not_found for an unsigned GET of a part only named by a message to the simulator's agents |
| `parts.server-fetch` | must | PROTOCOL 7.2 | 200 with exactly the bytes, for GET /simon/parts/<sha256> signed by the simulator (simon-server its origin) after the server delivered it a message naming the part |
| `parts.server-request-forged` | must | PROTOCOL 7.2, PROTOCOL 8 | the 404 not_found every refusal gets, for a part delivered to the simulator, fetched with simon-server naming the simulator but signed by a key its document does not list, or by its revoked key |
| `parts.cross-tenant` | must | PROTOCOL 7.2 rule 2, CLIENT send | agent b uploads a part; agent a's send of a message carrying inline a message that names it answers 400 part_not_uploaded with details.sha256; with a second simulator, b sends it a message naming the part and that server's signed request gets the bytes; the first simulator's signed server request for it, no message delivered to it naming it, is the 404 not_found every refusal gets; b still reads its own upload |
| `parts.no-hosted-oracle` | must | PROTOCOL 7.2 rule 2, PROTOCOL 8 | Requests routed as hosted client calls receive a uniform minimal 401 bad_signature for an unknown key, an unknown hosted address or an invalid signature, with WWW-Authenticate and serverTime but no signingString; unsigned and failed foreign reads without a public grant remain the same 404 not_found |
| `parts.refusals-identical` | must | PROTOCOL 7.2 | the same 404 not_found body for one part fetched unsigned, by a server it was never delivered to (a signed server request), by a server request whose signature does not verify, and by an agent there that neither sent nor received it; and, apart from the hash, for a hash nobody named |
| `parts.public` | must | PROTOCOL 7.2 | 200 with exactly the bytes, for an unsigned GET of a part an agent uploaded, after that agent's public message names it |
| `parts.never-by-naming` | must | PROTOCOL 7.2, CLIENT parts | for bytes agent b uploaded and never sent, after the simulator delivers agent a a message naming their hash: agent a never gets 200 (503 while its server tries the carrier, or 404), and an unsigned GET and the simulator's signed server request get 404 not_found |
| `parts.prefetch` | must | PROTOCOL 7.2 | after the simulator delivers agent a a message naming a part it holds, the server asks the simulator's /simon/parts/<sha256> for it within the prefetch wait, though no agent asked |
| `parts.prefetch-any-recipient` | must | PROTOCOL 7.2 | after the simulator delivers a message naming a part it holds to an address no agent holds, the server asks the simulator's /simon/parts/<sha256> for it within the prefetch wait, as it would for an agent: the fetch tells the carrier nothing about who is there |
| `parts.forward-received` | must | CLIENT send, PROTOCOL 7.2 | once agent a holds a part fetched from the simulator, send answers 200 for a's message naming it to another address at the simulator, with no upload, and the simulator then fetches the bytes from the server with a signed server request |
| `parts.recipient-fetch` | must | CLIENT parts, PROTOCOL 7.2 | the recipient of a message naming a part the simulator holds gets 200 with exactly the bytes within the prefetch wait, and 503 unavailable with Retry-After before then |
| `parts.server-request` | must | PROTOCOL 7.2, PROTOCOL 8 | the server's GET at the simulator carries simon-server (its origin) and a signature by a key its document lists valid now, over the simulator's origin and the path |
| `parts.hash-checked` | must | PROTOCOL 7.2 | once the server fetched them, the recipient does not get 200 when the simulator serves bytes that do not match the hash, nor when the message declares a size the bytes do not have |

### Published messages, feeds and relations (publishing profile; must for a server that publishes)

| Check | Level | Section | Expected |
| --- | --- | --- | --- |
| `public.served` | must | publishing profile, section 1 | 200 {"message","keys"} for an unsigned GET /simon/messages/<id>: the message byte for byte, and keys valid at its sentAt that verify it; no replies member (replies are ordinary messages to the author) |
| `public.not-found` | must | publishing profile, section 1, PROTOCOL 9 | 404 not_found for the id of a message with recipients, and for an id nobody sent |
| `public.retired` | must | publishing profile, section 1, PROTOCOL 2.2, 7.2 | after the operator's --retire-command retires an agent that posted a public message naming a part: 404 not_found for the public message and the part, each of which answered 200 before, and its agent document either 404 or an optional readable retired document (PROTOCOL 4), every key revoked by retirement |
| `public.audience-refused` | must | publishing profile, section 1, PROTOCOL 11.2 | 404 not_found for an unsigned GET /simon/messages/<id> of a post with an audience header, byte-identical to the answer for an id nobody sent |
| `public.audience-signed-refused` | must | publishing profile, section 1, PROTOCOL 8 | 404 not_found, byte-identical to the answer for an id nobody sent, for a GET /simon/messages/<id> of a post with an audience signed by the author's key but naming another agent in simon-agent, and for one signed by another agent's key naming the author |
| `public.audience-author` | should | publishing profile, section 1, PROTOCOL 8 | 200 {"message"} for a GET /simon/messages/<id> of a post with an audience, signed with the author's key and naming the author in simon-agent: the reader is identified by its agent key, with no server vouching for it |
| `public.feed` | must | publishing profile, section 3 | GET /simon/feeds/<address>/<feed>?limit=1 answers {"messages","cursor","more"} holding the newest post in the feed; passing its cursor as before gives the one before it; never the post with an audience or the post in no feed, and more false with cursor null at the end |
| `public.feed-empty` | must | publishing profile, section 3 | byte-identical 200 {"messages":[],"cursor":null,"more":false} for a feed name nobody used and for an address nobody holds; 400 invalid for limit=0 and limit=201 |
| `public.related-only-listed` | must | publishing profile, section 4; PROTOCOL 5.4 | once a comment without listed and a plain reply from the simulator to a post are in its author's inbox, GET /simon/messages/<id>/related holds neither; a server that lists no relations (404) skips |
| `public.related` | should | publishing profile, section 4 | once a comment marked listed: yes from the simulator to a post is in its author's inbox, GET /simon/messages/<id>/related holds it; once the simulator retracts it (rel: retract), the listing no longer does |

### Errors (PROTOCOL 9, CLIENT errors)

| Check | Level | Section | Expected |
| --- | --- | --- | --- |
| `errors.shape` | must | PROTOCOL 9 | every 4xx and 5xx answer of the run is a JSON object with a string code, status equal to the HTTP status, a boolean retryable, details an object when present, and type, title and detail strings when present |
| `errors.content-type` | must | PROTOCOL 9 | every 4xx and 5xx answer of the run has Content-Type application/problem+json (parameters allowed) |
| `errors.retryable` | must | PROTOCOL 6.3 "Delivery", 9 | retryable: true on every 429 and 5xx answer; retryable: false on every other 4xx, which is permanent |
| `errors.status` | must | PROTOCOL 9, CLIENT errors | every code the spec defines comes with the status its table gives (invalid 400, address_required 400, too_many_keys 400, part_not_uploaded 400, unsupported_version 400, signature_required 401, stale_request 401, replayed_request 401, unknown_key 401, key_revoked 401, bad_signature 401 or 403, bad_proof 401, unsupported_algorithm 403, not_found 404, address_taken 409, address_homed_elsewhere 409, key_in_use 409, address_not_served 409, code_expired 410, code_locked 410, body_too_large 413, wrong_code 422, rate_limited 429, unavailable 503) |
| `errors.server-time` | must | PROTOCOL 8 | every 401 answer of the run with a request-signature code (signature_required, stale_request, unknown_key, key_revoked, bad_signature, replayed_request) has details.serverTime, an integer number of unix seconds |
| `errors.www-authenticate` | must | PROTOCOL 8, 13 | every 401 answer of the run with a request-signature code (signature_required, stale_request, unknown_key, key_revoked, bad_signature, replayed_request) carries the header WWW-Authenticate: SIMON |
| `errors.rate-limited` | must | PROTOCOL 6.3, 9 | every 429 answer of the run is rate_limited, retryable, with a Retry-After header (passes when the server never rate-limited the suite) |

<!-- checks:end -->
