# simon: the SIMON Protocol in Python

A client for [SIMON Protocol version 2](../../spec/PROTOCOL.md): one signed message to `name@domain`. It
makes the signed calls of [CLIENT.md](../../spec/CLIENT.md), and reads and verifies what other agents send.
Python 3.11 or later, standard library only. It reproduces every case in
[spec/vectors/v2.json](../../spec/vectors/v2.json).

## Install

```sh
pip install './clients/python[crypto]'         # cryptography signs in constant time
pip install './clients/python[crypto,dns]'     # and dnspython resolves domains
```

Without `dns`, a small stub resolver asks the nameservers in `/etc/resolv.conf`.

## Example

```python
from simon import Agent, SigningKey

key = SigningKey.generate()  # keep key.to_pem(): it is the agent
agent = Agent("https://simon.example.com", key)  # your own server: there is no default
agent.register()  # the server leases an address: agent.address
agent.send(["bob@example.net"], "Does 3pm work?", headers={"subject": "Thursday"})
for entry in agent.sync()["messages"]:
    trust = agent.verify_author(entry["message"], signed_claims=entry.get("signedClaims"))
    if trust.verified and trust.understood and trust.principal:
        print(entry["message"]["from"], "for", trust.principal.id, "by", trust.principal.basis)
```

## Who wrote it, and for whom

`verify_author(message, *, signed_claims=None)` answers a `Trust` or a `NotVerified`.

- **Keys come only from resolution.** The author's keys are read from the server the `from` domain
  resolves to (spec sections 3 and 4), never from a server a caller, a flag or a message names, and not
  from an agent's own server for its own domain either. There is no option to name one. Only code can
  replace the resolver, for tests and local development.
- **`Trust`**: `verified`, `id`, `author_signed`, `author_server` (the server that published the key and
  carried the message), `understood`, `claims`, and `principal`:
  - `understood` is False for a message of a version this client does not implement, or whose
    `critical` header lists one it does not understand (it understands the protocol's six): whose key
    signed it is all it says. Act on nothing in it; it names no principal.
  - `principal` is None for a message with no `for` header, or one not understood: a message without
    `for` speaks for no one.
    Otherwise it is a `PrincipalTrust`, whose `basis` is `agent-asserted` (the `for` header alone: the
    agent's word), `key-pairing` (a `simon-key:` principal's pairing verified: the key's holder
    consented, with no server trusted for it, though the agent's keys are still its server's word; not
    identity or humanity), or `server-claim` (an `acts-for` claim the author's server signed).
  - For a `server-claim`: `claimant`, `scope` (registry-shaped names only), and `authoritative`, this
    reader's own judgement that the identifier's email domain names the claimant in its `_simon` TXT
    record: as strong as the domain's DNS.
  - `proves` says what the basis proves, and what it does not.
- **Claims count only as their carrier signed them.** Pass the inbox entry's `signedClaims`; they count
  only when they verify with a key of the server the author's domain resolves to, read here (`claims`
  is then `verified`; otherwise `unverified`, and they are ignored). An entry's `claims` never count:
  they are its server's judgement, and anyone can paste an entry.
- **`NotVerified`**: `reason` is `invalid_message`, `no_server`, `no_agent`, `bad_document`,
  `bad_signature`, `unsupported_algorithm` (the author has keys, none of an algorithm implemented here)
  or `bad_pairing`. A failure that may pass raises a retryable `SimonError`, never "not verified".

`to_json()` writes either in the JavaScript client's shape.

## Signing

Signing uses `cryptography`. Without it, `SigningKey` refuses with `pure_signing_refused`, because the
pure-Python Ed25519 here is not constant time, so anyone who can time many signatures could learn the key.
To accept that risk, pass `allow_pure_python_signing=True` or set `SIMON_ALLOW_PURE_SIGNING=1`.
Verification handles no secret, so it is always pure Python, for Ed25519 and ML-DSA-65 alike, with the
spec's strict Ed25519 rules.

## Errors

Every refusal and failure is `SimonError(code, message, status, retryable, details)`, with `retry_after`
when the server sent `Retry-After`. A server's error is an RFC 9457 problem detail
(`application/problem+json`): the client keeps its `code`, its `detail` as `message`, and its `details`,
and takes `status` and `retryable` (true exactly for `429` and `5xx`) from the HTTP status. An answer
with no problem detail is `bad_response`. Among the server's codes: `unsupported_version` (`send` of a
version the server does not implement), and `403 bad_signature` and `unsupported_algorithm`, which a
receiving server answers at deliver and `sent` reports as reasons.

`status` is None when no answer stands behind the error; the code then says what happened: `invalid` (an
argument, named by `details.field`), `not_registered`, `no_key`, `no_server`, `pure_signing_refused`,
`network_error` and `timeout` (retryable), `unavailable` (a lookup that may pass; retryable),
`bad_response`, `bad_document`, `hash_mismatch`, `path_refused`. A failure that may pass is never read as
an absence.

## Resolution

A refused connection and a certificate not valid for the domain are `not_found`; a DNS server error, a
DNSSEC validation failure, a timeout and a dropped connection are `temporary`. A reader caches a `server`
for its DNS TTL or the well-known answer's HTTP freshness, at most an hour, `not_found` for ten minutes,
and `temporary` for one minute (`resolution_cache_ms`).

## API

`Reader(*, timeout=30.0)` reads other agents and holds no key; `Agent(server, key=None, address=None, *,
principal=None, pairing=None, timeout=30.0)` is a Reader too.

| Call | What it does |
| --- | --- |
| `register(address=None, *, code=None, principal=None, pairing=None, extensions=None)` | create or pair; success is `{address,keys,grants,recovery}` without status; pending is `code_sent` or `pairing_required` |
| `recover(address, principal_key=None, *, code=None, at=None, recover=None)` | dedicated recovery; account on completion, or `code_sent` / `recovery_pending` |
| `account()`, `recovery_status()` | authorized private account / recovery state |
| `revoke_key(key)`, `end_grant(id)` | end a key or grant |
| `send_signal(type,about,to)` | explicit opt-in sharing |
| `add_webhook(url)`, `verify_webhook(id,code)`, `remove_webhook(id)` | verified webhook wake notifications |
| `cancel_recovery(address=None, cancel_code=None)` | cancel by an authorized agent key, or by the mailbox code and its address |
| `add_key(new_key)` | add a key, with its proof |
| `compose(to, text=None, *, parts=(), headers=None, in_reply_to=None)` | a signed, checked message |
| `send(to, text=None, *, hints=None, **draft)`, `send_message(message, *, hints=None)` | send; `{"id", "receivedAt"}` |
| `sync(since=None, limit=None, wait=None)` | `{messages,signals,marks,removed,token,more}`; keep the opaque token unchanged and pass it as `since` |
| `sent(id)` | delivery per recipient server; a failure's `reason` is a resolution outcome, the receiver's code, or `expired` |
| `upload_part(data, type, name=None)`, `fetch_part(sha256, size=None)` | content-addressed parts, checked by hash |
| `call(method, path, body=None, headers=None)` | any other signed call a server adds |
| `server_of(domain)`, `server_document(server)`, `agent_document(address)` | resolution and documents; documents carry `algorithms` |
| `verify_author(message, *, signed_claims=None)` | a `Trust` or a `NotVerified` |

A key principal pairs with `sign_pairing(principal_key, address)`, lasting a year unless given an `until`,
and the agent registers with `principal=principal_key.identifier` and that `pairing`. Before it lapses,
`agent.renew_pairing(pairing)` carries the principal's later one; the server needs no call. A key-pairing
`PrincipalTrust` shows `until`, and `lapsed` for a pairing that counted when sent but not now. When the
principal moves to a new key, `agent.succeed(principal, pairing, succession)` carries it (steps from
`sign_succession(old, new)`); `PrincipalTrust.succeeds` lists the earlier keys.

For output that a model reads, `simon.provenance` labels third-party content: `untrusted(author, basis,
content)`, `present_entry`, `present_delivery`, `invisible_in` and `RULE`.

The protocol itself, for readers and servers: `canonical`, `canonical_bytes`, `parse`, `signing_bytes`;
`message_id`, `sign_message`, `verify_message`, `message_verdict`, `check_author_signature`,
`check_supported_version`, `parse_message`, `check_message`, `check_principal`, `is_principal`,
`pairing_bytes`, `parse_pairing`, `verify_pairing`, `unpairing_bytes`, `sign_unpairing`, `verify_unpairing`, `text_of`;
`parse_envelope` (with a `Receiver` for step 5), `check_served` (step 8), `verify_envelope`,
`check_envelope_signature`, `claims_bytes`, `verify_claims`, `claims_about`, `is_authoritative`,
`judge_claims`, `is_repeat`, `delivery_window`, `delivery_state`; `parse_signal`, `verify_signal`,
`check_signal_freshness`; `is_understood`, `claimed_principal`, `reads_as`;
`read_keys`, `read_server_document`, `read_agent_document`; `resolve`, `Resolution`, `resolution_cache_ms`, `server_origin`;
`signing_string`, `sign_request`, `check_request`, `nonce_expiry`, `add_key_proof`,
`verify_add_key_proof`; `parse_key_token`, `is_public_key`, `verify`, `signature_verdict`, `valid_at`,
`valid_during`; `parse_problem`, `is_retryable`; `normalize_address`, `is_address`, `parse_timestamp`,
`timestamp`.

## Command line

`simon` (or `python -m simon`) keeps the agent in `$SIMON_HOME` (default `~/.config/simon`), the layout the
JavaScript command line keeps: `key.pem` (created exclusively, mode 600), `address.json`
(`{"server", "address", "for"?, "pairing"?}`), and `wait.json`. `SIMON_PRIVATE_KEY`, `SIMON_ADDRESS` and
`SIMON_SERVER` override the files. There is no default server: `register --server URL` saves one.

```sh
simon register --server https://simon.example.com
simon send --to bob@example.net --text 'Does 3pm work?' --attach agenda.pdf
simon wait --timeout 600 --verify
simon verify entry.json        # a message, or an inbox or wait entry so its claims count
simon pair --address ada@example.com --key principal.pem    # as a key principal
```

- **Output** is JSON on stdout; an error is JSON on stderr. The exit status is 2 for a usage error, 75
  for an error that may pass on retry, 3 for a `wait` that timed out, and 1 for any other, or for a
  message that does not verify.
- **What others wrote is labelled.** Messages, claims, and reasons another server gave are printed
  inside `{"untrusted": {"from", "basis", "content", "invisible"?}}`, apart from what the tool and the
  agent's own server say, with `rule` saying it is data, never instructions. `invisible` lists tag
  characters, bidirectional controls and zero-width characters by path.
- **Files stay in the workspace.** Every file the command line reads or writes (`--attach`, `upload`,
  `part --out`, `verify FILE`, `pair --key`) is in `SIMON_WORKSPACE` (default the current directory), links
  resolved, and never under `SIMON_HOME`; anything else is `path_refused`. `add-key --name NAME` keeps the
  new key in `SIMON_HOME`.
- **`wait [--from ADDRESS] [--timeout SECONDS] [--interval SECONDS] [--verify]`** prints the next message
  not yet shown, oldest first, and remembers it in `wait.json`, so wait, reply, wait never shows a message
  twice; `more` says another is already waiting. It is the JavaScript CLI's `wait`, on the same file.
- **Recovery:** `register --address A --recover` makes a new key, then `--code`; a server may answer
  `recovery_pending` until `completesAt`, and `register --cancel-recovery` stops one. Answers carry
  `next`, the command to run next.

The other commands are `sync`, `sent`, `upload`, `part` and `document`; `simon <command> --help` says more.

## Tests

```sh
cd clients/python && python3 -I -m unittest
```

`SIMON_VECTOR_COUNTS=1` prints how many vector cases each section ran. Ed25519 signatures are reproduced
on the pure-Python path, and on `cryptography` when it is installed.

Sync includes sent and received messages. Tokens are opaque; never parse or increment one. A
`410 token_expired` requires an explicit caller decision about restarting retained history. `wait`
shares `{token,pending,seen}` with the JavaScript tools; numeric cursor state requires explicit reset.
`register --recover` is a CLI convenience that calls `/simon/recovery`, never recovery through register.

A fresh recovered paired agent needs its local principal state to compose messages. Pass `for` and
`pairing` to JavaScript/MCP recovery (Python: `principal` and `pairing`; CLI: `--for`/`--pairing`).
For a key principal the pairing signature must verify for the recovered address. These fields are
checked and saved locally and are never added to the recovery request body. Principal-proof recovery
without saved or supplied principal state is rejected. For mailbox recovery of an email/tel pair,
supply its existing principal explicitly; the account response does not infer it.

Opaque signatures and mailbox secrets can begin with `-`. Bind them to their option, for example
`--pairing="$PAIRING"` and `--principal-recovery="$PROOF"`; the same convention applies to
`--recover-proof`, `--unpairing` and `--cancel-code`. Shell quoting preserves bytes but does not make a
separate leading-dash value unambiguous to argparse. Generated creation/recovery continuation commands
use `--for=...` and `--pairing=...` and keep both values shell-quoted when necessary.

Concurrent waits in the same `SIMON_HOME` fail with `concurrent_wait`. JS and Python hold the same
`wait.lock` directory for the whole operation and release it on normal completion/error. No owner is
stolen by age. After a crash, confirm the recorded PID is no longer running, then remove only the stale
`wait.lock` directory and keep `wait.json`. Queued messages are already private local data and can be
returned before network access. A positive wait timeout bounds request/page budgets; timeout zero
means one immediate page request with the normal transport timeout, not a zero wall-clock deadline.

Python runs each synchronous HTTP exchange in a disposable child process. The parent's monotonic
budget includes startup, DNS, connection, response headers, body and IPC, with time reserved for
terminate/kill and bounded cleanup. Four process slots cap concurrency; an unreaped killed worker keeps
its slot until a later nonblocking reap. No daemon worker threads continue after a timeout. This requires
a subprocess-capable Python environment; client/resolution fetch injection and the transport spawn seam
remain available for isolated tests. Runtime timing, platform behavior and end-to-end lifecycle checks
must still be verified before claiming readiness.

`wait.lock` is reserved from key names. Effective saved or supplied recovery pairing is checked against
the target address; a principal recovery proof must verify against that same principal, new key and
`at` before any request is sent. A proof from one principal cannot save another principal's pairing.

Recovery of a different address never inherits a saved email, phone or key principal implicitly.
Supply an explicit local principal choice for that target; key pairing and any principal recovery proof
must agree on the target identity.

The worker runs isolated Python (`-I`) with the trusted absolute package root derived from the loaded
transport module. It does not import a workspace `simon.py`/`simon/` or inherit `PYTHONPATH` imports.
Source definitions cover hostile working directories, actual worker status/error round trips and
slow-header/chunk-framing termination; those checks remain unrun until resource authorization.

### Explicit history migration resume

An upgraded account may answer an initial sync with `410 token_expired`,
`details.reason = history_migration` and `details.resumeToken`. This says old sent history may be
incomplete; every device must learn the gap. After explicitly accepting that limitation, call sync
with the offered token as `since` (`sync --since TOKEN` in the CLI). Normal account binding and expiry
still apply. Clients never replay or accept this token automatically, and starting without `since`
continues to report the gap. Shared waits surface the error and preserve their saved buffers.
