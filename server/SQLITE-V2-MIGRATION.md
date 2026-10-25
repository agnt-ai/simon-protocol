# Offline schema2 candidate conversion

`scripts/migrate-sqlite-v2.ts` is an explicit offline candidate builder for the legacy schema-2
server's layout (schema2), as recorded exactly in `test/fixtures/sqlite-v2.sql`. The normal
`SqliteStore` constructor still refuses schema2. Its existing schema3–7 upgrades are unchanged.

The result is `VERIFIED_COPY_HELD`, with `activationBlocked: true` and a nonzero CLI exit. It means
the retained data was structurally converted and checked in a private candidate cohort. It does
not mean the candidate is approved for serving. Schema2 contains no durable suppression history;
the tool cannot infer that deleted retractions never existed. Every result retains that blocking
hold and the host/runtime/BOM/backend adoption hold. File activity also retains a terminal-policy
history/adapter hold. There is no operational selection, promotion, force/reset or recovery-drain
override. No automatic startup migration is added.

**Wire version 2.** A schema2 store was written by a wire version 1 server, and its messages are version 1. This server reads version 1 only as a version it does not know, and a signed message cannot be rewritten, so its replies, retractions and files would silently fall away. The converter therefore refuses a store holding any version 1 message (`legacy_wire_version`). A store whose history must be kept stays on a wire version 1 release.

Activation prerequisite: retired agents carried over (`retired_at`, `unpairing: null`) stay private
under the server's default `SIMON_RETIRED_AGENT_DOCUMENTS=private`, matching legacy schema2's 404;
an activated host must not switch to `public` without a separate decision.

## Before any separately authorized execution

The host operator must stop inbound admission, stop every old/new worker and app-outbox sender,
finish in-flight requests/fetches/deliveries/hooks/outbox transactions, and hold a maintenance fence
that all old/new entrypoints and restart mechanisms respect. Durable remote app deliveries may
remain pending; they are preserved. The converter neither sends nor acknowledges them.

The private maintenance file attests `hostStopped`, `callbacksDrained` and `appOutboxStopped`, and
binds the exact origin, public server-key fingerprint, config digest, tool commit claim, trusted UTC
observation/provenance and externally held fence token. These are operator prerequisites, not a
claim that a file token proves every external process has stopped. The converter additionally
acquires actual SQLite `BEGIN IMMEDIATE` writer exclusion on **both** original files before either
snapshot. Failure to acquire the second exclusion releases the first. Reader processes are not
represented as stopped merely because SQLite granted a writer lock. Keep the external fence held
after the command and through any later separately selected activation procedure.

The source must be a regular, single-link file in an owned, non-writable-by-others directory.
Its required cohort file is `app-arrivals.sqlite` beside it. Symlink/alias/wrong-owner paths,
unsafe permissions and unrelated existing candidate directories are refused. Maintenance/fence
files must be private. The output parent must already exist and be owned, without group/other
write permission; the tool creates a fresh bundle with mode0700 and artifacts with mode0600.
The current source tool targets platforms with POSIX ownership and directory-fsync support;
other platforms need a separately reviewed binding. File/cohort size is capped at256MiB per
database including existing sidecars, and each table at250000 rows. Larger inventories require
separately selected capacity work; there is no unbounded/force override.

Example maintenance shape (placeholders are not usable credentials or an execution authorization):

```json
{
  "v": 1,
  "id": "unique-maintenance-identity",
  "origin": "https://host.example",
  "serverKey": "<existing public server key token>",
  "serverKeyFingerprint": "<sha256 of that public key token>",
  "configDigest": "<sha256 of the reviewed host configuration>",
  "toolCommit": "<40 lowercase hex characters for reviewed tool commit>",
  "observedAt": "2026-10-23T12:00:00.000Z",
  "clockProvenance": "<trusted maintenance-clock source>",
  "previousObservedAt": "2026-10-23T11:00:00.000Z",
  "hostStopped": true,
  "callbacksDrained": true,
  "appOutboxStopped": true,
  "fenceFile": "/absolute/private/host-maintenance.fence",
  "fenceToken": "<at least22 base64url characters, exact file content>",
  "limits": {
    "messageBytes": 262144,
    "requestBodyBytes": 1048576,
    "recipients": 100,
    "partBytes": 26214400
  }
}
```

Only a public signing-key token is accepted here. The converter does not need a private signing
key, does not sign/re-sign legacy messages and does not rotate origin/key authority. Bind the actual
runtime/tool dependency BOM independently: recording a supplied tool-commit/config claim does not
prove the executable or active host matches it. That remains an activation hold.

After those prerequisites and a separate execution authorization, the source entrypoint is:

```text
node server/scripts/migrate-sqlite-v2.ts --source /absolute/old/simon.sqlite --directory /absolute/private/new-bundle --maintenance /absolute/private/maintenance.json
```

Exit0 is help only; exit2 is invalid arguments; exit1 is refused/incomplete conversion; exit3 is a
verified copy with blocking holds; exit4 is the same verified copy, but releasing the source handles
and writer exclusions failed afterwards (`cleanupFailed: true`): check the source files and host
before anything else. Stdout/stderr contain status/codes/holds and numeric summary,
not addresses, keys, recovery code hashes/nonces or raw values. The private archives contain the
preserved source data and must not be posted as public review evidence.

## Consistent cut, preservation and refusal

The implementation uses the actual
[Node SQLite backup API](https://nodejs.org/api/sqlite.html#sqlitebackupsourceDb-path-options),
under both writer exclusions, rather than copying only main database files. Committed WAL state
is included in the snapshots. The external maintenance digest/fence is checked again after the
cut. Original SQL rows/schema are not changed by converter DML. Native SQLite may checkpoint its
own sidecars when handles close; the verified, WAL-aware schema2/outbox snapshots preserve the
logical pre-conversion cohort independently of those physical file housekeeping effects.

Preflight checks exact old table/index layouts, rejects unknown views/triggers/tables or reserved
layouts, checks SQLite integrity, safe integers, exact timestamps, identities/parents, key publication
capacity, body-ID binding, file projections, BLOB lengths/digests, consistent hash sizes and consumed
scope shapes. Publication flags must match the signed audience. Paired principals and published
key-document revocation tolerance are checked without rewriting authority. Consumed continuity
listed/signers/held state, both serving-note formats (and expired exact-null departure tombstones),
postmaster seeds, server-key timestamps and delivery move/refusal state are checked explicitly;
inert extension values remain byte-preserved. Unsupported consumed state refuses. It does not treat a raw hash, BLOB or fetch job as an attachment entitlement.
Known inline files must have the complete same old indexed binding set: a missing carried-file
index refuses instead of adding a new grant. Unknown-version interiors stay opaque.

Any non-null legacy `code` or `recovery` value refuses, even if a wall clock calls it expired.
The old recovery object lacks current owner-defence authority. The converter never invents
`startedAt`, `byKey`, `defended`, cancellation secrets or authority versions for it. Only exact JSON
`null` tombstones are nonusable: they remain in the immutable schema2 snapshot/row ledger and are
omitted from new operational reserved scopes. Counters/marks remain preserved. Legitimate old-host
completion/cancellation/drain, if needed, requires a separately authorized old-host procedure and
a new consistent cut. The bridge cannot select that product/security decision.

All12 old application tables plus `sqlite_sequence` are inventoried with ordered, type-aware row
hashes; BLOBs are hashed. The implementation preserves raw message JSON/id, carrier, judged claims,
received-at spelling, expiry/kept/public/from state and message rowids. It derives only a checked
known-v1 `in_reply_to`; unknown versions receive NULL. Absent legacy signed claims remain SQL NULL.
It does not claim to authenticate missing historical author documents or signing time from an ID.

Old sent `cursor` and `taken` are NULL: schema2 recorded no complete sent stream. Every legacy
agent gets persistent `sync-history-gap=true`. Each device's initial no-since sync receives410
`token_expired`, reason `history_migration` and an opaque resume token; one device does not clear
the flag, and the tool never automatically resumes. Numeric old cursors are not new tokens.
Backend explicit-resume handling is a separate host adoption gate.

Inbox cursors/event flags are preserved. Its old received-at is converted to exact epoch-ms;
no floating-point SQLite date rounding is used. The position high-watermark includes the old
`sqlite_sequence` deleted tail. Usable writable headroom is `(MAX_SAFE_INTEGER-1)-highWatermark`;
zero/negative headroom refuses. Message rowid at/above MAX_SAFE_INTEGER refuses because existing
first-page listing uses a strict sentinel. No renumbering is used to bypass those limits.

Arrivals/fetches retain original rowids and equal-due order. Delivery/arrival attempts, due dates,
deadlines, hints, statuses and leases are preserved. Fetches receive fresh recorded opaque
generations, revision0 and NULL token/exhausted; attempts/due/size/carrier are not reset. Existing
`files:give-up-rounds`, code/lookup/byte counters and terminal marks remain intact. Absence of an
old deleted job is not evidence that a new retry budget may start. The terminal-policy/adapter hold
blocks activation of file activity until that separate integration/history is resolved.

Retained same-author retractions receive only the current rule-derived owner/target/author markers
and bounded receipts, with original pending jobs preserved. Capacity/known marker completeness is
precomputed before the normal current-schema Store is opened on the private candidate for its actual
bootstrap, then the resulting receipt state is checked. New generations are fences, not signatures.
There is still no proof that missing/deleted old suppression history is complete; the historical
suppression hold remains on every output and cannot be overridden by this command.

The separate app outbox remains schema1. Its exact key/domain/body/since/rowid order is copied,
including pending v1/v2 wakeup bodies and unhosted/expired rows. Bodies are address/id/receivedAt
wakeups, not numeric sync cursors. The converted core and `app-arrivals.sqlite` are placed together
under `candidate/`; selecting a different directory without that matching outbox would create an
incorrect empty queue and is outside this tool. No dropUnhosted, retention sweep, network send,
hook emission or event acknowledgement runs during conversion. Actual standalone outbox failure
and downstream dedupe behavior still need that owner's integration proof.

## Journal, retry and recovery

The private bundle keeps `source-core.sqlite`, `source-app-arrivals.sqlite`, `candidate/` and
durable append-only journal files `001-SNAPSHOTTED`, `002-PREFLIGHT_OK`, `003-COPIED`,
`004-VERIFIED`, plus a redacted `REFUSED` marker when possible. Referenced files and journals are
fsynced, including the nested candidate directory before VERIFIED; the result records exact snapshot/candidate hashes, row ledger, observation/config/tool
claims, generation map, high-watermark, tombstone disposition and blocking holds. Full-disk/crash
may prevent the final refusal marker; absence of VERIFIED is never inferred as success. A bundle has
one meaning: once `004-VERIFIED` is durable, no later failure writes `REFUSED` (a crash leaves it
VERIFIED; a failure to release the source handles is reported as verified with `cleanupFailed`, not
as a refusal), and a bundle holding `REFUSED` is never reused, even beside a VERIFIED record.

Candidate copy is transactional. A failed partial copy, bootstrap, integrity/marker verification or
filesystem operation never returns a verified result or selects an operational path. A partial
bundle is preserved and cannot be blindly resumed (`refused_candidate_choose_new_directory` when it
holds `REFUSED`, `incomplete_candidate_choose_new_directory` otherwise); choose a fresh directory
from the frozen cohort.
A complete, matching VERIFIED bundle may be reused only with identical maintenance/input ledger,
capacity policy and exact artifact hashes. Its generations stay stable. Changed inputs, tampered
artifacts, unrelated paths or a previously used operational candidate are refused, not overwritten.

For a later separately selected pre-activation restore, stop/fence the new host and select the
verified original schema2 **and matching app-outbox snapshot**, old binary and old config as one
cohort. The old binary cannot read the current schema (8 or later): never relabel it or point the old executable at it.
After new messages, remote acknowledgements or other external effects, restoring old snapshots
can lose new state or repeat effects; forward reconciliation/dedupe requires a separate decision.
This tool offers no lossless post-activation rollback promise or operational rename command.

## Evidence boundaries

The authored synthetic tests use actual old DDL, genuine signing, real node:sqlite/WAL backups,
actual CLI subprocesses, current Store/sync code and fault injection at journal/copy/bootstrap/verify
boundaries. Fault injection is not a real power-loss/filesystem/HA deployment proof. No real
inventory, old-host drain, production database, activation, remote side effect or live restore is
performed by the tool's tests or its example command.
