# JSON Schemas

Draft 2020-12 shapes for SIMON wire objects. [PROTOCOL.md](../PROTOCOL.md), [CLIENT.md](../CLIENT.md) and [registry.md](../registry.md) govern; a disagreeing schema is wrong. Select a client body with `client.json#/$defs/<name>`; `client.json` itself is a definitions catalog, not a union of endpoints.

| File | Object |
| --- | --- |
| `message.json` | Version 1 message; `common.json#/$defs/anyMessage` is a message of any version (the section 1 invariants), which unsupported versions are judged by |
| `envelope.json`, `signal.json` | Server-to-server delivery and transient signal |
| `server-document.json`, `agent-document.json` | Documents, including optional sync/history advertisement and retirement evidence |
| `published.json`, `listing.json` | Published message and feed/related listing |
| `problem.json` | SIMON problem detail, including explicit sync migration gap details |
| `client.json` | Dedicated lifecycle, account, sync, signal, webhook and selected optional history/delegation bodies |
| `common.json` | Shared grammar and public key/claim shapes |

Important client definitions include `registerRequest` / `registerAnswer`, `recoveryRequest` / `recoveryAnswer` / `recoveryStatusAnswer`, `accountAnswer`, `addKeyRequest`, `cancelRecoveryRequest`, `unpairRequest`, `endGrantAnswer`, `syncAnswer` / `syncEntry`, `sendSignalRequest`, `webhookNotification`, and optional `historyAnswer`, `conversationsAnswer`, `marksRequest`, `grantTokenAnswer`. Registration creates or pairs; it does not silently recover. Successful registration, recovery and key changes return the account. Sync carries sent and received messages with an opaque token; the removed numeric inbox cursor is not a current API. Listing cursors are separate opaque values.

Objects remain open to unknown extension members wherever the protocol permits them. A version 1 message still has exactly its eight top-level members. A passing shape never means an unknown present header named in `critical` is understood, a missing `binding` is consent, or an absent `listed` opts a reply into public listing. A critical name whose header is absent is ignored. Only exact writer-signed `listed: yes`, on a valid non-published relation, gives that consent; principal consent for `acts-for` is separate.

Schema validation alone cannot establish:

- canonical bytes/base64url, UTF-8 byte bounds, the final signed 128 KiB document limit, aggregate carried-file work, or exact arithmetic;
- actual calendar moments, current/future key validity, retired-key ordering, origin/address binding, DNS authority, signatures or proof possession;
- authorization, key roles, current account membership, recovery atomicity, webhook URL/transport safety or endpoint availability;
- opaque-token account/origin binding, expiry, complete retention, deduplication or durable retraction suppression.

Document `keys` has at most 32 total entries, retained revoked entries included. Optional retirement evidence is a host disclosure choice. A fresh reader may lose verification when authenticated old keys disappear; stored messages are not a durable evidence archive. A `history` object with `retentionDays` advertises optional history calls; absent or false means a relay may offer retained sync only. Positive whole days or null describe history retention; no perpetual verification service follows. OAuth delegation likewise depends on host discovery. The reference host's webhook answer shapes are labeled as such because CLIENT specifies the verification behavior without fixing every success body.

`410 token_expired` is a gap. For `details.reason: history_migration`, each client must explicitly accept the limitation before using `details.resumeToken`; no automatic replay is implied. Signals are transient and may be dropped; received sync notes expire five minutes after arrival.

The `origin` grammar accepts production HTTPS only; explicit development HTTP origins do not match. The URL and address patterns are shape aids, not complete transport or IDNA validation. `unsignedSendRequest` intentionally leaves message semantics to the protocol validator.

`protocol/test/schemas.test.ts` validates the vectors against these schemas with a draft 2020-12 validator: every message, envelope, signal, document, published answer and problem the vectors accept is valid under its schema, and every one they refuse is invalid unless the test names the rule a schema cannot state (a size, canonical bytes, a calendar date, a signature, the receiving server's context, or a carried message's interior). The client API shapes beyond those are not checked against server answers; no readiness or interoperability result is asserted here.
