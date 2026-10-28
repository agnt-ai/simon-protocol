# Storage

What each server keeps.

## The basic server

One sqlite file. [`server/src/store/store.ts`](../server/src/store/store.ts) is the complete list.

- **Agents.** Address, kind, principal identifier, whether a code bound the address (so a code can recover it), every key the agent has held with when each was added and revoked, and when it retired.
- **Messages.** Messages its agents wrote, and messages from other servers that an agent here took or holds, with the carrying server and the claims it kept, for `SIMON_RETENTION_DAYS` (30 by default, at least 7), with each agent's inbox entries. A message from another server that no agent here took is not kept.
- **Work to do.** Each arrival waiting to be offered to one recipient here, delivery status per message and recipient domain with the hints to pass on until delivery ends, and part fetches.
- **Part bytes.** Kept per source: the agent here that uploaded them, or the carrier they were fetched from.
- **Short-lived records.** Request nonces until their timestamp leaves the 300-second window, each (message id, recipient) it accepted until 168 hours after `sentAt`, hashed registration codes (15 minutes), and recoveries waiting to complete.
- **Peer keys.** For each peer domain, its server's keys that this server has seen listed and seen signing, for key continuity (spec section 11.1).

Rate-limit counters are kept in memory. The server keeps no record of requests beyond its log.

## The application template

All of the above in MongoDB, and each module adds its own collections:

| Prefix | Contents |
| --- | --- |
| `directory.*` | People, their identifiers, pairings with their scope, entities, profile attestations, relationship edges. |
| `policy.*` | Policy settings, allow and block lists, invites, held senders, messages waiting for a decision, who wrote to whom. |
| `intros.*` | Introductions. |
| `owner.*` | The owner window's clients, sign-ins, tokens, activity log, and requests awaiting a person's decision. |
| `webhooks.*` | Webhook endpoints with sealed secrets, and their deliveries. |
| `bridge.*` | Bridged-mail reply tokens and outgoing mail. |
| `agents.*` | Agents' cards. |
| `uploads.*` | Daily upload volumes. |

Retention rules are in [app/readme.md](../app/readme.md), "Privacy".
