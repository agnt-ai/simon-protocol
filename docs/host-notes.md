# Notes for hosts

[`spec/protocol.md`](../spec/protocol.md) holds the rules every server follows. This note holds advice the core leaves to each host: choices that help its users and its neighbours, but that no other server needs to share to interoperate. How the reference server in `server/` makes them is in [`reference-server.md`](reference-server.md).

## Naming paired agents

- Give a paired agent a local part that does not reveal its principal. Its address reaches everyone it writes to; its principal reaches only those its messages tell.
- One agent and one identifier make one address (protocol.md 2.2), so a host that pairs many principals with one persona gives each its own address, keys and inbox.

## When identifiers change

An address and a `for` header last as long as the agent and its pairing, but people change email addresses and phone numbers, and some ask to be forgotten. A host whose principals' identifiers may change SHOULD name each principal by a key (`simon-key:`), held for them if they hold none, and carry their current identifiers as claims (the registry's `identifier`), one message at a time. An email address then never has to be signed into messages for good, and changing one changes no address and no pairing (protocol.md 12, "Erasure"). Such a host renews the pairings of the keys it holds before they lapse, as its principals' policy allows (protocol.md 2.2).

## Caching resolution

protocol.md section 3 bounds a cached answer by its source's lifetime, and never lets a failure that may pass become an absence. Within that, the reference library caps what it keeps:

- a `server` answer: its DNS TTL or HTTP freshness lifetime, at most one hour; ten minutes when it states none;
- `not_found`: ten minutes;
- `temporary`: 60 seconds, so one failing domain does not cost a lookup on every request, and a recovery is never hidden for long;
- `invalid_domain`, `invalid_record` and `conflict`: not cached.

A shorter cap costs lookups; a longer one delays a domain that moves. `spec/vectors/v1.json` section `resolution` (`cacheMs`) shows these caps.

## Limiting lookups

- **Agent documents.** Probing for addresses costs a server lookups of agents that are not there. A host MAY limit such lookups per client; past the limit, protocol.md section 4 requires it to answer every agent document alike, `429` with `Retry-After`, so the refusal tells nothing about any address. Verifying a message asks for the agent that wrote it, so the limit seldom touches verification.
- **Work for unauthenticated callers.** The core requires a bound on the DNS and document lookups an unsigned request can cause (protocol.md 11.2). How to bound them, per client network and per registrable domain of the name looked up, with pools that one caller cannot fill, is in `reference-server.md`.

## Budgets and quotas

Every limit beyond the protocol's minimums is a host's own: how many files it fetches at once, how many bytes it accepts from one carrier, how much one sender may send. Size them for the hardware and for fairness between senders. The reference server's defaults, and why, are in `reference-server.md`.
