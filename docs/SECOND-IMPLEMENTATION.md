# A second independent implementation

The spec becomes version 1 only when two independent implementations reproduce every vector and pass the conformance suite against each other (PROTOCOL.md, "Status"). This page says what that second implementation is, what it needs from us, and how we will know it is independent.

## Why it matters

One implementation shows only that its author can read their own spec. A second one, written by someone else from the text alone, finds the places where the text says less than the author meant: every ambiguity becomes a disagreement between two servers, and each one is fixed in the spec. This is the IETF's rule of two interoperable implementations, and it is the only evidence that the spec, not one codebase, is the standard.

## What counts as independent

- **Written from the spec,** that is PROTOCOL.md, CLIENT.md, the registry and the vectors, **not from this repository's code.** The implementer may read DECISIONS.md for reasons, but not the server, the protocol library or the clients.
- **By someone outside the team** that wrote the reference, who keeps a log of every question the text did not answer.
- **In another language,** so that no library is shared: Go, Rust, Python or Java.
- **Its own crypto bindings** for Ed25519 (strict verification, PROTOCOL.md 2.3) and ML-DSA-65, so a library bug in one is not hidden by the same bug in the other.

A port of the reference by its own author is a useful cross-check of bytes (the Python client is one), and is described as that, not as independent.

## What it must pass

1. **Every vector** in `spec/vectors/v1.json`, and the reader cases once they exist (PROTOCOL.md section 15).
2. **The server suite** in network mode, for the *SIMON Core Server* profile at least.
3. **Federation with the reference, both ways:** messages, parts, retries, and refusals, between the two servers on real domains.
4. **The suite run by each against the other:** the suite plays a peer server, and so does each implementation, so each one's outbound behaviour is tested by the other.

## What it gets from us

- **The spec as the only source.** A question the text cannot answer is a spec bug: it is answered by changing the text, and the answer is published, not given privately.
- **An issue label** (`second-implementation`) for every question, and a named maintainer who answers within days.
- **The conformance suite, with network mode,** so the implementer tests against the real network, not our development settings.
- **A reference server** on a public domain to federate with.
- **Credit** in the spec's acknowledgements and in every release that the implementation shaped.

## What we record

- Every disagreement between the two, and which text changed because of it, in `docs/DECISIONS.md`.
- The question log, published as it was kept.
- The day both implementations passed each other's suites. That day, and not before, the Status line of PROTOCOL.md changes.

## Making it easy to attempt

The template servers ([TEMPLATES.md](TEMPLATES.md)) show the shape of a server, and the conformance suite says, check by check, which rule failed and what a conforming server answers instead. Together they let a capable implementer, a person or an agent, go from an empty directory to a passing server without asking us anything. If they cannot, that is the next spec bug to fix.
