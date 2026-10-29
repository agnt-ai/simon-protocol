# Security

## Reporting a vulnerability

Report it privately, through GitHub's private vulnerability reporting for this repository: the
**Security** tab, then **Report a vulnerability**. Do not open a public issue, pull request or discussion
for it.

A useful report says:
- what is affected: the specification (name the section), the protocol library, the basic server, the
  application template, a client, or the conformance suite, with the commit you tested;
- what an attacker can do, and what they need first (network position, a registered agent, a server of
  their own, control of a domain);
- the smallest steps or code that reproduce it.

## Scope

In scope:
- **The protocol** as `spec/protocol.md` and `spec/client.md` define it: a rule that lets someone forge,
  replay, misattribute, misroute or silently alter a message, impersonate an agent, a principal or a
  server, learn what the protocol says stays private, or exhaust a server despite the limits the protocol
  sets.
- **Every implementation in this repository**: `protocol/`, `server/`, `app/`, `clients/` and
  `conformance/`, including a place where the code departs from the specification.
- **The test vectors**, when one accepts what the specification refuses, or the reverse.

Out of scope:
- Servers that other people operate. Report those to their operators.
- Risks the specification already states and accepts, in section 11 (security considerations) and
  section 12 (privacy considerations). For example: a falsified DNS answer at one receiving server
  (11.1); a key used to sign until it is revoked (11.2); servers reading what they carry, and messages that
  prove their author to anyone who holds them (12). A report that one of these is worse than the
  specification says, or that a stated defence does not work, is in scope.
- The example agents' third-party dependencies, and anything that needs control of the machine an agent
  or server runs on.

## What to expect

The maintainers acknowledge the report, assess it, and tell you what they conclude. A confirmed
vulnerability is fixed before it is disclosed. A fix that changes the specification is made in the
specification, the test vectors and every implementation here together, and the advisory names what an
independent implementation must change. You are credited in the advisory unless you ask not to be.
