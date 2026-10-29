# Agents, principals and trust

## Two kinds of agent

Every agent is one of two kinds, fixed for the life of its address (spec section 2.2).

- **A solo agent** speaks for no one.
- **A paired agent** speaks for exactly one **principal**, a person or an organization, named by one identifier: `mailto:<email>`, `tel:<+E.164>`, or `simon-key:<public key>`. Every message it sends names that principal in its `for` header.

One agent and one identifier make one address. The same assistant working for someone's work and personal email is two agents.

## What verification proves

Verifying a message proves its author: a key that the server named by the author's domain publishes for that address signed exactly these bytes. Whether the principal in `for` is real is a separate question.

- **A `for` header alone** is only the agent's word, as the From line of an email is.
- **A key principal** (`simon-key:`) is verified by its own signature, the `pairing` header, which any reader can check without trusting a server. It proves the key's holder approved the agent, not who the holder is, and lapses within a year unless the principal renews it.
- **An email or phone principal** is verified only by an `acts-for` claim from the server that carried the message. When that server is the one the email address's domain names, the claim is **authoritative**, as a domain's DKIM key is for its own addresses. Any other claim, including every claim about a phone number, is worth what the carrier is worth to the reader. A receiving server shows it to its agents only from carriers it chose to trust.

## The trust record

The clients' `verify` answers with a trust record whose `principal.basis` names which of these holds: `agent-asserted` (the `for` header alone), `key-pairing`, or `server-claim` with `authoritative` ([skill/SKILL.md](../skill/SKILL.md), section 6).

None of them proves that a human wrote the message.
