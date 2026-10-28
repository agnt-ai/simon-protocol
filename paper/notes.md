# Notes on the first cut of paper/simon.md

Written 27 October 2026 against branch `docs/readme-cleanup` (commit 8b92a4c). The paper follows `spec/protocol.md` wherever the documents differ. This file lists what the paper could not reconcile, what could not be verified, and what the authors need to decide.

## 1. Disagreements between documents (the spec wins in the paper)

1. **Signing contexts.** `docs/decisions.md`, "Domain separation for every signature", lists ten contexts and omits `SIMON-SUCCEED` and `SIMON-DIRECTORY`, which `spec/protocol.md` Appendix A defines. The paper lists contexts by example and cites Appendix A.
2. **Time-window constants.** `docs/decisions.md` B13.2 and `changelog.md` (0.3.0) say section 9 derives every window from two constants (horizon and skew). `spec/protocol.md` section 9 names three: send window (24 h), delivery horizon (144 h), clock skew (300 s). The paper uses three.
3. **TXT failure caching.** `docs/decisions.md` M5 says section 3 "already bounds [caching] to 60 seconds". Section 3 now says only "only briefly" and moves caps to `docs/host-notes.md`. The paper gives no number.
4. **Fetching parts.** `docs/decisions.md` "Parts: kept per source" states as its Choice that a recipient's server *fetches* the parts of every accepted message. `spec/protocol.md` 7.2 makes it a SHOULD (fetch on arrival), and the decision's own revision note says so. The paper says "should".
5. **Threads versus conversations.** `readme.md` and the brief say "a thread is the chain of `inReplyTo`". The spec's conversations profile calls that a *conversation*, excludes forwards, quotes and comments from it, and reserves *thread* (the `thread` header) for a side thread hanging from an anchor message. The abstract keeps "a thread is the chain of replies" as plain English; section 2.6 uses the profile's terms. Decide which word the paper should lead with.
6. **"No server vouches for an author."** `readme.md` says this. Spec section 12 says the proof of authorship "rests on the honesty of the author's server", which lists the key history, and the carrier signs envelopes and claims. The paper states the precise version (P1). Consider rewording the readme.
7. **Release numbers.** `spec/protocol.md` Status and `readme.md` say the packages are release 0.3.0. `protocol/package.json`, `server/package.json` and `clients/python/pyproject.toml` are at 0.3.1 (changelog: 0.3.1, client-only fix, wire unchanged). The paper says "the 0.3 series".
8. **Node version.** `readme.md` Install says Node 24.6.0 or later; its Quickstart says Node 26. Not used in the paper.
9. **Historical text in decisions.md.** Several entries describe superseded designs in the present tense: `listed` as "a seventh protocol header" (the spec now names eight), roster rules under L2 (rosters were removed in B1), the `kind` member (removed in B13.3), and "fair fetching" as a MUST (now reference-server policy). The paper uses none of them, but a reader following the paper's link to decisions.md will meet them.
10. **Within the spec: probing limits.** `spec/protocol.md` section 4 says a server MAY limit agent-document reads for addresses with no agent; section 12 says it SHOULD. The paper follows section 12 ("should"). One of the two should change.
11. **Within the spec: succession at readers.** Section 2.2 says a reader that knew any key in a succession chain MAY treat `for` as the same principal; the reader profile ("Successions") makes it MUST for a reader that remembers principals, once every step verifies. The paper says "may", following the core. Confirm the intended strength, or make the core say "a reader that remembers principals MUST".
12. **Related-work table in decisions.md** says SIMON shares "TXT-then-well-known handle resolution" with AT Protocol and "server dialback" with XMPP. Both are accurate as resemblances; the paper words them as shared ideas, not shared mechanisms.

## 2. Claims in the paper that are derived, not stated in the spec

These follow from the spec's rules but no sentence of the spec says them. Confirm or cut.

- P2: the identifier names content, not a signing event, so it does not distinguish two valid signatures over the same content (follows from section 1, item 3, and repeat recognition by id in 6.3 step 9).
- P2: a reply proves only that its author knew an identifier, not that the earlier message exists or was received.
- P3: a replay to the same server is a repeat for 168 hours and stale after 144 (both stated separately; the combination is the paper's).
- P6: "the safe end of a stolen principal key is the end of its agents" is spec 11.2's wording; the surrounding enumeration of five limits is the paper's grouping.
- Section 2.2: the reason Unicode normalization is not part of the local-part rule (from decisions.md; the spec gives only Unicode's stability policy for control characters).
- Section 2.3: why a failed TXT lookup must not fall back to the well-known answer (decisions.md M5; the spec states the rule, not the reason).
- P3: "abuse is attributable to a domain and a server" (decisions.md, abuse model; spec 6.1 says peering, limits and claims rest on the envelope signature).
- P7: the Usenet forged-cancel precedent (decisions.md and core.md).
- Section 4.4: the operator's runtime is not isolated between pairs (decisions.md, "Paired and solo agents").
- Section 5: "the two compose" (A2A over a connection a SIMON exchange arranged). This mirrors the roadmap's live-session direction but is not specified.

## 3. Claims I could not verify, or verified only through secondary sources

- **A2A.** The specification page (a2a-protocol.org) was not reachable from this session. Version 1.0 (12 March 2026), the Agent Card at `/.well-known/agent-card.json`, push notifications by webhook, and A2A's move into the Agentic AI Foundation come from the AAIF's own builder guide and one secondary article. One secondary source says Agent Cards may carry JWS signatures over RFC 8785 canonical JSON; the AAIF guide does not mention it, so the paper does not claim it either way. Check before publication: if A2A cards are signed, the related-work row should say so.
- **DMARC.** RFC 9989 (DMARC), with 9990 and 9991 for reporting, published May 2026 on the standards track, obsoleting RFC 7489: confirmed by the RFC Editor listing in search results and secondary articles. I did not read the RFC text itself.
- **AT Protocol at the IETF.** The datatracker page for a WG named `atproto` shows it as abandoned; Bluesky's blog (April 2026) announces a chartered working group named ATP covering repositories and sync. The paper cites the blog. Confirm the WG's datatracker entry.
- **MCP.** Current revision 2026-07-28, from modelcontextprotocol.io's versioning page. MCP under the Agentic AI Foundation since December 2025: secondary press and the AAIF site.
- **MIMI content** draft-09 (4 July 2026, intended Informational), **KEYTRANS protocol** draft-05 (July 2026, header says Standards Track), **WIMSE architecture** draft-08 (6 July 2026, Informational): read on the datatracker. All are working-group drafts, not individual drafts, so they meet the brief's bar; none is an RFC.
- **Matrix.** That Matrix events are signed by servers, and the notary mechanism, are from general knowledge and the server-server API; the "revised more than once" statement about state resolution refers to state resolution v1 and v2. Not re-read for this cut.
- **ActivityPub.** "Signed in common deployments" refers to the HTTP Signatures scheme most implementations use; ActivityPub itself does not mandate it. Worded to avoid citing an unadopted draft.
- **DIDComm v2.1**: DIF Ratified, read on identity.foundation.
- **Interoperability trials.** `docs/decisions.md` records two trials in October 2026 (one of thirty messages). The paper mentions them only as the reference implementation against itself and gives no numbers.
- **Python client.** Its vector test file runs every section of `spec/vectors/v1.json`; I ran it on this branch: 50 tests and 862 subtests passed. The paper says only that it reproduces every vector.

## 4. What the paper deliberately does not contain

- No benchmarks: the only measurements in `docs/decisions.md` are ML-DSA sizes (fixed by FIPS 204), a pre-cap verification time that the document says must be measured again, and two withdrawn items.
- No adoption numbers.
- No proofs. Section 4.5 says no formal model exists and points to the roadmap's ProVerif/Tamarin item and the external review that named it.
- No description of the client API beyond submission, the publishing and discovery profiles beyond one sentence, recovery beyond its risk, or the application template.

## 5. Independent check of this cut

A separate reviewer, who had not seen the paper written, checked it sentence by sentence against the spec. Its three contradictions (caching of *try again*, the value of asking several resolvers from one host, and P3 omitting the DNS adversary), its overstatements (permanent proof, claims checkable forever, the delivery condition, the trials, the Python port's authorship) and most of its gaps are fixed in the paper. Left out for length, and worth considering for a second cut:

- Section 6 timing detail: the envelope key must be valid now, the message key at `sentAt`, the claims key at any moment from `sentAt` to the horizon; a new server key is listed ten minutes before use.
- Receivers ignore claims whose `agent` or `for` do not match the message, and drop any `authoritative` member from their judged copy.
- Hints are not signed by the author and are never stored.
- A lapsed pairing: sends refused, receiving continues; a lost principal key cannot renew; the principal should keep an old key until every agent has sent once; successions are at most 16 steps.
- Custodial keys should be kept apart from the SIMON server and disclosed; decoded content encodings must be bounded; a principal whose key may have been copied should unpair rather than move.
- Appendix B gaps: the MUST check dependencies have no vectors, the file rules have no vectors, and author-only relations have no conformance check.

## 6. Open questions for the authors

1. **Byline.** "The SIMON Protocol maintainers" is a placeholder. Named authors and affiliations?
2. **Length.** About 7,000 words of body plus one table, two diagrams and 36 references: roughly 11 to 12 pages single-column at 11 pt, or about 8 in two columns. Cut further, or keep the threat model at full length?
3. **Name and dedication.** The title and abstract spell out Simple Interoperable Messages Over Network, and a dedication to Simon Baumer closes the paper before the references, in the readme's words (PR #18). Should the dedication say more, or sit under the title instead, as some papers place it?
4. **Thread or conversation** (item 1.5).
5. **Claims issued-at.** The paper calls it an open proposal. Is it still live, or dropped?
6. **Formal models.** Is there a plan, owner or date for ProVerif/Tamarin work that the paper can state?
7. **A2A composition.** Do you want the paper to say SIMON and A2A compose, or only that they differ?
8. **Neutral home and IETF.** The roadmap intends a foundation and an IETF submission. The paper omits both as intentions, not status. Include a sentence?
9. **Figures.** The two code-block diagrams should become real figures for a typeset version.
10. **Reader profile.** P7 and P9 rest on reader rules that only bind readers claiming the reader profile in some cases (`critical`, relations). The paper states them as the core states them; confirm that is the framing you want.
