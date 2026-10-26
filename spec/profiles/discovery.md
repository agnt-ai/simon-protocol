# SIMON discovery profile, draft 0.1

How an agent finds the assistant a person chose, from an identifier it already has: an email address or a phone number. The person's own app turns a name into an identifier from its contacts; nothing here searches by name, and nothing lists who is there.

**A profile is optional.** The core ([PROTOCOL.md](../PROTOCOL.md)) never depends on one. A server that answers lookups, or keeps a directory, implements all of this profile. The conventions of PROTOCOL.md apply here, its key words included. Section numbers below without a document name are this profile's.

## 1. Directory records

A **directory record** says that the holder of an identifier chose an assistant, on its issuer's word:

```json
{"identifier":"mailto:sarah@example.org","address":"sarah@assistants.example","revision":3,
 "issued":"2026-10-26T09:00:00Z","expires":"2027-10-26T09:00:00Z",
 "issuer":"https://simon.directory.example","signature":"..."}
```

- `identifier` is a `mailto:` or `tel:` identifier, written as PROTOCOL.md 2.2 writes it. A key principal needs no record: its key is already its name.
- `address` is the chosen assistant, an address as PROTOCOL.md 2.1 writes one.
- `revision` is a whole number from 1 to 2^53 − 1. Each new choice its issuer records for the identifier takes a higher one, never restarting, even after the identifier was unlisted.
- `issued` and `expires` are timestamps. `issued` is before `expires`, and `expires` is at most 366 days after it, as a pairing lasts (PROTOCOL.md 2.2): a choice nobody renews lapses.
- `issuer` is the https origin of the server that signed it, written as resolution writes one (PROTOCOL.md 3).
- `signature` is the issuer's base64url signature, with a key of the issuer's server document valid at `issued`, over `SIMON-DIRECTORY\n` and the canonical record without `signature` (PROTOCOL.md 5.1, Appendix A's `directory-signed`). The canonical record is every member the record carries but `signature`, those this profile does not define included, as for a message: a later draft may add a member, and its issuer signs it with the rest.

A reader takes a record only when every member above is as above, its `issuer` is the server the reader asked, it is for the identifier it asked about, `issued` is at most 5 minutes ahead of the reader's clock, the reader's clock is before `expires`, and the signature verifies over every member it arrived with. A member the reader does not know means nothing to it, but is signed like the rest: a record that carries a member its issuer did not sign does not verify, and a reader that passes a record on passes it whole.

## 2. Looking up

```
GET https://<server>/simon/lookup?identifier=<identifier, percent-encoded>
```

- A server that answers lookups says so in its server document (PROTOCOL.md 4) with the member `"discovery": true`. One without it answers none, and readers do not ask it.
- The identifier is percent-encoded as a form value is, `+` included: `tel:+14155550100` is sent as `tel%3A%2B14155550100`. A server reads the query as a form, where a bare `+` is a space.

- The asker signs the request with its agent key, naming itself in `simon-agent` (PROTOCOL.md 8), as a reader of a published message does (publishing profile, section 1). An unsigned request, or one whose signature fails, is `401`: lookups are attributable, so a server can bound what any one agent asks.
- The answer is `200 {"record"}`, the server's latest record for the identifier, or `404 not_found`. An identifier nobody listed, one that was unlisted, one whose record lapsed, and one the server never heard of all answer the same `404`, the same bytes, so an answer tells nothing about who is not there.
- A malformed identifier is `400 invalid`, with `details.field` set to `identifier`.

## 3. Who answers

A reader asks, in this order:

1. **The identifier's own domain.** For `mailto:`, when the domain's `_simon` TXT record names a server (PROTOCOL.md 3) whose server document says `discovery`, that server is the identifier's authority, as it is for claims (PROTOCOL.md 6.2): it speaks for its own domain's addresses, as a domain's DKIM key does. Its answer is final. When it answers `404`, the identifier has no record, and the reader asks no directory: a directory cannot speak for a domain that speaks for itself. When it fails, the lookup failed.
   - A domain whose `_simon` records are malformed or conflict (PROTOCOL.md 3's `invalid_record` and `conflict`) has no answer: the lookup failed, and the reader asks no directory. The domain tried to speak for itself, halfway through moving servers for instance, and a directory does not speak over it.
   - A server whose document does not say `discovery` has not taken up this profile. Its domain has not spoken, and the reader asks the directories it trusts, as for a domain that names no server.
2. **The directories the reader trusts,** in its own order, for every other identifier: an email address on a domain that names no server, such as a webmail provider's, and every phone number. Each is an https origin. The first record that verifies is the answer. A directory that answers anything else, a record that does not verify included, is passed over; when none holds a record and one of them failed, the lookup failed, and never means nobody. Which directories to trust is the reader's choice, as which carriers' claims to trust is (PROTOCOL.md 6.2). A host MAY offer its agents a default list.

A domain named only by its well-known answer (PROTOCOL.md 3) is not an authority here, as it is not for claims: whoever runs a domain's website need not run its mail.

**What a record proves** is its issuer's word that the holder of the identifier chose that assistant, as of `issued`. An authority's record is as strong as its domain's DNS. A directory's is as strong as its check, below, and the reader's trust in it. Neither says who or what runs the assistant. Messages from the assistant still name their principal on their own evidence (PROTOCOL.md 2.2).

## 4. Keeping a directory

A server that keeps a directory lists an identifier only once its holder has proved control of it, and only at its assistant's ask: no identifier is listed for someone else. A host's listing for an agent it hosts, below, counts as that assistant's ask.

```
POST https://<server>/simon/directory   {"identifier"}
POST https://<server>/simon/directory   {"identifier","code"}
```

- The listed agent signs both calls with its own agent key, naming itself in `simon-agent` (PROTOCOL.md 8): its signature is the assistant's consent. An agent hosted anywhere may list itself.
- The first call sends a code to the identifier, by email for `mailto:` or by text for `tel:`, naming the assistant that asks, and answers `202 {"status":"code_sent"}`. A directory that cannot reach that kind of identifier answers `400 invalid`, with `details.field` set to `identifier`.
- The same call with the code issues a new record for the identifier and the asking agent, replacing any earlier one, and answers `200 {"record"}`. A wrong or expired code is `401 bad_proof`. The holder of the identifier is who reads that code, so whoever lists an identifier chose that assistant.
- `DELETE https://<server>/simon/directory` with `{"identifier"}`, signed by the listed agent, unlists it at once and answers `200 {"status":"unlisted"}`, the same answer whatever the agent was listed for. Lookups then answer `404`.
- **The holder needs no assistant to leave.** The same call from anyone else, signed or not, answers `202 {"status":"code_sent"}`, and sends the identifier a code only when it is listed; with `{"identifier","code"}` it unlists it and answers `200 {"status":"unlisted"}`. A wrong or expired code is `401 bad_proof`. The answer and its bytes are the same whether or not the identifier is listed, and a directory SHOULD count the same limits and do the same work before it answers either way (section 6).
- **No one else can keep a holder listed.** A directory SHOULD bound unlisting codes apart from listing codes, so asking to be listed never uses up the holder's way out, and SHOULD NOT replace an unlisting code that has not expired: a request from anyone else then leaves the code in the holder's mailbox working. One outstanding unlisting code per identifier is also what keeps such requests from flooding it.
- **Codes.** A code SHOULD expire within minutes and allow a few wrong attempts. Wrong attempts SHOULD count against the client making them, so that a third party's guesses do not lock the holder out of its code, with an overall bound after which the code is dropped and a new one may be sent.
- **Renewing.** A record lapses unless renewed. The assistant renews it by the same two calls, or its host by the listing without a code below.
- **Without a code.** A server MAY list an identifier it has already proved control of by other means, for an agent it hosts and with its holder's consent, such as a host that verified an email address when it set up the person's assistant. Such a listing is the host's word, as an `acts-for` claim is.

## 5. When there is no record

An agent that finds no record does not guess an address and does not search.

*Note:* what it does instead is the host's choice. It might tell the one it acts for, who can send their contact a one-link invitation through their host, from which the contact's assistant sets itself up. Invitations are a host feature, not part of this profile.

## 6. Privacy

- **Opt-in only.** An identifier is listed only by its holder's choice, and a lookup for any other answers as for nobody.
- **No enumeration.** A server answers one identifier at a time, never a list or a search, and its answers and their bytes are the same for every identifier it has no record of, unlisting requests included (section 4). A server SHOULD bound lookups per asking agent and per registrable domain of the asking agents (by the Public Suffix List, say), since agents and subdomains are cheap to make, and SHOULD NOT do more work for a listed identifier than for an unlisted one before it answers. How high the bounds are, and whether a large host's agents share one, is the server's policy.
- **Codes are not spam.** A directory SHOULD bound the codes it sends per identifier, per asking agent and per client, and a listing code's message names the assistant that asked, so a holder who did not ask knows whom to ignore.
- **The asker is seen.** The answering server learns which agent asked about which identifier. An agent that asks about a contact reveals its interest to the contact's authority or directory, as a mail client reveals a recipient to its server.
- **A record links an identifier to an assistant** for anyone who knows the identifier. A holder who wants an assistant unlinked to their email address lists none, and relies on invitations.

## 7. Vectors

`spec/vectors/v1.json` section `directoryRecords` exercises the record: its signing bytes, its signature, and which records a reader takes at a given moment, among them one with a member its issuer signed and one with a member attached after signing.
