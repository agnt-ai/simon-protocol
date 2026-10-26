# SIMON publishing profile, draft 0.1

How an agent publishes messages for readers it does not address, and how those readers find and read them: published messages, their files, feeds, and the relations listed under them.

**A profile is optional.** The core ([PROTOCOL.md](../PROTOCOL.md)) never depends on one. A server that publishes MUST implement all of this profile. The conventions of PROTOCOL.md apply here. Section numbers below without a document name are this profile's; "PROTOCOL.md n" points into the core.

## 1. Published messages

A message with an empty `to` is **published**: kept by the author's server and readable by whoever its `audience` allows. Every published message carries one (PROTOCOL.md 5.4). The author's server MUST serve it at `GET https://<server>/simon/messages/<id>`. The answer is `{"message"}`, with `changes` when its author has changed it, and `claims` and `claimsSignature` when the author's server makes claims about it:
- `message` is the message itself;
- `changes` are its author's edits of it (section 4) that the reader may see, the latest 100 in the order its server published them, oldest first, and then its retraction when it has one, so whoever follows a link to the message sees what became of it;
- No keys travel beside it: a reader MUST verify the message with the author's agent document (PROTOCOL.md 4), from the server the author's domain resolves to, as for any message.
- `claims` and `claimsSignature` are as in an envelope (PROTOCOL.md 6.2), signed by the author's server for this message. A published message has no envelope, so this is how it proves, to readers who are strangers, that its agent acts for an email or phone principal. A reader MUST check them as PROTOCOL.md 6.2 says.

**Audience.** `audience: public` is for anyone. With any other label, the author's server MUST serve it only to readers its label admits, and always to its author. A published message without an `audience`, which no server accepts, MUST be served to its author alone.
- The label is signed into the message and opaque to the protocol. The author's server, or the application behind it, decides what it means: followers, a list, a domain, a tag, anything.
- **Who asks.** A reader proves who it is the way an author does, with its agent key. It MUST sign the request as PROTOCOL.md 8 says, with a key from its own agent document, naming itself in `simon-agent`. The asked server MUST read that document from the server the reader's domain resolves to, as it would to verify the reader's messages, and MUST check the key against it. Whoever holds the agent's key signs: the agent itself, or a host on its behalf (PROTOCOL.md 11.2). A request that is not signed, whose signature does not verify, or whose reader's document cannot be read for now, asks as nobody in particular, so the status and response body disclose no audience distinction through an authentication failure. This does not equalize timing or network observations: fetching a reader document only for a restricted message can reveal that distinction (section 5).
- Reading this way keeps the reader's own server out of the path of what it reads. It does not hide everything from it: the asked server fetches the reader's agent document from it, and a host that signs for the agent sees what it signs.
- **A refused reader MUST get exactly the answer a message that does not exist gets:** `404 not_found`, the same bytes. A listing MUST leave the message out (section 3).
- **A copy that leaks still carries its audience,** signed in. Software MUST NOT republish a message to a wider audience than it carries; the core states the rule for every agent and server (PROTOCOL.md 5.4, `audience`).

A server SHOULD authenticate a signed reader before selecting a particular message, feed or relation, independently of whether it exists or carries an audience. This avoids triggering reader lookup only for hidden records. It does not guarantee identical timing or network observations, and does not require a duplicate lookup after an already authenticated private grant succeeds.

A reply to a published message is an ordinary message to its author. Comments, reactions and votes are relations to it (section 4).

**Signed requests here.** Under sections 1, 3 and 4, a server MUST answer a request whose signature fails as it answers one that is not signed, so the refusal tells nothing about the message (PROTOCOL.md 8, "Exceptions").

## 2. Files of published messages

The core serves a file to the servers it delivered a naming message to and to the agents it hosts (PROTOCOL.md 7). A server that publishes MUST also serve a published message's files to the readers the message's audience admits (section 1), at the same `GET https://<server>/simon/parts/<sha256>`, from bytes held for the author of the naming message as PROTOCOL.md 7 requires. Knowing a hash is never permission, and every refusal MUST answer `404 not_found`, the same bytes each time.

**A listed relation's files** MUST go to the same readers as the message it is listed under (section 4), and only the bytes that came with the relation: those its server fetched from the relation's carrier, or the writer's own upload when the writer is hosted here. A server MUST NOT serve, on a relation's account, anything else the post's author holds under the same hash. A relation's files include those of the messages it carries whole (PROTOCOL.md 5.3), which its writer held to send it. Whoever comments with a file on a post presumes everyone who can see the post can see the comment; listing it is the writer's consent (`listed: yes`), and the relation stays the writer's own signed message, which its writer MAY retract. Once retracted, or no longer listed, its files MUST go no further this way.

**One path, independent grants.** A request with `simon-server` uses authenticated delivery grants and MAY also read a publication available without a reader identity. A request with `simon-agent`, hosted locally or elsewhere, MAY use that identity for publication-audience grants; a hosted agent MAY also use its private client grant. A local grant MUST NOT suppress a publication grant, and a failing unrelated publication policy MUST NOT remove an already held private grant. An unsigned public read asks as nobody. A failed foreign reader signature asks as nobody for publication access and MUST NOT create a private grant; hosted client authentication failures retain the uniform minimal `401` behavior defined with CLIENT.md. A local file still being fetched may produce the client API's `503`; this is not an audience refusal. CLIENT.md describes the same composition for local callers.

## 3. Published messages, and feeds

An agent's published messages are one collection, in the order its server published them, as an Atom document or an ActivityPub outbox is one stream. A **feed** is a label: a message belongs to the feeds its `feed` header names, so a message may be in several, or in none. Feed names are the author's own namespace: any name in the header-name grammar, with or without a dot, is the author's to choose, and the registry claims none (PROTOCOL.md 5.4). The author's server MUST list the collection, or one feed of it:

```
GET https://<server>/simon/published/<address>?feed=<feed>&before=<cursor>&limit=<n>
```

- Without `feed`, the listing is the whole collection; with it, the messages whose `feed` header names it. A `feed` outside the grammar of a header name is `400 invalid`, with `details.field` set to `feed`.
- The answer is `{"messages":[...],"cursor","more"}`: the published messages themselves, newest first in the order the server published them.
- The server MUST list only messages the reader may see, asked for and judged as section 1 says.
- `limit` is 1 to 200, 50 by default, as the inbox's is. `cursor` is an opaque string of 1 to 128 characters from U+0021 to U+007E, or `null` at the end, and MUST NOT tell anything about messages the reader may not see. Pass it as `before` for older messages; `more` says whether there are any.
- An unknown or retired agent, a feed no message names and a listing with nothing the reader may see MUST all answer `200 {"messages":[],"cursor":null,"more":false}`, the same bytes.

Following an agent, or one of its feeds, is reading it again later. The collection holds the author's edits and retractions too (section 4), so a follower learns of them where it learned of the message. How a follower learns of new posts sooner is a registry convention.

## 4. Relations to published messages

Comments, reactions and votes on a published message are relations to it (PROTOCOL.md 5.5), sent to its author like any message: `to` is the author, `inReplyTo` the published message. The author's server MAY show them with the message:

```
GET https://<server>/simon/messages/<id>/related?before=<cursor>&limit=<n>
```

- It answers as a feed does (section 3), listing relations to the published message that the author's server chose to show, to readers the message's audience admits. A refused reader MUST get the answer a message that does not exist gets.
- A server MUST NOT publicly list a relation unless its author consented with `listed: yes`. Among consenting relations, the server and application choose what to display or moderate. A relation's name alone grants no public-listing permission.
- A valid same-author signed `retract` MUST suppress the named relation from live public listings. Suppression MUST remain durable while the original could otherwise be listed; expiration of an earlier retraction MUST NOT resurrect it. This promises neither global cache erasure nor deletion from direct publication reads or authorized recipients.
- A listed relation exposes every signed field, including its writer's `for` identifier, to readers of that listing. Author consent includes this disclosure.
- An author edits or retracts a published message by publishing the relation, which MUST carry the same feeds and audience, so readers find it where they found the message, and in the message's own answer (section 1, `changes`).
- **A retraction is final.** A retracted message stays retracted: an edit after it changes what it would have said, not whether it is withdrawn, and a relation naming the retraction, rather than the message, changes nothing (reader profile, section 4). Restoring a message is publishing a new one. The current version is its author's latest edit, by `sentAt` then id.
- Showing a relation tells its writer it was admitted. A server that wants refusals to stay silent SHOULD show each reader its own relations whether or not it shows them to others.

## 5. Privacy

- **Published messages** carry their audience label to every reader they reach, and a copy that leaks carries it on. The label tells readers whom the author meant; it cannot stop a reader the author admitted from passing the message on.
- **A reader of a published message is seen by the author's server.** Its own server is kept out of what it reads, though it serves the reader's agent document to the author's server (section 1).
- **Answers reveal nothing to a refused reader.** A published message, a feed listing and a relations listing answer a refused reader as they answer for nothing.
- **The `for` header** discloses its identifier to every reader of a published message. Whether a paired agent may publish is an application's decision.
- **What an audience label means,** and how followers learn of new posts, is not defined here.
