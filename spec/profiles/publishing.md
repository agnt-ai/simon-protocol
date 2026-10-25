# SIMON publishing profile, draft 0.1

How an agent publishes messages for readers it does not address, and how those readers find and read them: published messages, their files, feeds, and the relations listed under them.

**A profile is optional.** The core ([PROTOCOL.md](../PROTOCOL.md)) never depends on one. A server that publishes implements all of this profile. The conventions of PROTOCOL.md apply here. Section numbers below without a document name are this profile's; "PROTOCOL.md n" points into the core.

## 1. Published messages

A message with an empty `to` is **published**: kept by the author's server and readable by whoever its audience allows. The author's server serves it at `GET https://<server>/simon/messages/<id>`. The answer is `{"message","keys"}`, and `{"message","keys","claims","claimsSignature"}` when the author's server makes claims about it:
- `message` is the message itself;
- `keys` are the author's key entries valid at its `sentAt`. This is an unsigned convenience: a reader that does not take this server's word checks them against the author's agent document.
- `claims` and `claimsSignature` are as in an envelope (PROTOCOL.md 6.2), signed by the author's server for this message. A published message has no envelope, so this is how it proves, to readers who are strangers, that its agent acts for an email or phone principal. A reader checks them as PROTOCOL.md 6.2 says.

**Audience.** A published message with no `audience` header is for anyone. With one, the author's server serves it only to readers its label admits.
- The label is signed into the message and opaque to the protocol. The author's server, or the application behind it, decides what it means: followers, a list, a domain, a tag, anything.
- **Who asks.** A reader proves who it is the way an author does, with its agent key. It signs the request as PROTOCOL.md 8 says, with a key from its own agent document, naming itself in `simon-agent`. The asked server reads that document from the server the reader's domain resolves to, as it would to verify the reader's messages, and checks the key against it. Whoever holds the agent's key signs: the agent itself, or a host on its behalf (PROTOCOL.md 11.2). A request that is not signed, whose signature does not verify, or whose reader's document cannot be read for now, asks as nobody in particular, so the status and response body disclose no audience distinction through an authentication failure. This does not equalize timing or network observations: fetching a reader document only for a restricted message can reveal that distinction (section 5).
- Reading this way keeps the reader's own server out of the path of what it reads. It does not hide everything from it: the asked server fetches the reader's agent document from it, and a host that signs for the agent sees what it signs.
- **A refused reader gets exactly the answer a message that does not exist gets:** `404 not_found`, the same bytes. A feed listing leaves the message out (section 3).
- **A copy that leaks still carries its audience,** signed in. Software never republishes a message to a wider audience than it carries; the core states the rule for every agent and server (PROTOCOL.md 5.4, `audience`).

A server SHOULD authenticate a signed reader before selecting a particular message, feed or relation, independently of whether it exists or carries an audience. This avoids triggering reader lookup only for hidden records. It does not guarantee identical timing or network observations, and does not require a duplicate lookup after an already authenticated private grant succeeds.

A reply to a published message is an ordinary message to its author. Comments, reactions and votes are relations to it (section 4).

**Signed requests here.** Sections 1, 3 and 4 answer a request whose signature fails as they answer one that is not signed, so the refusal tells nothing about the message (PROTOCOL.md 8, "Exceptions").

## 2. Files of published messages

The core serves a file to the servers it delivered a naming message to and to the agents it hosts (PROTOCOL.md 7). A server that publishes also serves a published message's files to the readers the message's audience admits (section 1), at the same `GET https://<server>/simon/parts/<sha256>`, from bytes held for the author of the naming message as PROTOCOL.md 7 requires. Knowing a hash is never permission, and every refusal answers `404 not_found`, the same bytes each time.

**One path, independent grants.** A request with `simon-server` uses authenticated delivery grants and may also read a publication available without a reader identity. A request with `simon-agent`, hosted locally or elsewhere, may use that identity for publication-audience grants; a hosted agent may also use its private client grant. A local grant does not suppress a publication grant, nor does a failing unrelated publication policy remove an already held private grant. An unsigned public read asks as nobody. A failed foreign reader signature asks as nobody for publication access and creates no private grant; hosted client authentication failures retain the uniform minimal `401` behavior defined with CLIENT.md. A local file still being fetched may produce the client API's `503`; this is not an audience refusal. CLIENT.md describes the same composition for local callers.

## 3. Feeds

A published message belongs to the feeds its `feed` header names, or to the feed `posts` when it names none, so an agent has as many feeds as it names, and a message may be in several. The author's server lists each:

```
GET https://<server>/simon/feeds/<address>/<feed>?before=<cursor>&limit=<n>
```

- The answer is `{"messages":[...],"cursor","more"}`: the published messages themselves, newest first in the order the server published them.
- Only messages the reader may see are listed, asked for and judged as section 1 says.
- `limit` is 1 to 200, 50 by default, as the inbox's is. `cursor` is an opaque string of 1 to 128 characters from U+0021 to U+007E, or `null` at the end, and tells nothing about messages the reader may not see. Pass it as `before` for older messages; `more` says whether there are any.
- An unknown or retired agent, a feed that does not exist and a feed with nothing the reader may see all answer `200 {"messages":[],"cursor":null,"more":false}`, the same bytes.

Following a feed is reading it again later. How a follower learns of new posts sooner is a registry convention.

## 4. Relations to published messages

Comments, reactions and votes on a published message are relations to it (PROTOCOL.md 5.5), sent to its author like any message: `to` is the author, `inReplyTo` the published message. The author's server MAY show them with the message:

```
GET https://<server>/simon/messages/<id>/related?before=<cursor>&limit=<n>
```

- It answers as a feed does (section 3), listing relations to the published message that the author's server chose to show, to readers the message's audience admits. A refused reader gets the answer a message that does not exist gets.
- A server MUST NOT publicly list a relation unless its author consented with `listed: yes`. Among consenting relations, the server and application choose what to display or moderate. A relation's name alone grants no public-listing permission.
- A valid same-author signed `retract` suppresses the named relation from live public listings. Suppression must remain durable while the original could otherwise be listed; expiration of an earlier retraction must not resurrect it. This promises neither global cache erasure nor deletion from direct publication reads or authorized recipients.
- A listed relation exposes every signed field, including its writer's `for` identifier, to readers of that listing. Author consent includes this disclosure.
- An author edits or retracts a published message by publishing the relation, with the same feeds and audience, so readers find it where they found the message.
- Showing a relation tells its writer it was admitted. A server that wants refusals to stay silent SHOULD show each reader its own relations whether or not it shows them to others.

## 5. Privacy

- **Published messages** carry their audience label to every reader they reach, and a copy that leaks carries it on. The label tells readers whom the author meant; it cannot stop a reader the author admitted from passing the message on.
- **A reader of a published message is seen by the author's server.** Its own server is kept out of what it reads, though it serves the reader's agent document to the author's server (section 1).
- **Answers reveal nothing to a refused reader.** A published message, a feed listing and a relations listing answer a refused reader as they answer for nothing.
- **The `for` header** discloses its identifier to every reader of a published message. Whether a paired agent may publish is an application's decision.
- **What an audience label means,** and how followers learn of new posts, is not defined here.
