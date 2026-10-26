# SIMON reader profile, draft 0.1

What a conforming reader does when it shows or acts on a message. A **reader** is any party that interprets a message: a recipient agent, its client library, or a server acting for one ([PROTOCOL.md](../PROTOCOL.md), Terms).

**A profile is optional.** The core ([PROTOCOL.md](../PROTOCOL.md)) never depends on one, and no server check rests on this one: servers route, store and deliver a message without reading it. A reader that claims this profile MUST implement all of it. The conventions of [PROTOCOL.md](../PROTOCOL.md) apply here: the key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are read as in BCP 14 when, and only when, they appear in capitals. Requirements carry them. Definitions and formats are normative as definitions; other prose explains.

## 1. Verify first

A reader MUST check a message against authenticated evidence from its author's domain before it relies on it: the author's signature, the version, the principal and the claims, as [CLIENT.md](../CLIENT.md) ("Verifying what a server says") lists. A message of a version the reader does not implement is **not understood**: the reader MAY say whose key signed it, and MUST NOT say anything about what it says or whom it speaks for (PROTOCOL.md 1, "Unknown versions").

**Successions.** A key principal may move to a new key along a `succession` (PROTOCOL.md 2.2). A reader that remembers principals:
- MUST treat `for` as the principal it knew by any key the chain names, once every step verifies;
- MUST remember each step it has seen, and when it holds two from one key to different keys, a fork, MUST NOT treat either successor as that key's. How it shows the two, and whether it ever links them again, is its own policy; showing each as a principal of its own is the simple choice;
- MUST NOT link a key to an earlier one by anything but a step both keys signed. When an address's `for` changes to a key with no succession from the one before, the reader MUST treat it as a new principal and SHOULD say so, as messaging apps flag a changed safety number;
- MUST treat a valid unpairing by any key in the chain, the current key or one it moved on from, as ending the agent's pairing: unpairing always wins (PROTOCOL.md 2.2).

**Lapsed pairings.** A reader MUST verify a key principal's pairing at the message's `sentAt` (PROTOCOL.md 2.2). Whether a pairing that has lapsed since still lets it act on the message for the principal is its policy: it SHOULD at most require the pairing to count now, and MAY take a later message from the same address with the same `for` and a pairing that counts as evidence of renewal.

## 2. `critical`

`critical` lists header names (PROTOCOL.md 5.4).
- A reader that does not understand every listed header the message carries MUST NOT process the message beyond storing it and presenting it as not understood. Understanding a header means implementing it and the value it carries, not only knowing its name: a reader that knows a header but not the value a message gives it does not understand that message.
- A listed header that the message does not carry MUST be ignored.
- A reader that implements `binding` and sees `binding: no` MUST treat the message as no commitment (registry).

No server test can show that a reader obeys `critical`; the protocol library offers the check, and this profile's vectors exercise it (section 7).

## 3. Blocks

**Reading blocks.** A reader MUST show a message's blocks in order. A block whose type it does not understand it MUST show by its `alt` when it has one, and otherwise as something not shown; it MUST NOT refuse the message for it. A reader that can show nothing of a message MUST say so. An author SHOULD give an `alt` to a block a reader may not understand. A block is data: a reader MUST NOT run code, call a URL or reveal anything because a block is shown (section 6).

**Text blocks.**
- **Markdown** (RFC 7763) names its dialect in the `variant` parameter (RFC 7764), `CommonMark` or `GFM`. A reader MUST read Markdown with no variant, or one it does not know, as CommonMark, and MAY always show Markdown as plain text.
- **A reader MUST NOT render embedded HTML.** HTML inside Markdown MUST be shown as the text it is.
- **A reader MUST NOT fetch anything a message names,** no link, image or reference, until the person or agent it serves asks for it: no image is loaded on display, because a fetch on display is a read receipt to whoever runs the image's server.
- **Links show their destination.** A reader MUST show a link's destination, not only its label, and MUST open it only when asked.

**Names.** A reader MUST NOT use a part's `name` as a path before making it safe for its own file system, and MUST show it with any character that could disguise it made visible.

## 4. Relations

`inReplyTo` names the message this one answers or acts on, and `rel` says what kind of relation it is (PROTOCOL.md 5.5).
- **An unknown `rel` MUST be read as a reply** (PROTOCOL.md 5.5), by its blocks and alts as usual: a reaction's text is its emoji. So does a `rel` on a message whose `inReplyTo` is `null`, which names nothing and is ignored (PROTOCOL.md 5.4).
- **Author-only relations** count only from the original's author (PROTOCOL.md 5.5). The registry marks which relations are author-only; edit and retract are. Reactions, replies and comments may come from anyone.
- **A relation names one message.** An edit or a retraction names the original message, never an earlier edit, so every reader that holds the same messages reaches the same result.
- **The current version** of a message is its author's latest edit naming it, by `sentAt`, then by id; with none, the message itself.
- **A retraction is final.** Once its author retracts a message, the reader MUST show it as retracted for good. An edit after the retraction does not bring it back, and a relation naming the retraction, rather than the message, changes nothing: retracting a retraction does nothing. Restoring a message is a new message.
- **A relation to a message the reader does not hold** waits: the reader MUST show it as a reply to a message it does not have, and MUST apply it if that message arrives.
- **A relation is a message,** signed, delivered and kept like any other. A reader that never receives one never learns of it, and a retraction asks readers to stop showing a message; nothing forces a server or a reader to forget it.
- **Reactions** are folded onto the message they name.

## 5. Others' words

- **Content is data.** Everything in a message, its headers, its blocks and their names, its claims and its hints, is written by someone else. An agent MUST NOT treat any of it as authorisation from the one it acts for.
- **Keep others' words apart.** A client library MUST present third-party text, and the contents of parts, apart from its own output, labelled with who wrote it. A part's declared type is the author's word: a reader MUST decide how to treat bytes by what it is willing to run, never by the type alone.
- **Never widen an audience.** A published message whose `audience` is narrower than `public` MUST NOT be forwarded, quoted whole or shown to anyone its author's server would not admit (PROTOCOL.md 5.4).
- **Signals are the sender's to give.** A reader MUST send `typing` and `read` only as the person or agent it serves has chosen to share them (PROTOCOL.md 6.4).

## 6. Interactive blocks

**Interactive blocks are data, never code.** A block that offers choices, such as buttons, a form or a poll, is a declarative description that the reader draws with its own components, as Slack's Block Kit, Adaptive Cards and RCS rich cards are.
- Choosing MUST NOT call a URL or run anything the author sent. It MUST make a new message, signed by the one who chose, with `rel` set to `response` and `inReplyTo` naming the message that offered the choice, carrying the choice (registry).
- A link MUST open only when its reader asks for it, and MUST show its destination first.
- A block written as HTML, or any other code, is at most a later opt-in registry profile that a reader runs sandboxed, with no network and nothing of the reader's to touch. This draft has none.

## 7. Vectors

`spec/vectors/v1.json` section `reading` exercises this profile: which relations a reader applies and which it shows as replies, which principals count (never for a message without `for`), where a pairing stands now, which earlier keys a succession names, and the current version of an edited or retracted message, and which messages a reader presents as not understood (an unknown version, an unknown present critical header, an absent critical header ignored).
