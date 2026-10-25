# SIMON conversations profile, draft 0.1

How readers group messages into conversations. Servers keep no conversation state, and nothing about a conversation is replicated between servers, so there is nothing for two servers to disagree about.

**A profile is optional.** The core ([PROTOCOL.md](../PROTOCOL.md)) never depends on one. A reader that claims this profile implements all of it, as the reader profile's conventions say.

## 1. A conversation

A **conversation** is a message, its **root**, together with every message whose chain of `inReplyTo` leads back to it, through replies and through relations the registry marks as staying in their conversation. A forward, a quote or a comment points at a message without joining its conversation. A conversation's id is its root's id. It is not an object anyone stores.

- The registry's `conversation` header names the root on every later message, so a reader that lacks part of the chain still knows where a message belongs. A reader that holds the chain and finds the header disagrees follows the chain.
- Its **name,** when it has one, is the root's `subject`. A later message's `subject` is that message's own; a reader may show the latest as the conversation's current name.

## 2. Who is in it

**There is no roster.** Each message's `to` is its author's choice of who receives it, and servers deliver to exactly that, no more. This is how email and texting work.
- **Replying.** A reply to everyone starts from the `to` of the message it answers, adds that message's `from`, and drops the replier's own address. Its author may add or leave out anyone.
- **Forks.** A reply that reaches more or fewer people than the message before it forks the conversation: it stays in the same conversation by its `inReplyTo` chain, and each branch has the recipients its messages name. A reader may show a branch apart when its recipients differ.
- **Nothing to forge.** Because no message changes who is in a conversation, no message can add someone behind another's back or outlast its sender's removal. Whoever can write to a person can include them; whoever replies decides whom the reply reaches.

A conversation's reach is bounded by each receiving server's `recipients` limit. Larger groups, list addresses and end-to-end encrypted groups (MLS, PROTOCOL.md 10) are not part of this draft.

## 3. Side threads

A **side thread** hangs from one message of a conversation. Every message in it carries the registry's `thread` header naming that message, its anchor, while its `inReplyTo` names the message it actually answers, which may be the anchor or a later message in the side thread. So one pointer says what a message answers and the other where it belongs, as email's `In-Reply-To` and `References` and Matrix's reply target and thread root do.

## 4. Vectors

`spec/vectors/v2.json` exercises the relations a reader applies (the reader profile). This profile adds no server rule and no signed form.
