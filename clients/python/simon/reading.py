"""The rules that bind readers rather than servers: what a reader may make of a message it holds.

No server test can show a reader obeys them, so they live here as functions, with vectors.

- A message of a version the reader does not implement, or listing in ``critical`` a header it does not
  understand, is presented as not understood (sections 1 and 5.4).
- A principal counts only for a paired agent (section 2.2).
- A relation the reader does not know is shown as a reply, and an author-only relation from anyone but the
  original's author is shown as a reply and never applied (section 5.5).
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Any

from .messages import VERSION, header

#: The relations the registry marks author-only: they change or withdraw the message they name.
AUTHOR_ONLY_RELATIONS = frozenset({"edit", "retract"})


def is_understood(message: Mapping[str, Any], understood: Collection[str]) -> bool:
    """Whether a reader that implements version 2 and understands the headers in ``understood`` may act on
    a message, or must present it as not understood: only whose key signed it, nothing it says."""
    if message["v"] != VERSION:
        return False
    critical = header(message, "critical")
    return critical is None or all(header(message, name) is None or name in understood for name in critical.split(","))


def claimed_principal(message: Mapping[str, Any], kind: str) -> str | None:
    """The principal a message names that may count, given what the author's agent document says its kind
    is: the ``for`` header of a version 2 message from a ``paired`` agent, or None. A solo agent, or an
    agent of a kind the reader does not know, speaks for no one whatever its message carries. Whether the
    principal is verified is a further question (a pairing, or a claim)."""
    if message["v"] != VERSION or kind != "paired":
        return None
    return header(message, "for")


def reads_as(
    message: Mapping[str, Any], target: Mapping[str, Any] | None, known: Collection[str]
) -> str:
    """How a reader that knows the relations in ``known`` reads a message, given the message its
    ``inReplyTo`` names (``target``, or None when the reader does not hold it):

    - ``reply``: no ``rel``, a ``rel`` the reader does not know, a ``rel`` on a message whose ``inReplyTo``
      is null (it names nothing, and is ignored), or an author-only relation whose author is not the
      target's. Shown by its parts, as a reply.
    - ``relation``: a relation the reader applies to the target.
    - ``pending``: a relation the reader would apply, to a target it does not hold yet.
    """
    rel = header(message, "rel")
    if rel is None or rel not in known or message.get("inReplyTo") is None:
        return "reply"
    if target is None:
        return "pending"
    if rel in AUTHOR_ONLY_RELATIONS and target["from"] != message["from"]:
        return "reply"
    return "relation"
