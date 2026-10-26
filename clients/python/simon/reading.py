"""The rules that bind readers rather than servers: what a reader may make of a message it holds.

No server test can show a reader obeys them, so they live here as functions, with vectors.

- A message of a version the reader does not implement, or listing in ``critical`` a header it does not
  understand, is presented as not understood (sections 1 and 5.4).
- A principal counts only for a message that names one in ``for``, on its evidence (section 2.2); a key
  principal's pairing counts while it has not lapsed.
- A relation the reader does not know is shown as a reply, and an author-only relation from anyone but the
  original's author is shown as a reply and never applied (section 5.5).
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Any

from .messages import VERSION, header, parse_pairing, principal_key, read_succession, verify_pairing
from .wire import parse_timestamp

#: The relations the registry marks author-only: they change or withdraw the message they name.
AUTHOR_ONLY_RELATIONS = frozenset({"edit", "retract"})


def is_understood(message: Mapping[str, Any], understood: Collection[str]) -> bool:
    """Whether a reader that implements version 1 and understands the headers in ``understood`` may act on
    a message, or must present it as not understood: only whose key signed it, nothing it says."""
    if message["v"] != VERSION:
        return False
    critical = header(message, "critical")
    return critical is None or all(header(message, name) is None or name in understood for name in critical.split(","))


def claimed_principal(message: Mapping[str, Any]) -> str | None:
    """The principal a message names: the ``for`` header of a message of this version, or None. It is only
    the agent's word until evidence backs it, a pairing that verifies or a claim the reader trusts (section
    2.2); a message without ``for`` speaks for no one."""
    if message["v"] != VERSION:
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


def pairing_standing(message: Mapping[str, Any], now_ms: int) -> str | None:
    """Where a key principal's pairing stands for a reader at ``now_ms`` (section 2.2), or None when the
    message names no key principal: ``counts`` (it counted when sent and has not lapsed), ``lapsed`` (it
    counted when sent, but ``now_ms`` is at or past its ``until``: act on nothing in it for the principal
    now), or ``refused`` (it did not count at ``sentAt``, so the message names its principal falsely). A
    reader whose clock runs behind the sender's may find a pairing reaching more than 366 days past its own
    now; that is the clocks' disagreement, not a lapse, so it counts."""
    principal = claimed_principal(message)
    if principal is None or principal_key(principal) is None:
        return None
    pairing, sent = header(message, "pairing"), parse_timestamp(message["sentAt"])
    if sent is None or not verify_pairing(message["from"], principal, pairing, sent):
        return "refused"
    until = parse_timestamp(parse_pairing(pairing)[0])  # type: ignore[index]
    return "lapsed" if now_ms >= until else "counts"  # type: ignore[operator]


def predecessors(message: Mapping[str, Any]) -> list[str] | str:
    """The earlier keys of a message's key principal, oldest first, as its ``succession`` header names them
    (section 2.2): ``[]`` when it carries none, or ``"refused"`` when it does not verify. A reader that knew
    any of them may treat ``for`` as the same principal, unless it holds a fork, two steps from one key to
    different keys: then neither successor inherits that key's place."""
    principal = claimed_principal(message)
    succession = header(message, "succession") if message["v"] == VERSION else None
    if principal is None or succession is None:
        return []
    steps = read_succession(succession, principal)
    return "refused" if steps is None else [step["from"] for step in steps]
