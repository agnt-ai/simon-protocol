"""Wait for received messages using opaque sync tokens.

wait.json is shared with the JavaScript CLI: {"token": null|string, "pending": [raw sync
entries], "seen": [message ids]}. Unmatched received entries stay pending; sent-only entries
are skipped. Legacy numeric cursor state requires an explicit reset.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from contextlib import contextmanager
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .client import Agent
from .errors import AgntError
from .wire import normalize_address

SEEN_KEPT = 1000
_HEX64 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class Waited:
    entry: dict[str, Any]
    #: Whether another message this wait would show is already waiting.
    more: bool


def wait_file(home: Path) -> Path:
    return Path(home) / "wait.json"


def read_wait_state(home: Path) -> dict[str, Any]:
    """The remembered state, or the beginning when there is none. A damaged file is an error, never a
    restart."""
    try:
        text = wait_file(home).read_text(encoding="utf-8")
    except FileNotFoundError:
        return {"token": None, "pending": [], "seen": []}
    try:
        s = json.loads(text)
    except ValueError:
        s = None

    ok = (
        isinstance(s, dict)
        and "token" in s
        and (s["token"] is None or isinstance(s["token"], str) and bool(s["token"]))
        and isinstance(s.get("pending"), list)
        and all(
            isinstance(e, dict) and isinstance(e.get("id"), str) and _HEX64.fullmatch(e["id"])
            and isinstance(e.get("message"), dict) and isinstance(e["message"].get("from"), str)
            and isinstance(e["message"].get("to"), list) and isinstance(e.get("carrier"), str)
            and isinstance(e.get("receivedAt"), str) and isinstance(e.get("claims"), list)
            for e in s["pending"]
        )
        and isinstance(s.get("seen"), list)
        and all(isinstance(x, str) and _HEX64.fullmatch(x) for x in s["seen"])
    )
    if not ok:
        raise AgntError(
            "invalid",
            "The wait state is damaged or uses the retired numeric cursor format; delete wait.json to start over explicitly.",
            details={"field": "wait.json"},
        )
    return s


def save_wait_state(home: Path, state: dict[str, Any]) -> None:
    """Replace wait.json atomically, mode 600."""
    home = Path(home)
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, fresh = tempfile.mkstemp(dir=home, prefix=".wait.json.")  # created with mode 600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(state, separators=(",", ":")) + "\n")
        os.replace(fresh, wait_file(home))
    except BaseException:
        os.unlink(fresh)
        raise


@contextmanager
def _locked(home: Path):
    """The same exclusive wait.lock directory as JS. Live, unknown and stale owners are never stolen."""
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = home / "wait.lock"
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        pid = None
        try:
            owner = json.loads((lock / "owner.json").read_text())
            if type(owner.get("pid")) is int and owner["pid"] > 0:
                pid = owner["pid"]
        except (ValueError, OSError, AttributeError):
            pass
        detail = f" (PID {pid})" if pid else ""
        raise AgntError("concurrent_wait", f"Another wait owns AGNT_HOME/wait.lock{detail}. Stop it first. After confirming its owner is no longer running, remove only the stale wait.lock directory; keep wait.json.", details={"field": "wait.lock", **({"ownerPid": pid} if pid else {})}) from None
    try:
        fd = os.open(lock / "owner.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"pid": os.getpid(), "createdAt": time.time()}, f)
        yield
    finally:
        (lock / "owner.json").unlink(missing_ok=True)
        lock.rmdir()


def wait_for_message(agent: Agent, home: Path, *, sender: str | None = None, timeout: float,
                     interval: float, clock: Callable[[], float] = time.monotonic,
                     sleep: Callable[[float], None] = time.sleep) -> Waited | None:
    """Positive timeout bounds requests and pages. Zero performs at most one immediate page request
    with the agent's normal transport timeout; buffered entries never need a request.
    """
    if not 0 <= timeout < float("inf") or not 0 < interval < float("inf"):
        raise AgntError("invalid", "Wait timeout is nonnegative and its interval is positive.")
    with _locked(Path(home)):
        return _wait_unlocked(agent, home, sender=sender, timeout=timeout, interval=interval, clock=clock, sleep=sleep)


def _wait_unlocked(
    agent: Agent,
    home: Path,
    *,
    sender: str | None = None,
    timeout: float,
    interval: float,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Waited | None:
    """The next message not yet shown (from ``sender``, when given), oldest first, once it is received;
    or None when ``timeout`` seconds pass first. It is marked shown before it is returned. A failure that
    may pass is waited out until the deadline; any other raises."""
    wanted_from = None
    if sender is not None:
        wanted_from = normalize_address(sender)
        if wanted_from is None:
            raise AgntError(
                "invalid", f"from is not an address (local@domain): {sender!r}", details={"field": "from"}
            )
    deadline = clock() + timeout
    while True:
        pause = interval
        try:
            found = _scan(agent, Path(home), wanted_from, lambda: deadline - clock(), timeout == 0)
            if found:
                return found
        except AgntError as e:
            if not e.retryable:
                raise
            if e.retry_after is not None:
                pause = max(pause, e.retry_after)
        left = deadline - clock()
        if left <= 0:
            return None
        sleep(min(pause, left))


def _scan(agent: Agent, home: Path, sender: str | None, remaining: Callable[[], float], once: bool) -> Waited | None:
    """Read complete pages and persist their pending entries before advancing the token."""
    state = read_wait_state(home)
    seen = list(dict.fromkeys(state["seen"]))
    seen_set = set(seen)
    pending = []
    pending_ids = set()
    for e in state["pending"]:
        if e["id"] not in seen_set and e["id"] not in pending_ids:
            pending.append(e)
            pending_ids.add(e["id"])

    def wanted(e: dict[str, Any]) -> bool:
        return sender is None or e["message"].get("from") == sender

    token = state["token"]
    def take(more: bool) -> Waited | None:
        index = next((i for i, e in enumerate(pending) if wanted(e)), None)
        if index is None:
            return None
        found = pending.pop(index)
        seen.append(found["id"])
        save_wait_state(home, {"token": token, "pending": pending, "seen": seen[-SEEN_KEPT:]})
        return Waited(found, more or any(wanted(e) for e in pending))

    buffered = take(False)
    if buffered is not None:
        return buffered
    while True:
        left = remaining()
        if not once and left <= 0:
            return None
        page = agent.sync(token, 200, request_timeout=agent.timeout if once else max(0.001, left))
        if (not isinstance(page, dict) or not isinstance(page.get("token"), str)
                or not page["token"] or not isinstance(page.get("messages"), list) or type(page.get("more")) is not bool):
            raise AgntError("bad_response", "sync did not return messages, token and more.")
        if page["more"] and page["token"] == token:
            raise AgntError("bad_response", "sync returned more without advancing its token.")
        for e in page["messages"]:
            if (not isinstance(e, dict) or not isinstance(e.get("id"), str)
                    or not _HEX64.fullmatch(e["id"]) or not isinstance(e.get("message"), dict)
                or not isinstance(e["message"].get("from"), str) or not isinstance(e["message"].get("to"), list)
                or not isinstance(e.get("carrier"), str) or not isinstance(e.get("receivedAt"), str) or not isinstance(e.get("claims"), list)):
                raise AgntError("bad_response", "sync returned a malformed message entry.")
            # sync includes sent messages too; wait is for messages addressed to this agent.
            if (agent.address in e["message"].get("to", [])
                    and e["id"] not in seen_set and e["id"] not in pending_ids):
                pending.append(e)
                pending_ids.add(e["id"])
        token = page["token"]
        save_wait_state(home, {"token": token, "pending": pending, "seen": seen[-SEEN_KEPT:]})
        if not once and remaining() <= 0:
            return None
        if once or not page["more"] or any(wanted(e) for e in pending):
            break

    return take(page["more"])
