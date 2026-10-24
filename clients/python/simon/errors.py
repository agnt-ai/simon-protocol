"""The one exception this package raises for a refusal or a failure, and the protocol's error shape.

On the wire an error is an RFC 9457 problem detail, sent as ``application/problem+json`` (spec section 9)::

    {"type": "about:blank", "title", "status", "code", "retryable", "detail", "details"?}

``code`` is stable and ``detail`` may change. ``retryable`` is true exactly for ``429`` and ``5xx``, so it
follows from the status; a client that does not know a code acts on the status and on ``retryable``.
"""

from __future__ import annotations

from typing import Any

PROBLEM_CONTENT_TYPE = "application/problem+json"
#: The scheme every request-signature ``401`` names in ``WWW-Authenticate`` (section 8).
AUTH_SCHEME = "SIMON"


def is_retryable(status: int) -> bool:
    """Whether an answer of this status may succeed if repeated later: ``429`` and ``5xx``, nothing else."""
    return status == 429 or 500 <= status <= 599


def title_of(code: str) -> str:
    """A code as a short title, ``bad_signature`` as ``Bad signature``, since ``about:blank`` has none."""
    return (code[:1].upper() + code[1:]).replace("_", " ")


class SimonError(Exception):
    """An error as the protocol writes it: a stable ``code``, a ``message`` that may change (a problem's
    ``detail``), ``status``, ``retryable`` and ``details``.

    ``status`` is the HTTP status of the server's answer, or of the answer a server gives for the same
    refusal; ``retryable`` then follows from it unless given. A server's refusal keeps the server's code,
    detail and details. ``status`` is None when no answer stands behind the error, and the code is then one
    of:

    - ``invalid``: an argument refused before sending; ``details.field`` names it.
    - ``not_registered``: the call needs the agent's address, and it has none yet.
    - ``no_key``: the call signs, and the agent has no key.
    - ``no_server``: the agent has no server configured, or a domain resolves to no server
      (``details.outcome``).
    - ``pure_signing_refused``: no constant-time signing here, and no opt-in to the pure-Python one.
    - ``network_error``, ``timeout``: no answer (retryable; ``details.url``).
    - ``unavailable``: a resolution or document fetch failed in a way that may pass (retryable).
    - ``bad_response``, ``bad_document``, ``hash_mismatch``: an answer that is not what the protocol says.
    - ``path_refused``: a file outside the workspace, or in the agent's own directory (the command line).

    The codes a server may answer are in spec section 9 and CLIENT.md, among them ``unsupported_version``
    (``send`` of a version the server does not implement), and ``403 bad_signature`` and
    ``unsupported_algorithm``, which a receiving server answers at deliver and ``sent`` reports as reasons.

    ``retry_after`` is the seconds a ``Retry-After`` header asked for, when there was one.
    """

    def __init__(
        self,
        code: str,
        message: str,
        status: int | None = None,
        retryable: bool | None = None,
        details: dict[str, Any] | None = None,
        *,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        if retryable is None:
            retryable = status is not None and is_retryable(status)
        self.retryable = retryable
        self.details = details or {}
        self.retry_after = retry_after

    def __str__(self) -> str:
        return (
            f"{self.code}: {self.message}"
            if self.status is None
            else f"{self.status} {self.code}: {self.message}"
        )

    def __repr__(self) -> str:
        fields = (self.code, self.message, self.status, self.retryable, self.details)
        return f"SimonError{fields!r}"

    def to_json(self) -> dict[str, Any]:
        """The error as this client prints it: ``{"error": {"code", "message", "status", "retryable",
        "details"?, "retryAfter"?}}``."""
        error: dict[str, Any] = {"code": self.code, "message": self.message, "status": self.status}
        error["retryable"] = self.retryable
        if self.details:
            error["details"] = self.details
        if self.retry_after is not None:
            error["retryAfter"] = self.retry_after
        return {"error": error}

    def to_problem(self) -> dict[str, Any]:
        """The problem detail a server sends for this error (section 9). It needs a ``status``."""
        if self.status is None:
            raise ValueError("Only an error with an HTTP status is a problem detail.")
        problem: dict[str, Any] = {
            "type": "about:blank",
            "title": title_of(self.code),
            "status": self.status,
            "code": self.code,
            "retryable": is_retryable(self.status),
            "detail": self.message,
        }
        if self.details:
            problem["details"] = self.details
        return problem

    def problem_headers(self) -> dict[str, str]:
        """The headers that answer carries: its content type; on a ``401`` the challenge HTTP requires; and
        ``Retry-After`` when ``details.retryAfter`` gives the seconds to wait."""
        headers = {"content-type": PROBLEM_CONTENT_TYPE}
        if self.status == 401:
            headers["www-authenticate"] = AUTH_SCHEME
        retry_after = self.details.get("retryAfter")
        if type(retry_after) is int:
            headers["retry-after"] = str(retry_after)
        return headers


def parse_problem(status: int, body: bytes, *, retry_after: int | None = None) -> SimonError | None:
    """The error an answer that is not a success carries: its problem detail's ``code``, ``detail`` (or
    ``title``) and ``details`` when they are the right types, with ``status`` and ``retryable`` taken from
    the HTTP status, which is what a client acts on. None when the body is no problem detail (no string
    ``code``), so the caller falls back on the status."""
    from .canonical import parse  # canonical imports this module

    try:
        value = parse(body)
    except SimonError:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("code"), str):
        return None
    code = value["code"]
    detail, title = value.get("detail"), value.get("title")
    message = detail if isinstance(detail, str) and detail else title if isinstance(title, str) else ""
    details = value.get("details")
    return SimonError(
        code,
        message or title_of(code),
        status,
        is_retryable(status),
        details if isinstance(details, dict) else None,
        retry_after=retry_after,
    )


def invalid(message: str, **details: Any) -> SimonError:
    """``400 invalid``, with ``details.field`` or ``details.canonical`` when given."""
    return SimonError("invalid", message, 400, False, details)
