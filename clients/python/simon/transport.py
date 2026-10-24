"""HTTP as the protocol needs it: no redirects followed, bounded bodies, and failures that may pass told
apart from a host that does not exist."""

from __future__ import annotations

import http.client
import math
import os
import pickle
import subprocess
import sys
import threading
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from email.message import Message


class HostNotFound(Exception):
    """The host's name does not exist (NXDOMAIN): an absence, not a failure that may pass."""


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirects)
_NO_SUCH_NAME = {getattr(socket, name) for name in ("EAI_NONAME", "EAI_NODATA") if hasattr(socket, name)}


@dataclass(frozen=True)
class Response:
    url: str
    status: int
    headers: Message
    body: bytes


def fetch(
    method: str,
    url: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    *,
    timeout: float = 30.0,
    max_bytes: int | None = None,
) -> Response:
    """A disposable bounded worker performs DNS, connection, headers and body reads. The parent alone
    owns its caller state. Startup and IPC count toward timeout; cleanup has a reserved budget. At most
    four workers may be active, including killed workers not yet reaped. No daemon threads survive a call.
    Existing client.fetch/resolution.fetch injection seams and this module's _SPAWN seam remain explicit.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise TimeoutError("The HTTP exchange has no remaining time.")
    deadline = time.monotonic() + timeout
    _reap_finished()
    if not _SLOTS.acquire(timeout=max(0, deadline - time.monotonic())):
        raise TimeoutError("No HTTP worker slot before the deadline.")
    process = None
    release_slot = True
    try:
        cleanup = min(0.2, timeout / 4)
        remaining = deadline - cleanup - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("No time remains to start the HTTP worker.")
        payload = pickle.dumps((method, url, body, headers, remaining, max_bytes), protocol=4)
        env = dict(os.environ)
        for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"):
            env.pop(name, None)
        # Never resolve simon from the caller's workspace or environment. Isolated Python retains its
        # installed standard/site packages, and this already-loaded module pins the trusted source root.
        package_root = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        bootstrap = f"import sys; sys.path.insert(0, {package_root!r}); from simon.transport import _worker; _worker()"
        process = _SPAWN([sys.executable, "-I", "-c", bootstrap], cwd=package_root,
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
        remaining = deadline - cleanup - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("HTTP worker startup exceeded its budget.")
        try:
            output, _ = process.communicate(payload, timeout=remaining)
        except subprocess.TimeoutExpired:
            raise TimeoutError("The HTTP exchange exceeded its absolute deadline.") from None
        if time.monotonic() >= deadline:
            raise TimeoutError("The HTTP exchange exceeded its absolute deadline.")
        if process.returncode != 0:
            raise ConnectionError("The HTTP worker exited without an answer.")
        try:
            ok, value = pickle.loads(output)
        except (ValueError, TypeError, EOFError, pickle.UnpicklingError):
            raise ConnectionError("The HTTP worker returned an invalid answer.") from None
        if time.monotonic() >= deadline:
            raise TimeoutError("Decoding the HTTP worker answer exceeded the request deadline.")
        if not ok:
            raise value
        return value
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    process.communicate(timeout=max(0, (deadline - time.monotonic()) / 2))
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    try:
                        process.communicate(timeout=max(0, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        # Keep the slot until a later call observes it reaped; never spawn an
                        # unbounded replacement or wait forever for an uninterruptible OS process.
                        with _PENDING_LOCK:
                            _PENDING.append(process)
                        release_slot = False
            for pipe in (process.stdin, process.stdout):
                if pipe is not None:
                    pipe.close()
        if release_slot:
            _SLOTS.release()


_SPAWN = subprocess.Popen
_SLOTS = threading.BoundedSemaphore(4)
_PENDING_LOCK = threading.Lock()
_PENDING: list[subprocess.Popen] = []


def _reap_finished() -> None:
    with _PENDING_LOCK:
        for process in list(_PENDING):
            if process.poll() is not None:
                _PENDING.remove(process)
                _SLOTS.release()


def _worker() -> None:
    """One trusted parent request and one result, using binary local IPC; never mutate caller state."""
    try:
        method, url, body, headers, timeout, max_bytes = pickle.loads(sys.stdin.buffer.read())
        answer = _fetch_sync(method, url, body, headers, timeout=timeout, max_bytes=max_bytes)
        result = (True, answer)
    except (HostNotFound, OSError) as e:
        result = (False, e)
    except Exception as e:
        result = (False, ConnectionError(f"HTTP worker failed: {type(e).__name__}"))
    sys.stdout.buffer.write(pickle.dumps(result, protocol=4))
    sys.stdout.buffer.flush()


def _fetch_sync(method: str, url: str, body: bytes | None, headers: dict[str, str] | None,
                *, timeout: float, max_bytes: int | None) -> Response:
    deadline = time.monotonic() + timeout
    request = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with _OPENER.open(request, timeout=timeout) as r:
            return Response(url, r.status, r.headers, _read(r, max_bytes, deadline))
    except urllib.error.HTTPError as e:
        with e:
            return Response(url, e.code, e.headers, _read(e, max_bytes, deadline))
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, socket.gaierror) and reason.errno in _NO_SUCH_NAME:
            raise HostNotFound(url) from None
        raise reason if isinstance(reason, OSError) else OSError(str(reason)) from None
    except http.client.HTTPException as e:  # a malformed or cut-off answer
        raise ConnectionError(f"{type(e).__name__}: {e}") from None


def _read(response, max_bytes: int | None, deadline: float) -> bytes:
    """Read one available chunk at a time, reducing the socket timeout against the original deadline.
    The parent worker deadline also bounds DNS, headers and chunked framing reads that may block
    inside urllib; partial progress cannot extend the complete exchange budget indefinitely.
    """
    chunks: list[bytes] = []
    size = 0
    while max_bytes is None or size <= max_bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("The HTTP response body exceeded the request deadline.")
        # urllib's HTTPResponse (also under HTTPError) owns this socket through its buffered reader.
        fp = getattr(response, "fp", None)
        if isinstance(fp, http.client.HTTPResponse):
            fp = fp.fp
        raw = getattr(fp, "raw", None)
        sock = getattr(raw, "_sock", None)
        if sock is not None:
            sock.settimeout(remaining)
        amount = 65536 if max_bytes is None else min(65536, max_bytes + 1 - size)
        chunk = response.read1(amount)
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    if time.monotonic() >= deadline:
        raise TimeoutError("The HTTP response body exceeded the request deadline.")
    return b"".join(chunks)
