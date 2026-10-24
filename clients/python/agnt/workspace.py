"""The one directory the command line reads and writes files in, for a model that runs it on the word of
whatever it last read. A path names a file in the workspace, after every symbolic link is resolved, and
never one under AGNT_HOME, where the keys live, even when AGNT_HOME is inside the workspace.

    AGNT_WORKSPACE      the workspace; default the current working directory

A refusal is ``path_refused``, with ``details.field`` naming the argument.
"""

from __future__ import annotations

import errno
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .errors import AgntError


@dataclass(frozen=True)
class Workspace:
    #: The workspace, its links resolved.
    root: Path
    #: AGNT_HOME, its links resolved as far as it exists.
    home: Path


def workspace(
    home: Path | str, env: Mapping[str, str] | None = None, cwd: Path | str | None = None
) -> Workspace:
    """The workspace for an environment and a key directory."""
    env = os.environ if env is None else env
    cwd = Path.cwd() if cwd is None else Path(cwd)
    root = cwd / (env.get("AGNT_WORKSPACE") or ".")
    try:
        real = Path(os.path.realpath(root, strict=True))
    except OSError:
        raise _refused("AGNT_WORKSPACE", f"The workspace {root} does not exist.") from None
    if not real.is_dir():
        raise _refused("AGNT_WORKSPACE", f"The workspace {root} is not a directory.")
    return Workspace(real, _real_as_far_as_exists(cwd / Path(home)))


def readable_path(ws: Workspace, file: str | Path, field: str = "path") -> Path:
    """A file to read: it exists, and it and every link to it lie in the workspace and outside AGNT_HOME."""
    try:
        real = Path(os.path.realpath(ws.root / file, strict=True))
    except OSError:
        raise _refused(field, f"No file {file} in the workspace.") from None
    _confine(ws, real, file, field)
    if _is_home_file(ws, real):
        raise _refused(field, f"{file} is a hard link to a file in the agent's key directory.")
    return real


def read_file(ws: Workspace, file: str | Path, field: str = "path") -> bytes:
    """Read a file in the workspace."""
    return readable_path(ws, file, field).read_bytes()


def writable_path(ws: Workspace, file: str | Path, field: str = "path") -> Path:
    """Where a file would be written in the workspace: its directory must exist there, and a link in the
    file's own place is refused, not followed, so nothing outside can be overwritten through one. Check
    before fetching what to write, so a refusal costs nothing."""
    wanted = ws.root / file
    try:
        directory = Path(os.path.realpath(wanted.parent, strict=True))
    except OSError:
        raise _refused(field, f"No directory for {file} in the workspace.") from None
    target = directory / wanted.name
    _confine(ws, target, file, field)
    if target.is_symlink():
        raise _link_refused(file, field)
    return target


def write_file(ws: Workspace, file: str | Path, data: bytes, field: str = "path") -> str:
    """Write a file in the workspace (see ``writable_path``); answers its path relative to the workspace."""
    target = writable_path(ws, file, field)
    try:
        # O_NOFOLLOW: a link put in place since the check is refused too.
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.EMLINK):
            raise _link_refused(file, field) from None
        raise
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return os.path.relpath(target, ws.root)


def _is_home_file(ws: Workspace, file: Path) -> bool:
    """Whether a file is one of AGNT_HOME's own under another name, through a hard link."""
    st = file.stat()
    if st.st_nlink < 2:
        return False
    try:
        names = list(ws.home.iterdir())
    except OSError:
        return False
    for name in names:
        try:
            h = name.stat()
        except OSError:
            continue
        if (h.st_ino, h.st_dev) == (st.st_ino, st.st_dev):
            return True
    return False


def _confine(ws: Workspace, real: Path, asked: str | Path, field: str) -> None:
    if not _within(ws.root, real):
        raise _refused(
            field, f"{asked} is outside the workspace. Files are read and written only in the workspace."
        )
    if _within(ws.home, real):
        raise _refused(field, f"{asked} is in the agent's key directory, which no command touches.")


def _within(directory: Path, path: Path) -> bool:
    return path == directory or directory in path.parents


def _real_as_far_as_exists(path: Path) -> Path:
    """A path with the links resolved in the part of it that exists."""
    rest: list[str] = []
    at = path
    while True:
        try:
            return Path(os.path.realpath(at, strict=True)).joinpath(*reversed(rest))
        except OSError:
            if at.parent == at:
                return path
            rest.append(at.name)
            at = at.parent


def _link_refused(file: str | Path, field: str) -> AgntError:
    return _refused(field, f"{file} is a symbolic link; files are written only as plain files.")


def _refused(field: str, message: str) -> AgntError:
    return AgntError("path_refused", message, details={"field": field})
