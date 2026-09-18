"""Filesystem helpers: atomic writes and restrictive permissions.

Two properties matter here. Files holding key material or plaintext must never
be readable by other local users, and a crash mid-write must never leave a
half-written keystore or state file behind.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

# Owner read/write only.
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700

_IS_WINDOWS = sys.platform == "win32"


def ensure_private_dir(path: Path) -> Path:
    """Create `path` (and parents) with owner-only permissions."""
    path.mkdir(parents=True, exist_ok=True)
    if not _IS_WINDOWS:
        try:
            path.chmod(PRIVATE_DIR_MODE)
        except OSError:
            pass  # e.g. a mounted volume that does not support chmod
    return path


def harden(path: Path) -> None:
    """Best-effort tightening of an existing file's permissions.

    On Windows POSIX modes are not enforced; confidentiality there rests on the
    NTFS ACLs of the containing user profile, which is why the keystore is
    additionally encrypted at rest.
    """
    if _IS_WINDOWS:
        return
    try:
        path.chmod(PRIVATE_FILE_MODE)
    except OSError:
        pass


def is_world_readable(path: Path) -> bool:
    """True if group or other can read `path`. Always False on Windows."""
    if _IS_WINDOWS:
        return False
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IRGRP | stat.S_IROTH))


def atomic_write_bytes(path: Path, data: bytes, *, private: bool = True) -> None:
    """Write `data` to `path` atomically.

    The temporary file is created in the destination directory so that the
    final rename stays on one filesystem and is therefore atomic.
    """
    directory = path.parent
    ensure_private_dir(directory) if private else directory.mkdir(
        parents=True, exist_ok=True
    )

    fd, tmp_name = tempfile.mkstemp(dir=str(directory), prefix=".tmp-", suffix=".part")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if private:
            harden(tmp_path)
        # Windows cannot rename onto an existing file.
        if _IS_WINDOWS and path.exists():
            path.unlink()
        os.replace(str(tmp_path), str(path))
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def atomic_write_text(path: Path, text: str, *, private: bool = True) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), private=private)


def atomic_write_json(path: Path, payload: Any, *, private: bool = True) -> None:
    atomic_write_text(
        path, json.dumps(payload, indent=2, sort_keys=True) + "\n", private=private
    )


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))
