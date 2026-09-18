"""Replay protection.

Authentication proves a message is genuine; it says nothing about whether it
is *new*. Without this, anyone who captured a ciphertext -- the mail provider,
anyone with inbox access, a backup -- could re-send it and have it accepted
forever. Two independent checks close that:

  * a freshness window, so old envelopes expire on their own, and
  * a persistent record of message ids already accepted, so nothing inside the
    window is processed twice.

The record only needs to cover the freshness window, so it is pruned to that
horizon and cannot grow without bound.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict

from .errors import ReplayError
from .fsutil import atomic_write_json, read_json
from .logging_setup import get_logger

log = get_logger(__name__)

MAX_STATE_BYTES = 16 * 1024 * 1024
# Hard ceiling in case max_message_age is configured very high.
MAX_TRACKED_IDS = 200_000


class ReplayGuard:
    """Tracks which message ids have already been accepted."""

    def __init__(self, path: Path, *, max_age: int, max_skew: int) -> None:
        self.path = path
        self.max_age = max_age
        self.max_skew = max_skew
        self._seen: Dict[str, int] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        if self.path.stat().st_size > MAX_STATE_BYTES:
            log.warning("replay state at %s is oversized; starting fresh", self.path)
            return
        try:
            data = read_json(self.path)
        except (json.JSONDecodeError, OSError):
            # Losing this file weakens replay protection but must not stop the
            # daemon; the freshness window still bounds the exposure.
            log.warning("replay state at %s is corrupt; starting fresh", self.path)
            return
        if isinstance(data, dict) and isinstance(data.get("seen"), dict):
            self._seen = {
                str(k): int(v)
                for k, v in data["seen"].items()
                if isinstance(v, int) and not isinstance(v, bool)
            }
        self._prune()

    def _prune(self) -> None:
        horizon = time.time() - self.max_age - self.max_skew
        self._seen = {k: v for k, v in self._seen.items() if v >= horizon}
        if len(self._seen) > MAX_TRACKED_IDS:
            # Keep the newest; the oldest are closest to expiring anyway.
            newest = sorted(self._seen.items(), key=lambda kv: kv[1], reverse=True)
            self._seen = dict(newest[:MAX_TRACKED_IDS])

    def _save(self) -> None:
        atomic_write_json(self.path, {"v": 1, "seen": self._seen}, private=True)

    def check_freshness(self, timestamp: int, *, now: float | None = None) -> None:
        """Reject envelopes that are too old or dated too far in the future."""
        current = time.time() if now is None else now
        age = current - timestamp
        if age > self.max_age:
            raise ReplayError(
                "message is %d seconds old, beyond the %d second acceptance window"
                % (int(age), self.max_age)
            )
        if -age > self.max_skew:
            raise ReplayError(
                "message is dated %d seconds in the future, beyond the %d second "
                "clock-skew allowance" % (int(-age), self.max_skew)
            )

    def check_unseen(self, message_id: str) -> None:
        if message_id in self._seen:
            raise ReplayError("message %s has already been processed" % message_id)

    def record(self, message_id: str, timestamp: int) -> None:
        """Mark a message accepted. Persisted immediately.

        Written before the plaintext is delivered, so a crash between the two
        costs a message rather than opening a replay window.
        """
        self._seen[message_id] = int(timestamp)
        self._prune()
        self._save()

    def __len__(self) -> int:
        return len(self._seen)
