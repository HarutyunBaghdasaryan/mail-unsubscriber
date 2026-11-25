"""Append-only action log (journal.jsonl, 0600): unsubscribed / failed / kept."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

from . import store


def _path():
    return store.app_dir() / "journal.jsonl"


def add(account: str, sender: str, action: str, host: str | None = None, status: int | str | None = None) -> None:
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "account": account,
           "sender": sender, "action": action, "host": host, "status": status}
    fd = os.open(_path(), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps(rec) + "\n")


def entries(account: str) -> list[dict]:
    p = _path()
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("account") == account:
            out.append(r)
    return out


def kept(account: str) -> set[str]:
    return {r["sender"] for r in entries(account) if r["action"] == "kept"}


def unsubscribed(account: str) -> dict[str, str]:
    """sender -> ISO time of the last successful unsubscribe."""
    return {r["sender"]: r["ts"] for r in entries(account) if r["action"] == "unsubscribed"}


def still_sending(account: str, last_seen: dict[str, datetime], days: int = 14) -> set[str]:
    """Senders unsubscribed >= `days` ago that still sent mail after that."""
    out = set()
    for sender, ts in unsubscribed(account).items():
        t = datetime.fromisoformat(ts)
        seen = last_seen.get(sender)
        if seen and seen > t + timedelta(days=days):
            out.add(sender)
    return out
