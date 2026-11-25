"""The unsubscribe flow (REQUIREMENTS R0, R6-R10). All side effects are injected so tests can prove
nothing is sent without: gate pass (scan) + fresh scan + user's yes + OS confirmation.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from . import journal
from .netguard import Blocked
from .selection import Filters, select

MAX_PER_RUN = 200
MAX_SCAN_AGE = timedelta(hours=1)


def run(
    account: str,
    scan: dict,
    filters: Filters,
    *,
    ask: Callable[[str], str],
    confirm: Callable[[list[str]], bool],
    post: Callable[[str], int],
    one_by_one: bool = False,
    now: datetime | None = None,
    out: Callable[[str], None] = print,
) -> int:
    now = now or datetime.now(timezone.utc)
    scanned = datetime.fromisoformat(scan["scanned_at"])
    if now - scanned > MAX_SCAN_AGE:
        out(f"The last scan is from {scanned:%Y-%m-%d %H:%M} UTC (older than 1 hour). Run `unsub scan` first.")
        return 1
    candidates, skipped = select(scan["decisions"], filters, journal.kept(account), set(journal.unsubscribed(account)))
    if skipped:
        out(f"Skipped {len(skipped)} matching sender(s) that are not safe or not eligible:")
        for d, why in skipped[:20]:
            out(f"  - {d['sender']}: {why}")
    if not candidates:
        out("Nothing to unsubscribe for this selection.")
        return 0
    candidates = candidates[:MAX_PER_RUN]
    out(f"\n{len(candidates)} sender(s) can be unsubscribed (checked: authenticated, signed one-click):")
    for i, d in enumerate(candidates, 1):
        out(f"  {i:>3}. {d['sender']:<45} {d['count']:>4} emails  {d.get('gmail_category') or '-':<11} via {d.get('unsub_host')}")

    chosen: list[dict] = []
    if one_by_one:
        for d in candidates:
            a = ask(f"Unsubscribe from {d['sender']}? [y/N/k=keep/q] ").strip().lower()
            if a == "q":
                break
            if a == "k":
                journal.add(account, d["sender"], "kept")
            elif a == "y":
                chosen.append(d)
    else:
        a = ask(f"\nType 'yes' to unsubscribe from all {len(candidates)} sender(s) listed above: ").strip().lower()
        if a == "yes":
            chosen = candidates
    if not chosen:
        out("Nothing confirmed. Nothing was sent.")
        return 0
    if not confirm([d["sender"] for d in chosen]):
        out("Not confirmed with Touch ID / password. Nothing was sent.")
        return 1

    ok = failed = 0
    for d in chosen:
        host = urlsplit(d["unsub_url"]).hostname
        try:
            status = post(d["unsub_url"])
        except Blocked as e:
            journal.add(account, d["sender"], "failed", host, str(e))
            out(f"  x {d['sender']}: blocked ({e})")
            failed += 1
            continue
        if 200 <= status < 300:
            journal.add(account, d["sender"], "unsubscribed", host, status)
            out(f"  ✓ {d['sender']} ({status})")
            ok += 1
        else:
            journal.add(account, d["sender"], "failed", host, status)
            hint = " (redirect: finish manually)" if 300 <= status < 400 else ""
            out(f"  x {d['sender']}: HTTP {status}{hint}")
            failed += 1
    out(f"\nDone: {ok} unsubscribed, {failed} failed.")
    return 0 if failed == 0 else 1
