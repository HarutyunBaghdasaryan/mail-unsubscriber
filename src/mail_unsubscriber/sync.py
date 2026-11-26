"""Incremental sync: keep per-email header data locally (0600), fetch only new mail, re-check states.

Stored per email: id, date, sender, provider auth result, DKIM signature domains/coverage, the two
unsubscribe headers, Spam/Junk flag, provider verdict, Gmail tab, open-in-mail link. Never subjects,
bodies or attachments.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from . import store
from .classify import classify, group_by_sender
from .gate import trace
from .model import AuthResult, DkimSig, MessageMeta

UNSUB_HEADERS = frozenset({"list-unsubscribe", "list-unsubscribe-post"})
FULL_AFTER = timedelta(days=7)  # stored data older than this -> full rescan
OVERLAP = timedelta(hours=1)  # re-read a little before the last sync to catch late arrivals


def to_dict(m: MessageMeta) -> dict:
    a = m.auth
    return {
        "id": m.id, "date": m.date.isoformat(), "from_addr": m.from_addr, "from_domain": m.from_domain,
        "auth": None if a is None else {"dmarc": a.dmarc, "from": a.dmarc_header_from,
                                         "dkim": sorted(a.dkim_pass_domains), "trusted": a.trusted},
        # only what the gate needs: does each signature cover the two unsubscribe headers
        "sigs": [[s.d, sorted(s.signed_headers & UNSUB_HEADERS)] for s in m.dkim_sigs],
        "lu": m.list_unsubscribe, "lup": m.list_unsubscribe_post, "junk": m.in_junk,
        "cat": m.ms_cat, "sfv": m.ms_sfv, "gcat": m.gmail_category, "link": m.web_link,
    }


def from_dict(d: dict) -> MessageMeta:
    a = d.get("auth")
    return MessageMeta(
        id=d["id"], date=datetime.fromisoformat(d["date"]), from_addr=d["from_addr"], from_domain=d["from_domain"],
        auth=None if a is None else AuthResult(a["dmarc"], a["from"], frozenset(a["dkim"]), a["trusted"]),
        dkim_sigs=tuple(DkimSig(s[0], frozenset(s[1])) for s in d.get("sigs", [])),
        list_unsubscribe=d.get("lu"), list_unsubscribe_post=d.get("lup"), in_junk=d.get("junk", False),
        ms_cat=d.get("cat"), ms_sfv=d.get("sfv"), gmail_category=d.get("gcat"), web_link=d.get("link"),
    )


def _path(account: str):
    d = store.app_dir() / "scans"
    d.mkdir(mode=0o700, exist_ok=True)
    return d / f"{account}.messages.json"


def load(account: str) -> dict | None:
    p = _path(account)
    return json.loads(p.read_text()) if p.exists() else None


def save(account: str, data: dict) -> None:
    store._write_private(_path(account), json.dumps(data))


def sync(account: str, acct: dict, provider, days: int, full: bool = False, progress=None,
         now: datetime | None = None) -> tuple[list[MessageMeta], str]:
    """Return (messages in window, mode) where mode is 'full' or 'incremental'."""
    now = now or datetime.now(timezone.utc)
    since_window = now - timedelta(days=days)
    data = load(account)
    stale = (data is None or data.get("days") != days
             or now - datetime.fromisoformat(data["synced_at"]) > FULL_AFTER)
    if full or stale:
        old_ids: set[str] = set()
        known: dict[str, float] = {}
        if acct["provider"] == "gmail":
            msgs = provider.fetch(since_window, acct.get("email"), progress, known, old_ids)
        else:
            msgs = provider.fetch(since_window, acct.get("email"), progress)
        mode = "full"
    else:
        msgs = [from_dict(d) for d in data["messages"]]
        known = {m.id: m.date.timestamp() for m in msgs}
        old_ids = set(data.get("old_ids", []))
        since = datetime.fromisoformat(data["synced_at"]) - OVERLAP
        if acct["provider"] == "gmail":
            new = provider.fetch(max(since, since_window), acct.get("email"), progress, known, old_ids)
        else:
            new = [m for m in provider.fetch(max(since, since_window), acct.get("email"), progress) if m.id not in known]
        msgs = msgs + new
        mode = "incremental"
    msgs = [m for m in msgs if m.date >= since_window]
    save(account, {"synced_at": now.isoformat(), "days": days, "messages": [to_dict(m) for m in msgs],
                   "old_ids": sorted(old_ids)[-20000:]})
    return msgs, mode


def recheck(account: str, provider, msgs: list[MessageMeta], senders: set[str]) -> list[MessageMeta]:
    """Refresh Spam/Junk state of the chosen senders' emails right before acting; drop deleted ones."""
    ids = [m.id for m in msgs if m.from_addr in senders]
    if not ids:
        return msgs
    st = provider.states(ids)
    out = []
    for m in msgs:
        if m.id in st:
            s = st[m.id]
            if s is None:
                continue
            if s["in_junk"] != m.in_junk:
                m = MessageMeta(**{**m.__dict__, "in_junk": s["in_junk"]})
        out.append(m)
    data = load(account) or {}
    data["messages"] = [to_dict(m) for m in out]
    save(account, data)
    return out


def build_scan(account: str, acct: dict, msgs: list[MessageMeta], days: int, user_kept=frozenset(),
               now: datetime | None = None) -> dict:
    """Classify and save the scan file used by show/explain/unsubscribe."""
    from collections import Counter

    from . import journal

    now = now or datetime.now(timezone.utc)
    kept = frozenset(user_kept) | frozenset(journal.kept(account))
    decisions = classify(msgs, protected_domains=frozenset(journal.protected_domains(account)), user_kept=kept)
    done = journal.unsubscribed(account)
    summary = {
        "messages_read": len(msgs), "senders": len(decisions),
        "groups": dict(Counter(d.group.value for d in decisions)),
        "reasons": dict(Counter(d.code.value for d in decisions)),
        "gmail_categories": dict(Counter(d.gmail_category for d in decisions if d.gmail_category)),
    }
    scan = {
        "account": account, "provider": acct["provider"], "scanned_at": now.isoformat(), "days": days,
        "summary": summary,
        "decisions": [dict(d.__dict__) | ({"unsubscribed_at": done[d.sender]} if d.sender in done else {})
                      for d in decisions],
        "traces": {s: trace(ms) for s, ms in group_by_sender(msgs).items()},
    }
    store.save_scan(account, scan)
    return scan
