"""Filters for `show` and `unsubscribe` (REQUIREMENTS R7a). Pure.

Several values in one filter = any of them; different filters = all must match.
Filters can only narrow the CAN_UNSUBSCRIBE list; other groups are never selectable.
"""

from __future__ import annotations

from dataclasses import dataclass, field


def _split(values: list[str] | None) -> set[str]:
    out: set[str] = set()
    for v in values or []:
        out |= {x.strip().lower() for x in v.split(",") if x.strip()}
    return out


@dataclass
class Filters:
    categories: set[str] = field(default_factory=set)
    senders: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    exclude_senders: set[str] = field(default_factory=set)
    exclude_domains: set[str] = field(default_factory=set)
    min_emails: int = 1

    @classmethod
    def from_args(cls, args) -> "Filters":
        return cls(
            categories=_split(getattr(args, "category", None)),
            senders=_split(getattr(args, "sender", None)),
            domains=_split(getattr(args, "domain", None)),
            exclude_senders=_split(getattr(args, "exclude_sender", None)),
            exclude_domains=_split(getattr(args, "exclude_domain", None)),
            min_emails=getattr(args, "min_emails", 1) or 1,
        )


def _domain_match(addr: str, domains: set[str]) -> bool:
    d = addr.rsplit("@", 1)[-1]
    return any(d == x or d.endswith("." + x) for x in domains)


def matches(dec: dict, f: Filters) -> bool:
    s = dec["sender"]
    if f.categories and (dec.get("gmail_category") or "") not in f.categories:
        return False
    if f.senders and s not in f.senders:
        return False
    if f.domains and not _domain_match(s, f.domains):
        return False
    if s in f.exclude_senders or (f.exclude_domains and _domain_match(s, f.exclude_domains)):
        return False
    return dec.get("count", 0) >= f.min_emails


def select(decisions: list[dict], f: Filters, kept: set[str] = frozenset(), done: set[str] = frozenset()):
    """Return (candidates, skipped) where skipped = [(decision, reason)] for matches that can't be acted on."""
    candidates, skipped = [], []
    for d in decisions:
        if not matches(d, f):
            continue
        if d["group"] != "CAN_UNSUBSCRIBE":
            skipped.append((d, f"{d['group']} ({d['code']})"))
        elif d["sender"] in kept:
            skipped.append((d, "kept by you"))
        elif d["sender"] in done:
            skipped.append((d, "already unsubscribed"))
        elif not d.get("unsub_url"):
            skipped.append((d, "no unsubscribe link saved"))
        else:
            candidates.append(d)
    candidates.sort(key=lambda d: (-d["count"], d["sender"]))
    return candidates, skipped
