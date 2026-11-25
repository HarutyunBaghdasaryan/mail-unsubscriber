"""Group messages by sender and assign each sender a group + reason code. Pure."""

from __future__ import annotations

from collections import Counter, defaultdict
from urllib.parse import urlsplit

from . import gate
from .headers import is_punycode
from .model import Code, Decision, Group, MessageMeta

OUTLOOK_CAT_DANGER = frozenset({"PHSH", "HPHSH", "HPHISH", "MALW", "SPOOF", "DIMP", "UIMP", "GIMP", "BIMP"})


def group_by_sender(messages: list[MessageMeta]) -> dict[str, list[MessageMeta]]:
    out: dict[str, list[MessageMeta]] = defaultdict(list)
    for m in messages:
        out[m.from_addr].append(m)
    return dict(out)


def _protected(domain: str, protected_domains: frozenset[str]) -> bool:
    return any(domain == p or domain.endswith("." + p) for p in protected_domains)


def classify_sender(
    sender: str,
    messages: list[MessageMeta],
    protected_domains: frozenset[str] = frozenset(),
    user_kept: frozenset[str] = frozenset(),
) -> Decision:
    ordered = sorted(messages, key=lambda m: m.date)
    newest = ordered[-1]
    domain = newest.from_domain
    cats = Counter(m.gmail_category for m in ordered if m.gmail_category)

    def decide(group: Group, code: Code, url: str | None = None) -> Decision:
        return Decision(
            sender=sender,
            group=group,
            code=code,
            count=len(ordered),
            first_seen=ordered[0].date,
            last_seen=newest.date,
            gmail_category=cats.most_common(1)[0][0] if cats else None,
            unsub_url=url,
            unsub_host=(urlsplit(url).hostname if url else None),
            web_link=newest.web_link,
        )

    if any(m.ms_cat and m.ms_cat.upper() in OUTLOOK_CAT_DANGER for m in ordered):
        return decide(Group.DANGER, Code.PROVIDER_PHISH)
    if is_punycode(domain):
        return decide(Group.DANGER, Code.PUNYCODE_FROM)
    if sender in user_kept:
        return decide(Group.KEEP, Code.USER_KEPT)
    if _protected(domain, protected_domains):
        return decide(Group.KEEP, Code.PROTECTED)
    result = gate.check(ordered)
    if result.passed:
        return decide(Group.CAN_UNSUBSCRIBE, Code.GATE_PASS, result.unsub_url)
    return decide(Group.UNSURE, result.code)


def classify(
    messages: list[MessageMeta],
    protected_domains: frozenset[str] = frozenset(),
    user_kept: frozenset[str] = frozenset(),
) -> list[Decision]:
    """All senders, biggest first."""
    decisions = [
        classify_sender(s, ms, protected_domains, user_kept) for s, ms in group_by_sender(messages).items()
    ]
    return sorted(decisions, key=lambda d: (-d.count, d.sender))

