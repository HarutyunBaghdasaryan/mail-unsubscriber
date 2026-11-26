"""What AI agents may see (REQUIREMENTS R14-R18). Pure.

Only: groups, reason codes, counts, dates, Gmail tab, validated addresses/domains, unsubscribe host.
Never: subjects, bodies, display names, full URLs, tokens. DANGER domains are defanged.
Every sender-written string is syntax-checked; anything odd is replaced, so email text cannot
smuggle instructions to the agent.
"""

from __future__ import annotations

import re

from .gate import EXPLAIN
from .headers import is_valid_domain
from .model import Code

_LOCAL_RE = re.compile(r"^[a-z0-9._%+\-]{1,64}$")
PERSONAL_DOMAINS = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com"}
OTHER_REASONS = {
    "PROVIDER_PHISH": "Provider marked an email as phishing/impersonation.",
    "PUNYCODE_FROM": "The From domain uses look-alike (punycode) characters.",
    "PROTECTED": "Domain is on your protected list.",
    "USER_KEPT": "You chose to keep this sender.",
}


def safe_domain(d: str | None) -> str | None:
    d = (d or "").lower()
    return d if is_valid_domain(d) else None


def safe_address(a: str | None) -> str:
    a = (a or "").lower()
    local, _, dom = a.rpartition("@")
    return a if _LOCAL_RE.match(local or "") and safe_domain(dom) else "<invalid-address>"


def defang(s: str) -> str:
    return s.replace(".", "[.]")


def agent_default(acct: dict) -> bool:
    """Personal mailboxes: on. Work mailboxes (company domain): off."""
    email = (acct.get("email") or "").lower()
    return email.rpartition("@")[2] in PERSONAL_DOMAINS


def agent_allowed(acct: dict) -> bool:
    v = acct.get("agent")
    return agent_default(acct) if v is None else v == "on"


def sender_row(d: dict) -> dict:
    sender = safe_address(d.get("sender"))
    if d.get("group") == "DANGER":
        sender = defang(sender)
    return {
        "sender": sender,
        "group": str(d.get("group")),
        "reason": str(d.get("code")),
        "emails": int(d.get("count") or 0),
        "gmail_tab": d.get("gmail_category") if d.get("gmail_category") in
        {"promotions", "updates", "social", "forums", "personal"} else None,
        "unsubscribe_host": safe_domain(d.get("unsub_host")),
        "first_seen": str(d.get("first_seen"))[:10],
        "last_seen": str(d.get("last_seen"))[:10],
    }


def reason_text(code: str) -> str:
    try:
        return EXPLAIN.get(Code(code)) or OTHER_REASONS.get(code, "")
    except ValueError:
        return ""


def trace_rows(rows: list[dict]) -> list[dict]:
    out = []
    for r in rows or []:
        own = [s for s in r.get("signatures", []) if s.get("aligned_pass")]
        out.append({
            "date": str(r.get("date"))[:16],
            "in_spam": bool(r.get("in_junk")),
            "provider_auth_header": r.get("auth_header") if r.get("auth_header") in {"ok", "missing", "untrusted"} else None,
            "dmarc": r.get("dmarc") if r.get("dmarc") in {"pass", "fail", "none", "temperror", "permerror"} else None,
            "dmarc_domain": safe_domain(r.get("dmarc_about")),
            "own_signature_covers_unsubscribe": (all(s.get("covers_unsubscribe") for s in own) if own else None),
            "one_click_https": bool(r.get("one_click") and r.get("https_unsubscribe")),
        })
    return out


def unsubscribe_command(account: str, category: list[str] | None, domains: list[str] | None,
                        senders: list[str] | None, min_emails: int) -> str:
    """The command the human runs. Values are re-validated so nothing odd can be injected."""
    parts = ["unsub", "unsubscribe", "--account", account if re.fullmatch(r"[A-Za-z0-9_-]{1,32}", account) else "ACCOUNT"]
    cats = [c for c in (category or []) if c in {"promotions", "updates", "social", "forums"}]
    doms = [d for d in (safe_domain(x) for x in domains or []) if d]
    snds = [s for s in (safe_address(x) for x in senders or []) if s != "<invalid-address>"]
    if cats:
        parts += ["--category", ",".join(cats)]
    if doms:
        parts += ["--domain", ",".join(doms)]
    for s in snds:
        parts += ["--sender", s]
    if min_emails > 1:
        parts += ["--min-emails", str(int(min_emails))]
    return " ".join(parts)


def trace_summary(rows: list[dict]) -> dict:
    """Counts across all emails of a sender, so agents get the picture without 50 rows."""
    from collections import Counter

    return {
        "emails": len(rows),
        "in_spam": sum(1 for r in rows if r["in_spam"]),
        "dmarc": dict(Counter(str(r["dmarc"]) for r in rows)),
        "provider_auth_header": dict(Counter(str(r["provider_auth_header"]) for r in rows)),
        "own_signature_covers_unsubscribe": dict(Counter(str(r["own_signature_covers_unsubscribe"]) for r in rows)),
        "one_click_https": sum(1 for r in rows if r["one_click_https"]),
    }
