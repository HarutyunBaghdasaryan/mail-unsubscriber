"""The unsubscribe gate (REQUIREMENTS §3.2). Pure: messages in, verdict out.

A sender may be unsubscribed only if ALL rules pass:
  G1  nothing in Spam/Junk; Outlook verdicts only on the allowlist
  G2  no DMARC fail; >= 2 messages with DMARC pass aligned to From; auth headers trusted
  G3  newest message: https List-Unsubscribe + One-Click, both covered by every passing,
      aligned DKIM signature (RFC 8058)
Unknown or odd input always denies.
"""

from __future__ import annotations

from dataclasses import dataclass

from .headers import aligned, https_unsubscribe_url, is_one_click
from .model import Code, MessageMeta

OUTLOOK_CAT_OK = frozenset({"NONE", "BULK"})
OUTLOOK_SFV_BAD = frozenset({"SPM", "BLK", "SKB"})
MIN_DMARC_PASSES = 2


@dataclass(frozen=True)
class GateResult:
    passed: bool
    code: Code
    unsub_url: str | None = None


def _deny(code: Code) -> GateResult:
    return GateResult(False, code)


def check(messages: list[MessageMeta]) -> GateResult:
    if not messages:
        return _deny(Code.NOT_AUTHENTICATED)
    from_domain = messages[0].from_domain

    # G1: provider verdicts can only block
    for m in messages:
        if m.in_junk:
            return _deny(Code.IN_SPAM)
        if m.ms_cat is not None and m.ms_cat.upper() not in OUTLOOK_CAT_OK:
            return _deny(Code.PROVIDER_FLAGGED)
        if m.ms_sfv is not None and m.ms_sfv.upper() in OUTLOOK_SFV_BAD:
            return _deny(Code.PROVIDER_FLAGGED)

    # G2: identity proven by the provider's own DMARC result
    passes = 0
    for m in messages:
        if m.auth is None:
            continue  # no result: does not count either way
        if not m.auth.trusted:
            return _deny(Code.AUTH_HEADER_UNTRUSTED)
        if m.auth.dmarc == "fail":
            return _deny(Code.DMARC_FAIL_SEEN)
        if m.auth.dmarc == "pass" and m.auth.dmarc_header_from == m.from_domain == from_domain:
            passes += 1
    if passes < MIN_DMARC_PASSES:
        return _deny(Code.NOT_AUTHENTICATED)

    # G3: signed one-click on the newest message
    newest = max(messages, key=lambda m: m.date)
    url = https_unsubscribe_url(newest.list_unsubscribe)
    if url is None or not is_one_click(newest.list_unsubscribe_post):
        return _deny(Code.NO_ONE_CLICK)
    if newest.auth is None or newest.auth.dmarc != "pass":
        return _deny(Code.NOT_AUTHENTICATED)
    good_domains = {d for d in newest.auth.dkim_pass_domains if aligned(d, from_domain)}
    sigs = [s for s in newest.dkim_sigs if s.d in good_domains]
    needed = {"list-unsubscribe", "list-unsubscribe-post"}
    if not sigs or not all(needed <= s.signed_headers for s in sigs):
        return _deny(Code.UNSUB_NOT_SIGNED)
    return GateResult(True, Code.GATE_PASS, url)


def trace(messages: list[MessageMeta]) -> list[dict]:
    """Per-message technical check results for `unsub explain` (no content, no URLs)."""
    rows = []
    for m in sorted(messages, key=lambda m: m.date):
        a = m.auth
        aligned_pass = {d for d in (a.dkim_pass_domains if a else ()) if aligned(d, m.from_domain)}
        rows.append({
            "date": m.date.isoformat(timespec="minutes"),
            "in_junk": m.in_junk,
            "ms_cat": m.ms_cat,
            "ms_sfv": m.ms_sfv,
            "auth_header": "missing" if a is None else ("untrusted" if not a.trusted else "ok"),
            "dmarc": a.dmarc if a else None,
            "dmarc_about": a.dmarc_header_from if a else None,
            "dkim_pass": sorted(a.dkim_pass_domains) if a else [],
            "signatures": [
                {"d": s.d, "aligned_pass": s.d in aligned_pass,
                 "covers_unsubscribe": {"list-unsubscribe", "list-unsubscribe-post"} <= s.signed_headers}
                for s in m.dkim_sigs
            ],
            "https_unsubscribe": https_unsubscribe_url(m.list_unsubscribe) is not None,
            "one_click": is_one_click(m.list_unsubscribe_post),
        })
    return rows


EXPLAIN = {
    Code.GATE_PASS: "All checks passed: authenticated sender, signed one-click unsubscribe.",
    Code.IN_SPAM: "At least one email from this sender is in Spam/Junk. Your provider handles it; not offered.",
    Code.PROVIDER_FLAGGED: "Microsoft flagged at least one email (spam/bulk verdict not on the allowlist).",
    Code.AUTH_HEADER_UNTRUSTED: "The provider's authentication header looked duplicated or forged on an email.",
    Code.DMARC_FAIL_SEEN: "At least one email FAILED the sender check (DMARC).",
    Code.NOT_AUTHENTICATED: "Fewer than 2 emails show a passing sender check (DMARC) for this From domain.",
    Code.NO_ONE_CLICK: "The newest email has no https one-click unsubscribe (RFC 8058).",
    Code.UNSUB_NOT_SIGNED: "The unsubscribe headers are not covered by the sender's own signature (DKIM).",
}
