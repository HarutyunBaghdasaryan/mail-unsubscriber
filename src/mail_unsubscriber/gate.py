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
