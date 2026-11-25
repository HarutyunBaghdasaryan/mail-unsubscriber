"""Synthetic header fixtures (example.com only; no real mail)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from mail_unsubscriber.headers import parse_dkim_signature, parse_from, trusted_auth
from mail_unsubscriber.model import MessageMeta

BASE = datetime(2026, 11, 1, tzinfo=timezone.utc)

GMAIL_AR = (
    "mx.google.com;\r\n       dkim=pass header.i=@news.example.com header.s=s1 header.b=AbCdEf12;\r\n"
    "       spf=pass (google.com: domain of bounce@news.example.com designates 192.0.2.1 as permitted sender)"
    " smtp.mailfrom=bounce@news.example.com;\r\n"
    "       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=news.example.com"
)
OUTLOOK_AR = (
    "spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=news.example.com; dkim=pass (signature was verified)"
    " header.d=news.example.com;dmarc=pass action=none header.from=news.example.com;compauth=pass reason=100"
)
SIG_OK = (
    "v=1; a=rsa-sha256; c=relaxed/relaxed; d=news.example.com; s=s1;\r\n"
    " h=from:to:subject:date:list-unsubscribe:list-unsubscribe-post:message-id; bh=xyz=; b=abc"
)
SIG_NO_LU = "v=1; a=rsa-sha256; d=news.example.com; s=s1; h=from:to:subject:date; bh=x; b=y"
SIG_ESP = "v=1; a=rsa-sha256; d=esp.example.net; s=e1; h=from:to:list-unsubscribe:list-unsubscribe-post; bh=x; b=y"
LU = "<mailto:u@news.example.com>, <https://list.esp.example.net/u/abc123>"
LUP = "List-Unsubscribe=One-Click"


def make(
    i: int = 0,
    frm: str = "News <deals@news.example.com>",
    ar: list[str] | None = None,
    authserv: str | None = "mx.google.com",
    sigs: list[str] | None = None,
    lu: str | None = LU,
    lup: str | None = LUP,
    **kw,
) -> MessageMeta:
    addr, domain = parse_from(frm)
    ars = [GMAIL_AR] if ar is None else ar
    parsed = [s for s in (parse_dkim_signature(x) for x in (sigs if sigs is not None else [SIG_OK])) if s]
    return MessageMeta(
        id=f"m{i}",
        date=BASE + timedelta(days=i),
        from_addr=addr,
        from_domain=domain,
        auth=trusted_auth(ars, authserv),
        dkim_sigs=tuple(parsed),
        list_unsubscribe=lu,
        list_unsubscribe_post=lup,
        **kw,
    )


@pytest.fixture
def mk():
    return make
