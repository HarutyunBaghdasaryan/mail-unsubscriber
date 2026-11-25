"""Provider-neutral data objects. Provider adapters fill them; the pure core reads them."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class Group(StrEnum):
    DANGER = "DANGER"
    KEEP = "KEEP"
    CAN_UNSUBSCRIBE = "CAN_UNSUBSCRIBE"
    UNSURE = "UNSURE"


class Code(StrEnum):
    # DANGER
    PROVIDER_PHISH = "PROVIDER_PHISH"
    PUNYCODE_FROM = "PUNYCODE_FROM"
    # KEEP
    PROTECTED = "PROTECTED"
    USER_KEPT = "USER_KEPT"
    # CAN_UNSUBSCRIBE
    GATE_PASS = "GATE_PASS"
    # UNSURE (first failing gate rule)
    IN_SPAM = "IN_SPAM"
    PROVIDER_FLAGGED = "PROVIDER_FLAGGED"
    AUTH_HEADER_UNTRUSTED = "AUTH_HEADER_UNTRUSTED"
    DMARC_FAIL_SEEN = "DMARC_FAIL_SEEN"
    NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
    NO_ONE_CLICK = "NO_ONE_CLICK"
    UNSUB_NOT_SIGNED = "UNSUB_NOT_SIGNED"


@dataclass(frozen=True)
class AuthResult:
    """Result of the provider's own Authentication-Results header for one message."""

    dmarc: str | None  # "pass", "fail", other, or None when absent
    dmarc_header_from: str | None  # lowercased domain the DMARC result is about
    dkim_pass_domains: frozenset[str] = frozenset()  # lowercased d= of passing DKIM results
    trusted: bool = True  # False when the header looked forged/duplicated: deny


@dataclass(frozen=True)
class DkimSig:
    d: str  # lowercased signing domain
    signed_headers: frozenset[str]  # lowercased header names from h=


@dataclass(frozen=True)
class MessageMeta:
    id: str
    date: datetime
    from_addr: str  # lowercased address
    from_domain: str  # lowercased domain
    auth: AuthResult | None = None  # None = no auth header found
    dkim_sigs: tuple[DkimSig, ...] = ()
    list_unsubscribe: str | None = None  # raw header value
    list_unsubscribe_post: str | None = None  # raw header value
    in_junk: bool = False  # Gmail SPAM label / Outlook Junk folder
    ms_cat: str | None = None  # Outlook X-Forefront-Antispam-Report CAT, if present
    ms_sfv: str | None = None  # Outlook X-Forefront-Antispam-Report SFV, if present
    gmail_category: str | None = None  # info only
    web_link: str | None = None  # info only


@dataclass(frozen=True)
class Decision:
    sender: str
    group: Group
    code: Code
    count: int
    first_seen: datetime
    last_seen: datetime
    gmail_category: str | None = None
    unsub_url: str | None = field(default=None, repr=False)  # internal; never shown to agents
    unsub_host: str | None = None
    web_link: str | None = None
