"""Pure, defensive parsers for the few headers we use. Malformed input returns None/empty."""

from __future__ import annotations

import re
from email.utils import getaddresses
from urllib.parse import urlsplit

from .model import AuthResult, DkimSig

MAX_HEADER = 8192
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


def _clip(value: str | None) -> str | None:
    if value is None or len(value) > MAX_HEADER:
        return None
    return value


def _unfold(value: str) -> str:
    return re.sub(r"\r?\n[ \t]+", " ", value)


def _strip_comments(value: str) -> str:
    out, depth = [], 0
    for ch in value:
        if ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        elif not depth:
            out.append(ch)
    return "".join(out)


def is_valid_domain(domain: str | None) -> bool:
    return bool(domain) and bool(_HOST_RE.match(domain))


def parse_from(value: str | None) -> tuple[str, str] | None:
    """Return (address, domain), lowercased, or None if not exactly one usable address."""
    value = _clip(value)
    if not value:
        return None
    addrs = [a for _, a in getaddresses([_unfold(value)]) if a]
    if len(addrs) != 1 or addrs[0].count("@") != 1:
        return None
    addr = addrs[0].strip().lower()
    domain = addr.rsplit("@", 1)[1]
    if not is_valid_domain(domain):
        return None
    return addr, domain


def is_punycode(domain: str) -> bool:
    return any(label.startswith("xn--") for label in domain.split("."))


def aligned(a: str, b: str) -> bool:
    """Conservative relaxed alignment: equal, or one is a subdomain of the other.

    Stricter than DMARC's organizational-domain rule (siblings like a.x.com / b.x.com
    are NOT treated as aligned), so it can only deny more, never allow more.
    """
    a, b = a.lower().rstrip("."), b.lower().rstrip(".")
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def split_auth_results(value: str) -> tuple[str | None, list[tuple[str, str, dict[str, str]]]]:
    """Split an Authentication-Results value into (authserv_id, [(method, result, props)])."""
    text = _strip_comments(_unfold(value))
    parts = [p.strip() for p in text.split(";") if p.strip()]
    authserv = None
    if parts and "=" not in parts[0].split()[0]:
        authserv = parts.pop(0).split()[0].lower()
    results = []
    for part in parts:
        tokens = part.split()
        if not tokens or "=" not in tokens[0]:
            continue
        method, _, result = tokens[0].partition("=")
        props = {}
        for tok in tokens[1:]:
            k, sep, v = tok.partition("=")
            if sep:
                props[k.lower()] = v.strip().strip('"').lower()
        results.append((method.lower(), result.lower(), props))
    return authserv, results


def auth_from_results(value: str) -> AuthResult:
    _, results = split_auth_results(value)
    dmarc = dmarc_from = None
    dkim_pass: set[str] = set()
    for method, result, props in results:
        if method == "dmarc" and dmarc is None:
            dmarc, dmarc_from = result, props.get("header.from")
        elif method == "dkim" and result == "pass":
            d = props.get("header.d")
            if not d and "header.i" in props:  # Gmail stamps header.i=@domain (or user@domain)
                d = props["header.i"].rpartition("@")[2]
            if d and is_valid_domain(d):
                dkim_pass.add(d)
    return AuthResult(dmarc=dmarc, dmarc_header_from=dmarc_from, dkim_pass_domains=frozenset(dkim_pass))


def trusted_auth(ar_values: list[str], authserv_id: str | None) -> AuthResult | None:
    """Pick the provider's own Authentication-Results header.

    authserv_id: the id the provider stamps (e.g. "mx.google.com"); None = provider stamps no id,
    then exactly one header must exist. Returns None if no header; untrusted result if ambiguous.
    """
    values = [v for v in (_clip(x) for x in ar_values) if v]
    if not values:
        return None
    if authserv_id is None:
        if len(values) != 1:
            return AuthResult(None, None, trusted=False)
        return auth_from_results(values[0])
    ours = [v for v in values if split_auth_results(v)[0] == authserv_id.lower()]
    first_id = split_auth_results(values[0])[0]
    if len(ours) != 1 or first_id != authserv_id.lower():
        return AuthResult(None, None, trusted=False)
    return auth_from_results(ours[0])


def parse_dkim_signature(value: str | None) -> DkimSig | None:
    value = _clip(value)
    if not value:
        return None
    tags: dict[str, str] = {}
    for part in re.sub(r"\s+", "", value).split(";"):
        k, sep, v = part.partition("=")
        if sep and k:
            tags[k.lower()] = v
    d = tags.get("d", "").lower()
    if not is_valid_domain(d) or "h" not in tags:
        return None
    return DkimSig(d=d, signed_headers=frozenset(h.lower() for h in tags["h"].split(":") if h))


def https_unsubscribe_url(value: str | None) -> str | None:
    """First https URI from a List-Unsubscribe value, or None. Rejects odd URLs."""
    value = _clip(value)
    if not value:
        return None
    for uri in re.findall(r"<([^<>]*)>", _unfold(value)):
        uri = uri.strip()
        if not uri.lower().startswith("https://") or len(uri) > 2048 or re.search(r"\s", uri):
            continue
        parts = urlsplit(uri)
        host = (parts.hostname or "").lower()
        if parts.username or parts.password or parts.port not in (None, 443) or not is_valid_domain(host):
            continue
        return uri
    return None


def is_one_click(value: str | None) -> bool:
    return value is not None and value.strip() == "List-Unsubscribe=One-Click"
