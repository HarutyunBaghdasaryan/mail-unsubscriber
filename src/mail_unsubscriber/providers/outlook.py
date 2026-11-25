"""Outlook adapter (Microsoft Graph; M365 + Outlook.com). Scope Mail.ReadBasic. Only GET requests."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime

import httpx

from ..headers import parse_dkim_signature, parse_from, trusted_auth
from ..model import MessageMeta

API = "https://graph.microsoft.com/v1.0/me"
SELECT = "id,receivedDateTime,parentFolderId,webLink,internetMessageHeaders"


def forefront(value: str | None) -> tuple[str | None, str | None]:
    """(CAT, SFV) from X-Forefront-Antispam-Report, e.g. '...;SFV:NSPM;...;CAT:NONE;...'."""
    if not value:
        return None, None
    fields = {}
    for part in value.split(";"):
        k, sep, v = part.partition(":")
        if sep:
            fields[k.strip().upper()] = v.strip().upper()
    return fields.get("CAT"), fields.get("SFV")


def to_meta(msg: dict, junk_folder_id: str | None, own_address: str | None = None) -> MessageMeta | None:
    hl = msg.get("internetMessageHeaders") or []

    def values(name: str) -> list[str]:
        return [h.get("value", "") for h in hl if h.get("name", "").lower() == name.lower()]

    frm = parse_from((values("From") or [None])[0])
    if frm is None or (own_address and frm[0] == own_address.lower()):
        return None
    ff = values("X-Forefront-Antispam-Report")
    cat, sfv = forefront(ff[0] if len(ff) == 1 else None)
    if len(ff) > 1:  # duplicated verdict header: don't trust it, deny via unknown CAT
        cat = "DUPLICATE"
    sigs = tuple(s for s in (parse_dkim_signature(v) for v in values("DKIM-Signature")) if s)
    return MessageMeta(
        id=msg["id"],
        date=datetime.fromisoformat(msg["receivedDateTime"].replace("Z", "+00:00")),
        from_addr=frm[0],
        from_domain=frm[1],
        auth=trusted_auth(values("Authentication-Results"), None),
        dkim_sigs=sigs,
        list_unsubscribe=(values("List-Unsubscribe") or [None])[0],
        list_unsubscribe_post=(values("List-Unsubscribe-Post") or [None])[0],
        in_junk=bool(junk_folder_id) and msg.get("parentFolderId") == junk_folder_id,
        ms_cat=cat,
        ms_sfv=sfv,
        web_link=msg.get("webLink"),
    )


class Outlook:
    def __init__(self, token: Callable[[], str], client: httpx.Client | None = None):
        self._token = token
        self._client = client or httpx.Client(timeout=60)

    def _get(self, url: str, params: dict | None = None) -> dict:
        for attempt in range(6):
            r = self._client.get(url, params=params, headers={"Authorization": f"Bearer {self._token()}"})
            if r.status_code in (429, 503, 504) and attempt < 5:
                time.sleep(min(float(r.headers.get("Retry-After", 2 ** attempt)), 60))
                continue
            r.raise_for_status()
            return r.json()
        raise RuntimeError("unreachable")

    def fetch(self, since: datetime, own_address: str | None = None,
              progress: Callable[[int], None] | None = None) -> list[MessageMeta]:
        junk = self._get(f"{API}/mailFolders/junkemail", {"$select": "id"}).get("id")
        me = own_address.lower() if own_address else None
        params = {
            "$select": SELECT,
            "$top": "100",
            "$orderby": "receivedDateTime desc",
            "$filter": f"receivedDateTime ge {since.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        }
        out: list[MessageMeta] = []
        url, p = f"{API}/messages", params
        while url:
            page = self._get(url, p)
            for m in page.get("value", []):
                meta = to_meta(m, junk, me)
                if meta:
                    out.append(meta)
            if progress:
                progress(len(out))
            url, p = page.get("@odata.nextLink"), None
        return out
