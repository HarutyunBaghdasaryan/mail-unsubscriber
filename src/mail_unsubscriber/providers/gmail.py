"""Gmail adapter. Scope gmail.metadata: Google itself refuses bodies. Only GET requests."""

from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import httpx

from ..headers import parse_dkim_signature, parse_from, trusted_auth
from ..model import MessageMeta

API = "https://gmail.googleapis.com/gmail/v1/users/me"
HEADERS = ["From", "Authentication-Results", "DKIM-Signature", "List-Unsubscribe", "List-Unsubscribe-Post", "Date"]
CATEGORIES = {"CATEGORY_PROMOTIONS": "promotions", "CATEGORY_UPDATES": "updates", "CATEGORY_SOCIAL": "social",
              "CATEGORY_FORUMS": "forums", "CATEGORY_PERSONAL": "personal"}


def to_meta(msg: dict, own_address: str | None = None) -> MessageMeta | None:
    """Convert one Gmail metadata message to MessageMeta; None if unusable or sent by the user."""
    hl = msg.get("payload", {}).get("headers", [])

    def values(name: str) -> list[str]:
        return [h.get("value", "") for h in hl if h.get("name", "").lower() == name.lower()]

    frm = parse_from((values("From") or [None])[0])
    if frm is None or (own_address and frm[0] == own_address.lower()):
        return None
    labels = set(msg.get("labelIds", []))
    cat = next((v for k, v in CATEGORIES.items() if k in labels), None)
    sigs = tuple(s for s in (parse_dkim_signature(v) for v in values("DKIM-Signature")) if s)
    return MessageMeta(
        id=msg["id"],
        date=datetime.fromtimestamp(int(msg.get("internalDate", "0")) / 1000, tz=timezone.utc),
        from_addr=frm[0],
        from_domain=frm[1],
        auth=trusted_auth(values("Authentication-Results"), "mx.google.com"),
        dkim_sigs=sigs,
        list_unsubscribe=(values("List-Unsubscribe") or [None])[0],
        list_unsubscribe_post=(values("List-Unsubscribe-Post") or [None])[0],
        in_junk="SPAM" in labels,
        gmail_category=cat,
        web_link=f"https://mail.google.com/mail/u/0/#all/{msg['id']}",
    )


class Gmail:
    def __init__(self, token: Callable[[], str], client: httpx.Client | None = None, workers: int = 8):
        self._token = token
        self._client = client or httpx.Client(timeout=30)
        self._workers = workers

    def _get(self, url: str, params: dict | list | None = None) -> dict:
        for attempt in range(5):
            r = self._client.get(url, params=params, headers={"Authorization": f"Bearer {self._token()}"})
            if r.status_code in (429, 500, 503) and attempt < 4:
                time.sleep(min(2 ** attempt, 20))
                continue
            r.raise_for_status()
            return r.json()
        raise RuntimeError("unreachable")

    def own_address(self) -> str | None:
        try:
            return self._get(f"{API}/profile")["emailAddress"].lower()
        except httpx.HTTPStatusError:
            return None

    def fetch(self, since: datetime, own_address: str | None = None,
              progress: Callable[[int], None] | None = None) -> list[MessageMeta]:
        me = (own_address or self.own_address() or "").lower() or None
        params = [("format", "metadata")] + [("metadataHeaders", h) for h in HEADERS]
        out: list[MessageMeta] = []
        page = None
        with ThreadPoolExecutor(self._workers) as pool:
            while True:
                lp = {"maxResults": 500, "includeSpamTrash": "true"}
                if page:
                    lp["pageToken"] = page
                listing = self._get(f"{API}/messages", lp)
                ids = [m["id"] for m in listing.get("messages", [])]
                msgs = list(pool.map(lambda i: self._get(f"{API}/messages/{i}", params), ids))
                older = False
                for m in msgs:
                    meta = to_meta(m, me)
                    if int(m.get("internalDate", "0")) / 1000 < since.timestamp():
                        older = True
                        continue
                    if meta:
                        out.append(meta)
                if progress:
                    progress(len(out))
                page = listing.get("nextPageToken")
                if older or not page:
                    return out
