"""Gmail adapter. Scope gmail.metadata: Google itself refuses bodies. Only GET requests."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import httpx

from ..headers import parse_dkim_signature, parse_from, trusted_auth
from ..model import MessageMeta
from . import ProviderError

API = "https://gmail.googleapis.com/gmail/v1/users/me"
HEADERS = ["From", "Authentication-Results", "DKIM-Signature", "List-Unsubscribe", "List-Unsubscribe-Post", "Date"]
MAX_RPS = 20  # 20 x 5 quota units = 100/s, well under the 250/s per-user limit
RATE_REASONS = {"rateLimitExceeded", "userRateLimitExceeded", "concurrentLimitExceeded"}



def _reason(r: httpx.Response) -> str | None:
    try:
        errs = r.json().get("error", {}).get("errors") or []
        return errs[0].get("reason") if errs else r.json().get("error", {}).get("status")
    except Exception:
        return None


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
    def __init__(self, token: Callable[[], str], client: httpx.Client | None = None, workers: int = 3):
        self._token = token
        self._lock = threading.Lock()
        self._next = 0.0
        self._sleep = time.sleep
        self._client = client or httpx.Client(timeout=30)
        self._workers = workers

    def _throttle(self) -> None:
        """Keep under Gmail's per-user quota: at most `MAX_RPS` requests per second across threads."""
        with self._lock:
            wait = self._next - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._next = max(self._next, time.monotonic()) + 1 / MAX_RPS

    def _get(self, url: str, params: dict | list | None = None) -> dict:
        attempts = 10  # with backoff this waits up to ~6 minutes before giving up
        for attempt in range(attempts):
            self._throttle()
            r = self._client.get(url, params=params, headers={"Authorization": f"Bearer {self._token()}"})
            if r.status_code < 400:
                return r.json()
            reason = _reason(r)
            retry = r.status_code in (429, 500, 503) or reason in RATE_REASONS
            if retry and attempt < attempts - 1:
                after = r.headers.get("Retry-After")
                self._sleep(float(after) if after and after.isdigit() else min(2 ** (attempt + 1), 60))
                continue
            raise ProviderError(f"Gmail refused the request ({r.status_code} {reason or ''}).".replace(" )", ")"))
        raise ProviderError("Gmail kept refusing requests (rate limit).")

    def own_address(self) -> str | None:
        try:
            return self._get(f"{API}/profile")["emailAddress"].lower()
        except ProviderError:
            return None

    def fetch(self, since: datetime, own_address: str | None = None,
              progress: Callable[[int], None] | None = None,
              known: dict[str, float] | None = None, old_ids: set[str] | None = None) -> list[MessageMeta]:
        """New messages since `since`. `known` = id -> unix time of messages we already have (skipped,
        no request); `old_ids` = ids seen before outside the window (skipped). Both are updated."""
        me = (own_address or self.own_address() or "").lower() or None
        known = {} if known is None else known
        old_ids = set() if old_ids is None else old_ids
        params = [("format", "metadata")] + [("metadataHeaders", h) for h in HEADERS]
        out: list[MessageMeta] = []
        page = None
        cutoff = since.timestamp()
        with ThreadPoolExecutor(self._workers) as pool:
            while True:
                lp = {"maxResults": 500, "includeSpamTrash": "true"}
                if page:
                    lp["pageToken"] = page
                listing = self._get(f"{API}/messages", lp)
                ids = [m["id"] for m in listing.get("messages", [])]
                todo = [i for i in ids if i not in known and i not in old_ids]
                msgs = list(pool.map(lambda i: self._get(f"{API}/messages/{i}", params), todo))
                in_window = sum(1 for i in ids if known.get(i, 0) >= cutoff)
                for m in msgs:
                    ts = int(m.get("internalDate", "0")) / 1000
                    if ts < cutoff:
                        old_ids.add(m["id"])  # Gmail's list is only roughly newest-first: skip, don't stop
                        continue
                    in_window += 1
                    known[m["id"]] = ts
                    meta = to_meta(m, me)
                    if meta:
                        out.append(meta)
                if progress:
                    progress(len(out))
                page = listing.get("nextPageToken")
                if in_window == 0 or not page:  # stop only when a whole page is older than the window
                    return out

    def states(self, ids: list[str]) -> dict[str, dict | None]:
        """Current junk state of known messages (labels only). None = message no longer exists."""
        def one(i):
            try:
                m = self._get(f"{API}/messages/{i}", {"format": "minimal"})
                return i, {"in_junk": "SPAM" in set(m.get("labelIds", []))}
            except ProviderError as e:
                if "404" in str(e):
                    return i, None
                raise
        with ThreadPoolExecutor(self._workers) as pool:
            return dict(pool.map(one, ids))
