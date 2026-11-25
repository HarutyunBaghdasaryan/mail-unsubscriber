"""The only network write in the app: one guarded RFC 8058 one-click POST.

https only, TLS verified, host must resolve to public addresses only, no redirects followed,
no cookies/Referer, 10 s timeout, response body never read beyond 64 KB and never parsed.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

import httpx

USER_AGENT = "mail-unsubscriber (RFC 8058 one-click)"
MAX_BODY = 64 * 1024


class Blocked(Exception):
    pass


def check_host(host: str, resolver=socket.getaddrinfo) -> None:
    try:
        infos = resolver(host, 443, type=socket.SOCK_STREAM)
    except OSError as e:
        raise Blocked(f"cannot resolve {host}") from e
    if not infos:
        raise Blocked(f"cannot resolve {host}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local:
            raise Blocked(f"{host} resolves to a non-public address")


def one_click(url: str, client: httpx.Client | None = None, resolver=socket.getaddrinfo) -> int:
    """POST List-Unsubscribe=One-Click. Returns HTTP status. Raises Blocked for unsafe targets."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise Blocked("only plain https URLs are allowed")
    check_host(parts.hostname, resolver)
    own = client is None
    client = client or httpx.Client(timeout=10, follow_redirects=False, verify=True)
    try:
        with client.stream(
            "POST", url,
            content=b"List-Unsubscribe=One-Click",
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": USER_AGENT},
        ) as r:
            read = 0
            for chunk in r.iter_bytes():
                read += len(chunk)
                if read >= MAX_BODY:
                    break
            return r.status_code
    except httpx.HTTPError as e:
        raise Blocked(f"request failed: {type(e).__name__}") from e
    finally:
        if own:
            client.close()
