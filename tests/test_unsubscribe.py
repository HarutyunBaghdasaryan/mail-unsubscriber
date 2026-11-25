"""T3 (network guard), T6 (nothing sent unless safe + fresh scan + yes + OS confirm), filters (R7a)."""

import socket
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from mail_unsubscriber import journal, netguard, unsubscribe
from mail_unsubscriber.selection import Filters, select

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)


def dec(sender, group="CAN_UNSUBSCRIBE", code="GATE_PASS", count=3, cat="promotions", url="https://u.example.net/x"):
    return {"sender": sender, "group": group, "code": code, "count": count, "gmail_category": cat,
            "unsub_url": url if group == "CAN_UNSUBSCRIBE" else None, "unsub_host": "u.example.net"}


SCAN = {
    "scanned_at": (NOW - timedelta(minutes=10)).isoformat(),
    "decisions": [
        dec("a@shop.example.com"),
        dec("b@news.example.org", cat="updates", count=5),
        dec("c@linkedin.example.com", cat="social"),
        dec("bank@alerts.example.com", group="UNSURE", code="NOT_AUTHENTICATED", cat="updates"),
        dec("phish@xn--bad.example", group="DANGER", code="PUNYCODE_FROM"),
    ],
}


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAIL_UNSUB_HOME", str(tmp_path))


def run(filters=Filters(), answer="yes", confirmed=True, scan=SCAN, one_by_one=False, answers=None):
    posted, lines = [], []
    seq = iter(answers or [])
    rc = unsubscribe.run(
        "gmail", scan, filters,
        ask=(lambda p: next(seq)) if answers else (lambda p: answer),
        confirm=lambda senders: confirmed,
        post=lambda url: posted.append(url) or 200,
        one_by_one=one_by_one, now=NOW, out=lines.append,
    )
    return rc, posted, "\n".join(lines)


# ---------- T6: nothing is sent unless every condition holds ----------

def test_happy_path_sends_only_safe_senders():
    rc, posted, out = run()
    assert rc == 0 and len(posted) == 3
    assert "bank@alerts.example.com" in out and "UNSURE" in out  # listed as skipped
    assert set(journal.unsubscribed("gmail")) == {"a@shop.example.com", "b@news.example.org", "c@linkedin.example.com"}


def test_no_yes_sends_nothing():
    for a in ("", "y", "YES please", "no"):
        assert run(answer=a)[1] == []


def test_touch_id_refused_sends_nothing():
    rc, posted, out = run(confirmed=False)
    assert rc == 1 and posted == [] and "Nothing was sent" in out


def test_old_scan_sends_nothing():
    old = dict(SCAN, scanned_at=(NOW - timedelta(hours=2)).isoformat())
    rc, posted, _ = run(scan=old)
    assert rc == 1 and posted == []


def test_unsure_and_danger_never_sent_even_when_named():
    rc, posted, out = run(Filters(senders={"bank@alerts.example.com", "phish@xn--bad.example"}))
    assert posted == [] and "Nothing to unsubscribe" in out


def test_already_done_and_kept_are_skipped():
    run()
    rc, posted, out = run()
    assert posted == [] and "already unsubscribed" in out
    journal.add("gmail", "x@keep.example.com", "kept")
    scan = dict(SCAN, decisions=[dec("x@keep.example.com")])
    assert run(scan=scan)[1] == []


def test_one_by_one():
    rc, posted, _ = run(one_by_one=True, answers=["y", "n", "k"])
    assert len(posted) == 1
    assert "c@linkedin.example.com" in journal.kept("gmail") or "a@shop.example.com" in journal.kept("gmail")


# ---------- R7a filters ----------

def test_filters_category_combination_and_exclusions():
    ds = SCAN["decisions"]
    c, _ = select(ds, Filters(categories={"promotions"}))
    assert [d["sender"] for d in c] == ["a@shop.example.com"]
    c, _ = select(ds, Filters(categories={"promotions", "updates"}))
    assert {d["sender"] for d in c} == {"a@shop.example.com", "b@news.example.org"}  # bank (UNSURE) excluded
    c, _ = select(ds, Filters(categories={"promotions", "updates"}, exclude_domains={"example.org"}))
    assert [d["sender"] for d in c] == ["a@shop.example.com"]
    c, _ = select(ds, Filters(domains={"linkedin.example.com"}))
    assert [d["sender"] for d in c] == ["c@linkedin.example.com"]
    c, _ = select(ds, Filters(min_emails=4))
    assert [d["sender"] for d in c] == ["b@news.example.org"]


# ---------- T3: network guard ----------

def fake_resolver(ip):
    return lambda host, port, type=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0"])
def test_guard_blocks_non_public(ip):
    with pytest.raises(netguard.Blocked):
        netguard.one_click("https://u.example.net/x", resolver=fake_resolver(ip))


def test_guard_blocks_ipv6_loopback():
    r = lambda host, port, type=0: [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", port, 0, 0))]
    with pytest.raises(netguard.Blocked):
        netguard.one_click("https://u.example.net/x", resolver=r)


def test_guard_rejects_http_and_credentials():
    for url in ("http://u.example.net/x", "https://user:pw@u.example.net/x"):
        with pytest.raises(netguard.Blocked):
            netguard.one_click(url, resolver=fake_resolver("93.184.216.34"))


def test_guard_posts_once_and_does_not_follow_redirect():
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    status = netguard.one_click("https://u.example.net/x", client=client, resolver=fake_resolver("93.184.216.34"))
    assert status == 302 and len(seen) == 1
    assert seen[0].method == "POST" and seen[0].content == b"List-Unsubscribe=One-Click"
    assert "cookie" not in {k.lower() for k in seen[0].headers} and "referer" not in {k.lower() for k in seen[0].headers}
