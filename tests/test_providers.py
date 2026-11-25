"""Adapters with simulated Google/Microsoft replies (httpx.MockTransport). No real network.

Checks: headers-only requests (T5), GET only / no writes (T4), parsing into MessageMeta, Spam/Junk,
window cut-off, sent-by-me filtering, duplicated verdict header.
"""

from datetime import datetime, timedelta, timezone

import httpx
from conftest import GMAIL_AR, LU, LUP, OUTLOOK_AR, SIG_OK

from mail_unsubscriber.classify import classify
from mail_unsubscriber.model import Group
from mail_unsubscriber.providers.gmail import Gmail
from mail_unsubscriber.providers.outlook import Outlook, forefront

NOW = datetime(2026, 11, 24, tzinfo=timezone.utc)


def recorder(handler):
    seen = []

    def wrapped(req: httpx.Request):
        seen.append(req)
        return handler(req)

    return httpx.Client(transport=httpx.MockTransport(wrapped)), seen


def gmail_msg(i, days_ago, frm="News <deals@news.example.com>", labels=()):
    hdrs = [("From", frm), ("Authentication-Results", GMAIL_AR), ("DKIM-Signature", SIG_OK),
            ("List-Unsubscribe", LU), ("List-Unsubscribe-Post", LUP)]
    return {"id": f"g{i}", "internalDate": str(int((NOW - timedelta(days=days_ago)).timestamp() * 1000)),
            "labelIds": list(labels), "payload": {"headers": [{"name": n, "value": v} for n, v in hdrs]}}


def test_gmail_headers_only_get_only_and_cutoff():
    msgs = {m["id"]: m for m in [gmail_msg(1, 1), gmail_msg(2, 2, labels=["CATEGORY_PROMOTIONS"]),
                                 gmail_msg(3, 3, frm="me@example.org"), gmail_msg(4, 200)]}

    def handler(req):
        path = req.url.path
        if path.endswith("/profile"):
            return httpx.Response(200, json={"emailAddress": "me@example.org"})
        if path.endswith("/messages"):
            return httpx.Response(200, json={"messages": [{"id": k} for k in msgs]})
        return httpx.Response(200, json=msgs[path.rsplit("/", 1)[1]])

    client, seen = recorder(handler)
    out = Gmail(lambda: "tok", client, workers=2).fetch(NOW - timedelta(days=90))
    assert sorted(m.id for m in out) == ["g1", "g2"]  # g3 sent by me, g4 outside window
    assert all(r.method == "GET" for r in seen)
    gets = [r for r in seen if "/messages/" in r.url.path]
    assert gets and all(r.url.params.get("format") == "metadata" for r in gets)
    assert classify(out)[0].group == Group.CAN_UNSUBSCRIBE


def test_gmail_spam_label_marks_junk():
    from mail_unsubscriber.providers.gmail import to_meta

    assert to_meta(gmail_msg(1, 1, labels=["SPAM"])).in_junk


def outlook_msg(i, days_ago, folder="inbox", extra=()):
    hdrs = [("From", "deals@news.example.com"), ("Authentication-Results", OUTLOOK_AR), ("DKIM-Signature", SIG_OK),
            ("List-Unsubscribe", LU), ("List-Unsubscribe-Post", LUP), *extra]
    return {"id": f"o{i}", "receivedDateTime": (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "parentFolderId": folder, "webLink": f"https://outlook.live.com/owa/?ItemID=o{i}",
            "internetMessageHeaders": [{"name": n, "value": v} for n, v in hdrs]}


def test_outlook_get_only_paging_and_select():
    pages = {"p1": [outlook_msg(1, 1), outlook_msg(2, 2)], "p2": [outlook_msg(3, 3, folder="JUNKID")]}

    def handler(req):
        if req.url.path.endswith("/junkemail"):
            return httpx.Response(200, json={"id": "JUNKID"})
        if req.url.params.get("page") == "2":
            return httpx.Response(200, json={"value": pages["p2"]})
        return httpx.Response(200, json={"value": pages["p1"],
                                         "@odata.nextLink": "https://graph.microsoft.com/v1.0/me/messages?page=2"})

    client, seen = recorder(handler)
    out = Outlook(lambda: "tok", client).fetch(NOW - timedelta(days=90))
    assert [m.id for m in out] == ["o1", "o2", "o3"]
    assert out[2].in_junk and not out[0].in_junk
    assert all(r.method == "GET" for r in seen)
    first = [r for r in seen if r.url.path.endswith("/messages")][0]
    assert "body" not in first.url.params.get("$select", "")
    assert classify(out)[0].code.value == "IN_SPAM"  # one Junk message blocks the sender


def test_forefront_parsing_and_duplicate_denies():
    assert forefront("CIP:192.0.2.1;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:x;PTR:y;CAT:NONE;SFS:(1)") == ("NONE", "NSPM")
    from mail_unsubscriber.providers.outlook import to_meta

    dup = ("X-Forefront-Antispam-Report", "SFV:NSPM;CAT:NONE")
    m = to_meta(outlook_msg(1, 1, extra=(dup, dup)), "JUNKID")
    assert m.ms_cat == "DUPLICATE"


def test_gmail_rate_limit_403_is_retried(monkeypatch):
    import mail_unsubscriber.providers.gmail as g

    monkeypatch.setattr(g.time, "sleep", lambda s: None)
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(403, json={"error": {"errors": [{"reason": "rateLimitExceeded"}]}})
        return httpx.Response(200, json={"emailAddress": "me@example.org"})

    client, _ = recorder(handler)
    assert Gmail(lambda: "tok", client).own_address() == "me@example.org" and calls["n"] == 3


def test_gmail_other_403_is_readable_error():
    import pytest

    from mail_unsubscriber.providers import ProviderError

    client, _ = recorder(lambda req: httpx.Response(403, json={"error": {"errors": [{"reason": "insufficientPermissions"}]}}))
    with pytest.raises(ProviderError, match="insufficientPermissions"):
        Gmail(lambda: "tok", client)._get("https://gmail.googleapis.com/gmail/v1/users/me/messages")
