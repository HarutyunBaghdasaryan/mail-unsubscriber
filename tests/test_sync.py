"""Incremental sync: only new mail is fetched, old data is reused, states are re-checked before acting."""

from datetime import datetime, timedelta, timezone

import pytest
from conftest import make

from mail_unsubscriber import sync
from mail_unsubscriber.model import Group

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
GMAIL = {"provider": "gmail", "email": "me@example.org"}


def msg(i, days_ago, **kw):
    m = make(i, **kw)
    return sync.from_dict({**sync.to_dict(m), "date": (NOW - timedelta(days=days_ago)).isoformat()})


class FakeGmail:
    def __init__(self, mailbox):
        self.mailbox = {m.id: m for m in mailbox}
        self.fetched_ids = []
        self.junk = set()

    def fetch(self, since, own, progress, known, old_ids):
        out = []
        for m in self.mailbox.values():
            if m.id in known or m.id in old_ids:
                continue
            if m.date < since:
                old_ids.add(m.id)
                continue
            self.fetched_ids.append(m.id)
            known[m.id] = m.date.timestamp()
            out.append(m)
        return out

    def states(self, ids):
        return {i: ({"in_junk": i in self.junk} if i in self.mailbox else None) for i in ids}


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAIL_UNSUB_HOME", str(tmp_path))


def test_roundtrip_keeps_everything_the_gate_needs():
    from mail_unsubscriber import gate

    a, b = [make(0), make(1)], [sync.from_dict(sync.to_dict(m)) for m in (make(0), make(1))]
    assert gate.check(a) == gate.check(b) and gate.check(b).passed
    assert b[0].auth == a[0].auth and b[0].list_unsubscribe == a[0].list_unsubscribe


def test_first_sync_is_full_then_incremental_fetches_only_new():
    box = FakeGmail([msg(0, 5), msg(1, 3), msg(2, 40)])
    msgs, mode = sync.sync("gmail", GMAIL, box, 30, now=NOW)
    assert mode == "full" and sorted(m.id for m in msgs) == ["m0", "m1"]
    box.mailbox["m3"] = msg(3, 0)
    box.fetched_ids.clear()
    msgs, mode = sync.sync("gmail", GMAIL, box, 30, now=NOW + timedelta(hours=2))
    assert mode == "incremental" and box.fetched_ids == ["m3"]
    assert sorted(m.id for m in msgs) == ["m0", "m1", "m3"]


def test_old_data_triggers_full_and_window_drops_old_mail():
    box = FakeGmail([msg(0, 5), msg(1, 3)])
    sync.sync("gmail", GMAIL, box, 30, now=NOW)
    _, mode = sync.sync("gmail", GMAIL, box, 30, now=NOW + timedelta(days=8))
    assert mode == "full"
    _, mode = sync.sync("gmail", GMAIL, box, 30, full=True, now=NOW + timedelta(days=8, hours=1))
    assert mode == "full"


def test_recheck_catches_mail_moved_to_spam_and_deleted_mail():
    box = FakeGmail([msg(0, 5), msg(1, 3)])
    msgs, _ = sync.sync("gmail", GMAIL, box, 30, now=NOW)
    scan = sync.build_scan("gmail", GMAIL, msgs, 30, now=NOW)
    assert scan["decisions"][0]["group"] == Group.CAN_UNSUBSCRIBE
    box.junk.add("m1")  # the user (or Gmail) moved one email to Spam after the scan
    msgs = sync.recheck("gmail", box, msgs, {"deals@news.example.com"})
    scan = sync.build_scan("gmail", GMAIL, msgs, 30, now=NOW)
    assert scan["decisions"][0]["code"] == "IN_SPAM"
    del box.mailbox["m1"]
    box.junk.clear()
    msgs = sync.recheck("gmail", box, msgs, {"deals@news.example.com"})
    assert [m.id for m in msgs] == ["m0"]


def test_stored_file_is_private_and_has_no_bodies(tmp_path):
    box = FakeGmail([msg(0, 5)])
    sync.sync("gmail", GMAIL, box, 30, now=NOW)
    p = sync._path("gmail")
    assert oct(p.stat().st_mode & 0o777) == "0o600"
    data = p.read_text().lower()
    assert "subject" not in data and "body" not in data
