import json

from conftest import GMAIL_AR

from mail_unsubscriber import cli, gate
from mail_unsubscriber.classify import classify


def test_trace_shows_missing_dmarc(mk):
    no_dmarc = GMAIL_AR.split(";\r\n       dmarc=")[0]
    rows = gate.trace([mk(0, ar=[no_dmarc]), mk(1)])
    assert rows[0]["auth_header"] == "ok" and rows[0]["dmarc"] is None
    assert rows[1]["dmarc"] == "pass" and rows[1]["dmarc_about"] == "news.example.com"
    assert rows[1]["signatures"][0] == {"d": "news.example.com", "aligned_pass": True, "covers_unsubscribe": True}
    assert "list.esp.example.net" not in json.dumps(rows)  # no unsubscribe URLs in the trace


def test_explain_command_reads_saved_scan(mk, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MAIL_UNSUB_HOME", str(tmp_path))
    from mail_unsubscriber import store

    store.save_account("gmail", "gmail", None)
    msgs = [mk(0), mk(1)]
    d = classify(msgs)[0]
    store.save_scan("gmail", {"scanned_at": "2026-11-24T00:00", "decisions": [d.__dict__],
                              "traces": {d.sender: gate.trace(msgs)}})
    assert cli.main(["explain", "deals@news.example.com"]) == 0
    out = capsys.readouterr().out
    assert "CAN_UNSUBSCRIBE" in out and "All checks passed" in out and "news.example.com" in out
    assert cli.main(["explain", "nobody@example.com"]) == 2
