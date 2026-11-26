from mail_unsubscriber import __version__
from mail_unsubscriber.cli import main


def test_version_string():
    assert __version__ == "0.1.0"


def test_no_command_prints_help(capsys):
    assert main([]) == 0
    assert "usage" in capsys.readouterr().out


def test_unsubscribe_without_terminal_refuses(capsys, monkeypatch):
    import sys

    monkeypatch.setattr(sys, "platform", "darwin")
    assert main(["unsubscribe"]) == 6  # no TTY under pytest: a human must run it
    assert "HUMAN_REQUIRED" in capsys.readouterr().err


def test_agent_switch(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MAIL_UNSUB_HOME", str(tmp_path))
    from mail_unsubscriber import store

    store.save_account("work", "outlook", "me@company.example")
    assert main(["agent", "--account", "work"]) == 0 and "off" in capsys.readouterr().out
    assert main(["agent", "on", "--account", "work"]) == 0 and ": on" in capsys.readouterr().out


def test_several_accounts_need_account_flag(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MAIL_UNSUB_HOME", str(tmp_path))
    from mail_unsubscriber import store

    store.save_account("gmail", "gmail", None)
    store.save_account("outlook", "outlook", None)
    assert main(["show"]) == 2
    assert "add --account NAME" in capsys.readouterr().err
    assert main(["show", "--account", "gmail"]) == 2
    assert 'No saved scan for "gmail"' in capsys.readouterr().err


def test_gmail_needs_both_client_values(monkeypatch):
    import pytest

    from mail_unsubscriber import clients

    monkeypatch.delenv("MAIL_UNSUB_GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.setenv("MAIL_UNSUB_GOOGLE_CLIENT_SECRET", "x")
    with pytest.raises(SystemExit, match="gmail-setup.md"):
        clients.google_client_secret()
    monkeypatch.setenv("MAIL_UNSUB_GOOGLE_CLIENT_ID", "id")
    assert clients.google_client_id() == "id" and clients.google_client_secret() == "x"
