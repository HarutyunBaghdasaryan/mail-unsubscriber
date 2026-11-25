from mail_unsubscriber import __version__
from mail_unsubscriber.cli import main


def test_version_string():
    assert __version__ == "0.0.1"


def test_no_command_prints_help(capsys):
    assert main([]) == 0
    assert "usage" in capsys.readouterr().out


def test_unsubscribe_without_terminal_refuses(capsys, monkeypatch):
    import sys

    monkeypatch.setattr(sys, "platform", "darwin")
    assert main(["unsubscribe"]) == 6  # no TTY under pytest: a human must run it
    assert "HUMAN_REQUIRED" in capsys.readouterr().err


def test_mcp_not_implemented(capsys):
    assert main(["mcp"]) == 2
