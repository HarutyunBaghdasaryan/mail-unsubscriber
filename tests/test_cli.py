from mail_unsubscriber import __version__
from mail_unsubscriber.cli import main


def test_version_string():
    assert __version__ == "0.0.1"


def test_no_command_prints_help(capsys):
    assert main([]) == 0
    assert "usage" in capsys.readouterr().out


def test_unimplemented_command_does_nothing(capsys):
    assert main(["unsubscribe"]) == 2
    assert "not implemented" in capsys.readouterr().err
