"""Local storage: accounts list and scan results (0600 files) + tokens in the OS keychain."""

from __future__ import annotations

import json
import os
from pathlib import Path

SERVICE = "mail-unsubscriber"


def app_dir() -> Path:
    default = Path.home() / "Library" / "Application Support" / SERVICE
    base = Path(os.environ.get("MAIL_UNSUB_HOME") or default)
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    return base


def _write_private(path: Path, data: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(data)
    os.chmod(path, 0o600)


def load_accounts() -> dict:
    p = app_dir() / "accounts.json"
    return json.loads(p.read_text()) if p.exists() else {}


def save_account(name: str, provider: str, email: str | None) -> None:
    accts = load_accounts()
    accts[name] = {"provider": provider, "email": email}
    _write_private(app_dir() / "accounts.json", json.dumps(accts, indent=1))


def set_account_field(name: str, key: str, value) -> None:
    accts = load_accounts()
    accts[name][key] = value
    _write_private(app_dir() / "accounts.json", json.dumps(accts, indent=1))


def remove_account(name: str) -> None:
    accts = load_accounts()
    accts.pop(name, None)
    _write_private(app_dir() / "accounts.json", json.dumps(accts, indent=1))


def _kr():
    import keyring  # imported lazily so tests and pure code never touch the OS keychain

    return keyring


def get_secret(name: str) -> str | None:
    return _kr().get_password(SERVICE, name)


def set_secret(name: str, value: str) -> None:
    _kr().set_password(SERVICE, name, value)


def delete_secret(name: str) -> None:
    kr = _kr()
    try:
        kr.delete_password(SERVICE, name)
    except kr.errors.PasswordDeleteError:
        pass


def save_scan(account: str, payload: dict) -> Path:
    d = app_dir() / "scans"
    d.mkdir(mode=0o700, exist_ok=True)
    p = d / f"{account}.json"
    _write_private(p, json.dumps(payload, indent=1, default=str))
    return p
