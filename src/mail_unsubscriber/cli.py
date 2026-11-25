"""Command-line entry point.

login / scan / explain / logout work now. show / unsubscribe / mcp are placeholders (not implemented: nothing acts).
Exit codes: 0 ok, 1 error, 2 usage/not implemented, 3 sign-in needed.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

from . import __version__

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_SIGNIN = 0, 1, 2, 3


def _err(msg: str, nxt: str | None = None) -> None:
    print(msg + (f"\nNext: {nxt}" if nxt else ""), file=sys.stderr)


def _pick_account(accounts: dict, name: str | None) -> str | None:
    if name:
        return name if name in accounts else None
    return next(iter(accounts)) if len(accounts) == 1 else None


def cmd_login(args) -> int:
    from . import auth, store

    name = args.account or args.provider
    if args.provider == "gmail":
        auth.google_login(name)
        email = None
        try:
            from .providers.gmail import Gmail

            email = Gmail(lambda: auth.google_token(name)).own_address()
        except Exception:
            pass
    else:
        result = auth.ms_login(name, args.email)
        email = (result.get("id_token_claims") or {}).get("preferred_username")
    store.save_account(name, args.provider, email)
    print(f'Signed in. Account "{name}" saved ({args.provider}, read-only, headers only).')
    return EXIT_OK


def summarize(decisions, messages_read: int) -> dict:
    return {
        "messages_read": messages_read,
        "senders": len(decisions),
        "groups": dict(Counter(d.group.value for d in decisions)),
        "reasons": dict(Counter(d.code.value for d in decisions)),
        "gmail_categories": dict(Counter(d.gmail_category for d in decisions if d.gmail_category)),
    }


def cmd_scan(args) -> int:
    from . import auth, store
    from .classify import classify
    from .providers import ProviderError

    accounts = store.load_accounts()
    name = _pick_account(accounts, args.account)
    if not name:
        _err("No such account (or several exist).", "unsub login --provider gmail|outlook [--account NAME]")
        return EXIT_SIGNIN
    acct = accounts[name]
    since = datetime.now(timezone.utc) - timedelta(days=args.days)

    def progress(n: int) -> None:
        print(f"\rread {n} messages", end="", file=sys.stderr, flush=True)

    try:
        if acct["provider"] == "gmail":
            from .providers.gmail import Gmail

            msgs = Gmail(lambda: auth.google_token(name)).fetch(since, acct.get("email"), progress)
        else:
            from .providers.outlook import Outlook

            msgs = Outlook(lambda: auth.ms_token(name)).fetch(since, acct.get("email"), progress)
    except auth.SignInNeeded:
        _err("\nSign-in expired.", f"unsub login --provider {acct['provider']} --account {name}")
        return EXIT_SIGNIN
    except ProviderError as e:  # provider refusals: readable message, no traceback, nothing saved
        _err(f"\n{e} Nothing was saved.", "try again in a few minutes")
        return EXIT_ERROR
    print(file=sys.stderr)
    decisions = classify(msgs)
    summary = summarize(decisions, len(msgs))
    from .classify import group_by_sender
    from .gate import trace

    traces = {sender: trace(ms) for sender, ms in group_by_sender(msgs).items()}
    path = store.save_scan(name, {
        "account": name, "provider": acct["provider"], "scanned_at": datetime.now(timezone.utc).isoformat(),
        "days": args.days, "summary": summary,
        "decisions": [{k: v for k, v in d.__dict__.items() if k != "unsub_url"} | {"unsub_url": d.unsub_url}
                      for d in decisions],
        "traces": traces,
    })
    if args.json:
        print(json.dumps({"schema": 1, "account": name, **summary}, indent=1))
    else:
        print(f"Account {name} ({acct['provider']}), last {args.days} days: {summary['messages_read']} messages, "
              f"{summary['senders']} senders")
        for g in ("DANGER", "CAN_UNSUBSCRIBE", "UNSURE", "KEEP"):
            print(f"  {g:<16}{summary['groups'].get(g, 0):>6} senders")
        print("Reasons: " + ", ".join(f"{k} {v}" for k, v in sorted(summary["reasons"].items(), key=lambda x: -x[1])))
        print(f"Saved (private): {path}")
    return EXIT_OK


def cmd_explain(args) -> int:
    from . import store
    from .gate import EXPLAIN
    from .model import Code

    accounts = store.load_accounts()
    name = _pick_account(accounts, args.account)
    path = store.app_dir() / "scans" / f"{name}.json" if name else None
    if not path or not path.exists():
        _err("No saved scan for this account.", "unsub scan [--account NAME]")
        return EXIT_USAGE
    data = json.loads(path.read_text())
    sender = args.sender.strip().lower()
    dec = next((d for d in data["decisions"] if d["sender"] == sender), None)
    if dec is None:
        _err(f"{sender} is not in the last scan ({data['scanned_at'][:16]}).")
        return EXIT_USAGE
    rows = (data.get("traces") or {}).get(sender)
    if args.json:
        print(json.dumps({"schema": 1, "sender": sender, "group": dec["group"], "code": dec["code"],
                          "messages": rows}, indent=1))
        return EXIT_OK
    code = Code(dec["code"])
    print(f"{sender}: {dec['group']} ({dec['code']}), {dec['count']} emails")
    print("Why: " + EXPLAIN.get(code, {"PROVIDER_PHISH": "Provider marked an email as phishing/impersonation.",
                                         "PUNYCODE_FROM": "The From domain uses look-alike (punycode) characters.",
                                         "PROTECTED": "Domain is on your protected list.",
                                         "USER_KEPT": "You chose to keep this sender."}.get(code.value, "")))
    if not rows:
        print("(No per-email details in this scan. Run the scan again to get them.)")
        return EXIT_OK
    print(f"{'date':<17} {'auth':<9} {'dmarc':<6} {'about':<28} {'own sig covers unsub':<21} {'1-click':<7} junk")
    for r in rows:
        own = [s for s in r["signatures"] if s["aligned_pass"]]
        sig = "none" if not own else ("yes" if all(s["covers_unsubscribe"] for s in own) else "NO")
        print(f"{r['date'][:16]:<17} {r['auth_header']:<9} {str(r['dmarc'] or '-'):<6} {str(r['dmarc_about'] or '-')[:28]:<28} "
              f"{sig:<21} {'yes' if r['one_click'] and r['https_unsubscribe'] else 'no':<7} {'yes' if r['in_junk'] else ''}")
    return EXIT_OK


def cmd_logout(args) -> int:
    from . import store

    accounts = store.load_accounts()
    name = _pick_account(accounts, args.account)
    if not name:
        _err("No such account.")
        return EXIT_USAGE
    store.delete_secret(name)
    store.remove_account(name)
    if args.purge:
        (store.app_dir() / "scans" / f"{name}.json").unlink(missing_ok=True)
    print(f'Signed out of "{name}"' + (" and deleted its scan." if args.purge else "."))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="unsub", description="Safely unsubscribe from marketing email.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")
    p = sub.add_parser("login", help="sign in (opens your browser)")
    p.add_argument("--provider", choices=["gmail", "outlook"], required=True)
    p.add_argument("--account")
    p.add_argument("--email", help="address hint for the sign-in page")
    p = sub.add_parser("scan", help="read headers and group senders (never acts)")
    p.add_argument("--account")
    p.add_argument("--days", type=int, default=90)
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("logout", help="sign out (and with --purge delete the saved scan)")
    p.add_argument("--account")
    p.add_argument("--purge", action="store_true")
    p = sub.add_parser("explain", help="why a sender got its group (technical checks only)")
    p.add_argument("sender")
    p.add_argument("--account")
    p.add_argument("--json", action="store_true")
    for c in ("show", "unsubscribe", "mcp"):
        sub.add_parser(c, help="not implemented yet")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return EXIT_OK
    handlers = {"login": cmd_login, "scan": cmd_scan, "explain": cmd_explain, "logout": cmd_logout}
    if args.command not in handlers:
        print(f"unsub {args.command}: not implemented yet", file=sys.stderr)
        return EXIT_USAGE
    try:
        return handlers[args.command](args)
    except KeyboardInterrupt:
        _err("\nStopped. Nothing was saved.")
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
