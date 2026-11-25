"""OS-level proof that a person confirmed: macOS Touch ID / account password (LocalAuthentication).

An agent can fake terminal input, but it cannot pass this dialog. Other systems: not supported in v1.
"""

from __future__ import annotations

import sys
import threading

LA_POLICY_DEVICE_OWNER_AUTH = 2  # biometrics or device password


def reason_text(senders: list[str]) -> str:
    domains = []
    for s in senders:
        d = s.rsplit("@", 1)[-1]
        if d not in domains:
            domains.append(d)
    shown = ", ".join(domains[:5]) + (f" and {len(domains) - 5} more" if len(domains) > 5 else "")
    return f"unsubscribe from {len(senders)} sender(s): {shown}"


def confirm(senders: list[str]) -> bool:
    if sys.platform != "darwin":
        return False
    try:
        from LocalAuthentication import LAContext
    except ImportError:
        return False
    ctx = LAContext.alloc().init()
    done, result = threading.Event(), {"ok": False}

    def reply(success, error):
        result["ok"] = bool(success)
        done.set()

    ctx.evaluatePolicy_localizedReason_reply_(LA_POLICY_DEVICE_OWNER_AUTH, reason_text(senders), reply)
    done.wait(120)
    return result["ok"]
