"""Built-in public OAuth clients: users just sign in, no app registration.

Google (early access): each user brings their own Google "Desktop app" client, set via
MAIL_UNSUB_GOOGLE_CLIENT_ID and MAIL_UNSUB_GOOGLE_CLIENT_SECRET (see docs/gmail-setup.md).
Microsoft: public client, no secret.

To use your own Microsoft registration instead, set MAIL_UNSUB_MS_CLIENT_ID.
"""

import os

GOOGLE_CLIENT_ID = os.environ.get("MAIL_UNSUB_GOOGLE_CLIENT_ID", "")
GOOGLE_SCOPES = ["https://www.googleapis.com/auth/gmail.metadata"]

MS_CLIENT_ID = os.environ.get("MAIL_UNSUB_MS_CLIENT_ID", "990e1510-bf68-45ed-a14a-7ef2b098f3d1")
MS_AUTHORITY = "https://login.microsoftonline.com/common"
MS_SCOPES = ["Mail.ReadBasic"]


GMAIL_SETUP_HELP = (
    "Gmail needs your own Google app (one-time, about 5 minutes): set MAIL_UNSUB_GOOGLE_CLIENT_ID and "
    "MAIL_UNSUB_GOOGLE_CLIENT_SECRET. Steps: "
    "https://github.com/HarutyunBaghdasaryan/mail-unsubscriber/blob/main/docs/gmail-setup.md")


def google_client_id() -> str:
    cid = os.environ.get("MAIL_UNSUB_GOOGLE_CLIENT_ID", "")
    if not cid or not os.environ.get("MAIL_UNSUB_GOOGLE_CLIENT_SECRET"):
        raise SystemExit(GMAIL_SETUP_HELP)
    return cid


def google_client_secret() -> str:
    google_client_id()  # both values must be set together
    return os.environ["MAIL_UNSUB_GOOGLE_CLIENT_SECRET"]
