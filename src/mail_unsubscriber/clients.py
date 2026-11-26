"""Built-in public OAuth clients: users just sign in, no app registration.

Google: "Desktop app" client. The client secret is not shipped in the code; provide it via
MAIL_UNSUB_GOOGLE_CLIENT_SECRET (Google treats desktop secrets as non-confidential, see
https://developers.google.com/identity/protocols/oauth2/native-app).
Microsoft: public client, no secret.

To use your own registrations instead (e.g. beyond Google's 100-user limit for unverified apps), set
MAIL_UNSUB_GOOGLE_CLIENT_ID / MAIL_UNSUB_GOOGLE_CLIENT_SECRET and/or MAIL_UNSUB_MS_CLIENT_ID.
"""

import os

GOOGLE_CLIENT_ID = os.environ.get(
    "MAIL_UNSUB_GOOGLE_CLIENT_ID", "261481826101-gfu4mvil9ktqra60vsjh2kpacjd6i4iu.apps.googleusercontent.com")
GOOGLE_SCOPES = ["https://www.googleapis.com/auth/gmail.metadata"]

MS_CLIENT_ID = os.environ.get("MAIL_UNSUB_MS_CLIENT_ID", "990e1510-bf68-45ed-a14a-7ef2b098f3d1")
MS_AUTHORITY = "https://login.microsoftonline.com/common"
MS_SCOPES = ["Mail.ReadBasic"]


def google_client_secret() -> str:
    secret = os.environ.get("MAIL_UNSUB_GOOGLE_CLIENT_SECRET", "")
    if not secret:
        raise SystemExit(
            "Gmail sign-in needs a Google client secret. Set MAIL_UNSUB_GOOGLE_CLIENT_SECRET "
            "(and MAIL_UNSUB_GOOGLE_CLIENT_ID for your own Google app). See README FAQ.")
    return secret
