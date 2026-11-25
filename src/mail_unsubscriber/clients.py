"""Built-in public OAuth clients (login only; users never register an app).

Google: desktop client. Google documents installed-app secrets as non-confidential
(https://developers.google.com/identity/protocols/oauth2/native-app). Until the public release the
secret is read from the environment (MAIL_UNSUB_GOOGLE_CLIENT_SECRET) instead of being embedded.
Microsoft: public client, no secret.
"""

import os

GOOGLE_CLIENT_ID = "261481826101-gfu4mvil9ktqra60vsjh2kpacjd6i4iu.apps.googleusercontent.com"
GOOGLE_SCOPES = ["https://www.googleapis.com/auth/gmail.metadata"]

MS_CLIENT_ID = "990e1510-bf68-45ed-a14a-7ef2b098f3d1"
MS_AUTHORITY = "https://login.microsoftonline.com/common"
MS_SCOPES = ["Mail.ReadBasic"]


def google_client_secret() -> str:
    secret = os.environ.get("MAIL_UNSUB_GOOGLE_CLIENT_SECRET", "")
    if not secret:
        raise SystemExit("Google sign-in needs MAIL_UNSUB_GOOGLE_CLIENT_SECRET until the public release.")
    return secret
