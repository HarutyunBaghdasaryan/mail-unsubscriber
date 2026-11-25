"""Sign-in with the provider's own page (system browser, PKCE, loopback). Tokens go to the keychain."""

from __future__ import annotations

import json

from . import clients, store


class SignInNeeded(Exception):
    pass


# ---------- Google ----------

def google_login(account: str):
    from google_auth_oauthlib.flow import InstalledAppFlow

    cfg = {
        "installed": {
            "client_id": clients.GOOGLE_CLIENT_ID,
            "client_secret": clients.google_client_secret(),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["http://localhost"],
        }
    }
    flow = InstalledAppFlow.from_client_config(cfg, clients.GOOGLE_SCOPES, autogenerate_code_verifier=True)
    creds = flow.run_local_server(
        host="localhost", port=0, open_browser=True,
        authorization_prompt_message="Opening your browser to sign in with Google...",
    )
    store.set_secret(account, creds.to_json())
    return creds


def google_token(account: str) -> str:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials

    raw = store.get_secret(account)
    if not raw:
        raise SignInNeeded(account)
    creds = Credentials.from_authorized_user_info(json.loads(raw), clients.GOOGLE_SCOPES)
    if not creds.valid:
        try:
            creds.refresh(Request())
        except Exception as e:  # expired/revoked refresh token (Testing mode: 7 days)
            raise SignInNeeded(account) from e
        store.set_secret(account, creds.to_json())
    return creds.token


# ---------- Microsoft ----------

def _ms_app(account: str):
    import msal

    cache = msal.SerializableTokenCache()
    raw = store.get_secret(account)
    if raw:
        cache.deserialize(raw)
    app = msal.PublicClientApplication(clients.MS_CLIENT_ID, authority=clients.MS_AUTHORITY, token_cache=cache)
    return app, cache


def ms_login(account: str, email: str | None = None) -> dict:
    app, cache = _ms_app(account)
    result = app.acquire_token_interactive(clients.MS_SCOPES, login_hint=email, prompt="select_account")
    if "access_token" not in result:
        raise SignInNeeded(result.get("error_description", "sign-in failed"))
    store.set_secret(account, cache.serialize())
    return result


def ms_token(account: str) -> str:
    app, cache = _ms_app(account)
    accts = app.get_accounts()
    result = app.acquire_token_silent(clients.MS_SCOPES, account=accts[0]) if accts else None
    if not result or "access_token" not in result:
        raise SignInNeeded(account)
    if cache.has_state_changed:
        store.set_secret(account, cache.serialize())
    return result["access_token"]
