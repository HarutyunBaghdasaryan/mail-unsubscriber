# Security policy

## Reporting a vulnerability

Please report security issues **privately** through GitHub:
**Security > Report a vulnerability** on this repository. Do not open a public issue.

You can expect an acknowledgement within 7 days.

## Design commitments

- Email headers only; message bodies and attachments are never fetched.
- Read-only mailbox permissions (Gmail `gmail.metadata`, Microsoft Graph `Mail.ReadBasic`).
- The only network write is an RFC 8058 one-click unsubscribe request that you approved,
  sent through a guard (https only, public addresses only, no redirects).
- No telemetry. Tokens stay in the operating system keychain.
- No real email data in this repository; tests use synthetic headers only.

## Built-in sign-in apps

- **Microsoft:** a public client: only an app ID, no secret.
- **Google:** a "Desktop app" client. Its client secret is **not stored in this repository**; it is
  provided at run time (`MAIL_UNSUB_GOOGLE_CLIENT_SECRET`). Even so, it grants no access by itself:
  every user still signs in and consents, with PKCE.
- **Use your own** instead: set `MAIL_UNSUB_GOOGLE_CLIENT_ID` / `MAIL_UNSUB_GOOGLE_CLIENT_SECRET` and/or
  `MAIL_UNSUB_MS_CLIENT_ID`.
- **If the shared Google client is abused:** the maintainer creates a new secret in Google Cloud,
  ships a new release, then deletes the old secret.
