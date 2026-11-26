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
- **Google (early access):** each user creates their own Google "Desktop app" client
  ([docs/gmail-setup.md](docs/gmail-setup.md)) and sets `MAIL_UNSUB_GOOGLE_CLIENT_ID` /
  `MAIL_UNSUB_GOOGLE_CLIENT_SECRET`. No Google client secret is stored in this repository.
- **Use your own Microsoft app** instead: set `MAIL_UNSUB_MS_CLIENT_ID`.
