# Privacy policy: mail-unsubscriber

_Last updated: 26 November 2026_

mail-unsubscriber is an open-source command-line tool that runs **entirely on your own computer**.
There is no server, no account with us, and no telemetry.

## What the app accesses

- **Gmail:** the `gmail.metadata` permission: message headers and labels, **never message bodies or
  attachments** (Google enforces this).
- **Outlook / Microsoft 365:** the `Mail.ReadBasic` permission; the app requests headers only.
- Access is read-only: the app cannot send, change, move or delete email.

## What the app stores, and where

On your computer only, in a folder readable only by you:
- per email: sender address, date, the provider's authentication result, whether the sender's
  signature covers the unsubscribe headers, the unsubscribe headers, spam/junk flag, Gmail tab;
- the results of each scan and a log of unsubscribes you confirmed.

Sign-in tokens are stored in your operating system's keychain. Run `unsub logout --purge` to delete
tokens and data.

## What leaves your computer

- Requests to Google or Microsoft to read headers (with your sign-in).
- For senders **you confirm**, one standard unsubscribe request (RFC 8058 one-click) to the address
  the sender put in its signed unsubscribe header. Nothing else.

We (the authors) receive **no data** of any kind. If you connect an AI assistant through the optional
MCP server, the assistant you choose receives sender addresses, counts and check results from your
last scan (never subjects, bodies, links or tokens); you can turn this off per account
(`unsub agent off --account NAME`).

## Google API data

mail-unsubscriber's use of information received from Google APIs adheres to the
[Google API Services User Data Policy](https://developers.google.com/terms/api-services-user-data-policy),
including the Limited Use requirements. Data is used only to show you which senders you can safely
unsubscribe from; it is not transferred, sold, or used for advertising.

## Contact

Questions or concerns: open an issue at
https://github.com/HarutyunBaghdasaryan/mail-unsubscriber/issues
(for security issues, use private vulnerability reporting, see [SECURITY.md](SECURITY.md)).
