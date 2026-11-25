# mail-unsubscriber

**Less noise, safely.** Unsubscribe from the marketing email you never read, in Gmail and Outlook,
without ever touching spam, phishing or the mail that matters.

> Status: **early release** (macOS). Gmail sign-in for public builds arrives with the first tagged release.
> Feedback welcome.

## Vision

Leaders spend a surprising part of their day deciding what *not* to read. Every promotion, digest
and "last chance" email takes a few seconds of attention, and a busy inbox gets hundreds of them a week.

This tool gives that attention back. It finds the senders that are safe to drop, shows you exactly
who they are, and unsubscribes in one confirmed step, so your inbox holds people and decisions,
not noise. It is built to be **cautious first**: when it is not sure, it does nothing.

## How it works

1. **Reads email headers only.** Never message bodies or attachments. Gmail enforces this for us;
   for Outlook the app only asks for headers.
2. **Sorts every sender into 4 groups:**

   | Group | Meaning | What the app does |
   |---|---|---|
   | **CAN UNSUBSCRIBE** | Proven sender with a signed one-click unsubscribe | Offers it to you |
   | **UNSURE** | Anything it can't prove (incl. everything in Spam) | Nothing. Shows why |
   | **DANGER** | Phishing / impersonation signs | Nothing. "Do not open" |
   | **KEEP** | Senders you protect | Nothing, ever |

3. **Unsubscribes only when it is sure _and_ you confirm.** "Sure" means the sender passed the
   sender check (DMARC) and its one-click unsubscribe (RFC 8058) is signed by its own domain (DKIM).
   You see the full list, type `yes`, and confirm with **Touch ID**. Nothing else is ever sent.

## Quick start (macOS)

```sh
git clone https://github.com/HarutyunBaghdasaryan/mail-unsubscriber.git
cd mail-unsubscriber
uv venv && uv pip install -r requirements.lock && uv pip install --no-deps -e .
source .venv/bin/activate
```

```sh
unsub login --provider gmail                  # opens Google's sign-in page
unsub login --provider outlook                # Microsoft 365 or Outlook.com
unsub scan --account gmail --days 30          # read headers, group senders (changes nothing)
unsub show --account gmail --category promotions
unsub explain someone@news.example.com --account gmail
unsub unsubscribe --account gmail --category promotions
```

No app registration needed: you just sign in with your own account.

## Choose what to unsubscribe from

Filters work with `show` (preview) and `unsubscribe`:

| You want | Add |
|---|---|
| Promotions only (Gmail tab) | `--category promotions` |
| Several tabs | `--category promotions,updates` |
| One company or sender | `--domain example.com` / `--sender news@example.com` |
| Everything except some | `--exclude-domain bank.example,airline.example` |
| Only frequent senders | `--min-emails 3` |

Never want to see a sender again? `unsub keep news@example.com`.
Prefer to decide one by one? `unsub unsubscribe --one-by-one`.

## Safety and privacy

- **Local only.** No servers, no telemetry. Sign-in tokens stay in the macOS Keychain.
- **Read-only mailbox access.** The app cannot change, move or delete mail.
- **Never follows links in emails.** The only request it sends is the standard one-click unsubscribe,
  over https, to a public server, without redirects or cookies.
- **Spam and phishing are never unsubscribed** (that would confirm your address to the sender).
- **Fresh data only.** Unsubscribing needs a scan from the last hour.
- Every action is logged locally, so nothing is repeated and you can see what was done.

Details: [docs/requirements.md](docs/requirements.md) · Report a vulnerability: [SECURITY.md](SECURITY.md)

## Commands

| Command | What it does |
|---|---|
| `login` / `logout [--purge]` | Sign in / out (purge deletes local scan data) |
| `scan` | Read headers and group senders. Never acts |
| `show` | List senders from the last scan, with filters (`--json` for scripts and AI agents) |
| `explain SENDER` | Why a sender got its group (technical checks only) |
| `unsubscribe` | Unsubscribe from safe senders after your confirmation |
| `keep SENDER` | Never offer this sender again |

## License

[MIT](LICENSE)
