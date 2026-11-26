# mail-unsubscriber

[![tests](https://github.com/HarutyunBaghdasaryan/mail-unsubscriber/actions/workflows/ci.yml/badge.svg)](https://github.com/HarutyunBaghdasaryan/mail-unsubscriber/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-MIT-blue)
![python](https://img.shields.io/badge/python-3.12%2B-blue)
![platform](https://img.shields.io/badge/platform-macOS-lightgrey)

### Less noise. More focus.

**Unsubscribe safely** from the marketing email you never read, in Gmail and Outlook,
without ever touching spam, phishing or the mail that matters.

> **Real result:** the author's first run unsubscribed from **66 marketing lists**, about
> **950 promotional emails a month**, in one confirmed step. Bank, health and family senders untouched.

> Status: **early release** (v0.1, macOS). Outlook works out of the box; Gmail needs a Google client during early access (see FAQ). Feedback welcome.

```text
$ unsub scan --account gmail
read 5484 messages
Account gmail (gmail), last 30 days: 5484 messages, 2151 senders
  DANGER               0 senders
  CAN_UNSUBSCRIBE    242 senders
  UNSURE            1869 senders
  KEEP                40 senders

$ unsub unsubscribe --account gmail --category promotions --exclude-domain bank.example
58 sender(s) can be unsubscribed (checked: authenticated, signed one-click):
    1. editorial@news.example.com          58 emails  promotions  via news.example.com
    2. deals@shop.example                  56 emails  promotions  via mail.esp.example.net
    ...
Type 'yes' to unsubscribe from all 58 sender(s) listed above: yes
  [Touch ID: "unsubscribe from 58 sender(s): news.example.com, shop.example and 50 more"]
  ✓ editorial@news.example.com (200)
  ...
Done: 55 unsubscribed, 3 failed.
```

## Vision

Leaders spend a surprising part of their day deciding what *not* to read. Every promotion, digest
and "last chance" email takes a few seconds of attention, and a busy inbox gets hundreds of them a week.

This tool gives that attention back. It finds the senders that are safe to drop, shows you exactly
who they are, and unsubscribes in one confirmed step, so your inbox holds people and decisions,
not noise. It is built to be **cautious first**: when it is not sure, it does nothing.

## Why it's secure: headers only, never the body

Many "unsubscribe" tools ask for full access to your mailbox and follow links inside emails. This one doesn't.

| What we never do | Why it matters |
|---|---|
| Read message bodies or attachments | Your conversations, documents and attachments never reach the app. For Gmail, Google itself enforces this: the app only holds the `gmail.metadata` permission ("labels and headers, but not the email body"). For Outlook, the app requests headers only |
| Click links inside emails | Unsubscribe links in the body are a classic phishing trick. We only use the standard unsubscribe **header**, and only when the sender signed it |
| Unsubscribe from spam or phishing | Doing so tells the sender your address is real. Those senders are only flagged |
| Write to your mailbox | Read-only access: nothing is moved, labelled or deleted |
| Send your data anywhere | Everything runs on your Mac. No servers, no telemetry |

**What the headers tell us is enough:** who really sent the email (the sender check your provider
already performed), whether the sender signed it, and whether it offers a standard one-click
unsubscribe. That is all the app needs, and nothing more.

## How it works

1. **Reads headers only** (see above).
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

## Why not just the "Unsubscribe" button in Gmail or Outlook?

Use it for one sender at a time. This tool adds:

- **Bulk, with filters:** e.g. every Gmail Promotions sender except your bank, in one step.
- **Gmail and Outlook** in one place.
- **Cautious by design:** it proves the sender first, skips spam and phishing, explains every decision
  (`unsub explain SENDER`) and lets you protect whole domains.
- **AI-assistant ready:** a read-only MCP server so Claude or other agents can tell you what's noisy.

## Install (macOS)

```sh
uv tool install git+https://github.com/HarutyunBaghdasaryan/mail-unsubscriber
```

Prefer pinned, hash-checked dependencies? Clone the repo and run
`uv venv && uv pip install -r requirements.lock && uv pip install --no-deps -e .`.

Then:

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
- **Re-checked right before acting.** `unsubscribe` fetches any new emails and re-checks the chosen
  senders on your provider (moved to Spam? deleted?) before asking you. Later scans read only new mail.
- Every action is logged locally, so nothing is repeated and you can see what was done.

Privacy: [PRIVACY.md](PRIVACY.md) · Report a vulnerability: [SECURITY.md](SECURITY.md)

## Commands

| Command | What it does |
|---|---|
| `login` / `logout [--purge]` | Sign in / out (purge deletes local scan data) |
| `scan [--full]` | Read headers and group senders (only new mail after the first scan). Never acts |
| `show` | List senders from the last scan, with filters (`--json` for scripts and AI agents) |
| `explain SENDER` | Why a sender got its group (technical checks only) |
| `unsubscribe` | Unsubscribe from safe senders after your confirmation |
| `keep SENDER` / `keep --domain bank.example` | Never offer this sender (or whole domain) again |
| `agent on\|off` | Allow or block AI agent access for an account |
| `mcp` | Read-only MCP server for AI agents |

## Use with AI agents (Claude Desktop, Claude Code, any MCP client)

Ask your assistant *"Which promotions can I drop?"* or *"Why is this sender unsure?"*.
The built-in MCP server is **read-only**: it can list accounts, summarize, show senders and explain
decisions from your last scan. It **cannot** scan, sign in or unsubscribe; it gives you the command
to run yourself (you confirm with `yes` and Touch ID). Agents never see subjects, bodies, links or
tokens, and sender text is validated so emails cannot smuggle instructions to the AI.

```sh
uv tool install "mail-unsubscriber[mcp] @ git+https://github.com/HarutyunBaghdasaryan/mail-unsubscriber"   # with the MCP extra
claude mcp add mail-unsubscriber -- unsub mcp    # Claude Code
```

Claude Desktop (`claude_desktop_config.json`):

```json
{ "mcpServers": { "mail-unsubscriber": { "command": "/path/to/mail-unsubscriber/.venv/bin/unsub", "args": ["mcp"] } } }
```

Personal mailboxes are visible to agents by default; work mailboxes are not.
Change it per account: `unsub agent on|off --account NAME`.

## FAQ

- **Which systems?** Unsubscribing needs macOS (Touch ID / password confirmation). Scan and show may
  work elsewhere but are untested.
- **Gmail sign-in during early access:** Gmail needs a Google client: set `MAIL_UNSUB_GOOGLE_CLIENT_ID`
  and `MAIL_UNSUB_GOOGLE_CLIENT_SECRET` (your own Google Cloud "Desktop app" client with the
  `gmail.metadata` scope). Outlook works out of the box.
- **Work Microsoft account asks for admin approval?** Some companies require an admin to approve new
  apps once. The app asks only for read access to headers (`Mail.ReadBasic`).
- **A sender is in the wrong group?** Run `unsub explain SENDER --json` and open an issue with the output
  (it contains no email content).

## Contributing

Issues and pull requests are welcome. Run `pytest` before sending changes; tests use made-up headers only,
never real email.

## License

[MIT](LICENSE)
