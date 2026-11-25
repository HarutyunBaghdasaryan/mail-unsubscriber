# mail-unsubscriber

Safely unsubscribe from marketing email in **Gmail** and **Outlook**, without touching spam or phishing.

> **Status: pre-alpha, design phase. Not usable yet.**

## How it works (planned)

- Reads **email headers only**: never message bodies or attachments.
- Read-only mailbox access: it cannot change, move or delete mail.
- Sorts senders into 4 groups: **DANGER**, **KEEP**, **CAN UNSUBSCRIBE**, **UNSURE**.
- Unsubscribes only when it is **sure** (the sender is authenticated and offers a signed RFC 8058
  one-click unsubscribe) **and** you confirm each sender, plus a Touch ID / password check on macOS.
- Spam, phishing and anything unclear are never unsubscribed by the tool.
- Runs locally. No servers, no telemetry.
- Works with local AI agents (CLI `--json`, optional MCP server), which can read results but never act.

## Security

See [SECURITY.md](SECURITY.md) and [docs/requirements.md](docs/requirements.md).

## License

[MIT](LICENSE)
