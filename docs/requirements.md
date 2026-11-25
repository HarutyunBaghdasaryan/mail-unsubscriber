# Mail Unsubscriber: Requirements (v0.8)

> Public-repo safe: no real addresses, domains, tenants or messages. MUST / MUST NOT per RFC 2119.

## 1. What it does

A command-line tool that reads **email headers only** from Gmail and Outlook, sorts senders into 4 groups, and
unsubscribes via the standard one-click method (RFC 8058) **only** when the app is sure and the user confirmed.

**R0 (overriding rule).** A sender is unsubscribed only if **both**:
1. **The app is sure:** it passes the gate (§3.2) on a scan **less than 1 hour old**; and
2. **The user confirmed it:** answered `y` for **that sender** in **that run**, then passed the macOS Touch ID /
   password check that lists the senders.

No `--force`, no "yes to all", no config or agent path that makes an UNSURE/DANGER sender eligible, no unattended mode.

**Why the gate works:** since 2024 Gmail requires bulk senders to pass DMARC and offer RFC 8058 one-click, and
RFC 8058 requires both unsubscribe headers to be DKIM-signed. Legit marketing carries this fingerprint; spam and
phishing usually don't, or the provider flags them. Small or loosely configured senders land in UNSURE: the accepted cost of R0.

**Not in scope:** bodies, AI, changing/deleting mail, sending mail, web UI, own phishing detection.

## 2. Mailbox access

- **R1** Sign-in: OAuth 2.0 authorization code + PKCE in the system browser, loopback `127.0.0.1`. Provider's own login page (MFA, passkeys, SSO, Conditional Access work). No passwords, IMAP or device code.
- **R2** Login only: the project ships one public client per provider (Google desktop client, secret documented by Google as non-confidential; Microsoft public client). Optional `client_id` override in config. Google client in Production status.
- **R3** Scopes: Gmail `gmail.metadata` (Google enforces headers + labels only); Outlook `Mail.Read` + `offline_access` (headers-only is enforced by our code, not Microsoft). No write or send scope.
- **R4** Fetch headers only (plus Outlook `webLink`): `From`, `Authentication-Results`, `DKIM-Signature`, `List-Unsubscribe`, `List-Unsubscribe-Post`, `Date`; Gmail `labelIds`; Outlook `X-Forefront-Antispam-Report`, folder id. Last 90 days incl. Spam/Junk.
- **R5** Tokens in the OS Keychain; `logout` revokes and deletes. `--provider gmail|outlook` at login.

## 3. Classification

### 3.1 Groups (sender = full From address, lowercased)

| Group | When | Codes | Shown as |
|---|---|---|---|
| **DANGER** | Any message with an Outlook phishing / malware / spoof / impersonation `CAT` (PHSH, HPHSH, MALW, SPOOF, DIMP, UIMP, GIMP, BIMP), or punycode (`xn--`) in the From domain | `PROVIDER_PHISH`, `PUNYCODE_FROM` | "Do not open, do not unsubscribe" |
| **KEEP** | Own / `org_domains` / protected domains, or user chose `k` | `PROTECTED`, `USER_KEPT` | Never touched |
| **CAN UNSUBSCRIBE** | Passes the gate | `GATE_PASS` | Offered, one by one, default `n` |
| **UNSURE** | Everything else | `IN_SPAM`, `PROVIDER_FLAGGED`, `DMARC_FAIL_SEEN`, `NOT_AUTHENTICATED`, `NO_ONE_CLICK`, `UNSUB_NOT_SIGNED`, `AUTH_HEADER_UNTRUSTED` | Never unsubscribed by the app; reason + manual step (provider's Unsubscribe button, filter) |

Order: DANGER, KEEP, then the gate; first failing gate rule gives the UNSURE code.
**Info only (never used by the gate):** Gmail category label, first-seen date, message count, unsubscribe host.

### 3.2 The gate (all must pass)

| Rule | Check | Fail code |
|---|---|---|
| G1 | No message from this sender in Spam/Junk; Outlook messages only with `CAT` in {NONE, BULK} and `SFV` not in {SPM, BLK, SKB} (allowlist: unknown values deny) | `IN_SPAM` / `PROVIDER_FLAGGED` |
| G2 | No message with `dmarc=fail`, and **at least 2 messages** with `dmarc=pass` aligned with the From domain, read only from the provider's own auth header (Gmail: `mx.google.com`; Outlook: EOP's). Duplicate or odd auth headers = deny | `DMARC_FAIL_SEEN` / `NOT_AUTHENTICATED` / `AUTH_HEADER_UNTRUSTED` |
| G3 | Newest message has an **https** `List-Unsubscribe` URL and `List-Unsubscribe-Post: List-Unsubscribe=One-Click`, both listed in `h=` of **every** `DKIM-Signature` whose `d=` passed and is aligned with From | `NO_ONE_CLICK` / `UNSUB_NOT_SIGNED` |

## 4. Unsubscribe action (macOS only in v1)

- **R6** `scan` never acts. `unsubscribe` needs an interactive terminal on macOS and a scan < 1 hour old.
- **R7** Per sender, biggest first: shows address, category, first seen, count, host; asks `y` / `n` (default) / `k` keep / `q`, read from `/dev/tty`.
- **R8** Then one Touch ID / password dialog (LocalAuthentication) **listing the chosen sender domains** (first 5 + "and N more"). Cancel = nothing sent.
- **R9** Sequential POST `List-Unsubscribe=One-Click` to the newest message's URL, max 200 per run. Never GET links, body links or mailto.
- **R9a** For UNSURE senders, `show` gives an **"open in Gmail / Outlook" link** to the newest message (Outlook: Graph `webLink`; Gmail: web URL built from the message id, format to confirm in S-GMAIL). The user opens it in their normal mail app and decides; the app reads and follows nothing in the message.
- **R10** Journal (JSONL): sender, host, time, status, `keep`. Next scan flags "still sending 14 days after unsubscribe: filter it".

## 5. Network guard (POST only)

- **R11** httpx, https + TLS verify, no cookies / Referer, generic User-Agent.
- **R12** Refuse hosts resolving to non-public addresses (private, loopback, link-local, CGNAT, multicast, `169.254.169.254`, `::1`, `fc00::/7`, `fe80::/10`).
- **R13** No redirects (3xx = "finish manually"); 10 s timeout; read max 64 KB; record status only.

## 6. Agents (Claude Desktop, Claude Code, others)

- **R14** Read-only: `scan`/`show --json`, or optional MCP server (`unsub mcp`, stdio) with one tool, `show` (filter by group / sender). No action, login, config or delete tools.
- **R15** Per-account `agent = on | off`; default **on** for personal, **off** for work accounts (Workspace domain, non-consumer Microsoft tenant).
- **R16** Agent output: groups, codes, counts, dates, Gmail category, validated domain names/addresses (syntax-checked, else dropped), unsubscribe host. Never display names, subjects, full URLs, tokens. DANGER domains defanged.
- **R17** Actions are handed to the user as a command (`unsub unsubscribe --sender ...`). Without a terminal, `unsubscribe` returns `HUMAN_REQUIRED` (exit 6).
- **R18** Honest limit (documented): an agent with a shell runs as the user and **can read the Keychain token and scan files**; Touch ID with the listed senders is what stops it acting. Users who don't trust their agent with mailbox access should not give it a shell.

## 7. Privacy and repo

- **R19** Local only: no telemetry, no lookups beyond provider APIs and approved POSTs.
- **R20** Stored: `scans/<account>.json` + `journal.jsonl`, `0600`, no subjects or bodies; `logout --purge` deletes. Logs: counts and errors only.
- **R21** Repo: no real data (only `example.com`), synthetic header fixtures, gitleaks pre-commit + CI (one allowlist entry for the Google desktop client secret), secret scanning + push protection, deps pinned with hashes (4 core + pyobjc LocalAuthentication; `mcp` extra optional), Dependabot, `SECURITY.md`. Docs = README sections.
- **R22** Exit codes: 0 ok · 1 error · 2 usage · 3 sign-in needed · 6 human required. `--json` errors: `{error, message, next}`.

## 8. Tests (automated, synthetic fixtures)

| # | Test |
|---|---|
| T1 | Gate rejects: dmarc fail anywhere, < 2 aligned passes, forged auth header above the real one, duplicate auth headers, unsigned or unaligned-signed unsubscribe headers, missing `-Post`, http/mailto only, Spam/Junk, unknown Outlook CAT/SFV, punycode From |
| T2 | Gate accepts a correctly signed, aligned one-click sender (Gmail and Outlook fixtures) |
| T3 | Guard blocks non-public IPs and redirects |
| T4 | Only metadata requests are made; no provider write calls; no network outside provider + approved POST (socket-blocking fixture) |
| T5 | Agent output from fixtures with injection text in display name and List-Id contains none of it |
| T6 | Nothing is POSTed unless gate pass + `y` + Touch ID success, across every command, flag and the MCP tool |

## 9. Before coding: 2 spikes (read-only, maintainer's own mailboxes, values redacted)

- **S-OUT:** Graph `internetMessageHeaders`: is EOP's `Authentication-Results` there and where, is `DKIM-Signature` kept, is `X-Forefront-Antispam-Report` there. If `DKIM-Signature` is dropped, Outlook senders can never pass G3 (report-only for Outlook).
- **S-GMAIL:** `format=metadata` + `metadataHeaders` work with `gmail.metadata`; header order keeps `mx.google.com` `Authentication-Results` on top.
