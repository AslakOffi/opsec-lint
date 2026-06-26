# opsec-lint

Scan your text for personal info leaks before you post it online.

opsec-lint is a CLI tool that catches the stuff you forget to remove — IP addresses, API keys, real locations, email addresses, phone numbers, system paths, and more. Run it on a draft message and it tells you exactly what to clean up.

> **Note:** This tool was originally built for French-speaking users. Some checks (phone numbers, postal codes, geolocation, street names) are primarily tailored to French formats and locations.

## Example

Say you're about to post this on a forum:

```
Hey team, it's 3am and I'm still working on this from Paris.
Shoot me a mail at music.music77@gmail.com if you need the config.
The server is running on 192.168.1.42, keys are in id_rsa.
Here's the Stripe key: sk_live_51HG3jKLmnOPqRsTuVwXyZ0123456789
```

Run `python -m opsec_lint scan message.txt` and get:

```
  opsec-lint v0.1.0

  ⚠ line 1 : TIMEZONE — "... it's 3am and I'm still working ..."
  ⚠ line 1 : GEO — "... still working on this from Paris ..."
  ⚠ line 2 : EMAIL — "... mail at music.music77@gmail.com if you ..."
  ⚠ line 3 : IP — "... running on 192.168.1.42, keys are ..."
  ⚠ line 3 : SENSITIVE_FILE — "... keys are in id_rsa ..."
  🔴 line 4 : API_KEY — "... sk_live_51HG3jKLmnOPqRsTuVwXyZ0123456789 ..."

  ---
  6 problems found (1 timezone, 1 geo, 1 email, 1 ip, 1 sensitive_file, 1 api_key)
  Clean up before posting!
```

## Install

```bash
git clone https://github.com/AslakOffi/opsec-lint.git
cd opsec-lint
pip install -e .
```

## Usage

```bash
# scan a file
python -m opsec_lint scan message.txt

# scan from stdin
echo "meet me at Place de la Bastille at 2pm" | python -m opsec_lint scan -

# only show medium severity and above
python -m opsec_lint scan --level medium message.txt
```

Severity levels: `low` · `medium` · `high` · `critical`

## What it detects

| Category | Examples |
|---|---|
| **Timezone** | "it's 3am", "à 10h du mat", UTC+2 |
| **Geolocation** | Cities, metro stations, street names, postal codes |
| **System paths** | `C:\Users\...`, `/home/...`, `~/.config/...` |
| **Emails** | Any email address |
| **Phone numbers** | FR mobile (06/07), international (+33, +1, ...) |
| **IBAN / Credit cards** | IBAN (FR76...), 16-digit card numbers |
| **API keys / Tokens** | Stripe, GitHub, AWS, GitLab, Slack, JWTs, generic `api_key=...` |
| **Sensitive files** | `id_rsa`, `.env`, `passwd`, `shadow`, `.git-credentials`, ... |
| **IP addresses** | Any valid IPv4 (private and public) |

## Tests

```bash
pytest
```

---

MIT License

Found a bug? [Open an issue.](https://github.com/AslakOffi/opsec-lint/issues)
