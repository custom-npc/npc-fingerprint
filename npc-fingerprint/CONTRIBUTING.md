# Contributing

<<<<<<< HEAD
Thanks for helping. The project has four standing rules; changes that break one will be asked to change.

1. **Defensive and read-only.** No exploitation, brute forcing, credential testing, subdomain enumeration or hidden-path discovery. Active checks are single read-only requests.
2. **Free and keyless.** No paid APIs, no API keys, no accounts. Data comes from public feeds fetched by `npc-fingerprint db update`.
3. **Evidence for every claim.** A detection or finding must say which signal produced it. Weak evidence is labelled weak, never hidden inside a confident label.
4. **Secrets stay redacted.** Nothing found on a target is printed or stored in full, and found credentials are never used.

## Setup

```bash
git clone https://github.com/YOUR-GITHUB-USER/npc-fingerprint && cd npc-fingerprint
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m playwright install chromium     # for the browser tests (they skip without it)
python -m unittest discover -s tests -v
ruff check .
```

## Tests

Tests use local fixture servers and generated data; they never contact a real third-party host. New behaviour needs a test, and bug fixes need a test that fails without the fix.

## Pull requests

Keep them focused, explain the why, and update `CHANGELOG.md` and the README when behaviour changes.
=======
This is a solo project. Bug reports and feature suggestions via
[Issues](https://github.com/custom-npc/npc-fingerprint/issues) are welcome.
Pull requests may not be reviewed promptly — open an issue first.

Project rules: defensive and read-only, free and keyless, evidence for every
claim, secrets always redacted.
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16
