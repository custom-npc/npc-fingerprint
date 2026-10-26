# npc-fingerprint

Defensive web technology fingerprinting and security-posture analysis for security analysts and developers.
It fetches public pages, renders them in a real browser, and reports **what they expose, with the evidence for every
claim**. No exploitation, no brute forcing, no credential attacks, no API keys.

```
╭─ npc-fingerprint ▸ https://localhost:45685/ ───────────────── 1.1s · db seed ╮
│ SURFACE TECH ● 3  HEADERS ▲ 3/6  CSP ▲ D  TLS ▲ 1.3 http/1.1  JS ▲ map!      │
│         EDGE ○ none  3P ● 0  HYG ● 0ck                                       │
│ NOTE ▲ seed fingerprints (29): run `npc-fingerprint db update`               │
├──────────────────────────────────┬───────────────────────────────────────────┤
│ STACK                       conf │ POSTURE                                   │
│  Next.js          ██████████ 100 │ ✔ HSTS         max-age 365d +sub          │
│  Nginx 1.24.0     ██████████ 100 │ ▲ CSP          grade D: script-src        │
│  React 18.2.0     ██████████ 100 │ ✖ X-Frame-Opt  framing allowed            │
│  ↳ Node.js        implied        │ ✔ X-Content-T  nosniff                    │
│                                  │ ✔ Referrer-Pol strict-origin-when-cross-o…│
│                                  │ ✖ Permissions  no feature restrictions    │
│                                  │ ▲ csp issues   3 (script-src ...)         │
├──────────────────────────────────┴───────────────────────────────────────────┤
│ TLS   ▲ UNTRUSTED (self-signed) · 1.3 · http/1.1 · exp 89d · Test Org (local…│
│ EDGE  ○ no CDN/WAF identified                                                │
│ FAV   ○ mmh3 1799806383 · no database match                                  │
│ JS    ▲ app.js 287 B · source map exposed                                    │
│ 3P    ● 0 third-party origins                                                │
│ HYG   ● 0 cookies · security.txt pass                                        │
╰──────────────────────────────────────────────────────────────────────────────╯
 -v evidence trace · --json · --no-browser · --baseline FILE
```
<sub>Real output (80 columns) from a scan of a local HTTPS test fixture, using the small bundled seed database.
The fixture serves a JavaScript-rendered page, so React is found by the browser pass and is invisible to static parsing.</sub>

## Features

| Module | What it does |
|---|---|
| **Technology detection** | Matches ~7.6k community fingerprints ([enthec/webappanalyzer](https://github.com/enthec/webappanalyzer), the living continuation of Wappalyzer's open data) against the *rendered* page: headers, cookies, meta, script URLs, JS globals, DOM selectors, XHR hosts, page text, CSS, script bodies, certificate issuer, DNS. Every detection lists the signal, location, matched text, pattern and confidence it came from. |
| **Header anomalies** | Flags conflicting identity headers in two tiers: *layered* (plausible behind proxies) and *contradiction* (implausible, e.g. `Server: Apache/2.2` while HTTP/2 was negotiated and no proxy is visible). Only contradictions mark a technology **disputed**. |
| **Favicon hashes** | Shodan-compatible mmh3 plus MD5 against a local database. A hash alone is capped at "possible"; it only raises confidence when another signal agrees. |
| **Security headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy: pass / weak / missing / n/a with a one-line reason each. |
| **TLS and HTTP** | CA, certificate SHA-256, validity, key, TLS version, ALPN (h2 / http/1.1), and HTTP/3 as *advertised* (Alt-Svc) or *observed*, never guessed. |
| **JS bundle banners** | First 500 bytes of the largest bundle (plus the other scripts, for free in browser mode) scanned for copyright / version / license-pointer comments. |
| **Library risk** | Client-side libraries whose *evidenced* version falls in a known-vulnerable range (offline [retire.js](https://github.com/RetireJS/retire.js) data), plus exposed source maps. |
| **CSP grading** | A-F grade with reasons (`unsafe-inline`, wildcards, `data:`, bypass-prone hosts, missing `object-src`/`base-uri`/`frame-ancestors`). |
| **Edge vs origin** | Separates what the CDN/WAF says from what the origin leaks through it (CNAME/NS lookups plus header layering). |
| **Third parties and SRI** | Third-party origins, scripts/styles without `integrity`, insecure subresources. |
| **Cookies and security.txt** | `Secure` / `HttpOnly` / `SameSite` / prefix rules (values are never stored or printed); RFC 9116 `security.txt` presence, validity and expiry. |
| **Baseline drift** | `--baseline previous.json` shows added / removed / changed technologies, headers, certificate rotation, library versions, edge and third parties; low-confidence flips are counted as noise, not changes. |

## Install

Requires Python 3.11+.

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install .                                           # from this directory
python -m playwright install chromium                   # add --with-deps on Linux
npc-fingerprint db update                               # downloads the databases (public sources, no keys)
```

Without `db update` the tool runs on a tiny **seed** set (29 technologies) and says so on every report.
`--no-browser` works without Chromium.

## Usage

```bash
npc-fingerprint -u https://example.com            # the scan card
npc-fingerprint -u example.com -v                 # + the evidence chain for every claim
npc-fingerprint -u https://example.com --json > report.json
npc-fingerprint -u https://example.com --baseline report.json    # what changed since last time
npc-fingerprint -u http://localhost:8000 --no-browser            # static only, no Chromium
npc-fingerprint -f targets.txt --json             # many targets, one browser, one connection pool
npc-fingerprint db status                         # what data is installed
```

| Flag | Meaning |
|---|---|
| `-u, --url URL` / positional | Target (repeatable). A bare host tries `https://` then `http://`. |
| `-f, --file FILE` | One target per line, `#` comments allowed. |
| `--json` | Pure JSON on stdout (no colour, no card). Notices go to stderr. |
| `-v, --verbose` | Evidence trace as an indented tree. |
| `--no-browser` | Skip JavaScript rendering (fast; misses SPAs). Also the automatic fallback if Chromium is missing. |
| `--baseline FILE` | Previous `--json` output, adds the drift view. |
| `--timeout SEC` | Per-target budget (default 20). |
| `--no-dns` | Skip CNAME/NS/MX/TXT/SOA lookups. |
| `--no-cache` | Ignore the favicon cache. |
| `--ascii`, `--no-color`, `--width N` | Terminal tuning. `NO_COLOR` is honoured; ASCII is automatic when the terminal cannot show Unicode. |
| `db update [--only enthec,favicons,retire] [--from-tar FILE]` | Build/refresh databases. `--from-tar` supports air-gapped builds. |

Exit codes: `0` ok, `1` at least one target unreachable, `2` usage error, `130` interrupted.
Environment: `NPC_FINGERPRINT_HOME` relocates the data/cache directory.

**JSON**: `{"schema_version": 1, "tool", "version", "generated_at", "db", "reports": [...]}`. `technologies` holds
confirmed / probable / disputed / implied entries; `weak` (<50%) is separate so consumers never mistake it for a detection.
Page-derived strings in the output are untrusted: escape them before rendering anywhere.

## How the output stays honest

* **Confidence bands**: >= 90 confirmed, 50-89 probable, < 50 weak (hidden from the card, listed under `weak`).
  Confidence is the capped sum of independent evidence; implied technologies are labelled `implied`, never `confirmed`.
* **`basis: claimed`**: a technology evidenced *only* by self-declared headers/meta (e.g. `Server`) is marked as such.
* **`disputed`**: header-only claims involved in a contradiction are capped at 40% and flagged.
* **Version conflicts** are reported rather than silently resolved.
* **Evidence everywhere**: `-v` prints signal, location, matched text, pattern, contribution and whether it was seen in the
  raw response, the rendered DOM, or both.

## Request budget

Per URL, browser mode: the page load itself, plus at most 1-2 favicon requests, 1 `security.txt`, up to 2 source-map `HEAD`s
(first-party only), and 1 TLS handshake (no HTTP request). Script bodies are reused from the page load (0 extra requests).
`--no-browser`: 1 GET, the same extras, and ranged 500-byte probes for at most 4 scripts. Connections are pooled,
favicons are cached for 24 h, DNS runs on a worker thread, slow targets return partial results marked as such, and
a failing module degrades to a warning instead of failing the scan. The report records every extra request it made.

## What makes this different from Wappalyzer

* **Explainable by construction.** Every match carries its evidence and rule; nothing is a bare label.
* **Honest about spoofing.** Identity headers are cross-checked against each other and against what the connection actually does.
* **Raw vs rendered.** Signals record whether they exist in the response, the rendered DOM, or both.
* **Open and current data.** Built on the maintained community fork, pinned by commit, reproducible, no account or key.
* **Beyond detection.** TLS, security headers, CSP quality, library advisories, edge/origin, third-party and SRI inventory, cookies,
  `security.txt` and drift in one pass, from the same evidence.
* **Scriptable.** A stable JSON schema, quiet stdout, meaningful exit codes.

## Data sources and licences

This project is **GPL-3.0-or-later** (`LICENSE`). Data it downloads keeps its own licence:
enthec/webappanalyzer (GPL-3.0), retire.js data (Apache-2.0), OWASP favicon database (CC BY 3.0), nuclei-templates favicon
list (check the repository's licence before redistributing a built copy). `db update` downloads at your request;
nothing is bundled except the small hand-written seed files. I am not a lawyer; verify before you redistribute.

## Limitations

* No fingerprinter can promise zero false positives. This one promises evidence, conservative bands and visible doubt.
* The bundled **seed** databases are hand-written and minimal. Real coverage needs `db update`.
* Static mode cannot see JS globals, DOM rules, XHR hosts or runtime CSS; `probe` and `robots` rules are never evaluated
  (path guessing is out of scope).
* Community regexes are JavaScript; a few do not port to Python. They are skipped and **counted** in the report footer.
  Install the `regex` package (a dependency) for per-match timeouts; the stdlib fallback refuses nested-quantifier patterns.
* `scripts` rules run on the first 256 KB of each script under a time budget (flagged when exceeded).
* HTTP/3 is reported as advertised/observed only; there is no QUIC probe. TLS reports the negotiated connection, not an
  enumeration of everything the server supports.
* Favicon matches are weak by nature (default pages, reused icons, honeypots). They are capped at "possible".
* The 500-byte banner window misses bundlers that move legal comments elsewhere; the tail of each captured script is also
  scanned, and `LICENSE.txt` pointers are reported.
* CSP grading is a heuristic, not a full CSP evaluator. Library advisories are version-based, not proof of exploitability.
* Third-party classification uses a built-in approximation of the public-suffix list unless `publicsuffixlist` is installed
  (`pip install .[psl]`).
* Page subresources load exactly as in any browser, including requests to internal addresses a hostile public page may
  contain. Only the tool's *own* follow-up requests are blocked from internal ranges when the target is public.
* Parsers for the enthec, nuclei and OWASP data are tested against fixtures shaped like those files (including a real
  `git archive` tarball); run `npc-fingerprint db status` after your first update and sanity-check the counts.

## Testing

```bash
python -m unittest discover -s tests -v       # 79 tests; browser tests are skipped if Chromium is missing
```

Manual targets (Step 11 of the build guide):

```bash
# 1. static site
npc-fingerprint -u https://example.com -v
# 2. JavaScript-heavy SPA: compare the two modes, the browser pass should find more
npc-fingerprint -u https://react.dev
npc-fingerprint -u https://react.dev --no-browser
# 3. local python http.server: expect 5 missing security headers, "TLS none", Python version evidence
python -m http.server 8000 &
npc-fingerprint -u http://localhost:8000 --no-browser
```

## Legal notice

Use this tool only on systems you own or are explicitly authorised to assess. It performs ordinary, passive page loads
and a few well-known-path requests, but you are responsible for complying with applicable law, terms of service and
scope agreements. The software is provided without warranty (see `LICENSE`).

## Layout

```
src/npc_fingerprint/
  cli.py scanner.py merge.py model.py regexcompat.py util.py
  fetch/    browser.py (Playwright)  static.py (niquests)  snapshot.py
  modules/  tech favicon secheaders anomaly tls bundle        <- the six requested modules
            libs csp edge thirdparty hygiene drift dnsprobe    <- the six approved extras
  db/       store.py update.py
  render/   layout.py (scan card)  trace.py (-v)  emit.py (Rich)  theme.py
  data/     anomaly_rules.toml edge_rules.toml seed_*.json
tests/      unit, integration and end-to-end tests with local fixture servers
docs/RESEARCH.md   why each resource was chosen and what was rejected
```
