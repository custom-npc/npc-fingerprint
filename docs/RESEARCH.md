# Research notes: why each resource was chosen

Snapshot of the landscape on **2026-10-24**, gathered by web research before any code was written. Version numbers
and dates are what the sources showed on that day; check them again before relying on them.

## Fingerprint data and engine

| Candidate | Finding | Verdict |
|---|---|---|
| **enthec/webappanalyzer** | Continuation of Wappalyzer's open data after Wappalyzer went private (Aug 2023), same JSON schema (headers, cookies, meta, scriptSrc, js, dom, xhr, certIssuer, dns, confidence tags, implies/excludes/requires). Technology PRs were still being merged in Oct 2026; a downstream sync counted ~7.6k technologies in 109 categories. GPL-3.0. | **Chosen** (data) |
| python-Wappalyzer | Archived; its `update=True` pulls from the AliasIO repository (the discontinued one); last stable release years old; static parsing only. | Rejected |
| wappalyzer-python3 | Fork of the archived project with 2026 releases; data source not confirmed; inherits the static design. | Rejected |
| wad, wappy and similar | Static HTML only; cannot evaluate JavaScript-variable rules. | Rejected |
| wappalyzer-next | Runs the official Wappalyzer extension in Chromium via Playwright; ~35 MB wheel; results carry version/confidence/categories but not *which* pattern matched; data is whatever snapshot each release bundles. | Rejected (explainability, data pinning); proves the approach |
| tanimachi | Wappalyzer-compatible engine over HAR; 0.0.x. | Rejected as a dependency |
| wappalyzergo | Good Go engine tracking the community data. | Design reference only (wrong language) |

Decision: a small matcher in this repository over the enthec data. It is the only way to emit evidence per match, pin the
data by commit, and evaluate runtime signals from a real page.

## Browser

Playwright (1.64.1 on 2026-10-22, Chromium 156). Gives rendered DOM, JS evaluation in the page's main world, response
bodies the page already downloaded (the bundle scan costs no extra request), a network log, and per-request protocol via
the DevTools protocol. Rejected: `rebrowser-playwright` (exists to evade automation detection; an honest scanner
should not hide), Selenium (driver management, weaker network visibility), pyppeteer (unmaintained as far as known).

## HTTP client (`--no-browser`)

niquests (3.21.0, July 2026): HTTP/1.1, HTTP/2 and HTTP/3, requests-compatible API, `http_version` on responses.
httpx's last stable release was Dec 2024; the Pydantic-maintained fork httpx2 is the fallback (Python 3.11+, no HTTP/3).
The client sits behind one small interface (`fetch/static.py`), and the code also runs on plain `requests`.

## Favicon hashes

`mmh3` (5.3.1, Oct 2026). Shodan hashes the base64 text **with newlines**; `base64.b64encode` gives a different hash.
Database: nuclei-templates `http/technologies/favicon-detect.yaml` (actively extended) plus the OWASP favicon database
(MD5, CC BY 3.0; contains sentinel entries such as a zero-byte favicon, which are ignored). 2026 research on favicon
fingerprinting notes the same hash often appears on unrelated infrastructure including honeypots, hence the "possible" cap.
Rejected: Shodan/Censys/ZoomEye lookups (keys, or the target leaves your machine).

## TLS and HTTP version

stdlib `ssl` (one handshake, ALPN, SNI) plus `cryptography` for certificate parsing. HTTP/3 cannot appear in TCP ALPN
(QUIC negotiates it), so it is reported as *advertised* (Alt-Svc) or *observed*. sslyze rejected: many connections, drifts
towards active scanning.

## Terminal

Rich 15.0.0 (Apr 2026) used through its low-level pieces (Console, Text, styles), not `Table`. The layout engine produces
plain (text, style) spans, so it is testable and terminal-library independent. Textual rejected for the default view
(event loop takes over the screen; not pipe-friendly). urwid/blessed/prompt_toolkit/curses would mean re-implementing colour
negotiation, wide-character handling and `NO_COLOR`.

## Library advisories

retire.js `jsrepository.json` (Apache-2.0; release 5.4.3 in May 2026). Only plain property chains from its `func`
extractors are ever evaluated in a page; database strings are never executed as code. NVD/KEV lookups were rejected (rate
limits; KEV has no version ranges, which would create false positives).

## Considered and dropped as extras

Header-order fingerprinting (no maintained public database), Shodan/Censys/InternetDB (keys or third-party leak),
WAF probing (attack-style payloads).
