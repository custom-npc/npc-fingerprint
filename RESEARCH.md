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


---

# Round 2 research (2026-10-30): CVE matching, live view, install method

## CVE data: why not just NVD

| Source | Finding | Verdict |
|---|---|---|
| **NVD API 2.0** | Free; without an API key the limit is 5 requests per rolling 30 s, too slow for per-scan lookups. | Rejected for scans |
| **NVD 2.0 JSON feeds** | Official, free, keyless, bulk: one gzip file per CVE year (refreshed nightly) plus `modified`/`recent` (every 2 h), each with a `.meta` sha256. | **Used** for products without a package ecosystem |
| **NVD data quality in 2026** | NIST changed its enrichment policy in April 2026 (enrichment is triaged) and mid-2026 analyses found most new CVEs unscored / awaiting analysis, i.e. with no CPE applicability data. NVD alone silently misses recent CVEs for nginx, Apache, PHP... | Not sufficient alone; the gap is counted and shown |
| **OSV.dev** | Free, no key; `POST /v1/query` with package + ecosystem + version matches versions server-side with ecosystem semantics (semver, PEP 440, Maven...), returns fixed versions, aliases (CVE), severity. Batch up to 1000. | **Used** for framework/library versions |
| CIRCL Vulnerability-Lookup | Keyless aggregator (NVD, CVE.org, GHSA...) but a single operator and 20 requests/minute for anonymous users. | Not a dependency |
| VulnCheck, Vulners, ProjectDiscovery vulnx | Need an API key or account. | Rejected (keyless rule) |

Enrichment (all free, keyless): **CISA KEV** (exploited in the wild), **FIRST EPSS** (daily CSV, exploitation probability), **Exploit-DB** (`files_exploits.csv`, `codes` column carries CVE IDs), **nuclei-templates** (`cves.json` for exact template IDs, `TEMPLATES-STATS.json` for the real tag vocabulary).

Design consequences: OSV is queried at scan time (cached 24 h, stale-if-error, `--offline` uses only the cache); NVD data is a local SQLite file built by `db update`, only for products the fingerprint database can detect, streamed so a multi-hundred-MB year never sits in memory; unchanged years are skipped via the published sha256; recent CVEs without applicability data are stored separately so the report can say how many it could not analyse. CVSS v3.x scores are computed locally from vectors (verified against reference values); v4-only records use the vendor label.

## Live view

Rich `Live` (already a dependency) rendering a few lines of text at 12 frames/s on stderr, transient. Measured: about 2.7% of one core. Alternatives rejected: Textual (full-screen event loop, not pipe-friendly), halo/yaspin/alive-progress (extra dependency for less control), any GPU/terminal-graphics approach (the brief ruled it out). It turns itself off for non-terminals, `--json`, `--quiet`, `--no-live` and `NPC_NO_ANIM=1`, falling back to one plain line per finished stage.

## Install method

Kali (and recent Debian/Ubuntu) enforce PEP 668, so system-wide `pip install` is refused; Kali documents **pipx** for Python tools, and **uv tool** is the modern equivalent. `install.sh` therefore prefers pipx, then uv, then a private virtualenv symlinked into `~/.local/bin`: all user-level, never `sudo`. Playwright's Chromium downloads into the user's cache; a system Chromium is used automatically if present. The only root-requiring path (Playwright's `install-deps` for missing system libraries) is documented as optional and never executed.

## Dependency floors (current at time of writing)

playwright 1.64, niquests 3.21, regex 2026.9, mmh3 5.3, rich 15, dnspython 2.9 (Python 3.11+), PyYAML 6.0.3. No upper bounds, so new installs take the newest releases; Dependabot raises weekly update PRs.

---

# Round 3 (2026-11-19): trust fix, visibility, decision log

Triggered by a real-world run against a Next.js site that reported 20 CVEs, including 4 critical, while the
Nuclei suggestions came back with zero matches and no explanation. The fix, and everything else in this round,
follows the mandate given: ship the trustworthy core first and verify it against that exact contradiction,
then add visibility, then depth — and choose accuracy over breadth wherever the two trade off.

## The core bug and its fix

The tool was computing one thing — "does this CVE's version range match?" — and silently relying on it to also
answer two different questions: "is this CVE really applicable here?" and "can I tell you how to verify it?"
A CVE can be a real, version-matched, critical finding and still have no Nuclei template; or it can
version-match a product whose CPE data says it only applies on Windows, while the target is plainly a
Linux-hosted Next.js app. Collapsing all of that into one list, with Nuclei suggestions silently drawn from
whichever subset happened to have templates, is exactly how a report ends up naming 20 CVEs while Nuclei
finds 0 matches.

The fix adds two independent, always-shown axes, on top of the existing risk ranking (exploited/weaponized/
likely/severe/minor):

- **`coverage`**: `testable` (a Nuclei template exists and nothing rules the match out), `no_template` (a real,
  version-matched CVE with nothing to auto-verify yet), or `env_mismatch` (the CVE's own CPE data names a
  platform the target isn't running). Nuclei suggestions are drawn **only** from `testable`; the report states
  the other two buckets' counts and examples by name, so the gap is explained, not silent.
- **`state`**: `confirmed` / `lead` / `unverified` / `suppressed`, driven by the same confidence signals already
  computed (banner-only version, distro backport, imprecise version string) plus the new platform check — shown
  with the same icon language the rest of the report already uses.

Verified directly: `tests/test_vulns.py::Platform` and `::PlatformDetect` reproduce the exact shape of the bug
(a Windows-only, KEV-eligible, Nuclei-templated CVE matched by version on a detected-Linux target) and assert
it becomes `coverage=env_mismatch`, `priority=suppressed`, `state=suppressed`, is excluded from Nuclei
suggestions, and is still shown — with the reason — if asked. `tests/test_report.py::CveTrustFix` renders the
same scenario through the actual terminal output, because the bug was in what a human reads, not just the
JSON.

## Research: NVD platform preconditions

CPE 2.3 strings carry a `target_sw` field (`cpe:2.3:a:vendor:product:version:*:*:*:*:windows:*:*`) that NVD
populates for genuinely platform-specific matches; the tool had been parsing CPE strings but discarding that
field. The other, less common pattern is two `cpeMatch` entries in one `AND`-operator node, one for the
software and one for an `o` (operating-system) CPE. Both are now captured per `affected` row; a row with no
platform data imposes no constraint (correct — most CVEs apply everywhere). A target's own platform is
inferred, conservatively, from Server/X-Powered-By banners (IIS/Windows strings, or a Linux distro string, both
*high* confidence) or from a recognised Linux-hosting edge (Vercel, Netlify, CloudFront, Fastly, Akamai,
Azure/Google front doors — *medium* confidence, since that's a hosting convention, not a certificate). No
signal means `unknown`, and `unknown` never suppresses a finding — a wrong guess here would trade a loud false
positive for a silent false negative, which is worse.

## Research: SARIF

SARIF 2.1.0 is the format GitHub code scanning, DefectDojo and Jira's security tooling all ingest, is an OASIS
standard, and needs no library (it's JSON with a documented shape, consistent with "stay dependency-light").
`artifactLocation.uri` accepts any URI, not only local file paths, which is the standard way DAST tools attach
a finding to a URL instead of a line in a checked-out repo. Suppressed (platform-mismatch) CVEs and passing
checks are deliberately excluded from SARIF output: a SARIF consumer treats every result as an alert to
triage, and re-including a mismatch there would recreate the exact problem this round fixes elsewhere.

## Research: npm dependency confusion

The standard, free, keyless check is a single `GET https://registry.npmjs.org/<url-encoded-name>`: `404` means
no one has published that exact package name publicly (the real exposure — a public package registered under
the same name could be preferred by a misconfigured install), `200` means the name is already taken (by the
owner or a squatter; informational, not urgent). This is an exact-name check, not a "scope ownership" check,
which the npm registry has no public API for. Candidates come from `@scope/name` literals in JavaScript and,
most usefully, from source-map `sources` arrays, which often retain real `node_modules` paths; a short
exclude-list of huge, certainly-public scopes (`@babel`, `@types`, `@angular`, ...) keeps the small request
budget pointed at names actually worth checking.

## Research: Next.js route and chunk recovery

`#__NEXT_DATA__`'s `buildId`, and that build's own `_buildManifest.js`/`_ssgManifest.js`, are Next.js's
*authoritative* route-to-chunk map — reading them is strictly more reliable than guessing at webpack internals,
and it costs two requests total, zero on non-Next.js sites. Chunk paths in the manifest are already rooted at
`/_next/...`, confirmed against a real Next.js build output mirror. For every other bundler, the tool only
follows literal `.js` references already present in already-mined code (the same evidentiary standard as a
`<script src>`) rather than attempting generic webpack-chunk-map parsing, which varies too much across
bundler versions and configs to parse with confidence — the "cheap version" the reviewer themselves flagged as
the better bet.

## Decision log

Each proposed item, and what was decided. "Implemented" items are covered above or in `CHANGELOG.md`; the
reasoning for everything else is here, since the mandate asked for it explicitly.

### Implemented now
3-bucket Nuclei coverage · OS precondition filtering · distro-backport detection (extended) · CVE confidence
scoring with explicit signals · SARIF output · Next.js manifest parsing · generic lazy-chunk following ·
source-map unpacking · passive schema discovery (robots.txt/sitemap.xml/well-known/OpenAPI convention paths) ·
API contract extraction (partial — see below) · non-REST schema extraction (GraphQL op names, tRPC paths;
partial — see below) · shadow version candidates · build-time env-var harvester · cloud/dependency-confusion
recon (buckets were already in; npm check added) · JWT metadata extraction · per-host rate-limit awareness
(partial — see below) · endpoint reachability proof · scope guard · `--scope` · state vocabulary
(confirmed/lead/unverified/suppressed/noise) applied to CVEs, reachability and the npm check.

### Implemented, but deliberately partial
- **API contract extraction**: endpoint existence, kind and now reachability/auth-boundary (401/403 vs 200)
  are extracted and verified. Binding each endpoint to its HTTP method, parameter names and body schema was
  *not* attempted with regex: a wrong method or parameter binding is a confident-looking wrong answer, which
  the "no false positives" rule treats as worse than not answering. This is the concrete reason tree-sitter
  AST was considered (below) and the reason full binding is deferred rather than shipped as a guess.
- **Non-REST schema extraction**: GraphQL operation names (survive minification, since they're part of the
  query-language text) and tRPC procedure paths are mined. Full operation *variable* schemas are not — same
  reasoning as above.
- **Rate-limit awareness**: the new, larger request volume now backs off globally for the rest of a target's
  verification phase if any response carries `Retry-After`. A full per-host matrix was judged low marginal
  value against a request budget this tool deliberately keeps small (tens of requests, not thousands).

### Deferred (not implemented this round, with reasons)
- **Authenticated dual-run comparison.** `--cookie`/`--header` ship now (a single authenticated session scans
  correctly). Automatically diffing an authenticated run against an anonymous one to surface privilege-
  escalation surface needs careful session/credential handling and a diffing design that doesn't produce
  false "privilege escalation" claims from incidental content differences — a half-built version of this risks
  exactly the overclaiming this round exists to remove. Worth a dedicated round.
- **Wayback Machine CDX mining (`--archive`).** Free and keyless (`web.archive.org/cdx/search/cdx`), but it's a
  new always-external, historical-surface feature with its own scope and privacy questions (old URLs can now
  point somewhere else entirely); better shipped deliberately with its own tests than folded into an already
  large round.
- **Proxy-ready exports** (`--export burp/openapi/http/ffuf`). An OpenAPI or Burp sitemap export is only as
  good as the method/parameter data behind it, which is the API-contract work deferred above. Shipping the
  export format now would mean exporting guesses.
- **Full OpenAPI reconstruction.** Same dependency as above, at a larger scale; the reviewer's own "minimal
  skeleton" framing still needs real method data to be honest.
- **Origin unmasking via header probing** (`X-Originating-IP`/`X-Forwarded-Host`/`X-Host`). This edges toward
  probing for an unintended origin rather than describing the one the target presents, and response-diff
  interpretation here is easy to get wrong without a careful baseline. TLS certificate SANs are already
  surfaced in the TLS section as the safer version of "what else does this certificate answer for".

### Rejected (not planned)
- **Full tree-sitter AST parsing.** Both the user and the reviewer flagged this as the highest-effort, most
  fragile item, and the research above agrees: minified single-line bundles break generic parsers in creative
  ways, `tree-sitter`/`tree-sitter-javascript` wheel availability across platforms works against the
  normal-user, no-root install goal, and the Next.js-manifest-plus-literal-reference approach shipped this
  round gets most of the realistic payoff for a fraction of the risk. Revisit only if the deferred API-contract
  work turns out to need it after the cheap version is given a fair trial.
- **Client-side RBAC mapping** (`hasRole('ADMIN')`-style gates). Agreeing with the reviewer's own skepticism:
  inferring which components or endpoints are "intended for privileged tiers" from a string match, without
  control-flow understanding, is exactly the kind of confident-sounding wrong conclusion the "no false
  positives" rule exists to prevent.
- **Multi-step business logic analysis.** Recognising a coupon-apply endpoint's parameters is within reach;
  understanding the business rule or race condition behind it is human analytical work. Automating it risks
  false confidence about things the tool cannot actually evaluate.

### Added that wasn't in either list
- The **userinfo/secret-redaction fix** below is a pure bug find from this round's own test suite, not a
  requested feature.
- A **confirmed npm dependency-confusion exposure** now produces a priority action (the only new action-list
  entry added this round; everything else new is reporting, not an action, on purpose — see "no false
  positives").
- **`--diff` as a documented alias for `--baseline`**, same flag.

## A bug this round's own tests caught

The URL miner stopped matching right at a credential separator, so `https://<secret>@host/path` (the exact
shape of a Sentry DSN) had its secret portion misread as a hostname and leaked into the third-party-hosts
list; separately, the redaction helper printed a URL-shaped secret's full `netloc` (which includes userinfo)
rather than just its host. Both are fixed, with regression tests (`tests/test_visibility.py::UrlUserinfoHandling`),
and the fix generalises to any future secret pattern shaped like a URL with embedded credentials.
