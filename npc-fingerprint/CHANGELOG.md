# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/), versions follow [SemVer](https://semver.org/).

<<<<<<< HEAD
## [0.3.0]

The trust fix this release exists for: a report could name several critical CVEs while the Nuclei suggestions
came back empty, with nothing explaining the gap. Fixed by splitting "is this CVE real for this target" from
"can Nuclei test it" into two explicit, always-shown axes.

### Added — correctness and trust
- **Platform-precondition checking.** The NVD importer now reads each CVE's CPE `target_sw` field and any
  sibling OS requirement, and a new target-platform detector (Server/X-Powered-By banners, Linux-hosting
  edges) checks it. A CVE whose version matches but whose platform doesn't becomes `coverage: env_mismatch`,
  priority `suppressed`, shown in its own report section with the reason — never silently dropped, never
  counted as exploitable. An undetermined platform never suppresses a finding.
- **Three-bucket Nuclei coverage** (`testable` / `no_template` / `env_mismatch`) on every CVE match. Nuclei
  suggestions are now drawn only from `testable`; the report states the other two buckets' counts and examples
  explicitly instead of a silent empty suggestion list.
- **Explicit confidence signals** (`confidence_signals`) and an explicit **state** (`confirmed` / `lead` /
  `unverified` / `suppressed`) on every CVE item, and on reachability/npm-confusion findings (plus `noise` for
  stale 404s) — additive fields alongside the existing `confidence`/`priority`.
- Distro-backport detection extended (`amzn2`/`amzn2023`, `el5`-`el9` with update suffixes).
- **SARIF 2.1.0 output** (`--output sarif`) for GitHub code scanning / DefectDojo / Jira. Suppressed (platform-mismatch) CVEs and passing checks are never emitted as alerts.
- **Scope guard** (`modules/scope.py`) and `--scope DOMAIN[,...]`: every new active-probing feature below checks it before requesting anything beyond the target's own domain.

### Added — visibility
- **Endpoint reachability proof**: a single read-only GET per discovered endpoint (ranked, capped), state-coded (`confirmed`/`lead`/`noise`/`unverified`/`suppressed`), with Retry-After backoff.
- **Shadow API versions**: `/api/v3/x` also checks `/api/v1/x`, `/api/v2/x` — derived from the app's own versioned-path convention, never a guessed path.
- **Passive schema discovery**: `robots.txt`, `sitemap.xml`, `.well-known/openid-configuration`, and four OpenAPI/Swagger convention paths — the same category as the existing `security.txt` check, never a guessed path.
- **Next.js route and chunk mining**: reads `#__NEXT_DATA__`'s buildId and the app's own `_buildManifest.js`/`_ssgManifest.js` for an authoritative route list and chunk map, then mines the chunks too.
- **Generic lazy-chunk following**: literal first-party `.js` references already in the code (that used to be discarded as "just an asset") are now fetched and mined, bounded per scan.
- **Source-map mining**: an already-confirmed-exposed map is fetched once; `sources`/`sourcesContent` are mined with the same endpoint/secret/env-var passes.
- **GraphQL operation names**, **tRPC procedure paths**, **build-time public env-var names** (`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, ...), **Sentry DSN** and **AWS Cognito identity pool ID** detection (both `info` severity — public-by-design, but worth knowing about).
- **npm dependency-confusion check**: scoped package names found in code/source maps are checked, one GET each, against the public npm registry (never the target) — an unpublished exact name is a real, verified exposure and becomes a priority action.
- **DOM/postMessage sink locator**: `postMessage` listeners without an apparent `.origin` check, and `innerHTML`/`document.write`/`eval`/`Function`/`location.href=` sinks — reported as leads for manual review, not confirmed findings.
- **JWT metadata**: algorithm, `kid`/`jku` when present, `alg: none` flagged high, and a page-wide note when multiple tokens use different algorithms.

### Added — session and output
- `--header NAME:VALUE` (repeatable) and `--cookie VALUE`: send on every request, for a single low-privilege authenticated scan.
- `--diff` as the documented alias for `--baseline` (same flag, same behaviour).
- `--output {text,json,sarif}`; `--json` still works as `--output json`.

### Fixed
- A URL-shaped secret containing userinfo (`https://<secret>@host/...`, the exact shape of a Sentry DSN) could
  have its secret portion misread as a hostname and leaked into the third-party-hosts list, and the redaction
  helper could print that same userinfo in full for any URL-shaped secret. Both are fixed, with regression tests.

### Changed
- JSON: additive only. `schema_version` stays `1`, `schema_minor` stays `1`. New report keys: none at the top
  level (the new data lives inside the existing `vulnerabilities`/`recon`/`active` objects). `vulnerabilities.items[].priority`
  gains a new possible value, `"suppressed"`.

=======
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16
## [0.2.0]

### Added
- **CVE matching** for every detected version: OSV.dev for framework/library versions, NVD 2.0 feeds for server software and CMSs, with CISA KEV, FIRST EPSS, Exploit-DB and nuclei-templates enrichment, ranked into *exploited / weaponized / likely / severe / minor*.
- **JavaScript recon**: API endpoints, internal/staging hosts, cloud-storage references, HTML comments and exposed secrets (always redacted, never validated).
- **Non-destructive active checks**: HTTP methods, CORS reflection, HTTP-to-HTTPS redirect, error-page disclosure, accepted TLS versions, GraphQL introspection. `--passive` turns them off.
- **Nuclei suggestions** (never executed): exact CVE template IDs and validated tags with ready-to-paste commands.
- **Live run view** (stderr, ~3% of one core): current stage, spinner and a scanning comet; plain lines when not a terminal, `--no-live`, `NPC_NO_ANIM=1` or `--json`.
- **Headed report** with one-line explanations per section, a priority action list, `--brief` and `--summary`.
- `npc-fingerprint setup` (user-level Chromium + all data), `setup --check`, `db update --only/--since/--force`, `install.sh`, the `npcf` alias, system-Chromium fallback.
- `--offline`, `--skip`, drift for CVEs / secrets / active checks, CI workflow and Dependabot.

### Changed
- JSON: additive only. `schema_version` stays `1`; new `schema_minor: 1`; new keys `vulnerabilities`, `recon`, `active`, `nuclei`, `actions`.
- Dependency floors raised to the current releases; no upper bounds.

## [0.1.0]
- Initial release: fingerprinting over the community Wappalyzer data, header anomalies, favicon hashes, security headers, TLS/HTTP, bundle banners, library risk, CSP grading, edge attribution, third-party/SRI, cookies and security.txt, baseline drift, scan card and `-v` trace.
