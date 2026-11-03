# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/), versions follow [SemVer](https://semver.org/).

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
