<h1 align="center">npc-fingerprint</h1>
<p align="center"><b>One command for defensive web recon.</b><br>
Fingerprinting · security posture · CVE matching with exploit data · JavaScript recon · read-only active checks · Nuclei suggestions<br>
Live in your terminal. Free. No API keys. No root.</p>

<p align="center">
  <img alt="license" src="https://img.shields.io/badge/license-GPL--3.0--or--later-blue">
  <img alt="python" src="https://img.shields.io/badge/python-3.11%2B-blue">
  <img alt="api keys" src="https://img.shields.io/badge/API%20keys-none-brightgreen">
  <img alt="root" src="https://img.shields.io/badge/root-not%20needed-brightgreen">
  <img alt="defensive" src="https://img.shields.io/badge/use-defensive%20only-orange">
</p>

```bash
npc-fingerprint -u https://example.com
```

While it runs you see what it is doing (a light animation, about 3% of one CPU core, drawn on stderr):

```
 npc-fingerprint ▸ https://shop.example.com/                              00:00
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 ✔ Load and render the page                HTTP 200 · 41 requests · browser
 ✔ TLS and HTTP protocol                   1.3 · h2 · Let's Encrypt R11
 ▲ Security headers                        2/6 present · CSP none
 ✔ Fingerprint technologies                9 technologies
 ✔ Favicon hashes                          no database match
 ✔ JavaScript bundles                      6 scripts · 2 banners
<<<<<<< HEAD
 ▲ Mine JavaScript for endpoints, secrets  5 endpoints · 1 secret
 ⠸ Verify endpoints and declared schemas   0.0s
=======
 ⠸ Mine JavaScript for endpoints, secrets  0.0s
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16
 ○ Non-destructive active checks
 ○ Match CVEs and exploit data
 ○ Suggest Nuclei templates
 ○ Assemble the report
<<<<<<< HEAD
 ▸ Checking discovered endpoints and declared schemas
=======
 ▸ Mining first-party JavaScript for endpoints and secrets
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16
```

Then a one-screen scan card, and a headed report below it:

```
<<<<<<< HEAD
╭─ npc-fingerprint ▸ http://127.0.0.1:45913/ ────────────────── 0.9s · db seed ╮
│ SURFACE TECH ● 4  HEADERS ✖ 0/6  CSP ✖ none  TLS ✖ none  CVE ✖ 6 1!          │
=======
╭─ npc-fingerprint ▸ http://127.0.0.1:60935/ ────────────────── 0.6s · db seed ╮
│ SURFACE TECH ● 4  HEADERS ✖ 0/6  CSP ✖ none  TLS ✖ none  CVE ✖ 5 1!          │
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16
│         SECRETS ✖ 1  ACTIVE ▲ 1 issue  JS ▲ 3 adv  EDGE ○ none               │
│ NOTE ▲ seed fingerprints (29): run `npc-fingerprint db update`               │
├──────────────────────────────────┬───────────────────────────────────────────┤
│ STACK                       conf │ POSTURE                                   │
│  Apache HTTP Ser… ██████████ 100 │ ○ HSTS         n/a: plain HTTP            │
│  jQuery 1.12.4    ██████████ 100 │ ✖ CSP          absent: no XSS backstop    │
│  PHP 7.4.3        ██████████ 100 │ ✖ X-Frame-Opt  framing allowed            │
│  WordPress 6.4.2  ██████████ 100 │ ✖ X-Content-T  MIME sniffing allowed      │
│                                  │ ✖ Referrer-Pol unset (browser default)    │
│                                  │ ✖ Permissions  no feature restrictions    │
├──────────────────────────────────┴───────────────────────────────────────────┤
│ TLS    ✖ none: served over plain HTTP                                        │
<<<<<<< HEAD
│ CVE    ✖ 1 exploited · 1 likely · 6 total                                    │
=======
│ CVE    ✖ 1 exploited · 1 likely · 5 total                                    │
│ RECON  ✖ 3 endpoints · 1 secrets (critical)                                  │
│ ACTIVE ▲ Error page                                                          │
│ JS     ▲ jquery-1.12.4.min.js 5.0 KB · jQuery 1.12.4 · 3 advisories (3 mediu…│
│ HYG    ▲ 0 cookies · security.txt missing                                    │
│ 3P     ▲ 1 third-party origin · 1 resource without SRI · declared only       │
│ EDGE   ○ no CDN/WAF identified                                               │
│ FAV    ○ mmh3 1799806383 · no database match                                 │
╰──────────────────────────────────────────────────────────────────────────────╯
 -v evidence trace · --json · --no-browser · --baseline FILE
```

```
╭─ npc-fingerprint ▸ http://127.0.0.1:60935/ ────────────────── 0.6s · db seed ╮
│ SURFACE TECH ● 4  HEADERS ✖ 0/6  CSP ✖ none  TLS ✖ none  CVE ✖ 5 1!          │
│         SECRETS ✖ 1  ACTIVE ▲ 1 issue  JS ▲ 3 adv  EDGE ○ none               │
│ NOTE ▲ seed fingerprints (29): run `npc-fingerprint db update`               │
├──────────────────────────────────┬───────────────────────────────────────────┤
│ STACK                       conf │ POSTURE                                   │
│  Apache HTTP Ser… ██████████ 100 │ ○ HSTS         n/a: plain HTTP            │
│  jQuery 1.12.4    ██████████ 100 │ ✖ CSP          absent: no XSS backstop    │
│  PHP 7.4.3        ██████████ 100 │ ✖ X-Frame-Opt  framing allowed            │
│  WordPress 6.4.2  ██████████ 100 │ ✖ X-Content-T  MIME sniffing allowed      │
│                                  │ ✖ Referrer-Pol unset (browser default)    │
│                                  │ ✖ Permissions  no feature restrictions    │
├──────────────────────────────────┴───────────────────────────────────────────┤
│ TLS    ✖ none: served over plain HTTP                                        │
│ CVE    ✖ 1 exploited · 1 likely · 5 total                                    │
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16
│ RECON  ✖ 3 endpoints · 1 secrets (critical)                                  │
│ ACTIVE ▲ Error page                                                          │
│ JS     ▲ jquery-1.12.4.min.js 5.0 KB · jQuery 1.12.4 · 3 advisories (3 mediu…│
│ HYG    ▲ 0 cookies · security.txt missing                                    │
│ 3P     ▲ 1 third-party origin · 1 resource without SRI · declared only       │
│ EDGE   ○ no CDN/WAF identified                                               │
│ FAV    ○ mmh3 1799806383 · no database match                                 │
╰──────────────────────────────────────────────────────────────────────────────╯
 -v evidence trace · --json · --no-browser · --baseline FILE

── Priority actions  ──────────────────────────────────────────────────────────
   Do these first. Most urgent at the top.
   ✖ CRITICAL Update Apache HTTP Server 2.4.41: CVE-2020-1927 is exploited in t…
<<<<<<< HEAD
   ✖ CRITICAL Rotate the exposed Stripe secret key in leak.js:1 (sk_l…dc (32))
=======
   ✖ CRITICAL Rotate the exposed Stripe secret key in leak.js:1 (sk\_l…dc (32))
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16
   ✖ HIGH     Update jQuery 1.12.4 -> 3.5.0: CVE-2020-11022 is likely to be exp…
   ✖ HIGH     Serve the site over HTTPS (it answers over plain HTTP only)
   ▲ MEDIUM   Add or tighten the Content-Security-Policy (absent: no browser-en…
   ○ LOW      Error page: default error page names Apache HTTP Server 2.4.41
   ○ LOW      Set the remaining security headers: X-Frame-Options, X-Content-Ty…

── Vulnerabilities (CVE)  ─────────────────────────────────────────────────────
   Known CVEs for the versions found, ranked by real-world exploitation.
<<<<<<< HEAD
   6 CVE(s) matched by version · 5 have no Nuclei template yet · 1 suppressed a…
   Exploited in the wild (1)
     Attackers are using these right now (CISA KEV). Patch first.
     ▲ CVE-2020-1927   HIGH 7.5   KEV no template Apache HTTP Server 2.4.41
       mod_rewrite open redirect in Apache HTTP Server 2.4.0 to 2.4.41 · versio…
   Likely to be exploited (1)
     High modelled chance of exploitation soon (EPSS).
     ✔ CVE-2020-11022  MEDIUM 6.1 EPSS 31% no template jQuery 1.12.4 ▸ 3.5.0
=======
   Exploited in the wild (1)
     Attackers are using these right now (CISA KEV). Patch first.
     CVE-2020-1927   HIGH 7.5   KEV nuclei Apache HTTP Server 2.4.41
       mod\_rewrite open redirect in Apache HTTP Server 2.4.0 to 2.4.41 · versio…
   Likely to be exploited (1)
     High modelled chance of exploitation soon (EPSS).
     CVE-2020-11022  MEDIUM 6.1 EPSS 31% jQuery 1.12.4 ▸ 3.5.0
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16
       XSS in jQuery htmlPrefilter
   checked: Apache HTTP Server 2.4.41, jQuery 1.12.4, PHP 7.4.3, WordPress 6.4.2
   Matches are by detected version. Banners can be spoofed and distributions
   backport fixes: treat 'medium'/'low' confidence as leads to verify.

── Nuclei: suggested next step  ───────────────────────────────────────────────
   Templates worth running next. Suggestions only; nothing was executed.
<<<<<<< HEAD
     tags: wordpress (1102), php (210), apache (143), graphql (22), jquery (14)
   ▸ nuclei -u http://127.0.0.1:45913/ -tags wordpress,php,apache,graphql,jquer…
   5 matched CVE(s) have no Nuclei template yet, including CVE-2020-1927,
   CVE-2020-11022, CVE-2020-11023 (+2 more)
   1 matched CVE(s) were suppressed as a platform mismatch, including
   CVE-2023-25690: see the CVE section for why
```
=======
     CVE-2020-1927     medium   Apache HTTP Server 2.4.41 matches CVE-2020-1927…
     tags: wordpress (1102), php (210), apache (143), graphql (22), jquery (14)
   ▸ nuclei -u http://127.0.0.1:60935/ -id CVE-2020-1927 -rl 20 -timeout 10
   ▸ nuclei -u http://127.0.0.1:60935/ -tags wordpress,php,apache,graphql,jquer…
   nuclei was not found in PATH (see
   https://github.com/projectdiscovery/nuclei); update templates with `nuclei…
```

>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16
<sub>Real output (80 columns, `--brief`) from a local test fixture with a small test database. `-v` adds every finding and the evidence behind each claim.</sub>

## What one command does

<<<<<<< HEAD
| Stage | What you get |
|---|---|
| **Fingerprint** | Technologies and versions from the community Wappalyzer data ([enthec/webappanalyzer](https://github.com/enthec/webappanalyzer)), matched against the *JavaScript-rendered* page. Every detection shows the header, cookie, script, DOM node or global it came from. |
| **Posture** | Security headers, CSP grade, TLS and certificate, HTTP/2/3, cookie flags, `security.txt`, third parties and SRI, edge/CDN attribution, header-contradiction detection. |
| **CVEs** | Each detected version is matched to known CVEs and ranked by what matters: *exploited in the wild* (CISA KEV) → *public exploit* (Exploit-DB) → *likely* (EPSS) → *severe on paper* → *minor*. A platform precondition (e.g. a Windows-only CVE) is checked against the target's detected OS; a mismatch is shown separately as *suppressed*, never mixed into the exploitable list. Fixed versions included. |
| **JS recon** | Endpoints (including Next.js's own route manifest and lazy-loaded chunks), GraphQL/tRPC operations, internal/staging hosts, cloud-storage references, build-time config, HTML comments, DOM/`postMessage` sinks, and **exposed secrets** — all found in code the site already serves. Secrets are always redacted and never tested. |
| **Verify** | A single read-only request per discovered endpoint (ranked, capped) to see what's actually live, plus the standard `robots.txt`/`sitemap.xml`/OpenAPI convention paths — the same category as `security.txt`. Never a guessed path. |
| **Active checks** | A handful of read-only requests: HTTP methods, CORS reflection, HTTP to HTTPS redirect, error-page disclosure, accepted TLS versions, GraphQL introspection, npm dependency-confusion (checked against the public npm registry, never the target). `--passive` turns the target-touching ones off. |
| **Nuclei** | Exact CVE template IDs and validated tags, with ready-to-paste, rate-limited commands — drawn only from CVEs Nuclei can actually test; the report says exactly how many were left out and why. **Suggested, never executed.** |
| **Report** | A priority action list, then headed sections with a one-line explanation each. `--json` for automation. |
=======
|Stage|What you get|
|-|-|
|**Fingerprint**|Technologies and versions from the community Wappalyzer data ([enthec/webappanalyzer](https://github.com/enthec/webappanalyzer)), matched against the *JavaScript-rendered* page. Every detection shows the header, cookie, script, DOM node or global it came from.|
|**Posture**|Security headers, CSP grade, TLS and certificate, HTTP/2/3, cookie flags, `security.txt`, third parties and SRI, edge/CDN attribution, header-contradiction detection.|
|**CVEs**|Each detected version is matched to known CVEs and ranked by what matters: *exploited in the wild* (CISA KEV) → *public exploit* (Exploit-DB) → *likely* (EPSS) → *severe on paper* → *minor*. Fixed versions included.|
|**JS recon**|Endpoints, internal/staging hosts, cloud-storage references, HTML comments and **exposed secrets** found in the site's own code. Secrets are always redacted and never tested.|
|**Active checks**|A handful of read-only requests: HTTP methods, CORS reflection, HTTP to HTTPS redirect, error-page disclosure, accepted TLS versions, GraphQL introspection. `--passive` turns them off.|
|**Nuclei**|Exact CVE template IDs and validated tags, with ready-to-paste, rate-limited commands. **Suggested, never executed.**|
|**Report**|A priority action list, then headed sections with a one-line explanation each. `--json` for automation.|
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16

Everything happens in the terminal. The tool drives a headless Chromium internally to render JavaScript; you never open a browser, and without Chromium it falls back to static analysis.

## Install (like any Kali tool: normal user, no root)

```bash
<<<<<<< HEAD
git clone https://github.com/YOUR-GITHUB-USER/npc-fingerprint.git
=======
git clone https://github.com/custom-npc/npc-fingerprint.git
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16
cd npc-fingerprint
./install.sh
```

<<<<<<< HEAD
`install.sh` uses **pipx** if present (the Kali default), else **uv**, else a private virtualenv in `~/.local/share/npc-fingerprint`. It never calls `sudo`, then runs `npc-fingerprint setup`, which at user level:

1. makes sure a Chromium is available (uses a system Chromium if you have one, otherwise downloads Playwright's into `~/.cache`);
=======
`install.sh` uses **pipx** if present (the Kali default), else **uv**, else a private virtualenv in `\~/.local/share/npc-fingerprint`. It never calls `sudo`, then runs `npc-fingerprint setup`, which at user level:

1. makes sure a Chromium is available (uses a system Chromium if you have one, otherwise downloads Playwright's into `\~/.cache`);
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16
2. downloads the data: fingerprints, favicon hashes, JavaScript advisories, **NVD CVE applicability**, KEV, EPSS, Exploit-DB and the Nuclei template index (public sources, no keys).

The first run downloads a few hundred MB (the NVD feeds dominate); later runs fetch only what changed. Check state any time with `npc-fingerprint setup --check`.

<<<<<<< HEAD
Other ways: `pipx install .`, `uv tool install .`, or `pip install .` inside a virtualenv, then `npc-fingerprint setup`. If PATH lacks `~/.local/bin`, the installer tells you the one line to add. Uninstall: `./install.sh --uninstall`.
=======
Other ways: `pipx install .`, `uv tool install .`, or `pip install .` inside a virtualenv, then `npc-fingerprint setup`. If PATH lacks `\~/.local/bin`, the installer tells you the one line to add. Uninstall: `./install.sh --uninstall`.
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16

**Minimal systems:** if Chromium cannot start because system libraries are missing, `setup` says so and the tool keeps working with `--no-browser` (static analysis). Fixing it without root is possible by installing a system Chromium; Playwright's own `install-deps` helper needs root once and is the only root-requiring option (never run for you).

## Use

```bash
npc-fingerprint -u https://example.com           # everything: live progress, then the report
npc-fingerprint -u example.com -v                # + all findings and the evidence trace
npc-fingerprint -u https://example.com --brief   # card, priority actions, CVEs, Nuclei only
npc-fingerprint -u https://example.com --json > report.json
<<<<<<< HEAD
npc-fingerprint -u https://example.com --output sarif > report.sarif   # for GitHub code scanning / DefectDojo
npc-fingerprint -u https://example.com --diff report.json       # what changed since last time
npc-fingerprint -f targets.txt --passive         # many targets, no active checks
npc-fingerprint -u https://example.com --cookie "session=abc123" --header "X-Api-Key:test"   # scan behind a login
npc-fingerprint -u https://example.com --scope api.example.net  # also allow verifying an extra, declared domain
=======
npc-fingerprint -u https://example.com --baseline report.json   # what changed since last time
npc-fingerprint -f targets.txt --passive         # many targets, no active checks
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16
npcf -u http://localhost:8000 --no-browser       # `npcf` is a short alias
npc-fingerprint db update                        # refresh the data (changed NVD years only)
```

<<<<<<< HEAD
| Flag | Meaning |
|---|---|
| `-u, --url` / positional, `-f FILE` | Targets. A bare host tries `https://` then `http://`. |
| `--output {text,json,sarif}` | Report format; `--json` still works as a shorthand for `--output json`. |
| `-v` / `--brief` / `--summary` | Everything + evidence / the parts you act on / the one-screen card only. |
| `--passive` | No active checks or endpoint/schema verification (the page is still loaded; the npm registry check still runs, since it never touches the target). |
| `--offline` | No network except the target; CVE data and npm checks from local files/caches only. |
| `--skip LIST` | Skip stages: `favicon,bundle,recon,verify,active,vulns,nuclei,dns`. |
| `--no-browser` | Static HTML only: fast, misses JavaScript-rendered content. |
| `--baseline FILE` / `--diff FILE` | Same flag, two names. Previous `--json`; adds a drift view (new/removed technologies, CVEs, secrets, header changes). |
| `--scope DOMAIN[,...]` | Extra domain(s), beyond the target's own, allowed for endpoint verification; anything else found stays reported, never requested. |
| `--header NAME:VALUE` (repeatable), `--cookie VALUE` | Sent on every request — for one low-privilege authenticated scan. There's no built-in unauthenticated-vs-authenticated diff yet (see Limitations). |
| `--no-live`, `--ascii`, `--no-color`, `-q`, `--width N` | Terminal tuning. `NO_COLOR` and `NPC_NO_ANIM=1` (reduced motion) are honoured. |
| `setup [--check --no-browser --no-data --since YEAR]`, `db update [--only LIST --force]`, `db status` | Install and refresh data. |
=======
|Flag|Meaning|
|-|-|
|`-u, --url` / positional, `-f FILE`|Targets. A bare host tries `https://` then `http://`.|
|`--json`|Pure JSON on stdout; no colour, no live view.|
|`-v` / `--brief` / `--summary`|Everything + evidence / the parts you act on / the one-screen card only.|
|`--passive`|No active checks (the page is still loaded).|
|`--offline`|No network except the target; CVE data from local files and caches.|
|`--skip LIST`|Skip stages: `favicon,bundle,recon,active,vulns,nuclei,dns`.|
|`--no-browser`|Static HTML only: fast, misses JavaScript-rendered content.|
|`--baseline FILE`|Previous `--json`; adds a drift view (new/removed technologies, CVEs, secrets, header changes).|
|`--no-live`, `--ascii`, `--no-color`, `-q`, `--width N`|Terminal tuning. `NO\_COLOR` and `NPC\_NO\_ANIM=1` (reduced motion) are honoured.|
|`setup \[--check --no-browser --no-data --since YEAR]`, `db update \[--only LIST --force]`, `db status`|Install and refresh data.|
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16

Exit codes: `0` ok, `1` a target was unreachable, `2` usage error, `130` interrupted.

### Reading the CVE section

<<<<<<< HEAD
Matching a version is not the same as being exploitable, so CVEs are grouped by evidence of real-world use, each with a one-line meaning, and a **state** icon that's consistent with the rest of the report:

| Group | Meaning |
|---|---|
| Exploited in the wild | In CISA's KEV catalogue. Patch first. |
| Public exploit available | Exploit code exists (Exploit-DB). |
| Likely to be exploited | EPSS probability of 10% or more in the next 30 days. |
| Severe, no known exploitation | High CVSS but no sign of use. |
| Lower priority | Everything else. |
| Suppressed: platform mismatch | The version matches, but the CVE needs an OS the target plainly isn't running (e.g. a Windows-only IIS CVE on a Linux-hosted site). Shown for transparency, never actionable, never suggested to Nuclei. |

Every match also carries:
- **A state** — ✔ confirmed, ▲ lead, ○ unverified, or − suppressed — driven by the evidence behind it, not just severity.
- **A coverage badge** — `nuclei` (Nuclei can test this now), `no template` (a real match, but Nuclei has nothing for it yet), or `mismatch` (platform-suppressed) — so a report naming several CVEs never leaves you guessing why Nuclei's suggestions came back shorter than the CVE list. A one-line summary above the groups spells out the same three counts.
- **Honest caveats**: a version taken only from a banner can be spoofed, and Linux distributions backport fixes without changing the version (`Apache/2.4.41 (Ubuntu)`), so those matches are marked *medium* confidence — leads to verify, not verdicts. `-v` shows the exact signals behind the confidence level (`confidence_signals`).
=======
Matching a version is not the same as being exploitable, so CVEs are grouped by evidence of real-world use, each with a one-line meaning:

|Group|Meaning|
|-|-|
|Exploited in the wild|In CISA's KEV catalogue. Patch first.|
|Public exploit available|Exploit code exists (Exploit-DB).|
|Likely to be exploited|EPSS probability of 10% or more in the next 30 days.|
|Severe, no known exploitation|High CVSS but no sign of use.|
|Lower priority|Everything else.|

Badges show `KEV`, `PoC`, `EPSS %` and `nuclei` (a template exists). Each match also carries honest caveats: a version taken only from a banner can be spoofed, and Linux distributions backport fixes without changing the version (`Apache/2.4.41 (Ubuntu)`), so those matches are marked *medium* confidence: leads to verify, not verdicts.
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16

### Where the CVE data comes from (and why)

* **OSV.dev** for framework and library versions (npm, PyPI, Packagist, Maven, RubyGems, Go): free, keyless, current, and version-range exact per ecosystem. Only a package name and version are sent, never the target. Answers are cached for 24 h and survive outages.
* **NVD 2.0 feeds** (official, free, bulk) for server software and CMSs without a package ecosystem (nginx, Apache, PHP, WordPress, ...), stored in a compact local SQLite file.
* **Enrichment:** CISA KEV, FIRST EPSS, Exploit-DB, nuclei-templates.

<<<<<<< HEAD
NVD alone is no longer enough: NIST now triages enrichment and many new CVEs arrive with no affected-product data. The tool counts those and tells you ("NVD has not analysed N recent CVEs that mention nginx") instead of silently reporting nothing. Details in [docs/RESEARCH.md](docs/RESEARCH.md), including the full round-3 decision log (every proposed feature: implemented, deferred, or rejected, with why).

## Guarantees

* **Defensive and read-only.** No exploitation, brute forcing, credential testing, subdomain enumeration or hidden-path discovery. Active and verification checks are single GET/OPTIONS/HEAD requests (plus one read-only GraphQL query if the site's own JavaScript names a GraphQL endpoint). Endpoint reachability and shadow-version checks follow only paths the site's own code or declared conventions named — nothing is guessed.
* **Scope-guarded.** Every new active-probing feature checks the target's own domain (or an explicitly declared `--scope`) before requesting anything; out-of-scope references are still reported, never fetched.
* **Secrets never leave the page in full.** Findings show the first 4 and last 2 characters and the length. Found credentials are never used or validated.
* **Nothing is executed for you.** Nuclei commands are text. The suggestion module has no way to launch a process (enforced by a test that patches `subprocess.run`/`Popen` to fail loudly if called).
* **Our own follow-up requests stay out of internal address space** when the target is public (no pointing the tool at `169.254.169.254` through a hostile page).
* **What leaves your machine:** requests to the target; package name and version to OSV; scoped package names to the public npm registry; DNS lookups to your resolver; downloads during `setup`/`db update`. Nothing else.
* **Evidence for every claim.** Weak evidence is labelled weak; header-only claims are marked `claimed`; contradictions mark technologies `disputed`; a CVE whose platform doesn't match is marked `suppressed`, never silently dropped or silently kept.
=======
NVD alone is no longer enough: NIST now triages enrichment and many new CVEs arrive with no affected-product data. The tool counts those and tells you ("NVD has not analysed N recent CVEs that mention nginx") instead of silently reporting nothing. Details in [docs/RESEARCH.md](docs/RESEARCH.md).

## Guarantees

* **Defensive and read-only.** No exploitation, brute forcing, credential testing, subdomain enumeration or hidden-path discovery. Active checks are single GET/OPTIONS/HEAD requests (plus one read-only GraphQL query if the site's own JavaScript names a GraphQL endpoint).
* **Secrets never leave the page in full.** Findings show the first 4 and last 2 characters and the length. Found credentials are never used or validated.
* **Nothing is executed for you.** Nuclei commands are text. The suggestion module has no way to launch a process.
* **Our own follow-up requests stay out of internal address space** when the target is public (no pointing the tool at `169.254.169.254` through a hostile page).
* **What leaves your machine:** requests to the target; package name and version to OSV; DNS lookups to your resolver; downloads during `setup`/`db update`. Nothing else.
* **Evidence for every claim.** Weak evidence is labelled weak; header-only claims are marked `claimed`; contradictions mark technologies `disputed`.
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16

## Limitations

* Version matching cannot see backports or custom builds; the caveats above are the mitigation, not a cure.
<<<<<<< HEAD
* **Platform detection is a lead, not a certificate.** It reads Server/X-Powered-By banners and known Linux-hosting edges (Vercel, Netlify, CloudFront, ...); an undetermined platform never suppresses a finding, but a platform *claimed* by a spoofable banner is still only as trustworthy as that banner.
* Technologies detected without a version cannot be matched and are listed as "not checked".
* NVD gaps (above). OSV covers packaged software only. CVSS v4-only records fall back to the vendor's severity label.
* Static mode cannot see JavaScript globals, DOM rules or XHR hosts. JS recon in static mode downloads at most 8 first-party scripts (plus any Next.js manifest chunks and lazy chunks found, bounded separately).
* The secret scanner is pattern-based: high-confidence formats are reliable; generic "hard-coded credential" hits are medium confidence by design.
* **DOM/`postMessage` sinks are leads, not findings**: a sink's presence, or a listener with no `.origin` check in the next ~300 characters of code, is a place worth a manual look, not proof of exploitability.
* **Next.js mining relies on the app's own build manifest**, which only exists for that framework; other bundlers only get the generic literal-reference lazy-chunk following, which finds less.
* **No automated authenticated-vs-unauthenticated comparison yet.** `--cookie`/`--header` let you scan one session (e.g. low-privilege logged-in); diffing that against an anonymous run to spot privilege-escalation surface is not implemented (see docs/RESEARCH.md for why it's deferred, not dropped).
=======
* Technologies detected without a version cannot be matched and are listed as "not checked".
* NVD gaps (above). OSV covers packaged software only. CVSS v4-only records fall back to the vendor's severity label.
* Static mode cannot see JavaScript globals, DOM rules or XHR hosts. JS recon in static mode downloads at most 8 first-party scripts.
* The secret scanner is pattern-based: high-confidence formats are reliable; generic "hard-coded credential" hits are medium confidence by design.
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16
* TLS version probing depends on your local OpenSSL; versions it cannot try are reported as "could not be tested", never as a pass.
* Page subresources load exactly as in any browser, including requests a hostile public page makes to internal addresses.
* Tested here with fixture servers and Playwright 1.56/Chromium 141; the CI workflow runs the matrix on Python 3.11-3.14 once the repo is on GitHub.

## Development

```bash
<<<<<<< HEAD
pip install -e ".[dev]" && python -m playwright install chromium
python -m unittest discover -s tests -v     # 220+ tests, local fixtures only, no real third-party hosts
=======
pip install -e ".\[dev]" \&\& python -m playwright install chromium
python -m unittest discover -s tests -v     # 160+ tests, local fixtures only, no real third-party hosts
>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16
ruff check .
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md), [SECURITY.md](SECURITY.md). Dependencies float to the newest releases (no upper bounds) and Dependabot opens weekly update PRs.

## Licence and data

GPL-3.0-or-later (`LICENSE`). Downloaded data keeps its own licence: enthec/webappanalyzer (GPL-3.0), retire.js (Apache-2.0), OWASP favicon database (CC BY 3.0), Exploit-DB (GPL-2.0 data), NVD/KEV/EPSS (public data), nuclei-templates (check its repository licence before redistributing a built copy). Nothing but small hand-written seed files is bundled. I am not a lawyer; verify before redistributing.

## Legal notice

Use this tool only on systems you own or are explicitly authorised to assess. It performs ordinary page loads and a few read-only requests, but you are responsible for complying with law, terms of service and scope agreements. Provided without warranty.
<<<<<<< HEAD
=======

>>>>>>> bb7f678485965c5717967a6ddc67f4a955146a16
