"""Command-line entry point: one command runs every feature.

    npc-fingerprint -u https://example.com        scan: fingerprint, posture, CVEs, JS recon, active checks, Nuclei suggestions
    npc-fingerprint setup                          one-time: user-level Chromium + databases (no root)
    npc-fingerprint db update | db status          refresh / inspect the data
"""
from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import SCHEMA_VERSION, TOOL_NAME, __version__
from .util import utcnow_iso

EPILOG = """\
examples:
  npc-fingerprint -u https://example.com            full scan (live progress, then a headed report)
  npc-fingerprint -u example.com -v                 add the evidence behind every claim
  npc-fingerprint -u https://example.com --json > report.json
  npc-fingerprint -u https://example.com --baseline report.json     what changed since last time
  npc-fingerprint -u http://localhost:8000 --no-browser --passive   static, no active checks
  npc-fingerprint setup                              first-time setup (browser + data), no root needed

Defensive reconnaissance only: public pages, read-only requests, nothing is exploited, brute-forced or guessed.
Scan only systems you own or are authorised to assess."""

SCAN_SKIPS = ("favicon", "bundle", "recon", "active", "vulns", "nuclei", "dns")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=TOOL_NAME, description="Evidence-based web fingerprinting, security posture, CVE matching, JS recon and Nuclei suggestions in one command.",
                                epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("urls", nargs="*", metavar="URL", help="targets (same as -u)")
    p.add_argument("-u", "--url", action="append", default=[], metavar="URL", help="target URL or host (repeatable); a bare host tries https then http")
    p.add_argument("-f", "--file", metavar="FILE", help="file with one target per line (# comments allowed)")
    p.add_argument("--json", action="store_true", help="machine-readable JSON on stdout (no colour, no live view; notices go to stderr)")
    p.add_argument("-v", "--verbose", action="store_true", help="show the evidence chain behind every claim and all findings")
    p.add_argument("--brief", action="store_true", help="only the card, priority actions, CVEs and Nuclei suggestions")
    p.add_argument("--summary", action="store_true", help="only the one-screen scan card")
    p.add_argument("--no-browser", action="store_true", help="skip JavaScript rendering (static HTML only; fast, misses SPAs)")
    p.add_argument("--passive", action="store_true", help="no active checks (CORS, methods, error page, TLS versions, GraphQL); the page is still loaded")
    p.add_argument("--offline", action="store_true", help="no network except the target: CVE data from local files and caches only")
    p.add_argument("--skip", metavar="LIST", help=f"comma list of stages to skip: {','.join(SCAN_SKIPS)}")
    p.add_argument("--baseline", metavar="FILE", help="previous --json report; adds a drift view (added/removed/changed)")
    p.add_argument("--timeout", type=float, default=20.0, metavar="SEC", help="per-target time budget (default 20)")
    p.add_argument("--no-dns", action="store_true", help="skip public DNS lookups (same as --skip dns)")
    p.add_argument("--no-cache", action="store_true", help="ignore the favicon and OSV caches")
    p.add_argument("--no-live", action="store_true", help="plain progress lines instead of the animated live view (also NPC_NO_ANIM=1)")
    p.add_argument("--ascii", action="store_true", help="ASCII-only glyphs (also automatic when the terminal cannot show Unicode)")
    p.add_argument("--no-color", action="store_true", help="disable colour (NO_COLOR is honoured too)")
    p.add_argument("--width", type=int, metavar="COLS", help="force the report width (default: terminal width, max 100)")
    p.add_argument("-q", "--quiet", action="store_true", help="no progress output on stderr")
    p.add_argument("--db-dir", metavar="DIR", help="use this database directory instead of the default")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    return p


def build_db_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=f"{TOOL_NAME} db", description="Manage the local databases.")
    sub = p.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("update", help="download and build the databases from public sources (no API keys)")
    u.add_argument("--only", metavar="LIST", help="comma list of: enthec,favicons,retire,nvd,enrich")
    u.add_argument("--from-tar", metavar="FILE", help="build the technology DB from a local webappanalyzer tarball (air-gapped use)")
    u.add_argument("--since", type=int, default=2010, metavar="YEAR", help="first NVD year to index (default 2010; later runs only fetch changed years)")
    u.add_argument("--force", action="store_true", help="re-download NVD years even if unchanged")
    u.add_argument("--timeout", type=float, default=90.0)
    u.add_argument("--db-dir", metavar="DIR")
    s = sub.add_parser("status", help="show what is installed")
    s.add_argument("--db-dir", metavar="DIR")
    return p


def build_setup_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=f"{TOOL_NAME} setup", description="One-time setup, entirely at user level (no root, no sudo): Chromium for JavaScript rendering and all databases.")
    p.add_argument("--check", action="store_true", help="only report what is installed and how fresh it is")
    p.add_argument("--no-browser", action="store_true", help="skip the Chromium step (static scanning still works)")
    p.add_argument("--no-data", action="store_true", help="skip the database downloads")
    p.add_argument("--since", type=int, default=2010, metavar="YEAR", help="first NVD year to index (default 2010)")
    p.add_argument("--no-live", action="store_true")
    p.add_argument("--ascii", action="store_true")
    p.add_argument("--db-dir", metavar="DIR")
    return p


# ----------------------------------------------------------------------------------------------------------
def _dep_versions() -> dict[str, str]:
    from importlib import metadata
    out = {}
    for name in ("playwright", "niquests", "regex", "mmh3", "cryptography", "rich", "dnspython", "pyyaml"):
        try:
            out[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            out[name] = "not installed"
    return out


def _age_days(iso: str | None) -> int | None:
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(iso.replace("Z", "+00:00"))).days
    except (AttributeError, ValueError):
        return None


def check_report(db_dir: str | None = None) -> list[tuple[str, str, str]]:
    """[(state, label, detail)] for `setup --check`; state is ok | warn | bad."""
    from .db import store
    from .fetch.browser import BrowserSession, BrowserUnavailable
    from .vulns.db import VulnDB
    rows: list[tuple[str, str, str]] = [("ok", "Python", f"{platform.python_version()} on {platform.system()}")]
    try:
        b = BrowserSession("check", 8)
        b.start()
        rows.append(("ok", "Chromium", b.browser_path or "ok"))
        b.close()
    except BrowserUnavailable as e:
        rows.append(("warn", "Chromium", f"unavailable (static scanning only): {e}"))
    db = store.load(db_dir)
    t = db.meta.get("technologies", {})
    age = _age_days(t.get("built_at"))
    rows.append(("warn" if db.seed else ("warn" if (age or 0) > 14 else "ok"), "Fingerprints",
                 "bundled seed only" if db.seed else f"{len(db.techs):,} technologies, built {t.get('built_at', '?')[:10]}" + (f" ({age} days old)" if age is not None else "")))
    v = VulnDB.open(db_dir)
    if v.available:
        m = v.meta()
        age = _age_days(m.get("updated_at"))
        rows.append(("warn" if (age or 0) > 14 else "ok", "CVE + exploit data", f"updated {m.get('updated_at', '?')[:10]}" + (f" ({age} days old)" if age is not None else "")
                     + f"; KEV {m.get('kev_count', '0')}, EPSS {m.get('epss_count', '0')}, Nuclei templates {m.get('nuclei_templates', '0')}"))
    else:
        rows.append(("warn", "CVE + exploit data", "not installed (OSV lookups still work online): run `npc-fingerprint setup`"))
    rows.append(("ok" if shutil.which("nuclei") else "warn", "Nuclei", shutil.which("nuclei") or "not found in PATH (only needed to run the suggested commands)"))
    for k, ver in _dep_versions().items():
        rows.append(("ok" if ver != "not installed" else "bad", f"  {k}", ver))
    return rows


def ensure_browser(say=lambda m: None) -> tuple[bool, str]:
    """User-level only: try launch; else `playwright install chromium` (downloads into ~/.cache, no root); retry."""
    from .fetch.browser import BrowserSession, BrowserUnavailable
    def attempt():
        b = BrowserSession("setup", 10)
        b.start()
        path = b.browser_path
        b.close()
        return path
    try:
        return True, attempt()
    except BrowserUnavailable as first:
        say("Chromium not found; installing it for your user (this downloads ~150 MB once)")
        try:
            r = subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], capture_output=True, text=True, timeout=1800)
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, f"could not run the Chromium installer: {e}"
        try:
            return True, attempt()
        except BrowserUnavailable as second:
            tail = (r.stderr or r.stdout or "").strip().splitlines()[-1:] or [""]
            msg = str(second)
            hint = ("Chromium needs system libraries that are missing. Without root you can still scan with --no-browser, or install a system Chromium "
                    "(then no download or extra libraries are needed). Optional, needs root once: `sudo python -m playwright install-deps chromium`.")
            return False, f"{msg} {tail[0]} | {hint}"


def setup_main(argv: list[str]) -> int:
    from .db import update as upd
    from .render import live
    from .render.theme import use_ascii
    a = build_setup_parser().parse_args(argv)
    if a.check:
        for state, label, detail in check_report(a.db_dir):
            print(f"[{ {'ok': 'ok', 'warn': '!!', 'bad': 'xx'}[state] }] {label:<20} {detail}")
        return 0
    steps = [("browser", "Chromium for JavaScript rendering"), ("enthec", "Technology fingerprints"), ("favicons", "Favicon hash database"),
             ("retire", "JavaScript library advisories"), ("nvd", "CVE applicability (NVD feeds)"), ("enrich", "Exploit data (KEV, EPSS, EDB, Nuclei)")]
    err = live.make_err_console()
    use_live = live.live_allowed(err, a.no_live, False, False)
    ascii_only = use_ascii(a.ascii, sys.stderr)
    plain = live.PlainReporter(ascii_only=ascii_only)
    pr = live.Progress(steps, "setup", on_done=None if use_live else plain.on_done)
    log_lines: list[str] = []
    failures = 0

    def run():
        nonlocal failures
        pr.start("browser", "Checking for Chromium")
        if a.no_browser:
            pr.skip("browser", "skipped (--no-browser)")
        else:
            ok, detail = ensure_browser(pr.say)
            pr.done("browser", detail if ok else "unavailable: static scanning still works", "ok" if ok else "warn")
            if not ok:
                log_lines.append(detail)
        if a.no_data:
            for k in ("enthec", "favicons", "retire", "nvd", "enrich"):
                pr.skip(k, "skipped (--no-data)")
        else:
            failures += upd.update(a.db_dir, None, None, log=lambda m: None, since=a.since, progress=pr)

    if use_live:
        with live.live_display(pr, err, ascii_only):
            run()
        for k in pr.steps:
            st, det, _ = pr.snapshot()
            print(f"  {st[k]:<5} {pr.labels[k]}: {det[k]}", file=sys.stderr)
    else:
        run()
    for ln in log_lines:
        print(f"note: {ln}", file=sys.stderr)
    print("\nSetup complete." if not failures else "\nSetup finished with warnings (see above); the tool still runs with what was installed.", file=sys.stderr)
    print("Try:  npc-fingerprint -u https://example.com", file=sys.stderr)
    return 1 if failures else 0


def db_main(argv: list[str]) -> int:
    from .db import update as upd
    a = build_db_parser().parse_args(argv)
    if a.cmd == "status":
        print(upd.status(a.db_dir))
        return 0
    only = set(a.only.split(",")) if a.only else None
    if only and not only <= set(upd.ALL_SOURCES):
        print(f"error: --only accepts {', '.join(upd.ALL_SOURCES)}", file=sys.stderr)
        return 2
    return upd.update(a.db_dir, only, a.from_tar, timeout=a.timeout, since=a.since, force_nvd=a.force)


def read_targets(args) -> list[str]:
    out = list(args.url) + list(args.urls)
    if args.file:
        for ln in Path(args.file).read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                out.append(ln)
    seen: set[str] = set()
    return [t for t in out if not (t in seen or seen.add(t))]


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "db":
        return db_main(argv[1:])
    if argv and argv[0] == "setup":
        return setup_main(argv[1:])
    args = build_parser().parse_args(argv)
    targets = read_targets(args)
    if not targets:
        build_parser().print_usage(sys.stderr)
        print(f"{TOOL_NAME}: error: give at least one target (-u URL), or run `{TOOL_NAME} setup` first", file=sys.stderr)
        return 2
    skip = set(filter(None, (args.skip or "").split(",")))
    if not skip <= set(SCAN_SKIPS):
        print(f"{TOOL_NAME}: error: --skip accepts {', '.join(SCAN_SKIPS)}", file=sys.stderr)
        return 2

    from .db import store
    from .modules import drift
    from .render import emit, live
    from .render.theme import use_ascii
    from .scanner import Options, Scanner

    def note(msg: str) -> None:
        if not args.quiet:
            print(msg, file=sys.stderr)

    baseline = None
    if args.baseline:
        try:
            baseline = drift.load_baseline(args.baseline)
        except (OSError, ValueError) as e:
            print(f"{TOOL_NAME}: error: cannot read baseline {args.baseline}: {e}", file=sys.stderr)
            return 2
    db = store.load(args.db_dir)
    age = _age_days((db.meta.get("technologies") or {}).get("built_at"))
    opts = Options(no_browser=args.no_browser, timeout=args.timeout, no_dns=args.no_dns, no_cache=args.no_cache, baseline=baseline,
                   passive=args.passive, offline=args.offline, skip=skip, db_dir=args.db_dir)
    console = None if args.json else emit.make_console(no_color=args.no_color, width=args.width)
    err_console = live.make_err_console(no_color=args.no_color)
    use_live = live.live_allowed(err_console, args.no_live, args.quiet, args.json)
    ascii_err = use_ascii(args.ascii, sys.stderr)
    plain = live.PlainReporter(ascii_only=ascii_err, quiet=args.quiet)

    reports: list[dict] = []
    failed = 0
    scanner = None
    try:
        scanner = Scanner(opts, db)
        if age is not None and age > 14:
            scanner.warnings.append(f"fingerprint database is {age} days old: run `{TOOL_NAME} db update`")
        for w in scanner.warnings:
            note(f"note: {w}")
        for i, t in enumerate(targets, 1):
            pr = live.Progress(live.SCAN_STEPS, t, on_done=None if use_live else plain.on_done)
            if not use_live:
                note(f"[{i}/{len(targets)}] scanning {t} ...")
            if use_live:
                with live.live_display(pr, err_console, ascii_err):
                    rep = scanner.scan(t, pr)
            else:
                rep = scanner.scan(t, pr)
            reports.append(rep)
            if rep["target"]["status"] is None:
                failed += 1
            if not args.json:
                emit.render_report(rep, console, verbose=args.verbose, ascii_only=args.ascii, width=args.width, brief=args.brief, summary_only=args.summary)
                if i < len(targets):
                    print()
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    finally:
        if scanner is not None:
            scanner.close()

    if args.json:
        first = reports[0] if reports else {}
        doc = {"schema_version": SCHEMA_VERSION, "schema_minor": 1, "tool": TOOL_NAME, "version": __version__, "generated_at": utcnow_iso(),
               "db": first.get("db", {}), "reports": reports}
        sys.stdout.write(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
