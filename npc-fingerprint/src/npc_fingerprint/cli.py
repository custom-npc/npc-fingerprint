"""Step 10: command-line entry point."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import SCHEMA_VERSION, TOOL_NAME, __version__
from .util import utcnow_iso

EPILOG = """\
examples:
  npc-fingerprint -u https://example.com
  npc-fingerprint -u example.com -v                 evidence trace for every detection
  npc-fingerprint -u https://example.com --json > report.json
  npc-fingerprint -u https://example.com --baseline report.json     what changed since last time
  npc-fingerprint -u http://localhost:8000 --no-browser             static only (no Chromium)
  npc-fingerprint db update                          download/refresh the fingerprint databases

Defensive reconnaissance only: it fetches public pages and reports what they expose.
Scan only systems you own or are authorised to assess."""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=TOOL_NAME, description="Evidence-based web technology fingerprinting and security-posture analysis.",
                                epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("urls", nargs="*", metavar="URL", help="targets (same as -u)")
    p.add_argument("-u", "--url", action="append", default=[], metavar="URL", help="target URL or host (repeatable); a bare host tries https then http")
    p.add_argument("-f", "--file", metavar="FILE", help="file with one target per line (# comments allowed)")
    p.add_argument("--json", action="store_true", help="machine-readable JSON on stdout (no colour, no card; notices go to stderr)")
    p.add_argument("-v", "--verbose", action="store_true", help="show the evidence chain behind every claim")
    p.add_argument("--no-browser", action="store_true", help="skip JavaScript rendering (static HTML only; fast, misses SPAs)")
    p.add_argument("--baseline", metavar="FILE", help="previous --json report; adds a drift view (added/removed/changed)")
    p.add_argument("--timeout", type=float, default=20.0, metavar="SEC", help="per-target time budget (default 20)")
    p.add_argument("--no-dns", action="store_true", help="skip public DNS lookups (CNAME/NS/MX/TXT/SOA)")
    p.add_argument("--no-cache", action="store_true", help="ignore the on-disk favicon cache")
    p.add_argument("--ascii", action="store_true", help="ASCII-only glyphs (also automatic when the terminal cannot show Unicode)")
    p.add_argument("--no-color", action="store_true", help="disable colour (NO_COLOR is honoured too)")
    p.add_argument("--width", type=int, metavar="COLS", help="force the card width (default: terminal width, max 100)")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress progress notices on stderr")
    p.add_argument("--db-dir", metavar="DIR", help="use this database directory instead of the default")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    return p


def build_db_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=f"{TOOL_NAME} db", description="Manage the local fingerprint databases.")
    sub = p.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("update", help="download and build the databases from public sources (no API keys)")
    u.add_argument("--only", metavar="LIST", help="comma list of: enthec,favicons,retire")
    u.add_argument("--from-tar", metavar="FILE", help="build the technology DB from a local webappanalyzer tarball (air-gapped use)")
    u.add_argument("--timeout", type=float, default=90.0)
    u.add_argument("--db-dir", metavar="DIR")
    s = sub.add_parser("status", help="show what is installed")
    s.add_argument("--db-dir", metavar="DIR")
    return p


def db_main(argv: list[str]) -> int:
    from .db import update as upd
    a = build_db_parser().parse_args(argv)
    if a.cmd == "status":
        print(upd.status(a.db_dir))
        return 0
    only = set(a.only.split(",")) if a.only else None
    if only and not only <= {"enthec", "favicons", "retire"}:
        print("error: --only accepts enthec, favicons, retire", file=sys.stderr)
        return 2
    return upd.update(a.db_dir, only, a.from_tar, timeout=a.timeout)


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
    args = build_parser().parse_args(argv)
    targets = read_targets(args)
    if not targets:
        build_parser().print_usage(sys.stderr)
        print(f"{TOOL_NAME}: error: give at least one target (-u URL)", file=sys.stderr)
        return 2

    from .db import store
    from .scanner import Options, Scanner
    from .modules import drift

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
    opts = Options(no_browser=args.no_browser, timeout=args.timeout, no_dns=args.no_dns, no_cache=args.no_cache, baseline=baseline)

    console = None
    if not args.json:
        from .render import emit
        console = emit.make_console(no_color=args.no_color, width=args.width)

    reports: list[dict] = []
    failed = 0
    scanner = None
    try:
        scanner = Scanner(opts, db)
        for w in scanner.warnings:
            note(f"note: {w}")
        for i, t in enumerate(targets, 1):
            note(f"[{i}/{len(targets)}] scanning {t} ...")
            rep = scanner.scan(t)
            reports.append(rep)
            if rep["target"]["status"] is None:
                failed += 1
            if not args.json:
                from .render import emit
                emit.render_report(rep, console, verbose=args.verbose, ascii_only=args.ascii, width=args.width)
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
        doc = {"schema_version": SCHEMA_VERSION, "tool": TOOL_NAME, "version": __version__, "generated_at": utcnow_iso(),
               "db": first.get("db", {}), "reports": reports}
        sys.stdout.write(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
