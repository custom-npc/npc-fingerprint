"""NVD 2.0 JSON feeds -> compact local applicability database.

Why feeds and not the API: official, free, keyless, bulk (nightly year files, 2-hourly modified/recent), no 5-requests-per-30-s
ceiling. Why only a *subset* is kept: we only need CVEs whose CPE applicability names a product the fingerprint database can
detect. Why a streaming parser: a year file inflates to hundreds of MB.

Known gap (2026): NIST no longer enriches most new CVEs, so recent entries often carry no CPE data at all. Those are kept in
`unanalyzed` so the tool can say "NVD has not analysed N CVEs that mention <product>" instead of silently reporting nothing.
"""
from __future__ import annotations

import codecs
import gzip
import json
import re
import shutil
import sqlite3
import tempfile
import urllib.request
from collections.abc import Callable, Iterator
from datetime import date
from pathlib import Path

from .. import UA_TOKEN
from ..util import cmp_version
from .cvss import severity as sev_of

FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
CPE_SPLIT = re.compile(r"(?<!\\):")
UNANALYZED_SINCE = "2024-01-01"

# Tech-name -> CPE (vendor, product) pairs NVD actually uses (several products changed vendor over time).
CPE_ALIASES: dict[str, list[tuple[str, str]]] = {
    "nginx": [("f5", "nginx"), ("nginx", "nginx"), ("igor_sysoev", "nginx")],
    "apachehttpserver": [("apache", "http_server")],
    "apache": [("apache", "http_server")],
    "php": [("php", "php")],
    "openssl": [("openssl", "openssl")],
    "wordpress": [("wordpress", "wordpress")],
    "drupal": [("drupal", "drupal")],
    "joomla": [("joomla", "joomla!")],
    "microsoftiis": [("microsoft", "internet_information_services")],
    "iis": [("microsoft", "internet_information_services")],
    "nodejs": [("nodejs", "node.js")],
    "apachetomcat": [("apache", "tomcat")],
    "tomcat": [("apache", "tomcat")],
    "lighttpd": [("lighttpd", "lighttpd")],
    "litespeed": [("litespeedtech", "litespeed_web_server"), ("litespeedtech", "openlitespeed")],
    "caddy": [("caddyserver", "caddy")],
    "haproxy": [("haproxy", "haproxy")],
    "varnish": [("varnish-cache", "varnish"), ("varnish-software", "varnish_cache")],
    "mysql": [("oracle", "mysql")],
    "mariadb": [("mariadb", "mariadb")],
    "postgresql": [("postgresql", "postgresql")],
    "jquery": [("jquery", "jquery")],
    "jqueryui": [("jqueryui", "jquery_ui")],
    "bootstrap": [("getbootstrap", "bootstrap"), ("twitter", "bootstrap")],
    "angularjs": [("angularjs", "angular.js"), ("google", "angularjs")],
    "django": [("djangoproject", "django")],
    "rubyonrails": [("rubyonrails", "rails"), ("rubyonrails", "ruby_on_rails")],
    "laravel": [("laravel", "laravel")],
    "grafana": [("grafana", "grafana")],
    "gitlab": [("gitlab", "gitlab")],
    "jenkins": [("jenkins", "jenkins")],
    "phpmyadmin": [("phpmyadmin", "phpmyadmin")],
    "magento": [("magento", "magento"), ("adobe", "magento")],
    "typo3": [("typo3", "typo3")],
    "moodle": [("moodle", "moodle")],
    "roundcube": [("roundcube", "webmail"), ("roundcube", "roundcube_webmail")],
    "squid": [("squid-cache", "squid")],
    "exim": [("exim", "exim")],
    "postfix": [("postfix", "postfix")],
    "owncloud": [("owncloud", "owncloud")],
    "nextcloud": [("nextcloud", "nextcloud_server"), ("nextcloud", "nextcloud")],
    "confluence": [("atlassian", "confluence_server"), ("atlassian", "confluence_data_center")],
    "jira": [("atlassian", "jira"), ("atlassian", "jira_server")],
    "elasticsearch": [("elastic", "elasticsearch")],
    "kibana": [("elastic", "kibana")],
    "springframework": [("vmware", "spring_framework"), ("pivotal_software", "spring_framework")],
    "apachestruts": [("apache", "struts")],
    "gunicorn": [("gunicorn", "gunicorn")],
    "werkzeug": [("palletsprojects", "werkzeug")],
    "flask": [("palletsprojects", "flask")],
}


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def parse_cpe(c: str) -> tuple[str, str, str, str, str] | None:
    parts = CPE_SPLIT.split(c or "")
    if len(parts) < 7 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    un = lambda s: re.sub(r"\\(.)", r"\1", s).lower()  # noqa: E731
    return parts[2], un(parts[3]), un(parts[4]), un(parts[5]), un(parts[6])


def wanted_products(techs: dict) -> set[tuple[str, str]]:
    """Every (vendor, product) the fingerprint DB can detect (its `cpe` fields) plus the alias table."""
    out: set[tuple[str, str]] = {p for lst in CPE_ALIASES.values() for p in lst}
    for t in techs.values():
        c = parse_cpe(t.get("cpe", "")) if isinstance(t, dict) else None
        if c:
            out.add((c[1], c[2]))
    return out


def products_for(name: str, tech: dict | None) -> list[tuple[str, str]]:
    out = list(CPE_ALIASES.get(norm(name), []))
    c = parse_cpe((tech or {}).get("cpe", ""))
    if c and (c[1], c[2]) not in out:
        out.append((c[1], c[2]))
    return out


# ----------------------------------------------------------------------------
# streaming parse
# ----------------------------------------------------------------------------

def iter_vulnerabilities(fp, chunk: int = 1 << 20) -> Iterator[dict]:
    """Yield each element of the top-level "vulnerabilities" array without loading the file."""
    dec, utf8 = json.JSONDecoder(), codecs.getincrementaldecoder("utf-8")("replace")
    buf = ""

    def more() -> bool:
        nonlocal buf
        data = fp.read(chunk)
        if not data:
            buf += utf8.decode(b"", final=True)
            return False
        buf += utf8.decode(data)
        return True

    start = -1
    while start < 0:
        i = buf.find('"vulnerabilities"')
        if i >= 0:
            j = buf.find("[", i)
            if j >= 0:
                start = j + 1
                break
        if not more():
            return
    buf, idx = buf[start:], 0
    while True:
        while True:
            while idx < len(buf) and buf[idx] in " \t\r\n,":
                idx += 1
            if idx < len(buf):
                break
            buf, idx = "", 0
            if not more():
                return
        if buf[idx] == "]":
            return
        try:
            obj, end = dec.raw_decode(buf, idx)
        except json.JSONDecodeError:
            if not more():
                raise
            buf, idx = buf[idx:], 0
            continue
        yield obj
        idx = end


def _pick_cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if not arr:
            continue
        m = sorted(arr, key=lambda x: 0 if x.get("type") == "Primary" else 1)[0]
        d = m.get("cvssData", {})
        score = d.get("baseScore")
        sev = (d.get("baseSeverity") or m.get("baseSeverity") or "").lower() or sev_of(score)
        return score, sev, d.get("vectorString")
    return None, None, None


def parse_item(item: dict, wanted: set[tuple[str, str]]):
    """-> (cve_row, [affected_rows], unanalyzed_row|None, unbounded_skipped) or None for rejected/irrelevant."""
    cve = item.get("cve", item)
    cid = cve.get("id")
    if not cid or cve.get("vulnStatus") == "Rejected":
        return None
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    if desc.startswith("** REJECT"):
        return None
    published = (cve.get("published") or "")[:10]
    score, sev, vector = _pick_cvss(cve.get("metrics", {}))
    cwe = next((w["value"] for ws in cve.get("weaknesses", []) for w in ws.get("description", []) if w.get("value", "").startswith("CWE-")), None)
    year = int(cid.split("-")[1]) if cid.count("-") == 2 and cid.split("-")[1].isdigit() else 0
    configs = cve.get("configurations") or []
    rows, unbounded = [], 0
    for cfg in configs:
        and_op = cfg.get("operator") == "AND"
        for node in cfg.get("nodes", []):
            if node.get("negate"):
                continue
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                c = parse_cpe(m.get("criteria", ""))
                if not c or (c[1], c[2]) not in wanted:
                    continue
                ver, upd = c[3], c[4]
                bounds = (m.get("versionStartIncluding"), m.get("versionStartExcluding"), m.get("versionEndIncluding"), m.get("versionEndExcluding"))
                if ver not in ("*", "-"):
                    if upd not in ("*", "-"):
                        continue                       # pre-release / update-specific CPE: do not guess
                    rows.append((cid, c[1], c[2], ver, None, None, None, None, int(and_op)))
                elif any(bounds):
                    rows.append((cid, c[1], c[2], None, *bounds, int(and_op)))
                else:
                    unbounded += 1                     # "all versions": too coarse to match a banner honestly
    cve_row = (cid, year, published, cve.get("vulnStatus", ""), score, sev, vector, cwe, desc[:400])
    un = None
    if not configs and published >= UNANALYZED_SINCE:
        un = (cid, year, published, score, sev, desc[:240])
    if not rows and un is None:
        return (None, [], None, unbounded) if unbounded else None
    return cve_row, rows, un, unbounded


def ingest(con: sqlite3.Connection, fp, wanted: set[tuple[str, str]], year: int | None = None) -> dict:
    stats = {"seen": 0, "kept": 0, "affected": 0, "unanalyzed": 0, "unbounded_skipped": 0}
    cves, aff, unal = [], [], []

    def flush():
        con.executemany("INSERT OR REPLACE INTO cve VALUES (?,?,?,?,?,?,?,?,?)", cves)
        for cid in {r[0] for r in aff}:
            con.execute("DELETE FROM affected WHERE cve = ?", (cid,))
        con.executemany("INSERT INTO affected VALUES (?,?,?,?,?,?,?,?,?)", aff)
        con.executemany("INSERT OR REPLACE INTO unanalyzed VALUES (?,?,?,?,?,?)", unal)
        cves.clear(); aff.clear(); unal.clear()

    for item in iter_vulnerabilities(fp):
        stats["seen"] += 1
        parsed = parse_item(item, wanted)
        if parsed is None:
            continue
        c, rows, un, unb = parsed
        stats["unbounded_skipped"] += unb
        if c is None:
            continue
        if rows:
            cves.append(c); aff += rows; stats["kept"] += 1; stats["affected"] += len(rows)
        elif un:
            cves.append(c)
        if un:
            unal.append(un); stats["unanalyzed"] += 1
        if len(cves) >= 4000:
            flush()
    flush()
    return stats


# ----------------------------------------------------------------------------
# year-by-year update (resumable, skips unchanged years via the .meta sha256)
# ----------------------------------------------------------------------------

def open_url(url: str, timeout: float = 90.0):
    req = urllib.request.Request(url, headers={"User-Agent": f"{UA_TOKEN} (db update)"})
    return urllib.request.urlopen(req, timeout=timeout)   # noqa: S310 - fixed https URLs


def parse_meta(text: str) -> dict[str, str]:
    return dict(ln.split(":", 1) for ln in text.splitlines() if ":" in ln)


def update_feeds(con: sqlite3.Connection, wanted: set[tuple[str, str]], since: int, opener: Callable = open_url,
                 log: Callable[[str], None] = lambda m: None, force: bool = False, tick: Callable[[str], None] = lambda s: None) -> dict:
    """Download + ingest every year >= `since`, plus nothing else: year files are refreshed nightly by NVD, so a
    re-run only re-downloads the years whose published sha256 changed (normally just the current one)."""
    meta_rows = {r[0]: r[1] for r in con.execute("SELECT key, value FROM meta")}
    totals = {"years": 0, "skipped": 0, "failed": 0, "kept": 0, "unanalyzed": 0}
    for year in range(since, date.today().year + 1):
        tick(f"NVD {year}")
        base = f"{FEED_BASE}/nvdcve-2.0-{year}"
        try:
            with opener(base + ".meta") as r:
                meta = parse_meta(r.read(10_000).decode("utf-8", "replace"))
            sig = meta.get("sha256") or meta.get("lastModifiedDate", "")
            if not force and sig and meta_rows.get(f"nvd_{year}") == sig:
                totals["skipped"] += 1
                continue
            with tempfile.NamedTemporaryFile(suffix=".json.gz", delete=False) as tmp:
                with opener(base + ".json.gz") as r:
                    shutil.copyfileobj(r, tmp, 1 << 20)
            try:
                con.execute("BEGIN")
                con.execute("DELETE FROM affected WHERE cve LIKE ?", (f"CVE-{year}-%",))
                con.execute("DELETE FROM cve WHERE year = ?", (year,))
                con.execute("DELETE FROM unanalyzed WHERE year = ?", (year,))
                with gzip.open(tmp.name, "rb") as fp:
                    st = ingest(con, fp, wanted, year)
                con.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (f"nvd_{year}", sig or "unknown"))
                con.commit()
            except Exception:
                con.rollback()
                raise
            finally:
                Path(tmp.name).unlink(missing_ok=True)
            totals["years"] += 1
            totals["kept"] += st["kept"]
            totals["unanalyzed"] += st["unanalyzed"]
            log(f"  NVD {year}: {st['seen']} CVEs scanned, {st['kept']} relevant, {st['unanalyzed']} awaiting analysis")
        except Exception as e:  # noqa: BLE001 - one bad year must not discard the rest
            totals["failed"] += 1
            log(f"  NVD {year}: FAILED ({type(e).__name__}: {e})")
    return totals


# ----------------------------------------------------------------------------
# version matching against one `affected` row
# ----------------------------------------------------------------------------

def row_matches(row, version: str) -> tuple[bool, str | None, str | None]:
    """(matches, fixed_version, human range). Unparseable versions never match (no guessing)."""
    if row["exact"]:
        c = cmp_version(version, row["exact"])
        return (c == 0), None, f"= {row['exact']}"
    lo_i, lo_e, hi_i, hi_e = row["vsi"], row["vse"], row["vei"], row["vee"]
    for bound, test in ((lo_i, lambda c: c >= 0), (lo_e, lambda c: c > 0), (hi_i, lambda c: c <= 0), (hi_e, lambda c: c < 0)):
        if bound:
            c = cmp_version(version, bound)
            if c is None or not test(c):
                return False, None, None
    parts = []
    if lo_i: parts.append(f">={lo_i}")
    if lo_e: parts.append(f">{lo_e}")
    if hi_i: parts.append(f"<={hi_i}")
    if hi_e: parts.append(f"<{hi_e}")
    return True, hi_e, ", ".join(parts)
