"""Exploitation / weaponisation enrichment loaders (all free, keyless, public):

  CISA KEV            known exploited in the wild (observation, not prediction)
  FIRST EPSS          probability of exploitation in the next 30 days
  Exploit-DB          public exploit code exists (files_exploits.csv)
  nuclei-templates    a Nuclei template exists (cves.json) + the tag vocabulary (TEMPLATES-STATS.json)
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import re
import sqlite3

SOURCES = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "exploitdb": "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
    "nuclei_cves": "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/HEAD/cves.json",
    "nuclei_stats": "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/HEAD/TEMPLATES-STATS.json",
}
CVE_RX = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def load_kev(con: sqlite3.Connection, data: bytes) -> int:
    doc = json.loads(data)
    rows = [(v["cveID"], v.get("dateAdded"), v.get("dueDate"), int(str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"),
             v.get("vulnerabilityName", ""), (v.get("requiredAction") or "")[:240]) for v in doc.get("vulnerabilities", []) if v.get("cveID")]
    if len(rows) < 100:
        raise ValueError(f"KEV feed has only {len(rows)} entries: refusing to replace the table")
    con.execute("DELETE FROM kev")
    con.executemany("INSERT OR REPLACE INTO kev VALUES (?,?,?,?,?,?)", rows)
    return len(rows)


def load_epss(con: sqlite3.Connection, data: bytes) -> int:
    text = (gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data).decode("utf-8", "replace")
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    rd = csv.reader(lines)
    header = next(rd, None)
    if not header or [h.strip().lower() for h in header[:3]] != ["cve", "epss", "percentile"]:
        raise ValueError("unexpected EPSS header")
    rows = []
    for r in rd:
        try:
            rows.append((r[0].upper(), float(r[1]), float(r[2])))
        except (IndexError, ValueError):
            continue
    if len(rows) < 1000:
        raise ValueError("EPSS feed suspiciously small")
    con.execute("DELETE FROM epss")
    con.executemany("INSERT OR REPLACE INTO epss VALUES (?,?,?)", rows)
    return len(rows)


def load_exploitdb(con: sqlite3.Connection, text: str) -> int:
    rows = []
    for r in csv.DictReader(io.StringIO(text)):
        eid = (r.get("id") or "").strip()
        for cve in {c.upper() for c in CVE_RX.findall(r.get("codes") or "")}:
            kind = " ".join(x for x in ((r.get("type") or "").strip(), (r.get("platform") or "").strip(), "verified" if (r.get("verified") or "0").strip() == "1" else "") if x)
            rows.append((cve, "exploit-db", eid, kind))
    if not rows:
        raise ValueError("no CVE-tagged exploits parsed from Exploit-DB CSV")
    con.execute("DELETE FROM exploit WHERE source = 'exploit-db'")
    con.executemany("INSERT INTO exploit VALUES (?,?,?,?)", rows)
    return len(rows)


def _json_records(text: str):
    text = text.strip()
    if text.startswith("["):
        yield from json.loads(text)
        return
    for ln in text.splitlines():
        ln = ln.strip().rstrip(",")
        if ln.startswith("{"):
            try:
                yield json.loads(ln)
            except ValueError:
                continue


def load_nuclei(con: sqlite3.Connection, cves_text: str | None, stats_text: str | None) -> tuple[int, int]:
    n_cves = n_tags = 0
    if cves_text:
        rows = []
        for rec in _json_records(cves_text):
            tid = str(rec.get("ID") or rec.get("id") or "").upper()
            if not CVE_RX.fullmatch(tid):
                continue
            info = rec.get("Info") or rec.get("info") or {}
            rows.append((tid, tid, str(info.get("Severity") or info.get("severity") or "").lower(), str(info.get("Name") or info.get("name") or "")[:120],
                         str(rec.get("file_path") or rec.get("path") or "")))
        if not rows:
            raise ValueError("no CVE templates parsed from nuclei cves.json")
        con.execute("DELETE FROM nuclei")
        con.executemany("INSERT OR REPLACE INTO nuclei VALUES (?,?,?,?,?)", rows)
        n_cves = len(rows)
    if stats_text:
        doc = json.loads(stats_text)
        tags = doc.get("tags", [])
        pairs = [(t["name"], int(t["count"])) for t in tags if isinstance(t, dict) and "name" in t and "count" in t] \
            if isinstance(tags, list) else [(k, int(v)) for k, v in tags.items()]
        if pairs:
            con.execute("DELETE FROM nuclei_tags")
            con.executemany("INSERT OR REPLACE INTO nuclei_tags VALUES (?,?)", pairs)
            n_tags = len(pairs)
    return n_cves, n_tags
