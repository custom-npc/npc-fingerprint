"""Local vulnerability knowledge base (SQLite, stdlib): NVD applicability + exploitation enrichment."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from ..util import data_dir

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS cve(id TEXT PRIMARY KEY, year INTEGER, published TEXT, status TEXT, cvss REAL, severity TEXT,
                               vector TEXT, cwe TEXT, summary TEXT);
CREATE TABLE IF NOT EXISTS affected(cve TEXT, vendor TEXT, product TEXT, exact TEXT, vsi TEXT, vse TEXT, vei TEXT, vee TEXT,
                                    conditional INTEGER);
CREATE INDEX IF NOT EXISTS affected_vp ON affected(vendor, product);
CREATE INDEX IF NOT EXISTS affected_cve ON affected(cve);
CREATE TABLE IF NOT EXISTS unanalyzed(id TEXT PRIMARY KEY, year INTEGER, published TEXT, cvss REAL, severity TEXT, summary TEXT);
CREATE TABLE IF NOT EXISTS kev(cve TEXT PRIMARY KEY, added TEXT, due TEXT, ransomware INTEGER, name TEXT, action TEXT);
CREATE TABLE IF NOT EXISTS epss(cve TEXT PRIMARY KEY, score REAL, pct REAL);
CREATE TABLE IF NOT EXISTS exploit(cve TEXT, source TEXT, ref TEXT, kind TEXT);
CREATE INDEX IF NOT EXISTS exploit_cve ON exploit(cve);
CREATE TABLE IF NOT EXISTS nuclei(cve TEXT PRIMARY KEY, template TEXT, severity TEXT, name TEXT, path TEXT);
CREATE TABLE IF NOT EXISTS nuclei_tags(tag TEXT PRIMARY KEY, n INTEGER);
"""


def db_path(directory: Path | None = None) -> Path:
    return (Path(directory) if directory else data_dir()) / "vulns.sqlite"


def connect(directory: Path | None = None, create: bool = False) -> sqlite3.Connection | None:
    p = db_path(directory)
    if not p.exists() and not create:
        return None
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(p))
    con.row_factory = sqlite3.Row
    if create:
        con.executescript(SCHEMA)
    return con


class VulnDB:
    """Read side. Every method degrades to an empty answer if the table or file is missing."""

    def __init__(self, con: sqlite3.Connection | None):
        self.con = con

    @classmethod
    def open(cls, directory: Path | None = None) -> "VulnDB":
        try:
            return cls(connect(directory))
        except sqlite3.Error:
            return cls(None)

    @property
    def available(self) -> bool:
        return self.con is not None

    def _q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        if self.con is None:
            return []
        try:
            return self.con.execute(sql, args).fetchall()
        except sqlite3.Error:
            return []

    def meta(self) -> dict[str, str]:
        return {r["key"]: r["value"] for r in self._q("SELECT key, value FROM meta")}

    def candidates(self, vendors: list[str], product: str) -> list[sqlite3.Row]:
        ph = ",".join("?" * len(vendors))
        return self._q(f"SELECT c.*, a.vendor, a.product, a.exact, a.vsi, a.vse, a.vei, a.vee, a.conditional FROM affected a "
                       f"JOIN cve c ON c.id = a.cve WHERE a.vendor IN ({ph}) AND a.product = ?", (*vendors, product))

    def cve(self, cve: str):
        rows = self._q("SELECT * FROM cve WHERE id = ?", (cve,))
        return rows[0] if rows else None

    def kev(self, cve: str):
        rows = self._q("SELECT * FROM kev WHERE cve = ?", (cve,))
        return rows[0] if rows else None

    def epss(self, cve: str):
        rows = self._q("SELECT * FROM epss WHERE cve = ?", (cve,))
        return rows[0] if rows else None

    def exploits(self, cve: str) -> list[sqlite3.Row]:
        return self._q("SELECT * FROM exploit WHERE cve = ?", (cve,))

    def nuclei(self, cve: str):
        rows = self._q("SELECT * FROM nuclei WHERE cve = ?", (cve,))
        return rows[0] if rows else None

    def nuclei_tag_counts(self) -> dict[str, int]:
        return {r["tag"]: r["n"] for r in self._q("SELECT tag, n FROM nuclei_tags")}

    def unanalyzed(self, term: str, limit: int = 200) -> list[sqlite3.Row]:
        return self._q("SELECT * FROM unanalyzed WHERE summary LIKE ? ORDER BY published DESC LIMIT ?", (f"%{term}%", limit))
