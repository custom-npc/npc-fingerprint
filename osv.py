"""OSV.dev client: free, keyless, continuously updated, version-range accurate for package ecosystems.

`POST /v1/query` matches the version server-side (ecosystem-aware semantics: semver, PEP 440, Maven, ...), so the
client only has to page through results and read fixed versions. Responses are cached on disk (24 h) so repeat scans
are instant and the tool keeps working offline for anything it has seen. Only package name + version are sent,
never the scanned host.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .. import UA_TOKEN
from ..util import cache_dir, cmp_version

BASE = "https://api.osv.dev"
CACHE_TTL = 24 * 3600
MAX_PAGES = 5


class OsvError(RuntimeError):
    pass


class OsvClient:
    def __init__(self, base: str = BASE, timeout: float = 8.0, offline: bool = False, use_cache: bool = True,
                 directory: Path | None = None):
        self.base, self.timeout, self.offline, self.use_cache = base.rstrip("/"), timeout, offline, use_cache
        self.dir = Path(directory) if directory else cache_dir() / "osv"
        self.stats = {"queries": 0, "cached": 0, "errors": 0}

    # -- cache ------------------------------------------------------------------------------------
    def _key(self, eco: str, pkg: str, ver: str) -> Path:
        return self.dir / (hashlib.sha1(f"{eco}\0{pkg}\0{ver}".encode()).hexdigest() + ".json")

    def _cache_get(self, p: Path, allow_stale: bool):
        try:
            d = json.loads(p.read_text())
            if allow_stale or time.time() - d["t"] < CACHE_TTL:
                return d["vulns"]
        except (OSError, ValueError, KeyError):
            pass
        return None

    def _cache_put(self, p: Path, vulns: list) -> None:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps({"t": time.time(), "vulns": vulns}))
        except OSError:
            pass

    # -- network ----------------------------------------------------------------------------------
    def _post(self, body: dict) -> dict:
        req = urllib.request.Request(self.base + "/v1/query", data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "User-Agent": f"{UA_TOKEN} (osv client)"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:   # noqa: S310 - fixed https endpoint
            return json.loads(r.read(20_000_000))

    def query(self, ecosystem: str, package: str, version: str) -> list[dict]:
        key = self._key(ecosystem, package, version)
        if self.use_cache:
            hit = self._cache_get(key, allow_stale=self.offline)
            if hit is not None:
                self.stats["cached"] += 1
                return hit
        if self.offline:
            raise OsvError("offline and not cached")
        vulns: list[dict] = []
        body = {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
        try:
            for _ in range(MAX_PAGES):
                self.stats["queries"] += 1
                data = self._post(body)
                vulns += data.get("vulns", [])
                tok = data.get("next_page_token")
                if not tok:
                    break
                body = {**body, "page_token": tok}
        except (urllib.error.URLError, OSError, ValueError) as e:
            self.stats["errors"] += 1
            stale = self._cache_get(key, allow_stale=True) if self.use_cache else None
            if stale is not None:
                return stale          # stale-if-error beats no answer
            raise OsvError(f"{type(e).__name__}: {e}") from e
        if self.use_cache:
            self._cache_put(key, vulns)
        return vulns

    def query_many(self, items: list[tuple[str, str, str]]) -> dict[tuple, list[dict] | OsvError]:
        out: dict[tuple, list[dict] | OsvError] = {}

        def one(t):
            try:
                return t, self.query(*t)
            except OsvError as e:
                return t, e
        with ThreadPoolExecutor(max_workers=4) as ex:
            for t, r in ex.map(one, items):
                out[t] = r
        return out


# ----------------------------------------------------------------------------
# reading OSV records
# ----------------------------------------------------------------------------

def cve_ids(vuln: dict) -> list[str]:
    ids = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
    if vuln.get("id", "").startswith("CVE-") and vuln["id"] not in ids:
        ids.insert(0, vuln["id"])
    return ids


def fixed_and_range(vuln: dict, package: str, ecosystem: str, version: str) -> tuple[str | None, str | None]:
    """(fixed version, human range) for the OSV `affected` interval that contains `version`."""
    for aff in vuln.get("affected", []):
        p = aff.get("package", {})
        if p.get("name", "").lower() != package.lower() or p.get("ecosystem", "").split(":")[0] != ecosystem:
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            intro: str | None = None
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    intro = ev["introduced"]
                elif "fixed" in ev:
                    lo_ok = intro in (None, "0") or (cmp_version(version, intro) or 0) >= 0
                    hi_ok = (cmp_version(version, ev["fixed"]) or 0) < 0
                    if lo_ok and hi_ok:
                        lo = "" if intro in (None, "0") else f">={intro}, "
                        return ev["fixed"], f"{lo}<{ev['fixed']}"
                    intro = None
                elif "last_affected" in ev:
                    lo_ok = intro in (None, "0") or (cmp_version(version, intro) or 0) >= 0
                    if lo_ok and (cmp_version(version, ev["last_affected"]) or 0) <= 0:
                        lo = "" if intro in (None, "0") else f">={intro}, "
                        return None, f"{lo}<={ev['last_affected']} (no fixed release listed)"
                    intro = None
    return None, None
