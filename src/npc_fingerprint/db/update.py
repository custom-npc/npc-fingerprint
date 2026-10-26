"""`npc-fingerprint db update`: build the local databases from public sources. No API keys anywhere.

  enthec/webappanalyzer       -> technologies.json + categories.json   (the living Wappalyzer-format fingerprints)
  nuclei-templates favicons   -> favicons.json (mmh3)                   (+ OWASP favicon DB, MD5)
  retire.js jsrepository.json -> retire.json                            (client-side library advisories)

Everything is written atomically, validated for plausibility, and recorded in meta.json (source URL,
commit when known, SHA-256 of the download, counts, timestamp) so every report can say which data it used.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from .. import UA_TOKEN
from ..util import data_dir, utcnow_iso

SOURCES = {
    "enthec": "https://github.com/enthec/webappanalyzer/archive/refs/heads/main.tar.gz",
    "nuclei": "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/HEAD/http/technologies/favicon-detect.yaml",
    "owasp": "https://raw.githubusercontent.com/OWASP/www-community/HEAD/_data/favicons-database.yml",
    "retire": "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json",
}
DROP_KEYS = {"icon", "description", "pricing", "saas", "oss", "css_note"}
MAX_DOWNLOAD = 300 * 1024 * 1024
SENTINEL_NAME = re.compile(r"zero.?byte|invalid|empty|no favicon|not a valid|blank", re.I)


class DBBuildError(RuntimeError):
    pass


def fetch(url: str, timeout: float = 90.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": f"{UA_TOKEN} (db update)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 - fixed https URLs above
        data = r.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise DBBuildError(f"{url} is larger than {MAX_DOWNLOAD // 1048576} MB; refusing")
    return data


def _atomic_write(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ----------------------------------------------------------------------------
# enthec/webappanalyzer
# ----------------------------------------------------------------------------

def parse_enthec_tar(data: bytes) -> tuple[dict, dict, str | None]:
    """Read technologies + categories straight from the tarball (members are never extracted to disk)."""
    techs: dict = {}
    cats: dict = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        commit = (getattr(tf, "pax_headers", {}) or {}).get("comment")   # GitHub archives carry the commit SHA here
        for m in tf:
            if not m.isfile() or m.size > 40 * 1024 * 1024:
                continue
            parts = m.name.split("/")
            if len(parts) >= 4 and parts[1:3] == ["src", "technologies"] and parts[3].endswith(".json"):
                techs.update(json.load(tf.extractfile(m)))
            elif len(parts) == 3 and parts[1:] == ["src", "categories.json"]:
                cats = json.load(tf.extractfile(m))
    if len(techs) < 500:
        raise DBBuildError(f"only {len(techs)} technologies found in the archive: layout changed or download truncated")
    compact = {n: {k: v for k, v in t.items() if k not in DROP_KEYS} for n, t in techs.items() if isinstance(t, dict)}
    cats = {str(k): {"name": v.get("name", str(k)), "priority": v.get("priority", 0)} for k, v in cats.items() if isinstance(v, dict)}
    return compact, cats, (commit if commit and re.fullmatch(r"[0-9a-f]{7,40}", commit) else None)


# ----------------------------------------------------------------------------
# favicons
# ----------------------------------------------------------------------------

def parse_nuclei_favicons(text: str) -> dict[str, dict[str, list]]:
    import yaml
    doc = yaml.safe_load(text) or {}
    out: dict[str, dict[str, list]] = {"mmh3": {}, "md5": {}}
    blocks = doc.get("http") or doc.get("requests") or []
    for req in blocks if isinstance(blocks, list) else []:
        for m in (req.get("matchers") or []):
            name = m.get("name")
            if not name:
                continue
            for dsl in m.get("dsl") or []:
                s = str(dsl)
                if "mmh3" in s:
                    for h in re.findall(r'"(-?\d{4,})"', s):
                        out["mmh3"].setdefault(h, [])
                        if [str(name), "nuclei"] not in out["mmh3"][h]:
                            out["mmh3"][h].append([str(name), "nuclei"])
                if "md5" in s:
                    for h in re.findall(r'"([0-9a-fA-F]{32})"', s):
                        out["md5"].setdefault(h.lower(), [])
                        if [str(name), "nuclei"] not in out["md5"][h.lower()]:
                            out["md5"][h.lower()].append([str(name), "nuclei"])
    return out


def _walk_hash_entries(node):
    if isinstance(node, dict):
        if "hash" in node and "name" in node:
            yield node
        for v in node.values():
            yield from _walk_hash_entries(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_hash_entries(v)


def parse_owasp_favicons(text: str) -> tuple[dict[str, list], list[str]]:
    import yaml
    doc = yaml.safe_load(text)
    md5: dict[str, list] = {}
    ignore: list[str] = []
    for e in _walk_hash_entries(doc):
        if str(e.get("algorithm", "MD5")).upper() != "MD5":
            continue
        h, name = str(e["hash"]).lower(), str(e["name"]).strip()
        if not re.fullmatch(r"[0-9a-f]{32}", h):
            continue
        if SENTINEL_NAME.search(name):
            ignore.append(h)
            continue
        lst = md5.setdefault(h, [])
        if [name, "owasp"] not in lst and len(lst) < 12:
            lst.append([name, "owasp"])
    return md5, sorted(set(ignore))


def build_favicons(nuclei_text: str | None, owasp_text: str | None) -> dict:
    mm: dict[str, list] = {}
    md: dict[str, list] = {}
    ignore_md5: list[str] = ["d41d8cd98f00b204e9800998ecf8427e"]
    counts = {}
    if nuclei_text:
        n = parse_nuclei_favicons(nuclei_text)
        mm.update(n["mmh3"])
        for k, v in n["md5"].items():
            md.setdefault(k, []).extend(v)
        counts["nuclei"] = len(n["mmh3"]) + len(n["md5"])
    if owasp_text:
        o, ign = parse_owasp_favicons(owasp_text)
        for k, v in o.items():
            md.setdefault(k, []).extend(v)
        ignore_md5 += ign
        counts["owasp"] = len(o)
    return {"mmh3": mm, "md5": md, "ignore": {"mmh3": [], "md5": sorted(set(ignore_md5))}, "counts": counts}


# ----------------------------------------------------------------------------
# orchestration
# ----------------------------------------------------------------------------

def update(directory: Path | None = None, only: set[str] | None = None, from_tar: str | None = None,
           log=lambda m: print(m, file=sys.stderr), timeout: float = 90.0, fetcher=fetch) -> int:
    d = Path(directory) if directory else data_dir()
    only = only or {"enthec", "favicons", "retire"}
    meta_path = d / "meta.json"
    try:
        meta = json.loads(meta_path.read_text())
    except (OSError, ValueError):
        meta = {}
    failures = 0

    if "enthec" in only:
        try:
            log("• fingerprints: enthec/webappanalyzer" + (f" (from {from_tar})" if from_tar else ""))
            raw = Path(from_tar).read_bytes() if from_tar else fetcher(SOURCES["enthec"], timeout)
            techs, cats, commit = parse_enthec_tar(raw)
            _atomic_write(d / "technologies.json", json.dumps(techs, separators=(",", ":")))
            _atomic_write(d / "categories.json", json.dumps(cats, separators=(",", ":")))
            meta["technologies"] = {"count": len(techs), "categories": len(cats), "commit": commit, "built_at": utcnow_iso(),
                                    "source": SOURCES["enthec"] if not from_tar else str(from_tar),
                                    "sha256": hashlib.sha256(raw).hexdigest()}
            log(f"  ok: {len(techs)} technologies, {len(cats)} categories, commit {commit or 'unknown'}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            log(f"  FAILED: {type(e).__name__}: {e}")

    if "favicons" in only:
        try:
            log("• favicon hashes: nuclei-templates + OWASP")
            texts: dict[str, str | None] = {}
            for key in ("nuclei", "owasp"):
                try:
                    texts[key] = fetcher(SOURCES[key], timeout).decode("utf-8", "replace")
                except Exception as e:  # noqa: BLE001
                    texts[key] = None
                    log(f"  warning: {key} source unavailable ({type(e).__name__}: {e})")
            if not any(texts.values()):
                raise DBBuildError("no favicon source could be downloaded")
            fav = build_favicons(texts["nuclei"], texts["owasp"])
            if not (fav["mmh3"] or fav["md5"]):
                raise DBBuildError("favicon sources parsed to zero hashes: format changed?")
            _atomic_write(d / "favicons.json", json.dumps(fav, separators=(",", ":")))
            meta["favicons"] = {"mmh3": len(fav["mmh3"]), "md5": len(fav["md5"]), "built_at": utcnow_iso(), "counts": fav["counts"]}
            log(f"  ok: {len(fav['mmh3'])} mmh3 hashes, {len(fav['md5'])} md5 hashes")
        except Exception as e:  # noqa: BLE001
            failures += 1
            log(f"  FAILED: {type(e).__name__}: {e}")

    if "retire" in only:
        try:
            log("• library advisories: retire.js")
            raw = fetcher(SOURCES["retire"], timeout)
            data = json.loads(raw)
            if not isinstance(data, dict) or "jquery" not in data:
                raise DBBuildError("unexpected retire.js format (no 'jquery' entry)")
            _atomic_write(d / "retire.json", raw)
            meta["retire"] = {"libraries": len(data), "built_at": utcnow_iso(), "sha256": hashlib.sha256(raw).hexdigest()}
            log(f"  ok: {len(data)} libraries")
        except Exception as e:  # noqa: BLE001
            failures += 1
            log(f"  FAILED: {type(e).__name__}: {e}")

    _atomic_write(meta_path, json.dumps(meta, indent=1))
    log(f"data directory: {d}")
    return 1 if failures else 0


def status(directory: Path | None = None) -> str:
    d = Path(directory) if directory else data_dir()
    lines = [f"data directory: {d}"]
    try:
        meta = json.loads((d / "meta.json").read_text())
    except (OSError, ValueError):
        meta = {}
    for name in ("technologies.json", "categories.json", "favicons.json", "retire.json"):
        p = d / name
        lines.append(f"  {name:18} {'%d KB' % (p.stat().st_size // 1024) if p.exists() else 'missing (bundled seed is used)'}")
    for k, v in meta.items():
        lines.append(f"  {k}: " + ", ".join(f"{a}={b}" for a, b in v.items() if a != "sha256" and a != "counts"))
    return "\n".join(lines)
