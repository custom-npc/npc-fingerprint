"""CVE matching: detected technology + exact version -> known vulnerabilities, ranked by what actually matters.

Sources, each used where it is strongest (research notes in docs/RESEARCH.md):
  * OSV.dev            frameworks / libraries (npm, PyPI, Packagist, Maven, RubyGems, Go): ecosystem-native, version-exact
  * NVD feeds (local)  server software and CMSs without a package ecosystem: CPE applicability ranges
  * retire.js          offline fallback for client-side libraries
Enrichment: CISA KEV (exploited), EPSS (likelihood), Exploit-DB (public exploit), nuclei-templates (template exists).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..util import trunc
from . import cvss
from .db import VulnDB
from .nvd import norm, products_for, row_matches
from .osv import OsvClient, OsvError, cve_ids, fixed_and_range

# normalised technology name -> (OSV ecosystem, package)
OSV_PACKAGES: dict[str, tuple[str, str]] = {
    "jquery": ("npm", "jquery"), "jqueryui": ("npm", "jquery-ui"), "bootstrap": ("npm", "bootstrap"), "react": ("npm", "react"),
    "vuejs": ("npm", "vue"), "vue": ("npm", "vue"), "angular": ("npm", "@angular/core"), "angularjs": ("npm", "angular"),
    "nextjs": ("npm", "next"), "nuxtjs": ("npm", "nuxt"), "express": ("npm", "express"), "lodash": ("npm", "lodash"),
    "momentjs": ("npm", "moment"), "underscorejs": ("npm", "underscore"), "axios": ("npm", "axios"), "handlebars": ("npm", "handlebars"),
    "socketio": ("npm", "socket.io"), "emberjs": ("npm", "ember-source"), "backbonejs": ("npm", "backbone"), "d3": ("npm", "d3"),
    "threejs": ("npm", "three"), "dompurify": ("npm", "dompurify"), "highcharts": ("npm", "highcharts"), "tinymce": ("npm", "tinymce"),
    "quill": ("npm", "quill"), "ckeditor": ("npm", "ckeditor4"), "swiper": ("npm", "swiper"), "videojs": ("npm", "video.js"),
    "django": ("PyPI", "django"), "flask": ("PyPI", "flask"), "werkzeug": ("PyPI", "werkzeug"), "gunicorn": ("PyPI", "gunicorn"),
    "laravel": ("Packagist", "laravel/framework"), "symfony": ("Packagist", "symfony/symfony"), "drupal": ("Packagist", "drupal/core"),
    "joomla": ("Packagist", "joomla/joomla-cms"), "typo3cms": ("Packagist", "typo3/cms-core"), "typo3": ("Packagist", "typo3/cms-core"),
    "magento": ("Packagist", "magento/community-edition"), "prestashop": ("Packagist", "prestashop/prestashop"),
    "cakephp": ("Packagist", "cakephp/cakephp"), "codeigniter": ("Packagist", "codeigniter4/framework"), "yii": ("Packagist", "yiisoft/yii2"),
    "phpmyadmin": ("Packagist", "phpmyadmin/phpmyadmin"), "matomo": ("Packagist", "matomo/matomo"), "mediawiki": ("Packagist", "mediawiki/core"),
    "roundcube": ("Packagist", "roundcube/roundcubemail"), "rubyonrails": ("RubyGems", "rails"), "rails": ("RubyGems", "rails"),
    "sinatra": ("RubyGems", "sinatra"), "springframework": ("Maven", "org.springframework:spring-core"),
    "springboot": ("Maven", "org.springframework.boot:spring-boot"), "apachestruts": ("Maven", "org.apache.struts:struts2-core"),
    "apachetomcat": ("Maven", "org.apache.tomcat:tomcat-catalina"), "tomcat": ("Maven", "org.apache.tomcat:tomcat-catalina"),
    "jetty": ("Maven", "org.eclipse.jetty:jetty-server"), "jenkins": ("Maven", "org.jenkins-ci.main:jenkins-core"),
    "elasticsearch": ("Maven", "org.elasticsearch:elasticsearch"), "grafana": ("Go", "github.com/grafana/grafana"),
    "gitea": ("Go", "code.gitea.io/gitea"),
}
TIERS = ("exploited", "weaponized", "likely", "severe", "minor")
TIER_MEANING = {
    "exploited": "Attackers are using these right now (CISA KEV). Patch first.",
    "weaponized": "Public exploit code exists. Expect it to be tried against you.",
    "likely": "High modelled chance of exploitation soon (EPSS).",
    "severe": "Serious on paper, but no sign of exploitation or public exploit.",
    "minor": "Lower impact or very unlikely to be exploited.",
}
EPSS_LIKELY = 0.10
DISTRO = re.compile(r"\b(ubuntu|debian|centos|red ?hat|rhel|fedora|suse|alpine|amazon|el[5-9]|deb\d+u\d+)\b", re.I)
IMPRECISE = re.compile(r"^\d+(\.\d+)?$")
VERSION_OK = re.compile(r"^\d+(\.\d+)+")


@dataclass
class Target:
    name: str
    version: str
    basis: str
    caveats: list[str] = field(default_factory=list)
    signals: set[str] = field(default_factory=set)


def targets_from(techs: list[dict], banners: dict[str, str]) -> tuple[list[Target], list[str]]:
    out, no_version = [], []
    seen = set()
    for t in techs:
        if t["status"] not in ("confirmed", "probable"):
            continue
        v = t.get("version")
        if not v:
            if t["name"] not in no_version:
                no_version.append(t["name"])
            continue
        v = v.strip()
        if not VERSION_OK.match(v) or (t["name"], v) in seen:
            continue
        seen.add((t["name"], v))
        cav = []
        sigs = {e["signal"] for e in t.get("evidence", [])}
        if t.get("basis") == "claimed":
            cav.append("version comes from a self-declared banner and could be spoofed")
        hdr_locs = {e["location"].lower() for e in t.get("evidence", []) if e["signal"] == "header"}
        banner_txt = " ".join(banners.get(h, "") or "" for h in hdr_locs)
        if banner_txt and DISTRO.search(banner_txt):
            cav.append("banner names a Linux distribution: distros patch without changing the version, so this may already be fixed")
        if IMPRECISE.match(v):
            cav.append(f"version {v} is imprecise: matching assumes the earliest patch level")
        out.append(Target(t["name"], v, t.get("basis", "observed"), cav, sigs))
    return out, no_version


def _sev(score, label):
    return cvss.severity(score) if score is not None else cvss.label_to_severity(label)


def _osv_match(vuln: dict, eco: str, pkg: str, ver: str) -> dict | None:
    if vuln.get("withdrawn"):
        return None
    ids = cve_ids(vuln)
    key = ids[0] if ids else vuln.get("id", "")
    vec = next((s["score"] for s in vuln.get("severity", []) if s.get("type") in ("CVSS_V3", "CVSS_V31") and s.get("score")), None)
    score = cvss.score_v3(vec) if vec else None
    label = (vuln.get("database_specific") or {}).get("severity")
    fixed, rng = fixed_and_range(vuln, pkg, eco, ver)
    summary = vuln.get("summary") or (vuln.get("details") or "").strip().splitlines()[0:1]
    if isinstance(summary, list):
        summary = summary[0] if summary else ""
    refs = [r["url"] for r in vuln.get("references", []) if r.get("type") in ("ADVISORY", "WEB", "FIX") and r.get("url")][:2]
    return {"id": key, "aliases": [i for i in [vuln.get("id")] + vuln.get("aliases", []) if i and i != key][:4], "source": "osv",
            "cvss": score, "severity": _sev(score, label), "vector": vec, "summary": trunc(summary, 160),
            "published": (vuln.get("published") or "")[:10], "fixed": fixed, "range": rng, "refs": refs, "conditional": False,
            "package": f"{eco}:{pkg}"}


def _nvd_matches(vdb: VulnDB, t: Target, tech_def: dict | None) -> list[dict]:
    by_product: dict[str, list[str]] = {}
    for vendor, product in products_for(t.name, tech_def):
        by_product.setdefault(product, []).append(vendor)
    out = []
    for product, vendors in by_product.items():
        for row in vdb.candidates(vendors, product):
            ok, fixed, rng = row_matches(row, t.version)
            if ok:
                out.append({"id": row["id"], "aliases": [], "source": "nvd", "cvss": row["cvss"], "severity": row["severity"],
                            "vector": row["vector"], "summary": trunc(row["summary"], 160), "published": row["published"],
                            "fixed": fixed, "range": rng, "refs": [], "conditional": bool(row["conditional"]),
                            "package": f"{row['vendor']}:{product}"})
    return out


def _merge(into: dict, m: dict) -> None:
    into["sources"] = sorted(set(into.get("sources", [])) | {m["source"]})
    for k in ("fixed", "range", "vector", "summary"):
        if not into.get(k) and m.get(k):
            into[k] = m[k]
    if m["source"] == "nvd" and m.get("cvss") is not None:
        into["cvss"], into["severity"] = m["cvss"], m["severity"] or into.get("severity")
    elif into.get("cvss") is None and m.get("cvss") is not None:
        into["cvss"], into["severity"] = m["cvss"], m["severity"] or into.get("severity")
    if not into.get("severity"):
        into["severity"] = m.get("severity")
    into["aliases"] = sorted(set(into.get("aliases", [])) | set(m.get("aliases", [])))[:4]
    into["refs"] = (into.get("refs", []) + [r for r in m.get("refs", []) if r not in into.get("refs", [])])[:2]
    into["conditional"] = into.get("conditional", False) or m.get("conditional", False)
    if not into.get("published") and m.get("published"):
        into["published"] = m["published"]


def _enrich(item: dict, vdb: VulnDB) -> None:
    cid = item["cve"]
    kev, epss = vdb.kev(cid), vdb.epss(cid)
    item["kev"] = {"added": kev["added"], "due": kev["due"], "ransomware": bool(kev["ransomware"]), "action": kev["action"]} if kev else None
    item["epss"] = {"score": round(epss["score"], 5), "percentile": round(epss["pct"], 5)} if epss else None
    item["exploits"] = [{"source": e["source"], "id": e["ref"], "kind": e["kind"], "url": f"https://www.exploit-db.com/exploits/{e['ref']}"}
                        for e in vdb.exploits(cid)][:5]
    nu = vdb.nuclei(cid)
    item["nuclei"] = {"template": nu["template"], "severity": nu["severity"], "name": nu["name"]} if nu else None
    if item["kev"]:
        k = item["kev"]
        item["priority"], item["why"] = "exploited", f"CISA KEV: exploited in the wild (added {k['added']}" + (", used by ransomware" if k["ransomware"] else "") + ")"
    elif item["exploits"]:
        item["priority"], item["why"] = "weaponized", f"public exploit code exists (Exploit-DB {item['exploits'][0]['id']})"
    elif item["epss"] and item["epss"]["score"] >= EPSS_LIKELY:
        item["priority"], item["why"] = "likely", f"EPSS: {item['epss']['score']:.0%} chance of exploitation in the next 30 days"
    elif item.get("severity") in ("critical", "high") or (item.get("cvss") or 0) >= 7.0:
        item["priority"], item["why"] = "severe", "high severity, but no known exploitation or public exploit"
    else:
        item["priority"], item["why"] = "minor", "lower impact or very unlikely to be exploited"


def _gaps(vdb: VulnDB, targets: list[Target]) -> list[dict]:
    out = []
    for name in sorted({t.name for t in targets}):
        term = re.escape(name.lower())
        rx = re.compile(rf"\b{term}(?:\s+(?:http\s+server|server|core|cms))?\s+(?:versions?\s+)?(?:before|prior to|through|up to|earlier than|<=?|from|v?\d)", re.I)
        rows = [r for r in vdb.unanalyzed(name.lower()) if rx.search(r["summary"] or "")]
        if rows:
            rows.sort(key=lambda r: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(r["severity"] or "", 4), r["published"]), reverse=False)
            out.append({"technology": name, "count": len(rows), "since": min(r["published"] for r in rows),
                        "examples": [{"cve": r["id"], "severity": r["severity"], "published": r["published"], "summary": trunc(r["summary"], 110)} for r in rows[:3]]})
    return out


def run(techs: list[dict], tech_defs: dict, vdb: VulnDB, osv: OsvClient | None, libs: dict | None, banners: dict[str, str]) -> dict:
    targets, no_version = targets_from(techs, banners)
    sources = {"osv": {"used": osv is not None, "queries": 0, "cached": 0, "errors": [], "packages": 0, "offline": bool(osv and osv.offline), "skipped": 0},
               "nvd": {"available": vdb.available, "built": vdb.meta().get("updated_at"), "analysed_through": vdb.meta().get("nvd_years")},
               "kev": {"available": bool(vdb.meta().get("kev_count"))}, "epss": {"available": bool(vdb.meta().get("epss_count"))}}
    matches: dict[tuple[str, str], dict] = {}
    no_source: list[str] = []
    notes: dict[str, list[str]] = {}

    def add(t: Target, m: dict) -> None:
        key = (m["id"], t.name)
        if key not in matches:
            matches[key] = {"cve": m["id"], "technology": t.name, "version": t.version, "caveats": list(t.caveats), "sources": [], "cvss": None,
                            "severity": None, "refs": [], "aliases": [], "package": m.get("package"), "fixed": None,
                            "range": None, "vector": None, "summary": "", "published": "", "conditional": False}
        _merge(matches[key], m)

    # --- OSV (framework/library versions) -------------------------------------------------------
    osv_jobs = {}
    for t in targets:
        mp = OSV_PACKAGES.get(norm(t.name))
        if mp and osv is not None:
            osv_jobs[(mp[0], mp[1], t.version)] = t
    if osv_jobs:
        sources["osv"]["packages"] = len(osv_jobs)
        results = osv.query_many(list(osv_jobs))
        for (eco, pkg, ver), res in results.items():
            t = osv_jobs[(eco, pkg, ver)]
            if isinstance(res, OsvError):
                if osv.offline:
                    sources["osv"]["skipped"] += 1
                else:
                    sources["osv"]["errors"].append(f"{pkg}: {res}")
                continue
            for v in res:
                m = _osv_match(v, eco, pkg, ver)
                if m and m["id"]:
                    add(t, m)
        sources["osv"]["queries"], sources["osv"]["cached"] = osv.stats["queries"], osv.stats["cached"]

    # --- NVD (server software, CMS) -----------------------------------------------------------------
    for t in targets:
        tdef = tech_defs.get(t.name)
        has_cpe = bool(products_for(t.name, tdef))
        has_osv = norm(t.name) in OSV_PACKAGES
        if not has_cpe and not has_osv:
            no_source.append(t.name)
            continue
        if has_cpe and vdb.available:
            for m in _nvd_matches(vdb, t, tdef):
                add(t, m)

    # --- retire.js fallback for client-side libraries -----------------------------------------------------
    tech_by_norm = {norm(t.name): t for t in targets}
    for lib in (libs or {}).get("libraries", []):
        t = tech_by_norm.get(norm(lib["library"]))
        if t is None:
            t = Target(lib["library"], lib["version"], "observed")
        for adv in lib.get("advisories", []):
            for i in adv.get("ids", []):
                if i.startswith("CVE-") and (i, t.name) not in matches:
                    fixed = None
                    mm = re.search(r"<\s*([\w.\-]+)\s*$", adv.get("range", ""))
                    if mm:
                        fixed = mm.group(1)
                    add(t, {"id": i, "aliases": [], "source": "retire.js", "cvss": None, "severity": adv.get("severity"), "vector": None,
                            "summary": adv.get("summary", ""), "published": "", "fixed": fixed, "range": adv.get("range"), "refs": adv.get("info", [])[:1],
                            "conditional": False, "package": f"retire.js:{lib['library']}"})

    items = list(matches.values())
    for it in items:
        if vdb.available:
            _enrich(it, vdb)
        else:
            it.update(kev=None, epss=None, exploits=[], nuclei=None)
            sev_ok = it.get("severity") in ("critical", "high")
            it["priority"], it["why"] = ("severe", "high severity (exploitation data not installed: run `npc-fingerprint setup`)") if sev_ok else ("minor", "exploitation data not installed")
        it["url"] = f"https://nvd.nist.gov/vuln/detail/{it['cve']}" if it["cve"].startswith("CVE-") else (it["refs"][0] if it["refs"] else "")
        it["confidence"] = "high"
        if it["caveats"]:
            it["confidence"] = "low" if any("imprecise" in c for c in it["caveats"]) else "medium"
        it["epss_score"] = (it["epss"] or {}).get("score", 0)
    order = {k: i for i, k in enumerate(TIERS)}
    items.sort(key=lambda x: (order[x["priority"]], -x["epss_score"], -(x["cvss"] or 0), x["cve"]))
    for it in items:
        it.pop("epss_score", None)

    by_tier = {k: sum(1 for i in items if i["priority"] == k) for k in TIERS}
    gaps = _gaps(vdb, targets) if vdb.available and targets else []
    degraded = bool(sources["osv"]["errors"] or sources["osv"]["skipped"]) or (not vdb.available) or (osv is None and any(norm(t.name) in OSV_PACKAGES for t in targets))
    return {
        "status": "partial" if degraded else "ok",
        "checked": [{"technology": t.name, "version": t.version} for t in targets],
        "sources": sources, "items": items, "by_priority": by_tier,
        "by_severity": {s: sum(1 for i in items if i.get("severity") == s) for s in ("critical", "high", "medium", "low")},
        "total": len(items), "no_version": no_version, "no_source": sorted(set(no_source)), "nvd_gaps": gaps,
        "tier_meaning": TIER_MEANING,
        "note": "Matches are by detected version. Banners can be spoofed and distributions backport fixes: treat 'medium'/'low' confidence as leads to verify.",
    }
