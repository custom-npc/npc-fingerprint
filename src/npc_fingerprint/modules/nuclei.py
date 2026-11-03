"""Nuclei suggestions (suggest only; this module never launches anything).

Turns what the scan learned into the next testing step:
  * exact template IDs for CVEs that matched a detected version AND have a Nuclei template (nuclei-templates `cves.json`),
  * technology tags validated against the real tag vocabulary (`TEMPLATES-STATS.json`) so the command does not silently match nothing,
  * a ready-to-paste, rate-limited command for each.
"""
from __future__ import annotations

import re
import shlex
import shutil

from ..vulns.db import VulnDB
from ..vulns.engine import TIERS

SKIP_CATEGORIES = {"Analytics", "Tag managers", "Font scripts", "Advertising", "SSL/TLS certificate authorities", "Marketing automation",
                   "Widgets", "CDN", "Cookie compliance", "Video players", "Maps"}
GENERIC_TOKENS = {"server", "http", "web", "framework", "js", "the", "cms", "core", "app", "software", "project", "httpserver", "webserver"}
EXTRA_TAGS = {"wordpress": ["wp-plugin"], "joomla": ["joomla"], "drupal": ["drupal"]}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def tag_candidates(name: str, vendor: str | None = None, product: str | None = None) -> list[str]:
    words = [w for w in re.split(r"[^A-Za-z0-9]+", name.lower()) if w and w not in GENERIC_TOKENS]
    # best guess first: leading word, then CPE product/vendor, then trailing word, then the whole name squashed
    cands = words[:1] + [_norm(x) for x in (product, vendor) if x] + words[1:] + [_norm(name)]
    out: list[str] = []
    for c in cands:
        if c and c not in out and c not in GENERIC_TOKENS and len(c) > 1:
            out.append(c)
    return out


def _cpe_parts(tdef: dict | None) -> tuple[str | None, str | None]:
    from ..vulns.nvd import parse_cpe
    c = parse_cpe((tdef or {}).get("cpe", ""))
    return (c[1], c[2]) if c else (None, None)


def suggest(rep: dict, vdb: VulnDB, tech_defs: dict, url: str) -> dict:
    tag_counts = vdb.nuclei_tag_counts() if vdb.available else {}
    have_index = bool(tag_counts)
    out: dict = {"executed": False, "installed": shutil.which("nuclei") is not None, "template_index": have_index,
                 "by_cve": [], "tags": [], "commands": {}, "notes": [],
                 "note": "Suggestions only: npc-fingerprint never runs Nuclei. Run it only against systems you are authorised to test."}
    # 1) exact CVE templates -------------------------------------------------------------------------
    order = {k: i for i, k in enumerate(TIERS)}
    seen: set[str] = set()
    for it in (rep.get("vulnerabilities") or {}).get("items", []):
        nu = it.get("nuclei")
        if nu and nu["template"] not in seen:
            seen.add(nu["template"])
            out["by_cve"].append({"template": nu["template"], "cve": it["cve"], "severity": nu.get("severity") or it.get("severity"),
                                  "technology": f"{it['technology']} {it['version']}", "priority": it["priority"],
                                  "why": f"{it['technology']} {it['version']} matches {it['cve']} ({it['priority']})"})
    out["by_cve"].sort(key=lambda x: (order.get(x["priority"], 9), x["template"]))
    out["by_cve"] = out["by_cve"][:25]

    # 2) technology tags --------------------------------------------------------------------------------
    chosen: dict[str, dict] = {}
    for t in rep.get("technologies", []):
        if t["status"] not in ("confirmed", "probable") or any(c in SKIP_CATEGORIES for c in t.get("categories", [])):
            continue
        vendor, product = _cpe_parts(tech_defs.get(t["name"]))
        cands = tag_candidates(t["name"], vendor, product)
        if have_index:
            cands = [c for c in cands if c in tag_counts]
        label = f"{t['name']} {t['version']}" if t.get("version") else t["name"]
        for c in cands[:2] if have_index else cands[:1]:
            e = chosen.setdefault(c, {"tag": c, "technologies": [], "templates": tag_counts.get(c), "verified": have_index})
            if label not in e["technologies"]:
                e["technologies"].append(label)
        for extra in EXTRA_TAGS.get(_norm(t["name"]), []):
            if (not have_index) or extra in tag_counts:
                e = chosen.setdefault(extra, {"tag": extra, "technologies": [], "templates": tag_counts.get(extra), "verified": have_index})
                if label not in e["technologies"]:
                    e["technologies"].append(label)
    # context-driven tags from other findings
    recon = rep.get("recon") or {}
    ctx = []
    if (recon.get("endpoints") or {}).get("graphql"):
        ctx.append(("graphql", "GraphQL endpoint referenced in site JavaScript"))
    if any(e["value"].lower().find(k) >= 0 for e in (recon.get("endpoints") or {}).get("by_kind", {}).get("admin", []) for k in ("swagger", "openapi", "api-docs")):
        ctx.append(("swagger", "Swagger/OpenAPI path referenced in site JavaScript"))
    if any(c["id"] == "cors" and c["status"] == "weak" for c in (rep.get("active") or {}).get("checks", [])):
        ctx.append(("cors", "CORS misconfiguration indicated by the active check"))
    if any(f["status"] == "weak" and f["severity"] in ("medium", "high") for f in rep.get("tls_findings", [])):
        ctx.append(("ssl", "TLS weaknesses found"))
    for tag, why in ctx:
        if (not have_index) or tag in tag_counts:
            chosen.setdefault(tag, {"tag": tag, "technologies": [why], "templates": tag_counts.get(tag), "verified": have_index})
    out["tags"] = sorted(chosen.values(), key=lambda e: (-(e["templates"] or 0), e["tag"]))[:12]
    if not have_index:
        out["notes"].append("template index not installed (run `npc-fingerprint setup`): tags are unverified guesses")

    # 3) commands --------------------------------------------------------------------------------------
    q = shlex.quote(url)
    polite = "-rl 20 -timeout 10"
    if out["by_cve"]:
        ids = ",".join(x["template"] for x in out["by_cve"][:12])
        out["commands"]["cve_templates"] = f"nuclei -u {q} -id {ids} {polite}"
    if out["tags"]:
        tags = ",".join(x["tag"] for x in out["tags"][:8])
        out["commands"]["technology_tags"] = f"nuclei -u {q} -tags {tags} -severity medium,high,critical {polite}"
    out["status"] = "ok" if out["commands"] else "nothing"
    if not out["commands"]:
        out["notes"].append("no version-matched CVE templates and no tag with templates for the detected technologies")
    if not out["installed"]:
        out["notes"].append("nuclei was not found in PATH (see https://github.com/projectdiscovery/nuclei); update templates with `nuclei -ut`")
    return out
