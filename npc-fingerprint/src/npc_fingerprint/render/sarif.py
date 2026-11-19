"""Minimal SARIF 2.1.0 output (`--output sarif`) for GitHub code scanning / DefectDojo / Jira ingestion.

Only actionable findings become SARIF results. CVEs suppressed as a platform mismatch are deliberately left
out: a SARIF consumer treats every result as an alert to triage, and re-including a mismatch there would
recreate the exact "4 critical findings that don't actually apply" problem this release fixes elsewhere.
"""
from __future__ import annotations

from .. import TOOL_NAME, __version__
from ..util import trunc

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SEV_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
TIER_LEVEL = {"exploited": "error", "weaponized": "error", "likely": "warning", "severe": "warning", "minor": "note"}


def _result(rule_id: str, level: str, message: str, uri: str, rules: dict, short: str) -> dict:
    rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": trunc(short, 150)}})
    return {"ruleId": rule_id, "level": level, "message": {"text": trunc(message, 500)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri or "about:target"}}}]}


def _build_run(rep: dict) -> dict:
    url = rep["target"].get("final_url") or rep["target"].get("url") or "about:target"
    rules: dict[str, dict] = {}
    results: list[dict] = []

    v = rep.get("vulnerabilities") or {}
    for it in v.get("items", []):
        if it.get("coverage") == "env_mismatch":
            continue   # platform mismatch: not a real alert for this target, see the "suppressed" tier in the report
        level = TIER_LEVEL.get(it["priority"], "warning")
        msg = f"{it['cve']}: {it['technology']} {it['version']} — {it['why']}" + (f" (fix: {it['fixed']})" if it.get("fixed") else "")
        results.append(_result(it["cve"], level, msg, it.get("url") or url, rules, f"Known CVE matched by detected version ({it['priority']})"))

    for f in rep.get("security_headers", []):
        if f["status"] in ("pass", "n/a"):
            continue
        level = SEV_LEVEL.get(f["severity"], "warning")
        results.append(_result(f"header-{f['id']}", level, f"{f['title']}: {f['reason']}", url, rules, "Missing or weak security header"))

    for f in rep.get("tls_findings", []):
        results.append(_result(f"tls-{f['id']}", SEV_LEVEL.get(f["severity"], "warning"), f["reason"], url, rules, "TLS or certificate issue"))

    for c in (rep.get("active") or {}).get("checks", []):
        if c["status"] != "weak":
            continue
        results.append(_result(f"active-{c['id']}", SEV_LEVEL.get(c["severity"], "warning"), f"{c['title']}: {c['reason']}", url, rules, "Active check finding"))

    for s in (rep.get("recon") or {}).get("secrets", {}).get("items", []):
        level = SEV_LEVEL.get(s["severity"], "warning")
        results.append(_result("secret-exposed", level, f"{s['type']} found in {s['where']}: {s['redacted']} — {s['note']}", url, rules, "Exposed secret in client-side code"))

    return {"tool": {"driver": {"name": TOOL_NAME, "version": __version__, "informationUri": "https://github.com/YOUR-GITHUB-USER/npc-fingerprint",
                                "rules": list(rules.values())}},
            "results": results}


def build(rep: dict) -> dict:
    """One target's SARIF document (a single run)."""
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [_build_run(rep)]}


def build_multi(reps: list[dict]) -> dict:
    """One SARIF document covering several targets, one SARIF `run` per target."""
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [_build_run(r) for r in reps]}
