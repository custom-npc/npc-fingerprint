"""CVSS v3.x base-score calculator (public formulas, FIRST CVSS v3.1 spec). v4.0 vectors are not computed."""
from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def score_v3(vector: str) -> float | None:
    """Base score for a CVSS:3.0 / 3.1 vector string, or None if it is not a valid v3 vector."""
    if not vector or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.50 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min((1.08 if scope_changed else 1.0) * (impact + expl), 10.0))


def severity(score: float | None) -> str | None:
    if score is None:
        return None
    return "none" if score == 0 else "low" if score < 4 else "medium" if score < 7 else "high" if score < 9 else "critical"


def label_to_severity(label: str | None) -> str | None:
    """Map vendor labels (GHSA: LOW/MODERATE/HIGH/CRITICAL) onto our four-step scale."""
    if not label:
        return None
    l = label.strip().lower()
    return {"moderate": "medium", "important": "high"}.get(l, l if l in ("low", "medium", "high", "critical") else None)
