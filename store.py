"""Load the fingerprint databases from the data dir, falling back to the bundled seed."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from ..util import data_dir

EMPTY_FAVICONS = {"mmh3": {}, "md5": {}, "ignore": {"mmh3": [], "md5": []}}


@dataclass
class DBBundle:
    techs: dict
    cats: dict
    favicons: dict
    retire: dict
    meta: dict = field(default_factory=dict)
    seed: bool = False
    notes: list[str] = field(default_factory=list)


def _seed(name: str):
    return json.loads(resources.files("npc_fingerprint").joinpath("data", name).read_text(encoding="utf-8"))


def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def load(directory: Path | None = None) -> DBBundle:
    d = Path(directory) if directory else data_dir()
    notes: list[str] = []
    techs = _load(d / "technologies.json")
    cats = _load(d / "categories.json")
    seed = False
    if not techs or not cats:
        techs, cats, seed = _seed("seed_technologies.json"), _seed("seed_categories.json"), True
        notes.append(f"using the bundled seed fingerprint set ({len(techs)} technologies); "
                     "run `npc-fingerprint db update` for the full community database")
    favicons = _load(d / "favicons.json")
    if not favicons:
        favicons = EMPTY_FAVICONS
        notes.append("no favicon database installed; run `npc-fingerprint db update` (favicon matching disabled)")
    retire = _load(d / "retire.json")
    if not retire:
        retire, rseed = _seed("seed_retire.json"), True
        notes.append("using the bundled seed retire.js subset; run `npc-fingerprint db update` for the full set")
    meta = _load(d / "meta.json") or {}
    return DBBundle(techs, cats, favicons, retire, meta, seed, notes)
