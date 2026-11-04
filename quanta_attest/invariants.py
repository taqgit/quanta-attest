"""Load the intent layer (intent/invariants.yaml)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .registry import REPO_ROOT

INVARIANTS_PATH = REPO_ROOT / "intent" / "invariants.yaml"


@dataclass(frozen=True)
class Invariant:
    id: str
    statement: str
    declaration: str
    rules: list[str] = field(default_factory=list)
    controls: list[str] = field(default_factory=list)


def load_invariants(path: Path = INVARIANTS_PATH) -> list[Invariant]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    out, seen = [], set()
    for raw in data["invariants"]:
        for key in ("id", "statement", "declaration", "rules"):
            if not raw.get(key):
                raise ValueError(f"{raw.get('id', '?')}: missing {key}")
        if raw["id"] in seen:
            raise ValueError(f"duplicate invariant {raw['id']}")
        seen.add(raw["id"])
        out.append(Invariant(**raw))
    return out


def invariants_for_rule(rule: str, invariants: list[Invariant] | None = None) -> list[str]:
    """Invariants a gateway rule protects. Every decision also evidences INV-0, INV-1 and INV-7."""
    invariants = invariants or load_invariants()
    ids = [inv.id for inv in invariants if rule in inv.rules]
    for always in ("INV-0", "INV-1"):
        if always not in ids:
            ids.insert(0 if always == "INV-0" else 1, always)
    if any(inv.id == "INV-7" for inv in invariants) and "INV-7" not in ids:
        ids.append("INV-7")
    return ids
