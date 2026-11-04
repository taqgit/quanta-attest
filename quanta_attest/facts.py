"""Gateway-established facts (INV-7).

The agent proposes an action and may claim facts about it: "this content is
public", "the user asked for this". A compromised or confused agent will claim
whatever gets the action through, so the gateway never decides on a claim.

It establishes each fact itself:

- classification: looked up from the data label of the object being moved
  (intent/data_labels.yaml), never from the agent;
- destination: worked out from the recipient's domain;
- origin: the instruction text is traced to a retrieved document (then
  "retrieved") or to something the user typed (then "user"); otherwise
  "unknown".

Claims that disagree with the established facts are recorded as conflicts in
the ledger, which is itself evidence that the agent misbehaved. Anything the
gateway cannot establish stays unknown and is held for a human (R6).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .registry import REPO_ROOT

LABELS_PATH = REPO_ROOT / "intent" / "data_labels.yaml"
CLASSIFICATIONS = ("public", "sensitive")
DATA_TOOLS = {"send_external_email"}  # tools that move data and so need its label


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower()).rstrip(".")


@dataclass(frozen=True)
class Facts:
    classification: str | None  # "public", "sensitive" or None when unknown
    destination: str  # "internal" or "external"
    origin: str  # "user", "retrieved" or "unknown"
    basis: dict = field(default_factory=dict)  # how each fact was established
    conflicts: list = field(default_factory=list)  # [{"fact", "claimed", "established"}]

    def as_meta(self) -> dict:
        return {"classification": self.classification or "unknown", "destination": self.destination,
                "origin": self.origin, "facts_source": "gateway", "facts_basis": self.basis,
                "fact_conflicts": self.conflicts}


class FactResolver:
    def __init__(self, path: Path = LABELS_PATH):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        self.internal_domains = {d.lower() for d in data.get("internal_domains", [])}
        self.objects = data.get("objects", {}) or {}

    def classification(self, tool: str, args: dict) -> tuple[str | None, str]:
        ref = args.get("data_ref")
        if not ref:
            return None, "no data reference" if tool in DATA_TOOLS else "not needed"
        label = (self.objects.get(ref) or {}).get("classification")
        if label in CLASSIFICATIONS:
            return label, f"data label of {ref}"
        return None, f"{ref} has no data label"

    def destination(self, tool: str, args: dict) -> tuple[str, str]:
        if tool not in DATA_TOOLS:
            return "internal", "tool does not send data out"
        to = str(args.get("to", ""))
        domain = to.rsplit("@", 1)[-1].lower() if "@" in to else ""
        if domain and domain in self.internal_domains:
            return "internal", f"recipient domain {domain} is internal"
        return "external", f"recipient domain {domain or 'missing'} is not internal"

    @staticmethod
    def origin(instruction: str, user_turns: list[str], retrieved: dict[str, str]) -> tuple[str, str]:
        ins = _norm(instruction)
        if not ins:
            return "unknown", "no instruction given"
        # Retrieved content is checked first: if the text appears in a document,
        # it is treated as coming from that document even if a user also typed it.
        for source, text in retrieved.items():
            if ins in _norm(text):
                return "retrieved", f"found in retrieved content {source}"
        for n, turn in enumerate(user_turns, 1):
            if ins in _norm(turn):
                return "user", f"matches user turn {n}"
        return "unknown", "not traceable to the user or to retrieved content"

    def resolve(self, tool: str, args: dict, instruction: str, user_turns: list[str],
                retrieved: dict[str, str], claimed: dict | None = None) -> Facts:
        cls, cls_basis = self.classification(tool, args)
        dest, dest_basis = self.destination(tool, args)
        org, org_basis = self.origin(instruction, user_turns, retrieved)
        established = {"classification": cls or "unknown", "destination": dest, "origin": org}
        conflicts = [{"fact": k, "claimed": v, "established": established[k]}
                     for k, v in (claimed or {}).items()
                     if k in established and v is not None and v != established[k]]
        return Facts(cls, dest, org,
                     {"classification": cls_basis, "destination": dest_basis, "origin": org_basis}, conflicts)
