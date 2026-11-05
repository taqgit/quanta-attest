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
  "unknown";
- for infrastructure changes, the target environment and any exposure
  findings are read from the change plan itself, never from the agent's
  description of it.

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
INFRA_TOOLS = {"apply_infra_change"}  # tools that change infrastructure from a plan
ADMIN_PORTS = {22, 3389, 1433, 3306, 5432, 6379, 27017}
OPEN_SOURCES = {"0.0.0.0/0", "::/0", "*", "any", "internet"}


def infra_findings(plan: dict) -> list[dict]:
    """Exposure findings in a change plan: admin ports open to the internet, public storage, encryption off."""
    findings = []
    for i, change in enumerate((plan or {}).get("changes", []) or []):
        attrs = change.get("attrs", {}) or {}
        res = change.get("resource", f"change {i + 1}")
        if "source" in attrs and "port" in attrs:
            src = str(attrs.get("source", "")).strip().lower()
            ports = attrs["port"] if isinstance(attrs["port"], list) else [attrs["port"]]
            admin = any(str(p) in ("*", "all") or (str(p).isdigit() and int(p) in ADMIN_PORTS) for p in ports)
            if src in OPEN_SOURCES and admin:
                findings.append({"change": i, "resource": res, "issue": "admin_port_open",
                                 "detail": f"port {attrs['port']} open to {attrs['source']}"})
        if attrs.get("public_access") is True:
            findings.append({"change": i, "resource": res, "issue": "public_storage",
                             "detail": "storage readable by anyone"})
        if attrs.get("encryption") is False:
            findings.append({"change": i, "resource": res, "issue": "encryption_disabled",
                             "detail": "encryption at rest turned off"})
    return findings


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower()).rstrip(".")


@dataclass(frozen=True)
class Facts:
    classification: str | None  # "public", "sensitive" or None when unknown
    destination: str  # "internal" or "external"
    origin: str  # "user", "retrieved" or "unknown"
    environment: str | None = None  # "prod", "nonprod", or None (unknown, or not an infrastructure change)
    findings: list = field(default_factory=list)  # infrastructure exposure findings
    basis: dict = field(default_factory=dict)  # how each fact was established
    conflicts: list = field(default_factory=list)  # [{"fact", "claimed", "established"}]

    def as_meta(self) -> dict:
        meta = {"classification": self.classification or "unknown", "destination": self.destination,
                "origin": self.origin, "facts_source": "gateway", "facts_basis": self.basis,
                "fact_conflicts": self.conflicts}
        if "environment" in self.basis:
            meta["environment"] = self.environment or "unknown"
            meta["infra_findings"] = self.findings
        return meta


class FactResolver:
    def __init__(self, path: Path = LABELS_PATH):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        self.internal_domains = {d.lower() for d in data.get("internal_domains", [])}
        self.objects = data.get("objects", {}) or {}
        self.environments = {str(k).lower(): v for k, v in (data.get("environments", {}) or {}).items()}

    def environment(self, tool: str, args: dict) -> tuple[str | None, str]:
        plan = args.get("plan") or {}
        ws = str(plan.get("workspace", "")).strip().lower()
        env = self.environments.get(ws)
        if env:
            return env, f"plan workspace {ws}"
        return None, f"workspace {ws or 'missing'} is not a known environment"

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
        basis = {"classification": cls_basis, "destination": dest_basis, "origin": org_basis}
        established = {"classification": cls or "unknown", "destination": dest, "origin": org}
        env, findings = None, []
        if tool in INFRA_TOOLS:
            env, basis["environment"] = self.environment(tool, args)
            findings = infra_findings(args.get("plan") or {})
            basis["findings"] = f"{len(findings)} exposure finding(s) read from the plan"
            established["environment"] = env or "unknown"
        conflicts = []
        for k, v in (claimed or {}).items():
            if k not in established or v is None:
                continue
            claim = self.environments.get(str(v).lower(), v) if k == "environment" else v
            if claim != established[k]:
                conflicts.append({"fact": k, "claimed": v, "established": established[k]})
        return Facts(cls, dest, org, env, findings, basis, conflicts)
