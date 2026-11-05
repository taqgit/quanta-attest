"""Policy gateway: one decision per tool request.

The authoritative policy is policy/gateway.rego, evaluated by Open Policy
Agent when an `opa` binary is available (QA_OPA environment variable, PATH, or
bin/opa). Otherwise the same rules are evaluated by the Python reference
implementation below. The test suite checks the two agree on every case.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from .registry import REPO_ROOT

REGO_PATH = REPO_ROOT / "policy" / "gateway.rego"
KNOWN_ROLES = {"Architect", "Engineer", "Reviewer", "Auditor"}
CHANGE_ROLES = {"Architect", "Engineer"}
INFRA_TOOLS = {"apply_infra_change"}
NEEDS_CLASSIFICATION = {"send_external_email"}
DECISIONS = ("ALLOW", "REQUIRE_APPROVAL", "DENY")


@dataclass(frozen=True)
class Request:
    tool: str
    role: str
    classification: str | None = None  # "public", "sensitive" or None when unknown
    destination: str = "internal"  # "internal" or "external"
    origin: str | None = None  # "user", "retrieved" or "unknown"; never assumed to be "user"
    environment: str | None = None  # infrastructure only: "prod" or "nonprod"; None when unknown
    infra_findings: int = 0  # infrastructure only: exposure findings the gateway read from the plan

    def to_input(self) -> dict:
        data = asdict(self)
        return {k: v for k, v in data.items() if v is not None}


@dataclass(frozen=True)
class Decision:
    decision: str
    rule: str
    reason: str
    engine: str

    @property
    def not_evaluable(self) -> bool:
        return self.rule == "R6"


def evaluate_python(req: Request) -> Decision:
    """Reference implementation of policy/gateway.rego, rule for rule."""
    def d(decision: str, rule: str, reason: str) -> Decision:
        return Decision(decision, rule, reason, "python")

    if req.origin == "retrieved":
        return d("DENY", "R1", "Instruction originated in retrieved content")
    if req.origin != "user":
        return d("REQUIRE_APPROVAL", "R6", "Not evaluable: instruction origin unknown")
    if req.tool in NEEDS_CLASSIFICATION and req.classification not in ("public", "sensitive"):
        return d("REQUIRE_APPROVAL", "R6", "Not evaluable: data classification missing")
    if req.tool in INFRA_TOOLS and req.infra_findings > 0:
        return d("DENY", "R7", "Infrastructure change would open admin access or storage to the internet, or turn off encryption")
    if req.tool in INFRA_TOOLS and req.environment not in ("prod", "nonprod"):
        return d("REQUIRE_APPROVAL", "R6", "Not evaluable: target environment unknown")
    if req.tool in ("search_corpus", "draft_checklist") and req.role in KNOWN_ROLES:
        return d("ALLOW", "R2", "Read-only tool")
    if req.tool == "file_review_ticket" and req.role == "Architect":
        return d("REQUIRE_APPROVAL", "R3", "Consequential action needs a Reviewer")
    if req.tool == "send_external_email" and req.classification == "sensitive":
        return d("DENY", "R4", "Sensitive content cannot be sent outside the organization")
    if (req.tool == "send_external_email" and req.classification == "public"
            and req.destination == "external" and req.role == "Architect"):
        return d("REQUIRE_APPROVAL", "R5", "External email needs a Reviewer")
    if req.tool in INFRA_TOOLS and req.environment == "prod" and req.role in CHANGE_ROLES:
        return d("REQUIRE_APPROVAL", "R8", "Production change needs a Reviewer")
    if req.tool in INFRA_TOOLS and req.environment == "nonprod" and req.role in CHANGE_ROLES:
        return d("ALLOW", "R9", "Safe change to a non-production environment")
    return d("DENY", "R0", "No rule allows this request")


def find_opa() -> str | None:
    for candidate in (os.environ.get("QA_OPA"), shutil.which("opa"),
                      str(REPO_ROOT / "bin" / "opa"), str(REPO_ROOT / "bin" / "opa.exe")):
        if candidate and Path(candidate).is_file():
            return candidate
    return None


def evaluate_opa(req: Request, opa: str) -> Decision:
    proc = subprocess.run(
        [opa, "eval", "-f", "json", "-I", "-d", str(REGO_PATH), "data.quanta.gateway.decision"],
        input=json.dumps(req.to_input()), capture_output=True, text=True, timeout=20, check=True,
    )
    value = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    return Decision(value["decision"], value["rule"], value["reason"], "opa")


def evaluate(req: Request, engine: str = "auto") -> Decision:
    """Evaluate with OPA when available ('auto' or 'opa'), else Python. Fails closed on error."""
    opa = find_opa() if engine in ("auto", "opa") else None
    if engine == "opa" and not opa:
        raise RuntimeError("OPA binary not found; set QA_OPA or add opa to PATH")
    if opa:
        try:
            return evaluate_opa(req, opa)
        except Exception as exc:  # an engine failure must never become an allow
            return Decision("DENY", "R0", f"Policy engine error, failing closed: {type(exc).__name__}", "opa")
    return evaluate_python(req)


def rego_snippet(rule: str) -> str:
    """The Rego source for one rule, for read-only display beside a decision."""
    text = REGO_PATH.read_text(encoding="utf-8")
    if rule == "R0":
        m = re.search(r"# --- R0:.*?(?=\n\norders)", text, re.S)
    else:
        m = re.search(rf"# --- {rule}:.*?(?=\n\n# ---|\Z)", text, re.S)
    return m.group(0).strip() if m else ""
