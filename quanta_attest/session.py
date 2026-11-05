"""A demo session: the model proposes, the policy decides, the ledger proves.

Tool proposals are scripted until the model is connected on Day 2; every
proposal still goes through the real gateway, approval queue and ledger.
"""

from __future__ import annotations

import hashlib
import json
import uuid

from . import assist, tools
from .facts import FactResolver
from .invariants import invariants_for_rule, load_invariants
from .ledger import Ledger, Signer
from .policy import REGO_PATH, Request, evaluate
from .search import KeywordIndex


def policy_version() -> str:
    return "rego-" + hashlib.sha256(REGO_PATH.read_bytes()).hexdigest()[:12]


def request_seal(request_id: str, tool: str, args: dict, facts: dict, requested_by: str, rule: str,
                 version: str) -> str:
    """Fingerprint of exactly what was decided. An approval signs this; execution must match it."""
    body = {"request_id": request_id, "tool": tool, "args": args, "requested_by": requested_by, "rule": rule,
            "policy_version": version, "classification": facts.get("classification"),
            "destination": facts.get("destination"), "origin": facts.get("origin")}
    if "environment" in facts:
        body["environment"] = facts["environment"]
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


class Session:
    def __init__(self, engine: str = "auto", index: KeywordIndex | None = None, signer: Signer | None = None,
                 resolver: FactResolver | None = None):
        self.id = "S-" + uuid.uuid4().hex[:6].upper()
        self.engine = engine
        self.index = index if index is not None else KeywordIndex.load()
        self.ledger = Ledger(signer)
        self.invariants = load_invariants()
        self.resolver = resolver or FactResolver()
        self.queue: dict[str, dict] = {}  # request_id -> pending request
        self.state: dict[str, str] = {}  # request_id -> allowed | held | denied | approved | rejected | refused
        self.outcomes: list[dict] = []
        # Gateway-side context the agent cannot write to: what the user typed, and what retrieval returned.
        self.user_turns: list[str] = []
        self.retrieved: dict[str, str] = {}
        self._n = 0

    # ---------- user channel and retrieval (gateway side) ----------
    def command(self, text: str) -> None:
        """Something the user typed. Only this channel can make an instruction's origin 'user'."""
        self.user_turns.append(text)

    def register_retrieved(self, source_id: str, text: str) -> None:
        """Content that came back from retrieval. An instruction found here has origin 'retrieved'."""
        self.retrieved[source_id] = text

    # ---------- questions ----------
    def ask(self, question: str, role: str, profile: str | None = None) -> dict:
        self.command(question)
        q = self.ledger.append(role, "question", {"profile": profile or "all"}, {"question": question})
        hits = self.index.search(question, profile=profile, k=3)
        chunk_ids = [c["chunk_id"] for _, c in hits]
        for _, c in hits:
            self.register_retrieved(c["chunk_id"], c["text"])
        r = self.ledger.append("System", "retrieval", {"passages": len(hits), "chunk_ids": chunk_ids})
        declined = not hits
        a = self.ledger.append("Model", "model_output",
                               {"kind": "answer", "citations": chunk_ids, "declined": declined},
                               {"passages": [c["text"] for _, c in hits]})
        return {"question": question, "hits": [c for _, c in hits], "declined": declined,
                "receipts": [q["seq"], r["seq"], a["seq"]]}

    # ---------- actions ----------
    def propose(self, tool: str, role: str, args: dict | None = None, instruction: str = "",
                claimed: dict | None = None, requested_by: str | None = None) -> dict:
        """The agent proposes; the gateway establishes the facts and decides.

        `claimed` holds the agent's own statements (classification, origin, destination). They are
        recorded, compared with what the gateway established, and never used for the decision (INV-7).
        """
        self._n += 1
        rid = f"REQ-{self._n:03d}"
        args = dict(args or {})
        requested_by = requested_by or f"{role.lower()}-1"
        facts = self.resolver.resolve(tool, args, instruction, self.user_turns, self.retrieved, claimed)
        req = self._request(tool, role, facts)
        meta = {"request_id": rid, "tool": tool, "role": role, "requested_by": requested_by,
                **facts.as_meta(), "claimed": claimed or {}}
        rec_req = self.ledger.append("Model", "tool_request", meta, {"args": args, "instruction": instruction})
        d = evaluate(req, self.engine)
        version = policy_version()
        seal = request_seal(rid, tool, args, meta, requested_by, d.rule, version)
        lane = self._assist(d, tool, role, args, instruction, meta, requested_by, extra_turns=[])
        rec_dec = self.ledger.append("Gateway", "policy_decision", {
            "request_id": rid, "decision": d.decision, "rule": d.rule, "reason": d.reason, "engine": d.engine,
            "policy_version": version, "invariants": invariants_for_rule(d.rule, self.invariants),
            "seal": seal, "fact_conflicts": len(facts.conflicts), "assist": lane["tips"],
            "assist_alternative": lane["alternative"]["summary"] if lane["alternative"] else None,
        })
        outcome = {"request_id": rid, "tool": tool, "role": role, "requested_by": requested_by, "args": args,
                   "instruction": instruction, "meta": meta, "decision": d.decision, "rule": d.rule,
                   "reason": d.reason, "engine": d.engine, "not_evaluable": d.not_evaluable, "seal": seal,
                   "conflicts": facts.conflicts, "assist": lane, "receipts": [rec_req["seq"], rec_dec["seq"]],
                   "result": None}
        if d.decision == "ALLOW":
            self.state[rid] = "allowed"
            outcome["result"] = self._execute(rid, tool, args, outcome)
        elif d.decision == "REQUIRE_APPROVAL":
            self.state[rid] = "held"
            self.queue[rid] = outcome
        else:
            self.state[rid] = "denied"
        self.outcomes.append(outcome)
        return outcome

    @staticmethod
    def _request(tool: str, role: str, facts) -> Request:
        return Request(tool=tool, role=role, classification=facts.classification, destination=facts.destination,
                       origin=facts.origin, environment=facts.environment, infra_findings=len(facts.findings))

    def _assist(self, d, tool: str, role: str, args: dict, instruction: str, meta: dict, requested_by: str,
                extra_turns: list[str]) -> dict:
        """Lane assist for a deny or hold; any suggested alternative is checked by the same policy first."""
        if d.decision == "ALLOW":
            return {"tips": [], "alternative": None}
        out = {"tips": assist.tips(d.rule, tool, args, meta, requested_by), "alternative": None}
        alt = assist.alternative_args(d.rule, tool, args)
        if alt is not None:
            facts = self.resolver.resolve(tool, alt, instruction, self.user_turns + extra_turns, self.retrieved)
            ad = evaluate(self._request(tool, role, facts), self.engine)
            out["alternative"] = {"args": alt, "decision": ad.decision, "rule": ad.rule, "reason": ad.reason,
                                  "summary": f"{ad.decision} by {ad.rule}: {ad.reason}"}
        return out

    def check(self, tool: str, role: str, args: dict | None = None, instruction: str = "",
              claimed: dict | None = None, requested_by: str | None = None, typed_by_user: bool = False) -> dict:
        """Check before you run: what the gateway would decide. Nothing is recorded and nothing runs.

        `typed_by_user=True` treats the instruction as typed by the person asking, as on the check screen or in a
        build pipeline where the change was committed by a person.
        """
        args = dict(args or {})
        extra = [instruction] if typed_by_user and instruction else []
        facts = self.resolver.resolve(tool, args, instruction, self.user_turns + extra, self.retrieved, claimed)
        d = evaluate(self._request(tool, role, facts), self.engine)
        meta = facts.as_meta()
        return {"tool": tool, "role": role, "decision": d.decision, "rule": d.rule, "reason": d.reason,
                "engine": d.engine, "not_evaluable": d.not_evaluable, "meta": meta, "conflicts": facts.conflicts,
                "assist": self._assist(d, tool, role, args, instruction, meta, requested_by or f"{role.lower()}-1",
                                       extra),
                "recorded": False}

    def _record(self, event: str, rid: str) -> dict | None:
        return next((r for r in reversed(self.ledger.records)
                     if r["event"] == event and r["meta"].get("request_id") == rid), None)

    def decide(self, request_id: str, approver_role: str, approve: bool, note: str = "",
               approver: str | None = None) -> dict:
        if request_id not in self.queue:
            raise KeyError(f"{request_id} is not waiting for approval")
        if approver_role != "Reviewer":
            raise PermissionError("Only a Reviewer can approve or reject (INV-3)")
        approver = approver or f"{approver_role.lower()}-1"
        outcome = self.queue[request_id]
        if approver == outcome["requested_by"]:
            raise PermissionError(f"{approver} requested this action, so another person must decide "
                                  "(separation of duties, INV-3)")
        self.queue.pop(request_id)
        sealed = self._record("policy_decision", request_id)["meta"]["seal"]
        rec = self.ledger.append(approver_role, "approval",
                                 {"request_id": request_id, "approved": approve, "rule": outcome["rule"],
                                  "approver": approver, "requested_by": outcome["requested_by"], "seal": sealed},
                                 {"note": note})
        outcome["receipts"].append(rec["seq"])
        self.state[request_id] = "approved" if approve else "rejected"
        if approve:
            outcome["result"] = self._execute(request_id, outcome["tool"], outcome["args"], outcome)
        return outcome

    def _refuse(self, rid: str, outcome: dict, reason: str):
        rec = self.ledger.append("Gateway", "execution_refused", {"request_id": rid, "reason": reason})
        outcome["receipts"].append(rec["seq"])
        self.state[rid] = "refused"
        raise PermissionError(f"{rid}: {reason}")

    def _execute(self, rid: str, tool: str, args: dict, outcome: dict) -> dict:
        # INV-0, defence in depth: nothing runs without an allow or a Reviewer's approval.
        if self.state.get(rid) not in ("allowed", "approved"):
            raise PermissionError(f"{rid} has no allow or approval")
        # INV-3: what runs must be exactly what was decided and, if held, exactly what was approved.
        req, dec = self._record("tool_request", rid), self._record("policy_decision", rid)
        if req is None or dec is None:
            self._refuse(rid, outcome, "no recorded request or decision")
        m = req["meta"]
        now = request_seal(rid, tool, args, m, m["requested_by"], dec["meta"]["rule"], dec["meta"]["policy_version"])
        if now != dec["meta"]["seal"]:
            self._refuse(rid, outcome, "request changed after the decision; seal does not match")
        if self.state[rid] == "approved":
            app = self._record("approval", rid)
            if not app or app["meta"]["seal"] != dec["meta"]["seal"] or not app["meta"]["approved"]:
                self._refuse(rid, outcome, "approval does not cover this exact request")
        try:
            result = tools.TOOLS[tool](args)
            ok = True
        except Exception as exc:
            result, ok = {"mocked": True, "summary": f"Tool failed: {type(exc).__name__}"}, False
        rec = self.ledger.append("Tool", "tool_result",
                                 {"request_id": rid, "tool": tool, "ok": ok, "mocked": result.get("mocked", True),
                                  "seal": dec["meta"]["seal"]},
                                 result)
        outcome["receipts"].append(rec["seq"])
        return result
