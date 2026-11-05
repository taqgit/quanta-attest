"""Tests for the intent, enforcement and evidence layers (acceptance criteria AC4 to AC9, AC13, AC15 to AC19)."""

import copy
import itertools
import json
import subprocess
import sys
from pathlib import Path

import pytest

from quanta_attest import evidence, policy
from quanta_attest.chunk import chunk_document
from quanta_attest.invariants import load_invariants
from quanta_attest.ledger import Ledger, Signer, verify
from quanta_attest.policy import Request, evaluate, evaluate_python, find_opa, rego_snippet
from quanta_attest.assist import remediate_plan
from quanta_attest.facts import FactResolver, infra_findings
from quanta_attest.scenarios import REQUESTER, REVIEWER, SCENARIOS, propose_scenario, run_all, scenario_args
from quanta_attest.search import KeywordIndex
from quanta_attest.session import Session
from quanta_attest.value import Inputs, compute

FIXTURES = Path(__file__).parent / "fixtures"
REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def index():
    chunks = []
    for name, profile in (("on-ai-directive", "public-sector"), ("eu-ai-act", "regulated"), ("osfi-e23", "regulated")):
        chunks += chunk_document((FIXTURES / f"{name}.txt").read_text(), doc_id=name, profile=profile,
                                 title=name, source_url="https://example.org", credit="test")
    return KeywordIndex([c.to_dict() for c in chunks])


@pytest.fixture
def session(index):
    return Session(engine="python", index=index)


# ---------- intent ----------

def test_invariants_cover_every_rule():
    invs = load_invariants()
    assert [i.id for i in invs] == [f"INV-{n}" for n in range(9)]
    rego = (REPO / "policy" / "gateway.rego").read_text()
    for inv in invs:
        assert inv.declaration and "=" in inv.declaration
        for rule in inv.rules:
            assert rule in ("structure", "answer-check", "facts") or f"# --- {rule}:" in rego


# ---------- enforcement ----------

@pytest.mark.parametrize("req,decision,rule", [
    (Request("send_external_email", "Architect", "public", "external", "retrieved"), "DENY", "R1"),
    (Request("send_external_email", "Architect", None, "external", "user"), "REQUIRE_APPROVAL", "R6"),
    (Request("draft_checklist", "Architect", None, "internal", "unknown"), "REQUIRE_APPROVAL", "R6"),
    (Request("draft_checklist", "Architect"), "REQUIRE_APPROVAL", "R6"),  # origin omitted is never "user"
    (Request("search_corpus", "Auditor", origin="user"), "ALLOW", "R2"),
    (Request("file_review_ticket", "Architect", "public", origin="user"), "REQUIRE_APPROVAL", "R3"),
    (Request("send_external_email", "Architect", "sensitive", "external", "user"), "DENY", "R4"),
    (Request("send_external_email", "Architect", "public", "external", "user"), "REQUIRE_APPROVAL", "R5"),
    (Request("delete_database", "Architect", origin="user"), "DENY", "R0"),
    (Request("search_corpus", "Intern", origin="user"), "DENY", "R0"),
    (Request("send_external_email", "Architect", "public", "internal", "user"), "DENY", "R0"),
])
def test_policy_decisions(req, decision, rule):
    d = evaluate_python(req)
    assert (d.decision, d.rule) == (decision, rule)


def test_missing_fact_is_never_allowed():  # AC13
    for tool, role, dest, origin in itertools.product(["send_external_email", "draft_checklist", "search_corpus"],
                                                      ["Architect", "Reviewer", "Auditor"],
                                                      ["internal", "external"], ["unknown", None]):
        assert evaluate_python(Request(tool, role, None, dest, origin)).decision != "ALLOW"
    for role, dest in itertools.product(["Architect", "Reviewer", "Auditor"], ["internal", "external"]):
        assert evaluate_python(Request("send_external_email", role, None, dest, "user")).decision != "ALLOW"


@pytest.mark.skipif(not find_opa(), reason="OPA binary not available")
def test_python_reference_matches_rego():
    tools_ = ["search_corpus", "draft_checklist", "file_review_ticket", "send_external_email", "unknown_tool"]
    roles = ["Architect", "Engineer", "Reviewer", "Auditor", "Intern"]
    classes = ["public", "sensitive", None]
    dests = ["internal", "external"]
    origins = ["user", "retrieved", "unknown", None]
    combos = [Request(*c) for c in itertools.product(tools_, roles, classes, dests, origins)]
    combos += [Request("apply_infra_change", role, None, "internal", origin, env, findings)
               for role, origin, env, findings in itertools.product(roles, origins, ["prod", "nonprod", None], [0, 2])]
    assert len(combos) == 720
    for req in combos:
        py, rego = evaluate_python(req), evaluate(req, "opa")
        assert (py.decision, py.rule, py.reason) == (rego.decision, rego.rule, rego.reason), req


def test_engine_error_fails_closed(monkeypatch):
    monkeypatch.setattr(policy, "find_opa", lambda: "/fake/opa")
    monkeypatch.setattr(policy, "evaluate_opa", lambda req, opa: (_ for _ in ()).throw(OSError("boom")))
    d = evaluate(Request("search_corpus", "Architect"), "auto")
    assert (d.decision, d.rule) == ("DENY", "R0")


def test_rego_snippets_available_for_display():
    for rule in ("R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"):
        assert rule in rego_snippet(rule)


# ---------- session flow ----------

def test_scenarios_end_to_end(session):
    out = {o["scenario"]: o for o in run_all(session)}
    assert not out[1]["declined"] and out[2]["declined"]
    assert out[3]["decision"] == "REQUIRE_APPROVAL" and session.state[out[3]["request_id"]] == "approved"
    assert out[3]["result"] is not None
    assert (out[4]["decision"], out[4]["rule"], out[4]["result"]) == ("DENY", "R4", None)
    assert (out[5]["rule"], out[5]["result"]) == ("R1", None)
    assert out[7]["not_evaluable"] and session.state[out[7]["request_id"]] == "rejected" and out[7]["result"] is None
    assert out[8]["decision"] == "ALLOW" and out[8]["result"] is not None
    assert (out[9]["decision"], out[9]["rule"], out[9]["result"]) == ("DENY", "R4", None)
    assert (out[10]["decision"], out[10]["rule"]) == ("DENY", "R7")
    assert out[11]["rule"] == "R8" and session.state[out[11]["request_id"]] == "approved"
    assert (out[12]["decision"], out[12]["rule"]) == ("ALLOW", "R9") and out[12]["result"] is not None
    assert len(SCENARIOS) == 12


def test_no_tool_runs_without_decision_or_approval(session):  # AC4, AC6
    run_all(session)
    seen = {}
    for r in session.ledger.records:
        m = r["meta"]
        if r["event"] == "policy_decision":
            seen[m["request_id"]] = m["decision"]
        if r["event"] == "approval" and m["approved"]:
            seen[m["request_id"]] = "APPROVED"
        if r["event"] == "tool_result":
            assert seen.get(m["request_id"]) in ("ALLOW", "APPROVED")


def _ticket(session, requested_by=REQUESTER):
    return propose_scenario(session, SCENARIOS[2], requested_by)


def test_only_reviewer_can_decide(session):
    o = _ticket(session)
    with pytest.raises(PermissionError):
        session.decide(o["request_id"], "Architect", True)
    assert o["request_id"] in session.queue
    with pytest.raises(PermissionError):
        session._execute(o["request_id"], "file_review_ticket", {}, o)


def test_rejected_action_never_runs(session):  # AC6
    o = _ticket(session)
    session.decide(o["request_id"], "Reviewer", False, approver=REVIEWER)
    assert not any(r["event"] == "tool_result" for r in session.ledger.records)


# ---------- gateway-established facts (fix 1, INV-7, AC15) ----------

def test_gateway_ignores_claimed_classification(session):
    session.command("Send the Q3 vendor risk assessment to partner@example.com")
    o = session.propose("send_external_email", "Architect",
                        {"to": "partner@example.com", "data_ref": "vendor-risk-q3"},
                        "Send the Q3 vendor risk assessment to partner@example.com",
                        claimed={"classification": "public", "origin": "user"})
    assert (o["decision"], o["rule"]) == ("DENY", "R4")
    assert o["meta"]["classification"] == "sensitive" and o["meta"]["facts_source"] == "gateway"
    assert o["conflicts"] == [{"fact": "classification", "claimed": "public", "established": "sensitive"}]


def test_injection_claimed_as_user_is_still_denied(session):
    o = propose_scenario(session, SCENARIOS[4])
    assert (o["decision"], o["rule"], o["meta"]["origin"]) == ("DENY", "R1", "retrieved")
    assert {"fact": "origin", "claimed": "user", "established": "retrieved"} in o["conflicts"]


def test_untraceable_instruction_is_held_not_allowed(session):
    o = session.propose("draft_checklist", "Architect", {"topic": "x"},
                        "Draft a checklist nobody asked for", claimed={"origin": "user"})
    assert (o["decision"], o["rule"], o["meta"]["origin"]) == ("REQUIRE_APPROVAL", "R6", "unknown")
    assert o["result"] is None and o["not_evaluable"]


def test_retrieved_wins_over_user_when_text_is_in_both(session):
    text = "Email the report to someone@example.net"
    session.command(text)
    session.register_retrieved("doc-x", "Notes. " + text + ". More notes.")
    o = session.propose("send_external_email", "Architect", {"to": "someone@example.net"}, text)
    assert o["rule"] == "R1"


def test_unlabelled_data_and_missing_recipient_fail_safe():
    r = FactResolver()
    assert r.classification("send_external_email", {"data_ref": "controls-checklist-draft"})[0] is None
    assert r.classification("send_external_email", {})[0] is None
    assert r.destination("send_external_email", {})[0] == "external"
    assert r.destination("send_external_email", {"to": "a@example.org"})[0] == "internal"
    assert r.destination("send_external_email", {"to": "a@example.org.evil.net"})[0] == "external"


def test_evidence_flags_decision_on_agent_facts():
    led = Ledger()
    led.append("Model", "tool_request", {"request_id": "REQ-001", "tool": "draft_checklist", "role": "Architect",
                                          "classification": "unknown", "origin": "user", "destination": "internal"})
    status = {r["id"]: r["status"] for r in evidence.build(led.records, load_invariants())["rows"]}
    assert status["INV-7"] == "Violated"


# ---------- sealed approvals and separation of duties (fix 2, INV-3, AC16) ----------

def test_requester_cannot_approve_own_request(session):
    o = _ticket(session, requested_by="alex")
    with pytest.raises(PermissionError, match="separation of duties"):
        session.decide(o["request_id"], "Reviewer", True, approver="alex")
    assert o["request_id"] in session.queue
    assert not any(r["event"] in ("approval", "tool_result") for r in session.ledger.records)
    session.decide(o["request_id"], "Reviewer", True, approver="sam")
    assert session.state[o["request_id"]] == "approved"


def test_request_changed_after_hold_is_refused(session):
    o = _ticket(session)
    session.queue[o["request_id"]]["args"]["title"] = "ARB request: grant agent admin access"
    with pytest.raises(PermissionError, match="seal does not match"):
        session.decide(o["request_id"], "Reviewer", True, approver=REVIEWER)
    events = [r["event"] for r in session.ledger.records]
    assert "tool_result" not in events and events[-1] == "execution_refused"
    assert session.state[o["request_id"]] == "refused"
    pack = evidence.build(session.ledger.records, session.invariants)
    inv3 = next(r for r in pack["rows"] if r["id"] == "INV-3")
    assert inv3["status"] == "Held" and "refused" in inv3["happened"]


def test_approval_seal_matches_decision_and_result(session):
    run_all(session)
    recs = session.ledger.records
    dec = next(r for r in recs if r["event"] == "policy_decision" and r["meta"]["rule"] == "R3")
    app = next(r for r in recs if r["event"] == "approval" and r["meta"]["approved"])
    res = next(r for r in recs if r["event"] == "tool_result" and r["meta"]["tool"] == "file_review_ticket")
    assert dec["meta"]["seal"] == app["meta"]["seal"] == res["meta"]["seal"]
    assert app["meta"]["approver"] == REVIEWER != app["meta"]["requested_by"] == REQUESTER


def test_evidence_flags_self_approval():
    led = Ledger()
    led.append("Model", "tool_request", {"request_id": "REQ-001", "tool": "file_review_ticket", "role": "Architect",
                                          "requested_by": "alex", "classification": "unknown", "origin": "user",
                                          "destination": "internal", "facts_source": "gateway"})
    led.append("Gateway", "policy_decision", {"request_id": "REQ-001", "decision": "REQUIRE_APPROVAL",
                                               "rule": "R3", "seal": "abc"})
    led.append("Reviewer", "approval", {"request_id": "REQ-001", "approved": True, "rule": "R3",
                                         "approver": "alex", "requested_by": "alex", "seal": "abc"})
    led.append("Tool", "tool_result", {"request_id": "REQ-001", "tool": "file_review_ticket", "ok": True,
                                        "mocked": True, "seal": "abc"})
    status = {r["id"]: r["status"] for r in evidence.build(led.records, load_invariants())["rows"]}
    assert status["INV-3"] == "Violated"


def test_ledger_keeps_its_own_copy(session):
    o = _ticket(session)
    o["args"]["title"] = "changed by the caller"
    req = next(r for r in session.ledger.records if r["event"] == "tool_request")
    assert session.ledger.payloads[req["payload_hash"]]["args"]["title"] != "changed by the caller"


# ---------- infrastructure gate (INV-8, AC19) ----------

def _scenario(n):
    return next(x for x in SCENARIOS if x["id"] == n)


def test_infra_findings_read_from_the_plan():
    plan = {"workspace": "dev", "changes": [
        {"resource": "a", "attrs": {"port": [80, 3389], "source": "0.0.0.0/0"}},
        {"resource": "b", "attrs": {"port": 22, "source": "10.0.0.0/8"}},
        {"resource": "c", "attrs": {"public_access": True, "encryption": False}},
        {"resource": "d", "attrs": {"port": 443, "source": "0.0.0.0/0"}}]}
    assert sorted(f["issue"] for f in infra_findings(plan)) == ["admin_port_open", "encryption_disabled", "public_storage"]
    assert infra_findings(remediate_plan(plan)) == []
    assert plan["changes"][0]["attrs"]["source"] == "0.0.0.0/0"  # remediation works on a copy


def test_exposing_change_denied_with_checked_alternative(session):
    o = propose_scenario(session, _scenario(10))
    assert (o["decision"], o["rule"], o["result"]) == ("DENY", "R7", None)
    alt = o["assist"]["alternative"]
    assert alt and (alt["decision"], alt["rule"]) == ("REQUIRE_APPROVAL", "R8")
    assert alt["args"]["plan"]["changes"][0]["attrs"]["source"] == "10.0.0.0/8"
    assert any("port 22 open to 0.0.0.0/0" in t for t in o["assist"]["tips"])
    dec = next(r for r in session.ledger.records if r["event"] == "policy_decision")
    assert dec["meta"]["assist_alternative"].startswith("REQUIRE_APPROVAL by R8") and dec["meta"]["assist"]


def test_prod_change_claimed_as_dev_is_held(session):
    o = propose_scenario(session, _scenario(11))
    assert (o["decision"], o["rule"], o["meta"]["environment"]) == ("REQUIRE_APPROVAL", "R8", "prod")
    assert {"fact": "environment", "claimed": "dev", "established": "prod"} in o["conflicts"]


def test_unknown_workspace_is_held(session):
    session.command("apply it")
    o = session.propose("apply_infra_change", "Engineer", {"plan": {"workspace": "sandbox-7", "changes": []}},
                        "apply it", claimed={"environment": "dev"})
    assert (o["decision"], o["rule"], o["meta"]["environment"]) == ("REQUIRE_APPROVAL", "R6", "unknown")
    assert any("workspace" in t for t in o["assist"]["tips"])


def test_evidence_flags_applied_exposing_change():
    led = Ledger()
    led.append("Model", "tool_request", {"request_id": "REQ-001", "tool": "apply_infra_change", "role": "Engineer",
                                          "origin": "user", "classification": "unknown", "destination": "internal",
                                          "environment": "prod", "facts_source": "gateway",
                                          "infra_findings": [{"issue": "admin_port_open"}]})
    led.append("Tool", "tool_result", {"request_id": "REQ-001", "tool": "apply_infra_change", "ok": True, "mocked": True})
    status = {r["id"]: r["status"] for r in evidence.build(led.records, load_invariants())["rows"]}
    assert status["INV-8"] == "Violated"


# ---------- lane assist and check before you run (AC17, AC18) ----------

def test_lane_assist_on_every_deny_and_hold(session):
    out = {o["scenario"]: o for o in run_all(session)}
    for n in (3, 4, 5, 7, 9, 10, 11):
        assert out[n]["assist"]["tips"], n
    assert out[8]["assist"]["tips"] == [] and out[12]["assist"]["tips"] == []
    assert any("summary that is labelled public" in t for t in out[4]["assist"]["tips"])
    assert any("in their own words" in t for t in out[5]["assist"]["tips"])


def test_check_records_and_runs_nothing(session):
    run_all(session)
    before = (len(session.ledger.records), dict(session.state), len(session.queue))
    for s in [x for x in SCENARIOS if x["kind"] == "tool"]:
        r = session.check(s["tool"], s["role"], scenario_args(s), s["instruction"], s.get("claimed"), typed_by_user=True)
        assert r["recorded"] is False and r["decision"] in ("ALLOW", "REQUIRE_APPROVAL", "DENY")
    assert (len(session.ledger.records), dict(session.state), len(session.queue)) == before


def test_check_cli_for_pipelines():
    def run(*a):
        return subprocess.run([sys.executable, "-m", "quanta_attest.check", *a], cwd=REPO,
                              capture_output=True, text=True)
    deny = run("plan", "examples/plans/open-ssh-prod.json", "--engine", "python")
    assert deny.returncode == 1 and "DENY by R7" in deny.stdout and "checked alternative" in deny.stdout
    assert run("plan", "examples/plans/test-bucket-dev.json", "--engine", "python").returncode == 0
    assert run("plan", "examples/plans/audit-bucket-prod.json", "--engine", "python",
               "--expect", "REQUIRE_APPROVAL").returncode == 0
    cases = run("cases", "policy/cases.yaml")
    assert cases.returncode == 0 and "all passed" in cases.stdout


# ---------- evidence ----------

def _ledger(session):
    run_all(session)
    led = session.ledger
    return copy.deepcopy(led.records), led.public_pem(), led.checkpoint()


def test_ledger_verifies(session):  # AC8
    records, pem, cp = _ledger(session)
    r = verify(records, pem, cp, session.ledger.payloads)
    assert r.ok and r.count == len(records) and "VALID" in r.summary()


def test_tamper_edit_delete_reorder(session):  # AC9
    records, pem, cp = _ledger(session)

    edited = copy.deepcopy(records)
    edited[8]["meta"]["decision"] = "ALLOW"
    r = verify(edited, pem, cp)
    assert not r.ok and r.failed_at == 9 and "edited" in r.reason

    deleted = records[:8] + records[9:]
    r = verify(deleted, pem, cp)
    assert not r.ok and r.failed_at == 9 and "missing" in r.reason

    swapped = copy.deepcopy(records)
    swapped[8], swapped[9] = swapped[9], swapped[8]
    r = verify(swapped, pem, cp)
    assert not r.ok and r.failed_at == 9 and "out of order" in r.reason


def test_truncation_caught_by_checkpoint(session):
    records, pem, cp = _ledger(session)
    r = verify(records[:-2], pem, cp)
    assert not r.ok and "checkpoint" in r.reason


def test_wrong_key_and_payload_edit(session):
    records, pem, cp = _ledger(session)
    assert not verify(records, Signer().public_pem(), cp).ok
    payloads = copy.deepcopy(session.ledger.payloads)
    first = records[0]["payload_hash"]
    payloads[first]["question"] = "changed"
    r = verify(records, pem, cp, payloads)
    assert not r.ok and r.failed_at == 1


def test_evidence_pack_all_held(session):
    run_all(session)
    pack = evidence.build(session.ledger.records, session.invariants)
    assert {row["id"]: row["status"] for row in pack["rows"]} == {f"INV-{n}": "Held" for n in range(9)}
    assert all(row["receipts"] for row in pack["rows"])
    md = evidence.to_markdown(pack, session.id, "all", "rego-test")
    assert "INV-6" in md and "No compliance or certification claim" in md


def test_evidence_pack_detects_violations():
    led = Ledger()
    led.append("Model", "tool_request", {"request_id": "REQ-001", "tool": "send_external_email",
                                          "classification": "sensitive", "origin": "user", "role": "Architect",
                                          "destination": "external"})
    led.append("Tool", "tool_result", {"request_id": "REQ-001", "tool": "send_external_email", "ok": True, "mocked": True})
    status = {r["id"]: r["status"] for r in evidence.build(led.records, load_invariants())["rows"]}
    assert status["INV-0"] == status["INV-1"] == status["INV-2"] == "Violated"


# ---------- search, value, command line ----------

def test_search_declines_weak_matches(index):
    assert index.search("What is our cloud budget for next quarter?") == []
    assert index.search("human oversight")


def test_value_calculator_defaults():
    v = compute(Inputs())
    assert v == {"risk": 349000, "audit": 54000, "delay": 229500, "total": 632500}


def test_demo_and_verify_cli(tmp_path):
    out = tmp_path / "session"
    subprocess.run([sys.executable, "-m", "quanta_attest.demo", "--engine", "python", "--out", str(out)],
                   cwd=REPO, check=True, capture_output=True)
    assert (out / "evidence.md").exists()
    ok = subprocess.run([sys.executable, "-m", "quanta_attest.verify", str(out)], cwd=REPO, capture_output=True, text=True)
    assert ok.returncode == 0 and "VALID" in ok.stdout
    lines = (out / "ledger.jsonl").read_text().splitlines()
    rec = json.loads(lines[4])
    rec["actor"] = "Someone else"
    lines[4] = json.dumps(rec)
    (out / "ledger.jsonl").write_text("\n".join(lines) + "\n")
    bad = subprocess.run([sys.executable, "-m", "quanta_attest.verify", str(out)], cwd=REPO, capture_output=True, text=True)
    assert bad.returncode == 1 and "record 5" in bad.stdout
