"""Evidence pack: what each invariant needed, what happened, and which receipts prove it.

Status is computed from the ledger alone, so an auditor can recompute it:
Held (exercised, no violation), Violated (with the record that breaks it) or
Not exercised (nothing in this session tested it).
"""

from __future__ import annotations

from .invariants import Invariant
from .ledger import VerifyResult

NEEDS_CLASSIFICATION = {"send_external_email"}


def _index(records: list[dict]):
    reqs, decs, apps, results, answers, refused = {}, {}, {}, {}, [], []
    for r in records:
        m, e = r["meta"], r["event"]
        if e == "tool_request":
            reqs[m["request_id"]] = r
        elif e == "policy_decision":
            decs[m["request_id"]] = r
        elif e == "approval":
            apps[m["request_id"]] = r
        elif e == "execution_refused":
            refused.append(r)
        elif e == "tool_result":
            results[m["request_id"]] = r
        elif e == "model_output" and m.get("kind") == "answer":
            answers.append(r)
    return reqs, decs, apps, results, answers, refused


def _approval_ok(app: dict | None, dec: dict, req: dict, result: dict) -> bool:
    """A Reviewer who is not the requester approved, before the run, the exact sealed request."""
    if not app or not app["meta"]["approved"] or app["actor"] != "Reviewer" or app["seq"] > result["seq"]:
        return False
    m = app["meta"]
    if "seal" in dec["meta"]:  # sealed decisions: the seal must carry through approval to execution
        if m.get("seal") != dec["meta"]["seal"] or result["meta"].get("seal") != dec["meta"]["seal"]:
            return False
    requester = req["meta"].get("requested_by")
    return not (requester and m.get("approver") == requester)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def build(records: list[dict], invariants: list[Invariant], verified: VerifyResult | None = None) -> dict:
    reqs, decs, apps, results, answers, refused = _index(records)
    rows = []

    def row(inv: Invariant, status: str, happened: str, receipts: list[int]):
        rows.append({"id": inv.id, "statement": inv.statement, "declaration": inv.declaration,
                     "enforced_by": ", ".join(inv.rules), "controls": ", ".join(inv.controls),
                     "status": status, "happened": happened, "receipts": sorted(set(receipts))})

    for inv in invariants:
        if inv.id == "INV-0":
            bad = [results[r]["seq"] for r in results if r not in decs or decs[r]["seq"] > results[r]["seq"]]
            row(inv, "Violated" if bad else ("Held" if reqs else "Not exercised"),
                f"{_plural(len(reqs), 'tool request')}, {_plural(len(results), 'tool run')}; every run followed a gateway decision"
                if not bad else f"tool ran without a gateway decision at record {bad[0]}",
                bad or [r["seq"] for r in results.values()])
        elif inv.id == "INV-1":
            missing = [reqs[r]["seq"] for r in reqs if r not in decs]
            row(inv, "Violated" if missing else ("Held" if reqs else "Not exercised"),
                f"{_plural(len(reqs), 'request')}, {_plural(len(decs), 'decision')} recorded"
                if not missing else f"request at record {missing[0]} has no recorded decision",
                missing or [d["seq"] for d in decs.values()])
        elif inv.id == "INV-2":
            leaked = [results[r]["seq"] for r in results
                      if reqs[r]["meta"]["tool"] == "send_external_email" and reqs[r]["meta"]["classification"] == "sensitive"]
            denied = [d["seq"] for d in decs.values() if d["meta"]["rule"] == "R4"]
            row(inv, "Violated" if leaked else ("Held" if denied else "Not exercised"),
                f"{_plural(len(denied), 'attempt')} to send sensitive content denied by R4" if not leaked
                else f"sensitive content sent at record {leaked[0]}", leaked or denied)
        elif inv.id == "INV-3":
            held = [r for r, d in decs.items() if d["meta"]["decision"] == "REQUIRE_APPROVAL"]
            bad = [results[r]["seq"] for r in held if r in results and
                   not _approval_ok(apps.get(r), decs[r], reqs[r], results[r])]
            approved = sum(1 for r in held if r in apps and apps[r]["meta"]["approved"])
            rejected = sum(1 for r in held if r in apps and not apps[r]["meta"]["approved"])
            waiting = sum(1 for r in held if r not in apps)
            receipts = ([decs[r]["seq"] for r in held] + [apps[r]["seq"] for r in held if r in apps]
                        + [x["seq"] for x in refused])
            extra = f"; {_plural(len(refused), 'changed request')} refused at execution" if refused else ""
            row(inv, "Violated" if bad else ("Held" if held else "Not exercised"),
                f"{_plural(len(held), 'action')} held: {approved} approved by someone other than the requester, "
                f"{rejected} rejected, {waiting} waiting{extra}"
                if not bad else f"held action ran without a valid, independent approval at record {bad[0]}",
                bad or receipts)
        elif inv.id == "INV-4":
            ran = [results[r]["seq"] for r in results if reqs[r]["meta"]["origin"] == "retrieved"]
            blocked = [d["seq"] for d in decs.values() if d["meta"]["rule"] == "R1"]
            row(inv, "Violated" if ran else ("Held" if blocked else "Not exercised"),
                f"{_plural(len(blocked), 'planted instruction')} blocked by R1; no tool ran" if not ran
                else f"retrieved instruction triggered a tool at record {ran[0]}", ran or blocked)
        elif inv.id == "INV-5":
            bad = [a["seq"] for a in answers if not a["meta"]["citations"] and not a["meta"]["declined"]]
            cited = sum(1 for a in answers if a["meta"]["citations"])
            declined = sum(1 for a in answers if a["meta"]["declined"])
            row(inv, "Violated" if bad else ("Held" if answers else "Not exercised"),
                f"{cited} cited, {declined} declined as out of corpus" if not bad
                else f"uncited answer at record {bad[0]}", bad or [a["seq"] for a in answers])
        elif inv.id == "INV-6":
            unknown = [r for r, q in reqs.items() if q["meta"]["origin"] != "retrieved" and (
                       q["meta"]["origin"] == "unknown" or
                       (q["meta"]["tool"] in NEEDS_CLASSIFICATION and q["meta"]["classification"] == "unknown"))]
            bad = [decs[r]["seq"] for r in unknown if r in decs and decs[r]["meta"]["decision"] == "ALLOW"]
            row(inv, "Violated" if bad else ("Held" if unknown else "Not exercised"),
                f"{_plural(len(unknown), 'request')} with a missing fact held for a human by R6" if not bad
                else f"request with a missing fact was allowed at record {bad[0]}",
                bad or [decs[r]["seq"] for r in unknown if r in decs])
        elif inv.id == "INV-7":
            untrusted = [q["seq"] for q in reqs.values() if q["meta"].get("facts_source") != "gateway"]
            overridden = [q for q in reqs.values() if q["meta"].get("fact_conflicts")]
            claims = sum(len(q["meta"]["fact_conflicts"]) for q in overridden)
            row(inv, "Violated" if untrusted else ("Held" if reqs else "Not exercised"),
                f"{_plural(len(reqs), 'decision')} made on gateway facts; {_plural(claims, 'false agent claim')} "
                f"overridden in {_plural(len(overridden), 'request')}" if not untrusted
                else f"decision made on facts the gateway did not establish at record {untrusted[0]}",
                untrusted or [q["seq"] for q in overridden] or [q["seq"] for q in reqs.values()])
        else:
            row(inv, "Not exercised", "No automatic check defined", [])

    held = sum(1 for r in rows if r["status"] == "Held")
    violated = sum(1 for r in rows if r["status"] == "Violated")
    return {"rows": rows, "held": held, "violated": violated, "total": len(rows),
            "records": len(records), "verified": verified.summary() if verified else "not verified"}


def to_markdown(pack: dict, session_id: str, profile: str, policy_version: str) -> str:
    lines = [
        f"# Evidence pack: session {session_id}",
        "",
        f"Profile: {profile} · Policy: {policy_version} · Records: {pack['records']}",
        f"Ledger: {pack['verified']}",
        f"Invariants: {pack['held']} held, {pack['violated']} violated, "
        f"{pack['total'] - pack['held'] - pack['violated']} not exercised, of {pack['total']}",
        "",
        "| ID | Invariant | Declaration | Status | What happened | Receipts | Control areas |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in pack["rows"]:
        receipts = " ".join(f"#{n}" for n in r["receipts"]) or "-"
        lines.append(f"| {r['id']} | {r['statement']} | `{r['declaration']}` | {r['status']} | {r['happened']} | {receipts} | {r['controls']} |")
    lines += [
        "",
        "Verify independently: `python -m quanta_attest.verify <session folder>`. The verifier needs only the",
        "ledger, the checkpoint and the public key; it never sees questions, answers or documents.",
        "",
        "Demo evidence: signed with a demo key. Control areas are mapped by area; clause numbers are",
        "confirmed against the ingested documents before a pack is issued. No compliance or certification claim.",
    ]
    return "\n".join(lines) + "\n"
