"""Check before you run: ask the gateway what it would decide, without recording or running anything.

  python -m quanta_attest.check plan examples/plans/open-ssh-prod.json [--role Engineer] [--expect DENY]
  python -m quanta_attest.check cases policy/cases.yaml

`plan` is the developer and build-pipeline preflight for an infrastructure change. The plan was committed by
a person, so the instruction counts as theirs. Exit code 1 when the gateway would deny (or when --expect does
not match), so a pipeline stops before deployment. Lane-assist tips are printed with the decision.

`cases` runs policy regression cases (gateway inputs with expected decisions) on the Python reference and, when
installed, on Open Policy Agent. Exit code 1 on any mismatch.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from .policy import Request, evaluate, find_opa
from .search import KeywordIndex
from .session import Session


def check_plan(path: str, role: str, engine: str, expect: str | None) -> int:
    plan = json.loads(Path(path).read_text(encoding="utf-8"))
    s = Session(engine=engine, index=KeywordIndex([]))
    instruction = f"Apply change plan {Path(path).name}"
    r = s.check("apply_infra_change", role, {"plan": plan, "plan_file": Path(path).name}, instruction,
                requested_by="pipeline", typed_by_user=True)
    print(f"{Path(path).name}: {r['decision']} by {r['rule']} ({r['engine']}): {r['reason']}")
    print(f"  environment: {r['meta'].get('environment')} · findings: {len(r['meta'].get('infra_findings', []))}")
    for t in r["assist"]["tips"]:
        print(f"  tip: {t}")
    alt = r["assist"]["alternative"]
    if alt:
        print(f"  checked alternative: {alt['summary']}")
        print("  " + json.dumps(alt["args"]["plan"]))
    print("  nothing was recorded or run")
    if expect:
        return 0 if r["decision"] == expect else 1
    return 1 if r["decision"] == "DENY" else 0


def check_cases(path: str) -> int:
    cases = yaml.safe_load(Path(path).read_text(encoding="utf-8"))["cases"]
    engines = ["python"] + (["opa"] if find_opa() else [])
    failures = 0
    for c in cases:
        req = Request(**c["input"])
        for engine in engines:
            d = evaluate(req, engine)
            want = c["expect"]
            ok = d.decision == want["decision"] and d.rule == want["rule"]
            failures += not ok
            print(f"{'PASS' if ok else 'FAIL'} [{engine}] {c['name']}: {d.decision} by {d.rule}"
                  + ("" if ok else f" (expected {want['decision']} by {want['rule']})"))
    print(f"{len(cases)} cases on {', '.join(engines)}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="quanta_attest.check")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("path")
    p.add_argument("--role", default="Engineer")
    p.add_argument("--engine", default="auto")
    p.add_argument("--expect", choices=["ALLOW", "REQUIRE_APPROVAL", "DENY"])
    c = sub.add_parser("cases")
    c.add_argument("path", nargs="?", default="policy/cases.yaml")
    a = ap.parse_args(argv)
    return check_plan(a.path, a.role, a.engine, a.expect) if a.cmd == "plan" else check_cases(a.path)


if __name__ == "__main__":
    sys.exit(main())
