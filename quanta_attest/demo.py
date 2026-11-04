"""Run the full scripted demo from the command line and write its evidence.

    python -m quanta_attest.demo                  # writes data/session/
    python -m quanta_attest.demo --engine python  # force the Python reference policy

Then verify independently:
    python -m quanta_attest.verify data/session
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import evidence
from .ledger import verify
from .registry import REPO_ROOT
from .scenarios import run_all
from .session import Session, policy_version


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--engine", choices=["auto", "opa", "python"], default="auto")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "data" / "session")
    ap.add_argument("--profile", default=None, help="limit answers to one sector profile")
    args = ap.parse_args()

    s = Session(engine=args.engine)
    for o in run_all(s, args.profile):
        if "decision" in o:
            label = "not evaluable, held" if o["not_evaluable"] else o["decision"]
            print(f"scenario {o['scenario']}: {o['tool']:20} {label:22} {o['rule']}  receipts {o['receipts']}")
        else:
            print(f"scenario {o['scenario']}: {'declined' if o['declined'] else 'cited ' + str(len(o['hits']))} "
                  f" receipts {o['receipts']}")

    s.ledger.save(args.out)
    result = verify(s.ledger.records, s.ledger.public_pem(), s.ledger.checkpoint(), s.ledger.payloads)
    pack = evidence.build(s.ledger.records, s.invariants, result)
    (args.out / "evidence.md").write_text(
        evidence.to_markdown(pack, s.id, args.profile or "all profiles", policy_version()), encoding="utf-8")
    (args.out / "evidence.json").write_text(json.dumps(pack, indent=2), encoding="utf-8")
    print(f"\n{result.summary()}")
    print(f"Invariants: {pack['held']} held, {pack['violated']} violated, of {pack['total']}")
    print(f"Written to {args.out}")


if __name__ == "__main__":
    main()
