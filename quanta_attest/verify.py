"""Independent ledger verifier.

    python -m quanta_attest.verify data/session

Needs only ledger.jsonl, checkpoint.json and public_key.pem: no questions,
answers or documents. Exit code 0 when VALID, 1 otherwise.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .ledger import load_folder, verify


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    records, checkpoint, public_pem = load_folder(Path(sys.argv[1]))
    result = verify(records, public_pem, checkpoint)
    print(result.summary())
    sys.exit(0 if result.ok else 1)


if __name__ == "__main__":
    main()
