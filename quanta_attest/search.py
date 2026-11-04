"""Placeholder keyword retrieval for the Day 1 skeleton.

Day 2 replaces this with embedding retrieval. Keeping the same interface,
search(query, profile, k) -> list of (score, chunk dict), means the
interface code does not change.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path

from .registry import REPO_ROOT

CHUNKS_PATH = REPO_ROOT / "data" / "chunks.jsonl"
STOPWORDS = set(
    "a an and are as at be by for from has have how in is it its of on or that the this to was what when where which "
    "who why will with does do should must can may i we you our your".split()
)


def tokenize(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9]+", text.lower()) if t not in STOPWORDS and len(t) > 1]


class KeywordIndex:
    def __init__(self, chunks: list[dict]):
        self.chunks = chunks
        self.tfs = [Counter(tokenize(c["section_heading"] + " " + c["text"])) for c in chunks]
        df = Counter(t for tf in self.tfs for t in tf)
        n = max(len(chunks), 1)
        self.idf = {t: math.log(1 + n / d) for t, d in df.items()}

    @classmethod
    def load(cls, path: Path = CHUNKS_PATH) -> "KeywordIndex":
        if not path.exists():
            return cls([])
        with path.open(encoding="utf-8") as fh:
            return cls([json.loads(line) for line in fh if line.strip()])

    def search(self, query: str, profile: str | None = None, k: int = 3,
               min_coverage: float = 0.5) -> list[tuple[float, dict]]:
        """Top-k chunks. A chunk must contain at least min_coverage of the distinct query
        terms, so a question that only brushes the corpus is declined rather than answered."""
        terms = list(dict.fromkeys(tokenize(query)))
        scored = []
        for chunk, tf in zip(self.chunks, self.tfs):
            if profile and chunk["profile"] != profile:
                continue
            matched = [t for t in terms if tf[t]]
            if not terms or len(matched) / len(terms) < min_coverage:
                continue
            score = sum(self.idf.get(t, 0) * (1 + math.log(tf[t])) for t in matched)
            if score > 0:
                scored.append((score, chunk))
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[:k]
