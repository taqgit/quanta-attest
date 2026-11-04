"""Load and validate the corpus registry (corpus/registry.yaml)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "corpus" / "registry.yaml"

REQUIRED_FIELDS = ("id", "profile", "title", "publisher", "url", "url_status", "format", "terms", "credit")
ALLOWED_FORMATS = {"html", "pdf"}
ALLOWED_STATUS = {"verified", "confirm"}


@dataclass(frozen=True)
class Document:
    id: str
    profile: str
    title: str
    publisher: str
    url: str
    url_status: str
    format: str
    terms: str
    credit: str
    version: str = ""
    optional: bool = False
    excerpts_only: bool = False
    extra: dict = field(default_factory=dict)


def load_registry(path: Path = REGISTRY_PATH) -> tuple[dict[str, str], list[Document]]:
    """Return (profiles, documents), raising ValueError on any invalid entry."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    profiles: dict[str, str] = data["profiles"]
    docs: list[Document] = []
    seen: set[str] = set()
    known = {f.name for f in Document.__dataclass_fields__.values()}

    for raw in data["documents"]:
        missing = [f for f in REQUIRED_FIELDS if not raw.get(f)]
        if missing:
            raise ValueError(f"{raw.get('id', '?')}: missing fields {missing}")
        if raw["id"] in seen:
            raise ValueError(f"duplicate id {raw['id']}")
        if raw["profile"] not in profiles:
            raise ValueError(f"{raw['id']}: unknown profile {raw['profile']}")
        if raw["format"] not in ALLOWED_FORMATS:
            raise ValueError(f"{raw['id']}: format must be one of {ALLOWED_FORMATS}")
        if raw["url_status"] not in ALLOWED_STATUS:
            raise ValueError(f"{raw['id']}: url_status must be one of {ALLOWED_STATUS}")
        if not raw["url"].startswith("https://"):
            raise ValueError(f"{raw['id']}: url must use https")
        seen.add(raw["id"])
        extra = {k: v for k, v in raw.items() if k not in known}
        docs.append(Document(**{k: v for k, v in raw.items() if k in known}, extra=extra))
    return profiles, docs
