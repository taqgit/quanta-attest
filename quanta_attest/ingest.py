"""Download the corpus from official sources, extract text and chunk it.

Usage:
    python -m quanta_attest.ingest                 # verified URLs only
    python -m quanta_attest.ingest --include-confirm --include-optional
    python -m quanta_attest.ingest --from-dir tests/fixtures   # offline test

Outputs (all git-ignored):
    data/raw/<doc_id>.<html|pdf>   the downloaded original
    data/chunks.jsonl              one chunk per line, with section metadata
    data/manifest.json             what was fetched, when, its SHA-256 and chunk count
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup

from .chunk import chunk_document
from .registry import REPO_ROOT, Document, load_registry

DATA_DIR = REPO_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
USER_AGENT = "QuantaAttest-demo/0.1 (portfolio demo; contact via GitHub repository)"
DROP_TAGS = ("script", "style", "nav", "header", "footer", "aside", "form", "noscript", "svg", "button")


def html_to_text(html: str) -> str:
    """Turn an HTML page into plain text with markdown-style headings."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(DROP_TAGS):
        tag.decompose()
    root = soup.find("main") or soup.find("article") or soup.body or soup
    lines: list[str] = []
    for el in root.find_all(["h1", "h2", "h3", "h4", "h5", "h6", "p", "li", "td", "dd", "dt"]):
        if el.find_parent(["li", "td"]) and el.name in ("p",):
            continue  # paragraph already captured through its list item or cell
        text = " ".join(el.get_text(" ", strip=True).split())
        if not text:
            continue
        if el.name.startswith("h"):
            lines += ["", f"{'#' * int(el.name[1])} {text}", ""]
        else:
            lines += [text, ""]
    return "\n".join(lines)


def pdf_to_text(data: bytes) -> str:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    pages = []
    for page in reader.pages:
        text = page.extract_text() or ""
        # Drop running headers/footers that are just page numbers.
        text = re.sub(r"(?m)^\s*(Page\s+)?\d+\s*(of\s+\d+)?\s*$", "", text)
        pages.append(text)
    return "\n\n".join(pages)


def fetch(doc: Document) -> bytes:
    import requests

    resp = requests.get(doc.url, headers={"User-Agent": USER_AGENT}, timeout=60)
    resp.raise_for_status()
    return resp.content


def extract(doc: Document, data: bytes) -> str:
    if doc.format == "pdf":
        return pdf_to_text(data)
    return html_to_text(data.decode("utf-8", errors="replace"))


def run(include_confirm: bool, include_optional: bool, from_dir: Path | None, max_chars: int) -> int:
    profiles, docs = load_registry()
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    manifest, all_chunks, failures = [], [], 0

    for doc in docs:
        if doc.url_status == "confirm" and not include_confirm:
            print(f"skip  {doc.id:28} url not yet confirmed in registry.yaml")
            continue
        if doc.optional and not include_optional:
            print(f"skip  {doc.id:28} optional document")
            continue
        try:
            if from_dir:
                src = from_dir / f"{doc.id}.{doc.format if doc.format == 'pdf' else 'txt'}"
                if not src.exists():
                    print(f"skip  {doc.id:28} no fixture at {src}")
                    continue
                data = src.read_bytes()
                text = data.decode("utf-8") if src.suffix == ".txt" else extract(doc, data)
            else:
                data = fetch(doc)
                (RAW_DIR / f"{doc.id}.{doc.format}").write_bytes(data)
                text = extract(doc, data)
        except Exception as exc:  # report and keep going; one bad source must not stop the build
            failures += 1
            print(f"FAIL  {doc.id:28} {type(exc).__name__}: {exc}")
            continue

        chunks = chunk_document(
            text,
            doc_id=doc.id,
            profile=doc.profile,
            title=doc.title,
            source_url=doc.url,
            credit=doc.credit,
            max_chars=max_chars,
        )
        sections = len({c.section_path for c in chunks})
        all_chunks.extend(chunks)
        manifest.append(
            {
                "id": doc.id,
                "profile": doc.profile,
                "url": doc.url,
                "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "chunks": len(chunks),
                "sections": sections,
                "source": "fixture" if from_dir else "official",
            }
        )
        print(f"ok    {doc.id:28} {len(chunks):4} chunks in {sections:3} sections")

    with (DATA_DIR / "chunks.jsonl").open("w", encoding="utf-8") as fh:
        for c in all_chunks:
            fh.write(json.dumps(c.to_dict(), ensure_ascii=False) + "\n")
    (DATA_DIR / "manifest.json").write_text(
        json.dumps({"profiles": profiles, "documents": manifest}, indent=2), encoding="utf-8"
    )
    print(f"\n{len(all_chunks)} chunks from {len(manifest)} documents written to data/; {failures} failed")
    return 1 if failures else 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--include-confirm", action="store_true", help="also fetch entries whose URL is not yet confirmed")
    parser.add_argument("--include-optional", action="store_true", help="also fetch optional documents")
    parser.add_argument("--from-dir", type=Path, help="read <doc_id>.txt or .pdf files from this folder instead of the web")
    parser.add_argument("--max-chars", type=int, default=1200, help="maximum characters per chunk")
    args = parser.parse_args()
    sys.exit(run(args.include_confirm, args.include_optional, args.from_dir, args.max_chars))


if __name__ == "__main__":
    main()
