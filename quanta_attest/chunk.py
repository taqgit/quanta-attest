"""Section-aware chunking.

Splits a document's plain text into chunks that never cross a section
boundary, and records where each chunk sits: its section number, heading and
the path of parent headings. That metadata is what makes a citation precise
("GO-ITS 25.11, section 4.2 Access control") rather than "somewhere in the PDF".
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass

# Headings recognised, most specific first. Each pattern yields (number, title).
HEADING_PATTERNS = [
    # "Article 9" / "Article 9 Risk management system" (EU legal texts)
    re.compile(r"^(Article\s+\d+[a-z]?)\s*[:.\-–]?\s*(.*)$", re.IGNORECASE),
    # "Annex III" / "Appendix A: Glossary"
    re.compile(r"^((?:Annex|Appendix|Schedule)\s+[A-Z0-9IVXL]+)\s*[:.\-–]?\s*(.*)$", re.IGNORECASE),
    # "Section 6" / "Part 2 Scope"
    re.compile(r"^((?:Section|Part|Chapter)\s+\d+[a-z]?)\s*[:.\-–]?\s*(.*)$", re.IGNORECASE),
    # "6.3.11 Implementing measures" / "2.4 Scope" / "1. Introduction" / "A.2 Scope"
    re.compile(r"^((?:[A-Z]\.)?\d+(?:\.\d+)*)\.?\s+([A-Z][^\n]{0,120})$"),
    # "A. Overview" / "C. Risk assessment" (lettered top-level parts)
    re.compile(r"^([A-Z])\.\s+([A-Z][^\n]{0,120})$"),
    # Markdown headings produced by HTML extraction: "## Scope"
    re.compile(r"^(#{1,6})\s+(.+)$"),
]

MAX_HEADING_WORDS = 14
INNER_NUMBER = re.compile(r"^((?:Article|Annex|Appendix|Section|Part|Chapter)\s+[A-Z0-9IVXL]+|(?:[A-Z]\.)?\d+(?:\.\d+)*)\.?\s+(.+)$")


@dataclass
class Chunk:
    chunk_id: str
    doc_id: str
    profile: str
    title: str
    section_number: str
    section_heading: str
    section_path: str
    text: str
    char_count: int
    source_url: str
    credit: str

    def to_dict(self) -> dict:
        return asdict(self)

    def citation(self) -> str:
        where = " ".join(p for p in (self.section_number, self.section_heading) if p).strip()
        return f"{self.title}, {where}" if where else self.title


def _depth(number: str) -> int:
    if number.startswith("#"):
        return len(number)
    if re.match(r"^(Article|Annex|Appendix|Schedule|Section|Part|Chapter)", number, re.IGNORECASE):
        return 1
    core = re.sub(r"^[A-Z]\.", "1.", number)
    return core.count(".") + 1


def match_heading(line: str) -> tuple[str, str] | None:
    """Return (number, heading) if the line looks like a section heading."""
    line = line.strip()
    if not line or len(line.split()) > MAX_HEADING_WORDS or line.endswith((",", ";")):
        return None
    for pattern in HEADING_PATTERNS:
        m = pattern.match(line)
        if m:
            number, heading = m.group(1).strip(), m.group(2).strip()
            if number.startswith("#"):
                return number, heading  # inner numbering is parsed in split_sections
            # A bare number followed by a long sentence ending in a period is body text.
            if heading.endswith(".") and len(heading.split()) > 8:
                return None
            return number, heading
    return None


def split_sections(text: str) -> list[dict]:
    """Split text into sections, each with number, heading, path and body."""
    sections: list[dict] = []
    stack: list[tuple[int, str]] = []  # (depth, label) of open headings
    current = {"number": "", "heading": "", "path": "", "lines": []}
    awaiting_title = False  # "Article 12" on one line, its title on the next

    for line in text.splitlines():
        if awaiting_title and line.strip():
            awaiting_title = False
            if len(line.split()) <= MAX_HEADING_WORDS and not line.strip().endswith("."):
                current["heading"] = line.strip()
                label = f"{current['number']} {current['heading']}"
                stack[-1] = (stack[-1][0], label)
                current["path"] = " > ".join(l for _, l in stack)
                continue
        found = match_heading(line)
        if found:
            if any(l.strip() for l in current["lines"]):
                sections.append(current)
            number, heading = found
            depth = _depth(number)
            if number.startswith("#"):
                inner = INNER_NUMBER.match(heading)
                number, heading = (inner.group(1), inner.group(2).strip()) if inner else ("", heading)
            label = f"{number} {heading}".strip()
            while stack and stack[-1][0] >= depth:
                stack.pop()
            stack.append((depth, label))
            current = {
                "number": number,
                "heading": heading,
                "path": " > ".join(l for _, l in stack),
                "lines": [],
            }
            awaiting_title = not heading
        else:
            current["lines"].append(line)

    if any(l.strip() for l in current["lines"]):
        sections.append(current)
    return sections


def _paragraphs(lines: list[str]) -> list[str]:
    paras, buf = [], []
    for line in lines:
        if line.strip():
            buf.append(line.strip())
        elif buf:
            paras.append(" ".join(buf))
            buf = []
    if buf:
        paras.append(" ".join(buf))
    return paras


def _pack(paras: list[str], max_chars: int) -> list[str]:
    """Pack paragraphs into pieces up to max_chars, splitting long paragraphs at sentences."""
    pieces, buf = [], ""
    for para in paras:
        units = [para] if len(para) <= max_chars else re.split(r"(?<=[.!?])\s+", para)
        for unit in units:
            while len(unit) > max_chars:  # a single run-on sentence
                pieces.append(unit[:max_chars])
                unit = unit[max_chars:]
            if buf and len(buf) + 1 + len(unit) > max_chars:
                pieces.append(buf)
                buf = unit
            else:
                buf = f"{buf} {unit}".strip() if buf else unit
    if buf:
        pieces.append(buf)
    return pieces


def chunk_document(
    text: str,
    *,
    doc_id: str,
    profile: str,
    title: str,
    source_url: str,
    credit: str,
    max_chars: int = 1200,
    min_chars: int = 40,
) -> list[Chunk]:
    """Chunk a document's text without crossing section boundaries."""
    chunks: list[Chunk] = []
    for section in split_sections(text):
        for piece in _pack(_paragraphs(section["lines"]), max_chars):
            if len(piece) < min_chars:
                continue
            digest = hashlib.sha256(f"{doc_id}|{section['path']}|{piece}".encode()).hexdigest()[:12]
            chunks.append(
                Chunk(
                    chunk_id=f"{doc_id}:{digest}",
                    doc_id=doc_id,
                    profile=profile,
                    title=title,
                    section_number=section["number"],
                    section_heading=section["heading"],
                    section_path=section["path"],
                    text=piece,
                    char_count=len(piece),
                    source_url=source_url,
                    credit=credit,
                )
            )
    return chunks
