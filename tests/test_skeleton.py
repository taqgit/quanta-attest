"""Day 1 tests: registry validity, section-aware chunking and offline ingest."""

from pathlib import Path

import pytest

from quanta_attest.chunk import chunk_document, match_heading, split_sections
from quanta_attest.ingest import html_to_text
from quanta_attest.registry import load_registry
from quanta_attest.search import KeywordIndex

FIXTURES = Path(__file__).parent / "fixtures"


def _chunks(name: str, **kw):
    return chunk_document(
        (FIXTURES / f"{name}.txt").read_text(),
        doc_id=name, profile="test", title=name, source_url="https://example.org", credit="test", **kw
    )


def test_registry_is_valid():
    profiles, docs = load_registry()
    assert set(profiles) == {"public-sector", "cross-industry", "regulated"}
    assert len(docs) >= 10
    assert {d.profile for d in docs} == set(profiles)
    assert all(d.url.startswith("https://") for d in docs)


@pytest.mark.parametrize(
    "line,expected",
    [
        ("6.3.11 Implementing measures", ("6.3.11", "Implementing measures")),
        ("1. Introduction", ("1", "Introduction")),
        ("A.2 Scope", ("A.2", "Scope")),
        ("A. Overview", ("A", "Overview")),
        ("Article 14", ("Article 14", "")),
        ("Annex III", ("Annex III", "")),
        ("## 3.1 In scope", ("##", "3.1 In scope")),
    ],
)
def test_headings_are_recognised(line, expected):
    assert match_heading(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        "This directive applies to all ministries, agencies and boards.",
        "2 The organization must assess each system before it is deployed to production use.",
        "",
    ],
)
def test_body_text_is_not_a_heading(line):
    assert match_heading(line) is None


def test_markdown_sections_keep_numbers_and_parent_path():
    sections = {s["number"]: s for s in split_sections((FIXTURES / "on-ai-directive.txt").read_text())}
    assert sections["3.1"]["heading"] == "In scope"
    assert sections["3.1"]["path"] == "Sample AI Directive > 3 Application and scope > 3.1 In scope"
    assert sections["3.2"]["path"].endswith("3 Application and scope > 3.2 Out of scope")


def test_article_titles_on_the_next_line_are_attached():
    chunks = _chunks("eu-ai-act")
    by_number = {c.section_number: c for c in chunks}
    assert by_number["Article 14"].section_heading == "Human oversight"
    assert by_number["Article 12"].citation() == "eu-ai-act, Article 12 Record-keeping"
    assert by_number["Annex III"].section_heading == "High-risk use cases"


def test_lettered_parts_nest_their_subsections():
    by_number = {c.section_number: c for c in _chunks("osfi-e23")}
    assert by_number["A.2"].section_path == "A Overview > A.2 Scope"
    assert by_number["C.2"].section_path == "C Risk assessment > C.2 Model risk rating"


def test_chunks_never_cross_sections_and_respect_size():
    chunks = _chunks("on-ai-directive", max_chars=120)
    assert all(c.char_count <= 120 for c in chunks)
    risk = [c for c in chunks if c.section_number == "4"]
    assert len(risk) >= 2  # the long section was split
    assert all("Research prototypes" not in c.text for c in risk)  # no bleed from 3.2


def test_chunk_ids_are_stable():
    first = [c.chunk_id for c in _chunks("osfi-e23")]
    second = [c.chunk_id for c in _chunks("osfi-e23")]
    assert first == second and len(set(first)) == len(first)


def test_html_extraction_keeps_headings_and_drops_navigation():
    html = """<html><body><nav>Menu Home Contact</nav><main>
      <h1>Sample Standard</h1><h2>2.4 Scope</h2><p>Applies to all ministries.</p>
      <ul><li>Item one</li></ul></main><footer>Copyright</footer></body></html>"""
    text = html_to_text(html)
    assert "## 2.4 Scope" in text and "Applies to all ministries." in text
    assert "Menu" not in text and "Copyright" not in text
    assert split_sections(text)[-1]["number"] == "2.4"


def test_keyword_search_filters_by_profile():
    index = KeywordIndex([c.to_dict() for c in _chunks("eu-ai-act") + _chunks("osfi-e23")])
    hits = index.search("human oversight", k=1)
    assert hits and hits[0][1]["section_number"] == "Article 14"
    assert index.search("human oversight", profile="nonexistent") == []
