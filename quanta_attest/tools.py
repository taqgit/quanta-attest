"""Tools behind the gateway.

All are mocked except `file_review_ticket`, which creates a real GitHub issue
when GITHUB_TOKEN and QA_GITHUB_REPO ("owner/repo") are set. Use a token
scoped to that one repository. Nothing here is reachable except through
Session, which checks for an allow or an approval first (INV-0).
"""

from __future__ import annotations

import os


def _draft_checklist(args: dict) -> dict:
    topic = args.get("topic", "the request")
    return {"mocked": True, "summary": f"Checklist drafted for {topic} from cited sources"}


def _file_review_ticket(args: dict) -> dict:
    token, repo = os.environ.get("GITHUB_TOKEN"), os.environ.get("QA_GITHUB_REPO")
    title = args.get("title", "ARB request")
    body = args.get("body", "Raised by Quanta Attest.")
    if not (token and repo):
        return {"mocked": True, "summary": f"Would create GitHub issue: {title}"}
    import requests

    resp = requests.post(
        f"https://api.github.com/repos/{repo}/issues",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        json={"title": title, "body": body}, timeout=30,
    )
    resp.raise_for_status()
    return {"mocked": False, "summary": f"Created issue #{resp.json()['number']} in {repo}", "url": resp.json()["html_url"]}


def _send_external_email(args: dict) -> dict:
    return {"mocked": True, "summary": f"Would send “{args.get('subject', '')}” to {args.get('to', '')}"}


def _search_corpus(args: dict) -> dict:
    return {"mocked": False, "summary": f"Searched the corpus for: {args.get('query', '')}"}


def _apply_infra_change(args: dict) -> dict:
    plan = args.get("plan") or {}
    n = len(plan.get("changes", []) or [])
    return {"mocked": True, "summary": f"Would apply {n} change(s) to workspace {plan.get('workspace', '?')}"}


TOOLS = {
    "search_corpus": _search_corpus,
    "draft_checklist": _draft_checklist,
    "file_review_ticket": _file_review_ticket,
    "send_external_email": _send_external_email,
    "apply_infra_change": _apply_infra_change,
}
