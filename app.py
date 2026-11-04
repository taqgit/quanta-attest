"""Quanta Attest demo app.

Run with:  streamlit run app.py

The model proposes, the policy decides, the ledger proves. Tool proposals are
scripted until the model is connected (Day 2); the gateway, approvals, signed
ledger, verifier and evidence pack are real.
"""

from __future__ import annotations

import copy
import json

import pandas as pd
import streamlit as st

from quanta_attest import evidence
from quanta_attest.invariants import load_invariants
from quanta_attest.ledger import verify
from quanta_attest.policy import find_opa, rego_snippet
from quanta_attest.registry import REPO_ROOT, load_registry
from quanta_attest.facts import FactResolver
from quanta_attest.scenarios import SCENARIOS, propose_scenario, run_all
from quanta_attest.search import KeywordIndex
from quanta_attest.session import Session, policy_version
from quanta_attest.value import OFFERS, SOURCES, Inputs, compute

st.set_page_config(page_title="Quanta Attest", page_icon="◆", layout="wide")

CLAIM = ("**Demo.** Enforcement is real inside this app; the tools behind the gateway are mocked, except the "
         "optional GitHub issue. Evidence is signed with a demo key. Tool proposals are scripted until the model "
         "is connected, and names stand in for single sign-on. No compliance, certification or production claim.")
PAGES = ["Tour", "Ask", "Policy decisions", "Approvals", "Ledger", "Evidence pack", "Value"]
BADGE = {"ALLOW": "Allowed", "REQUIRE_APPROVAL": "Held for approval", "DENY": "Denied"}


@st.cache_resource
def get_index() -> KeywordIndex:
    return KeywordIndex.load()


def session() -> Session:
    if "qa" not in st.session_state:
        st.session_state.qa = Session(index=get_index())
    return st.session_state.qa


def claim_boundary() -> None:
    st.caption(CLAIM)


def invariant_lines(ids: list[str]) -> str:
    by_id = {i.id: i for i in load_invariants()}
    return "\n".join(f"- **{i}** {by_id[i].statement}  \n  `{by_id[i].declaration}`" for i in ids if i in by_id)


def show_outcome(o: dict) -> None:
    label = "Not evaluable: held for a human" if o["not_evaluable"] else BADGE[o["decision"]]
    box = {"ALLOW": st.success, "REQUIRE_APPROVAL": st.warning, "DENY": st.error}[o["decision"]]
    with st.container(border=True):
        box(f"**{label}** · `{o['tool']}` · rule {o['rule']}: {o['reason']}")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Requested by", f"{o['requested_by']} ({o['role']})")
        c2.metric("Classification", o["meta"]["classification"])
        c3.metric("Origin", o["meta"]["origin"])
        c4.metric("Receipts", " ".join(f"#{n}" for n in o["receipts"]))
        basis = o["meta"]["facts_basis"]
        st.caption(f"Facts established by the gateway, not the agent (INV-7): classification from "
                   f"{basis['classification']}; origin {basis['origin']}; destination: {basis['destination']}.")
        for c in o["conflicts"]:
            st.warning(f"The agent claimed {c['fact']} = **{c['claimed']}**; the gateway established "
                       f"**{c['established']}**. The decision used the established fact, and the conflict is "
                       "recorded in the ledger.")
        state = s.state.get(o["request_id"], "")
        st.markdown(f"Status: **{state}** · engine: {o['engine']} · {o['request_id']} · seal `{o['seal'][:12]}`")
        if o["result"]:
            st.markdown(f"Tool result: {o['result']['summary']}" + (" (mocked)" if o["result"].get("mocked") else ""))
        dec = next((r for r in s.ledger.records if r["event"] == "policy_decision"
                    and r["meta"]["request_id"] == o["request_id"]), None)
        if dec:
            st.markdown("Invariants this decision evidences:\n" + invariant_lines(dec["meta"]["invariants"]))
        with st.expander(f"Policy as code: rule {o['rule']} (read-only)"):
            st.code(rego_snippet(o["rule"]), language="rego")


profiles, _ = load_registry()
s = session()

with st.sidebar:
    st.header("◆ Quanta Attest")
    st.caption("The model proposes, the policy decides, the ledger proves.")
    page = st.radio("Screen", PAGES, key="page", label_visibility="collapsed")
    st.divider()
    labels = {"All profiles": None, **{v: k for k, v in profiles.items()}}
    profile = labels[st.selectbox("Sector profile", list(labels))]
    role = st.selectbox("Acting as", ["Architect", "Reviewer", "Auditor"],
                        help="Role switching stands in for single sign-on.")
    name = st.text_input("Your name", value="alex",
                         help="Stands in for a signed-in identity. Whoever requests an action cannot approve it.").strip() or "alex"
    st.divider()
    st.caption(f"Session {s.id} · {len(s.ledger.records)} records · {len(s.queue)} waiting for approval")
    st.caption(f"Policy {policy_version()} · engine: {'OPA' if find_opa() else 'Python reference'}")
    if st.button("Start a new session"):
        del st.session_state["qa"]
        st.rerun()

# ------------------------------------------------------------------ Tour
if page == "Tour":
    st.title("From architectural intent to verifiable evidence")
    claim_boundary()
    t1, t2, t3, t4 = st.tabs(["1 · Intent", "2 · Enforce", "3 · Evidence", "4 · Value"])
    with t1:
        st.subheader("What must remain true")
        st.write("Each invariant holds or is violated, with no third state. Each has a one-line declaration "
                 "and the gateway rules that enforce it.")
        st.dataframe(pd.DataFrame([{"ID": i.id, "Invariant": i.statement, "Declaration": i.declaration,
                                    "Enforced by": ", ".join(i.rules)} for i in load_invariants()]),
                     hide_index=True, width="stretch")
    with t2:
        st.subheader("Every action gets exactly one decision before it runs")
        st.write("Run the scripted session: two questions and six proposed actions. A Reviewer who is not the "
                 "requester approves the review ticket and rejects the email with no data classification. In two "
                 "requests the agent makes false claims; the gateway overrides both.")
        if st.button("Run the demo script", type="primary"):
            run_all(s, profile)
        for o in s.outcomes:
            label = "not evaluable, held" if o["not_evaluable"] else BADGE[o["decision"]]
            st.markdown(f"- `{o['tool']}`: **{label}** by {o['rule']} ({s.state[o['request_id']]})")
    with t3:
        st.subheader("Signed, hash-chained, independently verifiable")
        if s.ledger.records:
            res = verify(s.ledger.records, s.ledger.public_pem(), s.ledger.checkpoint(), s.ledger.payloads)
            (st.success if res.ok else st.error)(res.summary())
            pack = evidence.build(s.ledger.records, s.invariants, res)
            st.metric("Invariants held", f"{pack['held']} of {pack['total']}")
        else:
            st.info("Run the demo script in step 2 first.")
    with t4:
        st.subheader("Why a buyer pays")
        v = compute(Inputs())
        st.metric("Illustrative annual value for one AI project", f"${v['total']:,.0f}",
                  help="Default assumptions; adjust them on the Value screen.")
        st.write("Start with a one-week assessment; earn the readiness engagement; keep the evidence current "
                 "with a retainer. Open the Value screen for the drivers, sources and offers.")

# ------------------------------------------------------------------ Ask
elif page == "Ask":
    st.title("Ask the policy corpus")
    claim_boundary()
    if not s.index.chunks:
        st.warning("No corpus loaded. Run `python -m quanta_attest.ingest` first.")
    q = st.chat_input("Ask about a policy, standard or control")
    if q:
        st.session_state.setdefault("chat", []).append(s.ask(q, role, profile))
    for turn in st.session_state.get("chat", []):
        with st.chat_message("user"):
            st.markdown(turn["question"])
        with st.chat_message("assistant"):
            if turn["declined"]:
                st.markdown("The documents in this profile don't cover that, so there is nothing I can cite. "
                            "I won't guess.")
                st.caption(f"Declined · receipts {turn['receipts']}")
            else:
                st.markdown("Most relevant passages (model answers arrive with the Day 2 model connection):")
                for n, c in enumerate(turn["hits"], 1):
                    st.markdown(f"**[{n}] {c['title']}**: {c['section_path'] or 'untitled section'}  \n"
                                f"> {c['text'][:500]}  \n[Source]({c['source_url']}) · {c['credit']}")
                st.caption(f"Cited · receipts {turn['receipts']}")

# ------------------------------------------------------------------ Decisions
elif page == "Policy decisions":
    st.title("Policy decisions")
    claim_boundary()
    st.write("Every proposed action gets exactly one decision before anything runs. "
             "Anything no rule allows is denied; a missing fact sends the request to a human.")
    st.subheader("Run a scenario")
    tool_scenarios = [x for x in SCENARIOS if x["kind"] == "tool"]
    cols = st.columns(3)
    for i, sc in enumerate(tool_scenarios):
        if cols[i % 3].button(f"{sc['id']} · {sc['title']}", width="stretch"):
            propose_scenario(s, sc, name)
    with st.expander("Try your own request"):
        st.caption("You control what really happened. The agent's claims are shown to the gateway, which ignores "
                   "them and establishes the facts itself.")
        labels = FactResolver().objects
        c1, c2, c3 = st.columns(3)
        tool = c1.selectbox("Tool", ["send_external_email", "file_review_ticket", "draft_checklist",
                                     "search_corpus", "delete_database"])
        data_ref = c2.selectbox("Data being sent", list(labels) + ["controls-checklist-draft (unlabelled)", "none"])
        to = c3.text_input("Recipient", "partner@example.com")
        instruction = st.text_input("Instruction the agent acted on", "Email the checklist to partner@example.com")
        c4, c5, c6 = st.columns(3)
        source = c4.selectbox("Where that instruction really came from",
                              ["You typed it", "A retrieved document", "Nowhere traceable"])
        claim_cls = c5.selectbox("Agent claims classification", ["(no claim)", "public", "sensitive"])
        claim_org = c6.selectbox("Agent claims origin", ["(no claim)", "user", "retrieved"])
        if st.button(f"Propose as {name} ({role})"):
            if source == "You typed it":
                s.command(instruction)
            elif source == "A retrieved document":
                s.register_retrieved(f"custom-{len(s.retrieved) + 1}", f"Retrieved text. {instruction}. End.")
            args = {"subject": "Custom request", "to": to}
            if data_ref != "none":
                args["data_ref"] = data_ref.split(" ")[0]
            claimed = {k: v for k, v in (("classification", claim_cls), ("origin", claim_org)) if v != "(no claim)"}
            s.propose(tool, role, args, instruction, claimed, name)
    st.subheader("This session")
    if not s.outcomes:
        st.info("No actions proposed yet.")
    for o in reversed(s.outcomes):
        show_outcome(o)

# ------------------------------------------------------------------ Approvals
elif page == "Approvals":
    st.title("Approvals")
    claim_boundary()
    st.write("Held actions wait here. Nothing runs until an accountable Reviewer decides, and the decision "
             "is signed into the ledger.")
    if not s.queue:
        st.info("Nothing is waiting. Run scenario 3 or 7 on the Policy decisions screen.")
    if s.queue and role != "Reviewer":
        st.warning("Switch **Acting as** to Reviewer to approve or reject (INV-3).")
    for rid, o in list(s.queue.items()):
        with st.container(border=True):
            st.markdown(f"**{rid}** · `{o['tool']}` requested by **{o['requested_by']}** ({o['role']}) · "
                        f"rule {o['rule']}: {o['reason']}")
            if o["not_evaluable"]:
                st.warning(f"{o['reason']}. Establish the missing fact, or reject.")
            st.json(o["args"])
            st.caption(f"You are approving exactly this request, sealed as `{o['seal'][:16]}`. If anything in it "
                       "changes before it runs, the gateway refuses to run it.")
            if name == o["requested_by"]:
                st.info(f"You ({name}) requested this, so another person must decide. Change **Your name** to try.")
            note = st.text_input("Note for the record", key=f"note-{rid}")
            c1, c2 = st.columns(2)
            for col, label, ok in ((c1, "Approve", True), (c2, "Reject", False)):
                if col.button(label, key=f"{label}-{rid}", disabled=role != "Reviewer",
                              type="primary" if ok else "secondary"):
                    try:
                        s.decide(rid, role, ok, note, approver=name)
                        st.rerun()
                    except PermissionError as exc:
                        st.error(str(exc))

# ------------------------------------------------------------------ Ledger
elif page == "Ledger":
    st.title("Audit ledger")
    claim_boundary()
    recs = s.ledger.records
    if not recs:
        st.info("The ledger is empty. Ask a question or run a scenario first.")
    else:
        st.dataframe(pd.DataFrame([{
            "Seq": r["seq"], "Time (UTC)": r["ts"][11:19], "Actor": r["actor"], "Event": r["event"],
            "Detail": ", ".join(f"{k}={v}" for k, v in r["meta"].items() if k in ("tool", "decision", "rule", "approved", "passages", "declined")),
            "Payload hash": r["payload_hash"][:12] + "…", "Record hash": r["record_hash"][:12] + "…",
        } for r in recs]), hide_index=True, width="stretch")
        res = verify(recs, s.ledger.public_pem(), s.ledger.checkpoint(), s.ledger.payloads)
        (st.success if res.ok else st.error)(res.summary())

        st.subheader("Tamper test (scenario 6)")
        st.write("Change a copy of the ledger, then verify the copy. The original is never modified.")
        c1, c2 = st.columns(2)
        n = c1.number_input("Record", 1, len(recs), min(9, len(recs)))
        how = c2.selectbox("Change", ["Edit its decision or actor", "Delete it", "Swap it with the next record"])
        if st.button("Verify the tampered copy", type="primary"):
            copy_ = copy.deepcopy(recs)
            i = n - 1
            if how.startswith("Edit"):
                if "decision" in copy_[i]["meta"]:
                    copy_[i]["meta"]["decision"] = "ALLOW"
                else:
                    copy_[i]["actor"] = "Someone else"
            elif how.startswith("Delete"):
                del copy_[i]
            elif i + 1 < len(copy_):
                copy_[i], copy_[i + 1] = copy_[i + 1], copy_[i]
            st.error(verify(copy_, s.ledger.public_pem(), s.ledger.checkpoint()).summary())

        st.subheader("Verify it yourself")
        cp = s.ledger.checkpoint()
        c1, c2, c3 = st.columns(3)
        c1.download_button("ledger.jsonl", "\n".join(json.dumps(r) for r in recs) + "\n", "ledger.jsonl")
        c2.download_button("checkpoint.json", json.dumps(cp, indent=2), "checkpoint.json")
        c3.download_button("public_key.pem", s.ledger.public_pem(), "public_key.pem")
        st.code("python -m quanta_attest.verify <folder with the three files>", language="bash")

# ------------------------------------------------------------------ Evidence
elif page == "Evidence pack":
    st.title("Evidence pack")
    claim_boundary()
    res = verify(s.ledger.records, s.ledger.public_pem(), s.ledger.checkpoint(), s.ledger.payloads)
    pack = evidence.build(s.ledger.records, s.invariants, res)
    c1, c2, c3 = st.columns(3)
    c1.metric("Invariants held", f"{pack['held']} of {pack['total']}")
    c2.metric("Violated", pack["violated"])
    c3.metric("Ledger", "VALID" if res.ok else "FAILED", f"{pack['records']} records", delta_color="off")
    st.caption(f"Session {s.id} · Policy {policy_version()}")
    st.dataframe(pd.DataFrame([{
        "ID": r["id"], "Invariant": r["statement"], "Declaration": r["declaration"], "Status": r["status"],
        "What happened": r["happened"], "Receipts": " ".join(f"#{n}" for n in r["receipts"]),
        "Control areas": r["controls"],
    } for r in pack["rows"]]), hide_index=True, width="stretch")
    st.download_button("Download evidence pack (Markdown)",
                       evidence.to_markdown(pack, s.id, profile or "all profiles", policy_version()),
                       f"evidence-{s.id}.md")
    st.caption("Control areas are mapped by area; clause numbers are confirmed against the ingested documents "
               "before a pack is issued.")

# ------------------------------------------------------------------ Value
elif page == "Value":
    st.title("Why a buyer pays")
    claim_boundary()
    st.write("An illustrative annual value for AI projects at one organization. Each driver combines sourced "
             "market data with an assumption you can change. This is an estimate, not a return figure.")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.subheader("Risk avoided")
        breach = st.number_input("Average breach cost", value=6_980_000, step=100_000)
        pp = st.slider("Breach likelihood removed (percentage points)", 0.0, 20.0, 5.0, 0.5)
    with c2:
        st.subheader("Audit preparation")
        hours = st.slider("Evidence-gathering hours per audit", 100, 800, 400, 25)
        audits = st.slider("Audits per year", 1, 6, 1)
    with c3:
        st.subheader("Faster approval")
        weeks = st.slider("Weeks of governance delay removed", 0.0, 26.0, 8.5, 0.5)
        team = st.slider("Team size", 1, 20, 5)
        projects = st.slider("AI projects", 1, 20, 1)
    rate = st.slider("Blended hourly rate", 60, 250, 135, 5)
    v = compute(Inputs(breach, pp, hours, audits, rate, weeks, team, 40, projects))
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Risk avoided", f"${v['risk']:,.0f}")
    m2.metric("Audit preparation", f"${v['audit']:,.0f}")
    m3.metric("Faster approval", f"${v['delay']:,.0f}")
    m4.metric("Total per year", f"${v['total']:,.0f}")
    st.caption("Sources mix Canadian and US dollars; convert before showing a client.")
    with st.expander("Sources"):
        for group in SOURCES.values():
            for text, url in group:
                st.markdown(f"- [{text}]({url})")
    st.subheader("Offers")
    st.dataframe(pd.DataFrame(OFFERS, columns=["Offer", "Duration", "Price (CAD, before tax)", "What you get"]),
                 hide_index=True, width="stretch")
