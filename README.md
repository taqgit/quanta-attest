# Quanta Attest

**The model proposes, the policy decides, the ledger proves.**

Quanta Attest is a demonstration of a governed AI agent. It answers only from cited public policy documents, every tool request gets exactly one policy decision before it can run, and every step is written to a signed, tamper-evident ledger that anyone can verify.

> **Demo.** Enforcement is real inside this app; the tools behind the gateway are mocked, except an optional GitHub issue. Evidence is signed with a demo key. Tool proposals are scripted until the model is connected. No compliance, certification or production claim.

Three layers, each answering one question:

| Layer | Question | In this repository |
| --- | --- | --- |
| Intent (Binary Architecture) | What must remain true? | `intent/invariants.yaml`: INV-0 to INV-7, each with a one-line declaration; `intent/data_labels.yaml`: the data labels the gateway trusts |
| Enforcement (BinaryQuanta) | What stops it being broken? | `policy/gateway.rego`: rules R0 to R6, evaluated by Open Policy Agent |
| Evidence (Evidence as a Service) | What proves it held? | `quanta_attest/ledger.py` and `evidence.py`: signed hash chain, verifier, evidence pack |

## For architects

- **Invariants first, rules second.** Reviewers approve plain-language intent, not code. Each invariant holds or is violated; there is no third state.
- **The gateway sits outside the model.** The model holds no tool credentials, so it can only propose (INV-0).
- **Default deny.** Anything no rule allows is refused (R0). An instruction planted in a retrieved document is refused before any allow rule is checked (R1).
- **The gateway establishes the facts; the agent only claims them (INV-7).** Classification comes from the data label of the object being sent, destination from the recipient's domain, and origin from tracing the instruction to what the user typed or to a retrieved document. The agent's claims are recorded and compared, never used to decide. A false claim is overridden and logged as a conflict (scenario 9; scenario 5 also claims "the user asked").
- **Missing facts fail closed.** If a rule cannot be decided, because content has no data label or an instruction cannot be traced to the user or a document, the request is held for a Reviewer and labelled "not evaluable" (R6, INV-6). It is never allowed, and an omitted origin is never assumed to be the user.
- **Sealed approvals with separation of duties (INV-3).** A held request is fingerprinted at decision time and the seal is signed into the ledger. The approval signs the same seal, and the gateway recomputes it before running: a request changed after the decision is refused and the refusal is recorded. The person who requested an action cannot approve or reject it.
- **The ledger holds hashes and metadata, not content,** so it can be handed to an auditor.

## For engineers

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m pytest -q                       # 58 tests
python -m quanta_attest.ingest            # fetch the corpus from official sources
python -m quanta_attest.demo              # run all scenarios; writes data/session/
python -m quanta_attest.verify data/session
streamlit run app.py                      # Tour, Ask, Policy decisions, Approvals, Ledger, Evidence pack, Value
```

**OPA.** The policy is `policy/gateway.rego`. When an `opa` binary is on PATH, in `bin/`, or named by `QA_OPA`, the app evaluates it with OPA; otherwise it uses the Python reference implementation in `quanta_attest/policy.py`. A test checks the two agree on 480 request combinations, and `opa test policy` runs the Rego unit tests. A policy-engine error fails closed (deny).

**Tamper evidence.** Each record is hashed over its fields and the previous record's hash, then signed with Ed25519. A signed checkpoint over the last record catches truncation. Editing, deleting or reordering any record fails verification and names the record.

**Real GitHub issue (optional).** Set `GITHUB_TOKEN` (scoped to one repository) and `QA_GITHUB_REPO=owner/repo`. Without them the ticket tool is mocked.


## Corpus: links, not documents

The repository never contains the policy documents. `corpus/registry.yaml` lists each document's official URL, publisher, version and reuse terms; ingest downloads them at build time into `data/` (git-ignored). Profiles: public sector (Ontario AI directive, GO-ITS, Canada's Directive on Automated Decision-Making), cross-industry (NIST AI RMF, NIST CSF 2.0, OECD AI Recommendation) and regulated industry (EU AI Act, OSFI E-23).

## Production path

The demo stands in for production controls by design: the role switch and the "Your name" field would be the organization's single sign-on, the data labels would come from the organization's labelling service (for example Microsoft Purview or Amazon Macie), the signing key would sit in a managed key vault or HSM with rotation, checkpoints would also be signed with Sigstore cosign, and hosting would be in-country. The same engine could also gate infrastructure changes proposed by AI coding agents.

## Licence

Code: Apache License 2.0. Corpus documents: their publishers' terms, as listed in `corpus/registry.yaml`.
