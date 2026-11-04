# Quanta Attest policy gateway.
#
# Every tool request gets exactly one decision: ALLOW, REQUIRE_APPROVAL or DENY.
# Candidate rules are ranked by `order`; the lowest wins. Anything no rule
# matches is denied (R0). R1 is checked first, so an instruction planted in a
# retrieved document is refused before any allow rule can apply.
#
# Input: {"tool", "role", "classification", "destination", "origin"}. These are
# facts the gateway established itself (quanta_attest/facts.py, INV-7); the
# agent's own claims never reach this policy. origin is "user", "retrieved" or
# "unknown"; a missing field is treated as unknown.
# Query: data.quanta.gateway.decision

package quanta.gateway

import rego.v1

known_roles := {"Architect", "Reviewer", "Auditor"}

needs_classification := {"send_external_email"}

known_classification if input.classification in {"public", "sensitive"}

# --- R1: instruction originated in retrieved content
candidates contains {"order": 1, "rule": "R1", "decision": "DENY", "reason": "Instruction originated in retrieved content"} if {
	input.origin == "retrieved"
}

# --- R6: a fact the rules need is missing
candidates contains {"order": 2, "rule": "R6", "decision": "REQUIRE_APPROVAL", "reason": "Not evaluable: instruction origin unknown"} if {
	not input.origin == "user"
}

candidates contains {"order": 3, "rule": "R6", "decision": "REQUIRE_APPROVAL", "reason": "Not evaluable: data classification missing"} if {
	input.tool in needs_classification
	not known_classification
}

# --- R2: read-only tools for any known role
candidates contains {"order": 4, "rule": "R2", "decision": "ALLOW", "reason": "Read-only tool"} if {
	input.tool in {"search_corpus", "draft_checklist"}
	input.role in known_roles
}

# --- R3: review ticket by an Architect needs a Reviewer
candidates contains {"order": 5, "rule": "R3", "decision": "REQUIRE_APPROVAL", "reason": "Consequential action needs a Reviewer"} if {
	input.tool == "file_review_ticket"
	input.role == "Architect"
}

# --- R4: sensitive content never leaves the organization
candidates contains {"order": 6, "rule": "R4", "decision": "DENY", "reason": "Sensitive content cannot be sent outside the organization"} if {
	input.tool == "send_external_email"
	input.classification == "sensitive"
}

# --- R5: public content sent externally needs a Reviewer
candidates contains {"order": 7, "rule": "R5", "decision": "REQUIRE_APPROVAL", "reason": "External email needs a Reviewer"} if {
	input.tool == "send_external_email"
	input.classification == "public"
	input.destination == "external"
	input.role == "Architect"
}

# --- R0: default deny
default decision := {"order": 99, "rule": "R0", "decision": "DENY", "reason": "No rule allows this request"}

orders := {c.order | some c in candidates}

decision := c if {
	some c in candidates
	c.order == min(orders)
}
