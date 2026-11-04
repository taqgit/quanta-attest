package quanta.gateway_test

import rego.v1

import data.quanta.gateway

test_injection_denied_first if {
	d := gateway.decision with input as {"tool": "send_external_email", "role": "Architect", "classification": "public", "destination": "external", "origin": "retrieved"}
	d.rule == "R1"
	d.decision == "DENY"
}

test_missing_classification_held if {
	d := gateway.decision with input as {"tool": "send_external_email", "role": "Architect", "destination": "external", "origin": "user"}
	d.rule == "R6"
	d.decision == "REQUIRE_APPROVAL"
}

test_sensitive_email_denied if {
	d := gateway.decision with input as {"tool": "send_external_email", "role": "Architect", "classification": "sensitive", "destination": "external", "origin": "user"}
	d.rule == "R4"
}

test_ticket_needs_reviewer if {
	d := gateway.decision with input as {"tool": "file_review_ticket", "role": "Architect", "origin": "user"}
	d.decision == "REQUIRE_APPROVAL"
}

test_unknown_tool_denied if {
	d := gateway.decision with input as {"tool": "delete_database", "role": "Architect", "origin": "user"}
	d.rule == "R0"
	d.decision == "DENY"
}

test_unknown_role_denied if {
	d := gateway.decision with input as {"tool": "search_corpus", "role": "Intern", "origin": "user"}
	d.rule == "R0"
}

test_unknown_origin_held if {
	d := gateway.decision with input as {"tool": "draft_checklist", "role": "Architect", "origin": "unknown"}
	d.rule == "R6"
	d.decision == "REQUIRE_APPROVAL"
	d.reason == "Not evaluable: instruction origin unknown"
}

test_missing_origin_is_never_user if {
	d := gateway.decision with input as {"tool": "draft_checklist", "role": "Architect"}
	d.rule == "R6"
	d.decision == "REQUIRE_APPROVAL"
}
