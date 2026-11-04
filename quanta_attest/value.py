"""Value calculator: three drivers, each from sourced market data plus a stated assumption.

The output is an annual value estimate per AI project, not a return figure.
Sources mix Canadian and US dollars; convert before showing a client.
"""

from __future__ import annotations

from dataclasses import dataclass

SOURCES = {
    "risk": [
        ("IBM Cost of a Data Breach 2025, Canada: average breach CA$6.98M",
         "https://canada.newsroom.ibm.com/2025-07-30-IBM-Report-Canadians-Data-Security-Under-Increased-Threat,-While-Breach-Costs-Surge"),
        ("High shadow-AI use adds about $670K per breach (summary of the IBM report)",
         "https://www.nudgesecurity.com/post/shadow-ai-the-emerging-security-threat-in-ibms-2025-cost-of-a-data-breach-report"),
    ],
    "audit": [
        ("Manual SOC 2 evidence collection: about 300 to 600 staff hours per cycle (vendor estimate)",
         "https://expiryedge.com/blogs/soc-2-evidence-collection/"),
    ],
    "delay": [
        ("56% take 6 to 18 months from intake to production; 44% say governance is too slow (McKinsey, via Aperion)",
         "https://aperion.ai/blog/ai-governance-fastest-path-to-yes/"),
        ("82.9% saw AI projects delayed by security or compliance review (EMA)",
         "https://securitybrief.asia/story/enterprise-ai-deployments-slowed-by-security-reviews"),
    ],
}


@dataclass
class Inputs:
    breach_cost: float = 6_980_000  # CA$, IBM 2025 Canada average
    breach_reduction_pp: float = 5.0  # assumption: percentage points of annual breach likelihood removed
    audit_hours: float = 400  # within the 300 to 600 hour range
    audits_per_year: float = 1
    hourly_rate: float = 135
    delay_weeks_removed: float = 8.5  # assumption: about two months of governance delay
    team_size: float = 5
    hours_per_week: float = 40
    projects: float = 1


def compute(i: Inputs) -> dict:
    risk = i.breach_cost * i.breach_reduction_pp / 100
    audit = i.audit_hours * i.audits_per_year * i.hourly_rate
    delay = i.delay_weeks_removed * i.team_size * i.hours_per_week * i.hourly_rate * i.projects
    return {"risk": round(risk), "audit": round(audit), "delay": round(delay), "total": round(risk + audit + delay)}


OFFERS = [
    ("Assessment", "1 week", "$9,500", "Gap assessment and an evidence-pack template for one AI use case"),
    ("Readiness", "3 to 4 weeks", "$28,000 to $38,000", "Gateway, approvals and signed evidence around one agent, with an evidence pack for its review board"),
    ("Retainer", "Monthly", "$3,000 to $5,000", "Policy updates and a quarterly evidence pack"),
]
