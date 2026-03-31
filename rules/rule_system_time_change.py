from rules.rule_base import BaseRule


class RuleSystemTimeChange(BaseRule):
    name = "System Time Change (Event ID 4616)"
    description = "Detects Windows system time changes, attackers change clock before timestomping"
    score = 40

    def analyze(self, events):
        findings = []
        for e in events:
            if e.get("event_id") == 4616:
                findings.append({
                    "file": e.get("source", "Event Log"),
                    "reason": (
                        f"System time was changed at {e['timestamp']} "
                        f"(Event ID 4616), may indicate clock manipulation for timestomping"
                    ),
                    "score": self.score,
                    "rule": self.name,
                })
        return findings
