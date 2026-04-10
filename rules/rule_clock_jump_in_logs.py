from rules.rule_base import BaseRule
from datetime import timedelta


class RuleClockJumpInLogs(BaseRule):
    name = "System Clock Jump Detected"
    description = "Detects when event log timestamps jump backwards, sign of clock manipulation"
    score = 45

    def __init__(self, min_jump_minutes=5):
        self.min_jump_minutes = min_jump_minutes

    def analyze(self, events):
        findings = []
        if len(events) < 2:
            return findings

        events_sorted = sorted(events, key=lambda x: x["record_id"])

        for i in range(1, len(events_sorted)):
            prev = events_sorted[i - 1]
            curr = events_sorted[i]

            diff = prev["timestamp"] - curr["timestamp"]
            if diff > timedelta(minutes=self.min_jump_minutes):
                findings.append({
                    "file": "Event Log",
                    "reason": (
                        f"Timestamp jumped backwards by {int(diff.total_seconds() / 60)} minutes "
                        f"between record {prev['record_id']} ({prev['timestamp']}) "
                        f"and record {curr['record_id']} ({curr['timestamp']})"
                    ),
                    "score": self.score,
                    "rule": self.name,
                })

        return findings
