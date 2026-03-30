from rules.rule_base import BaseRule


class RuleRecordSequenceGap(BaseRule):
    name = "Event Log Record Sequence Gap"
    description = "Detects gaps in event log record IDs, sign of deleted log entries"
    score = 45

    def __init__(self, min_gap=5):
        self.min_gap = min_gap

    def analyze(self, events):
        findings = []
        if len(events) < 2:
            return findings

        # Group by source log file
        by_source = {}
        for e in events:
            src = e.get("source", "unknown")
            by_source.setdefault(src, []).append(e)

        for source, evts in by_source.items():
            sorted_evts = sorted(evts, key=lambda x: x["record_id"])
            for i in range(1, len(sorted_evts)):
                prev_id = sorted_evts[i - 1]["record_id"]
                curr_id = sorted_evts[i]["record_id"]
                gap = curr_id - prev_id
                if gap > self.min_gap:
                    findings.append({
                        "file": source,
                        "reason": f"Record ID gap of {gap} between record {prev_id} and {curr_id}, {gap - 1} log entries may have been deleted",
                        "score": self.score,
                        "rule": self.name,
                    })

        return findings
