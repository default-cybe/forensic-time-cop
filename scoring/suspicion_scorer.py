class SuspicionScorer:
    def __init__(self, findings, config=None):
        self.findings = findings
        self.config = config or {}
        sev = self.config.get("severity", {})
        self.high_threshold = sev.get("high", 70)
        self.medium_threshold = sev.get("medium", 40)

    def score_by_file(self):
        scores = {}

        for f in self.findings:
            fname = f["file"]
            if fname not in scores:
                scores[fname] = {
                    "file": fname,
                    "total_score": 0,
                    "severity": "",
                    "rules_triggered": set(),
                    "reasons": [],
                    "hit_count": 0,
                }
            scores[fname]["total_score"] += f["score"]
            scores[fname]["rules_triggered"].add(f["rule"])
            scores[fname]["reasons"].append(f["reason"])
            scores[fname]["hit_count"] += 1

        result = []
        for fname, data in scores.items():
            s = data["total_score"]
            if s >= self.high_threshold:
                sev = "HIGH"
            elif s >= self.medium_threshold:
                sev = "MEDIUM"
            else:
                sev = "LOW"

            # Cap reasons at 5, show total count
            reasons = data["reasons"]
            if len(reasons) > 5:
                reasons = reasons[:5] + [f"... and {len(reasons) - 5} more findings"]

            result.append({
                "file": fname,
                "total_score": s,
                "severity": sev,
                "rules_triggered": sorted(data["rules_triggered"]),
                "reasons": reasons,
                "hit_count": data["hit_count"],
            })

        return sorted(result, key=lambda x: x["total_score"], reverse=True)
