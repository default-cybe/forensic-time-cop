import pandas as pd
from rules.rule_base import BaseRule

SKIP_PATHS = [
    "Python", "node_modules", "site-packages", ".cache",
    "NuGet", "packages", "Tools", "PathUnknown",
    "OneDrive", "Microsoft\\Edge", "Microsoft\\Windows",
    ".vscode", ".git", "conda", ".npm",
]


class RuleBirthtimeMtimeGap(BaseRule):
    name = "Birthtime vs Mtime Gap"
    description = "Detects when modification time is earlier than birth time"
    score = 35

    def __init__(self, min_gap_seconds=3600):
        self.min_gap_seconds = min_gap_seconds

    def analyze(self, df):
        findings = []
        for _, row in df.iterrows():
            try:
                created = row["Created0x10"]
                modified = row["LastModified0x10"]

                if pd.isnull(created) or pd.isnull(modified):
                    continue

                # Skip directories and copied files
                if str(row.get("IsDirectory", "")).strip().lower() in ("true", "1"):
                    continue
                if str(row.get("Copied", "")).strip().lower() in ("true", "1"):
                    continue

                diff = abs((created - modified).total_seconds())
                if modified < created and diff > self.min_gap_seconds:
                    parent = str(row.get("ParentPath", ""))

                    # Skip noisy paths
                    if any(sp.lower() in parent.lower() for sp in SKIP_PATHS):
                        continue

                    name = row.get("FileName", "Unknown")
                    full_path = f"{parent}\\{name}" if parent else name
                    findings.append({
                        "file": full_path,
                        "reason": (
                            f"Modified time ({modified}) is earlier than birth time ({created}) "
                            f"by {int(diff)} seconds, possible touch-based timestomp"
                        ),
                        "score": self.score,
                        "rule": self.name,
                    })
            except Exception:
                continue
        return findings
