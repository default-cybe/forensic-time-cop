import pandas as pd
from rules.rule_base import BaseRule

SKIP_PATHS = [
    "Windows", "Program Files", "Program Files (x86)",
    "System32", "SysWOW64", "WinSxS", "assembly",
    "Python", "node_modules", "site-packages", ".cache",
    "NuGet", "packages", "Tools", "PathUnknown",
    "OneDrive", "Microsoft\\Edge", "Microsoft\\Windows",
    ".vscode", ".git", "conda", ".npm",
]


class RuleZeroedNanoseconds(BaseRule):
    name = "Zeroed Nanoseconds"
    description = "Detects timestamps with zeroed subseconds, signature of timestomping tools"
    score = 30

    def __init__(self, user_paths_only=True):
        self.user_paths_only = user_paths_only

    def analyze(self, df):
        findings = []
        for _, row in df.iterrows():
            try:
                si = row["Created0x10"]
                if pd.isnull(si):
                    continue
                if not (hasattr(si, "nanosecond") and si.nanosecond == 0 and si.microsecond == 0):
                    continue

                # Skip directories
                if str(row.get("IsDirectory", "")).strip().lower() in ("true", "1"):
                    continue

                # Skip copied files
                if str(row.get("Copied", "")).strip().lower() in ("true", "1"):
                    continue

                parent = str(row.get("ParentPath", ""))

                # Skip system paths to reduce false positives
                if self.user_paths_only:
                    if any(sp.lower() in parent.lower() for sp in SKIP_PATHS):
                        continue

                name = row.get("FileName", "Unknown")
                full_path = f"{parent}\\{name}" if parent else name
                findings.append({
                    "file": full_path,
                    "reason": f"SI timestamp has zeroed subseconds ({si}), likely set by a timestomping tool",
                    "score": self.score,
                    "rule": self.name,
                })
            except Exception:
                continue
        return findings
