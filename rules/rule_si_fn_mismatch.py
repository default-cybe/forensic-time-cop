import pandas as pd
from rules.rule_base import BaseRule

# Paths where SI<FN is expected (installs, updates, package managers, OS dirs)
NOISY_PATHS = [
    "Python", "node_modules", "pip", ".cache", "conda",
    "NuGet", "packages", "Tools", "dist", "bin", "obj",
    "site-packages", ".npm", ".cargo", "go\\pkg",
    "PathUnknown", "Users\\Default", "OneDrive",
    "lib-amd", "lib-commonjs", ".vscode", ".git",
    "Microsoft\\Edge", "Microsoft\\Windows",
]


class RuleSIFNMismatch(BaseRule):
    name = "SI < FN Timestamp Mismatch"
    description = "Detects when $STANDARD_INFORMATION timestamp is earlier than $FILE_NAME timestamp"
    score = 40

    def analyze(self, df):
        findings = []
        for _, row in df.iterrows():
            try:
                si = row["Created0x10"]
                fn = row["Created0x30"]

                if pd.isnull(si) or pd.isnull(fn):
                    continue

                # Skip copied files, SI<FN is normal
                if str(row.get("Copied", "")).strip().lower() in ("true", "1"):
                    continue

                # Skip directories
                if str(row.get("IsDirectory", "")).strip().lower() in ("true", "1"):
                    continue

                if si < fn:
                    parent = str(row.get("ParentPath", ""))

                    # Skip known noisy paths
                    if any(np.lower() in parent.lower() for np in NOISY_PATHS):
                        continue

                    name = row.get("FileName", "Unknown")
                    full_path = f"{parent}\\{name}" if parent else name
                    findings.append({
                        "file": full_path,
                        "reason": f"SI timestamp ({si}) is earlier than FN timestamp ({fn})",
                        "score": self.score,
                        "rule": self.name,
                    })
            except Exception:
                continue
        return findings
