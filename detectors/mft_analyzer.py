import re
import pandas as pd
from rules.rule_si_fn_mismatch import RuleSIFNMismatch
from rules.rule_zeroed_nanoseconds import RuleZeroedNanoseconds
from rules.rule_birthtime_mtime_gap import RuleBirthtimeMtimeGap

DEFAULT_EXCLUDE = [
    "Windows", "Program Files", "Program Files (x86)",
    "AppData", "ProgramData", "System32", "SysWOW64",
]


class CustomMFTRule:
    """Simple pattern-matching rule defined in config.yaml."""

    def __init__(self, rule_def):
        self.name = rule_def.get("name", "Custom Rule")
        self.description = rule_def.get("description", "")
        self.score = rule_def.get("score", 25)
        self.column = rule_def.get("column", "ParentPath")
        self.pattern = rule_def.get("pattern", "")

    def analyze(self, df):
        findings = []
        if not self.pattern or self.column not in df.columns:
            return findings

        mask = df[self.column].astype(str).str.contains(
            self.pattern, case=False, na=False,
        )
        for _, row in df[mask].iterrows():
            findings.append({
                "file": row.get("FileName", "Unknown"),
                "reason": f"{self.description}, matched '{self.pattern}' in {self.column}",
                "score": self.score,
                "rule": self.name,
            })
        return findings


class MFTAnalyzer:
    def __init__(self, csv_path, fullscan=False, config=None):
        self.csv_path = csv_path
        self.fullscan = fullscan
        self.config = config or {}

        rule_cfg = self.config.get("rules", {})
        scan_cfg = self.config.get("scan", {})

        self.exclude_paths = scan_cfg.get("exclude_paths", DEFAULT_EXCLUDE)
        self.target_paths = scan_cfg.get("target_paths", [])

        # Build rule list from config
        self.rules = []

        if rule_cfg.get("si_fn_mismatch", {}).get("enabled", True):
            r = RuleSIFNMismatch()
            r.score = rule_cfg.get("si_fn_mismatch", {}).get("score", 40)
            self.rules.append(r)

        if rule_cfg.get("zeroed_nanoseconds", {}).get("enabled", True):
            user_only = rule_cfg.get("zeroed_nanoseconds", {}).get("user_paths_only", True)
            r = RuleZeroedNanoseconds(user_paths_only=user_only)
            r.score = rule_cfg.get("zeroed_nanoseconds", {}).get("score", 30)
            self.rules.append(r)

        if rule_cfg.get("birthtime_mtime_gap", {}).get("enabled", True):
            gap = rule_cfg.get("birthtime_mtime_gap", {}).get("min_gap_seconds", 3600)
            r = RuleBirthtimeMtimeGap(min_gap_seconds=gap)
            r.score = rule_cfg.get("birthtime_mtime_gap", {}).get("score", 35)
            self.rules.append(r)

        # Custom MFT rules from config
        for custom in self.config.get("custom_rules", []):
            if custom.get("type") == "mft":
                self.rules.append(CustomMFTRule(custom))

    def load(self):
        self.df = pd.read_csv(self.csv_path, low_memory=False)
        self.df["Created0x10"] = pd.to_datetime(self.df["Created0x10"], errors="coerce", utc=True)
        self.df["Created0x30"] = pd.to_datetime(self.df["Created0x30"], errors="coerce", utc=True)
        self.df["LastModified0x10"] = pd.to_datetime(self.df["LastModified0x10"], errors="coerce", utc=True)

        exclude_pattern = "|".join(re.escape(p) for p in self.exclude_paths)
        target_pattern = "|".join(re.escape(p) for p in self.target_paths) if self.target_paths else ""

        if self.fullscan:
            print(f"[*] Full scan mode, analyzing {len(self.df)} files")
        elif target_pattern:
            mask = self.df["ParentPath"].astype(str).str.contains(
                target_pattern, case=False, na=False,
            )
            self.df = self.df[mask]
            print(f"[*] Targeted scan mode, analyzing {len(self.df)} files")
        else:
            # Default: scan everything except system paths
            mask = ~self.df["ParentPath"].astype(str).str.contains(
                exclude_pattern, case=False, na=False,
            )
            self.df = self.df[mask]
            print(f"[*] Default scan, analyzing {len(self.df)} non-system files")

    def run(self):
        self.load()
        all_findings = []
        for rule in self.rules:
            findings = rule.analyze(self.df)
            all_findings.extend(findings)
        return all_findings
