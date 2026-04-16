import pandas as pd
from rules.rule_linux_fs import (
    RuleLinuxMtimeCtimeMismatch,
    RuleLinuxZeroedNanoseconds,
    RuleLinuxBirthtimeGap,
)


class LinuxFSAnalyzer:
    """Analyze Linux filesystem CSV (equivalent of MFTAnalyzer for Windows)."""

    def __init__(self, csv_path, fullscan=False, config=None):
        self.csv_path = csv_path
        self.fullscan = fullscan
        self.config = config or {}
        rule_cfg = self.config.get("rules", {})

        self.rules = []

        r = RuleLinuxMtimeCtimeMismatch()
        r.score = rule_cfg.get("linux_mtime_ctime", {}).get("score", 40)
        self.rules.append(r)

        r = RuleLinuxZeroedNanoseconds()
        r.score = rule_cfg.get("linux_zeroed_ns", {}).get("score", 30)
        self.rules.append(r)

        r = RuleLinuxBirthtimeGap()
        r.score = rule_cfg.get("linux_birthtime_gap", {}).get("score", 35)
        self.rules.append(r)

    def load(self):
        self.df = pd.read_csv(self.csv_path, low_memory=False)

        for col in ["ModifyTime", "ChangeTime", "AccessTime"]:
            if col in self.df.columns:
                self.df[col] = pd.to_datetime(self.df[col], errors="coerce", utc=True)

        if "BirthTime" in self.df.columns:
            self.df["BirthTime"] = pd.to_datetime(
                self.df["BirthTime"], errors="coerce", utc=True,
            )

        if not self.fullscan:
            # Filter to user-writable paths
            system_dirs = ["/usr", "/lib", "/lib64", "/sbin", "/bin", "/boot", "/etc"]
            mask = ~self.df["ParentDir"].astype(str).apply(
                lambda p: any(p.startswith(sd) for sd in system_dirs)
            )
            self.df = self.df[mask]

        print(f"[*] Linux FS scan, analyzing {len(self.df)} files")

    def run(self):
        self.load()
        all_findings = []
        for rule in self.rules:
            findings = rule.analyze(self.df)
            all_findings.extend(findings)
        return all_findings
