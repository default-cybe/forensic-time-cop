"""
Linux filesystem detection rules.

Key insight: on Linux, ctime (inode change time) is updated by the kernel
whenever file metadata changes. Userspace cannot set ctime directly.
So if mtime << ctime, someone backdated the file with touch/utimensat.
This is the Linux equivalent of SI < FN on NTFS.
"""

import pandas as pd
from rules.rule_base import BaseRule

SKIP_PATHS = [
    "/usr", "/lib", "/lib64", "/lib32", "/sbin", "/bin", "/boot",
    "/snap", "/etc/alternatives", "/.cache", "/node_modules",
    "/site-packages", "/.npm", "/.cargo", "/__pycache__",
]


def _skip_mask(df):
    """Vectorized filter: skip directories + noisy paths."""
    mask = pd.Series(True, index=df.index)

    # Skip directories
    if "IsDirectory" in df.columns:
        is_dir = df["IsDirectory"].astype(str).str.strip().str.lower()
        mask &= ~is_dir.isin(["true", "1"])

    # Skip noisy paths
    if "ParentDir" in df.columns:
        parent_lower = df["ParentDir"].astype(str).str.lower()
        for sp in SKIP_PATHS:
            mask &= ~parent_lower.str.contains(sp.lower(), na=False)

    return mask


class RuleLinuxMtimeCtimeMismatch(BaseRule):
    name = "Modify Time < Change Time (Linux)"
    description = (
        "Detects mtime earlier than ctime, ctime is kernel-set and cannot be "
        "faked via touch/utimensat, so mtime < ctime = likely timestomped"
    )
    score = 40

    def __init__(self, min_gap_seconds=3600):
        self.min_gap_seconds = min_gap_seconds

    def analyze(self, df):
        if "ModifyTime" not in df.columns or "ChangeTime" not in df.columns:
            return []

        mask = _skip_mask(df)
        mask &= df["ModifyTime"].notna() & df["ChangeTime"].notna()

        sub = df[mask].copy()
        if sub.empty:
            return []

        diff = (sub["ChangeTime"] - sub["ModifyTime"]).dt.total_seconds()
        hits = sub[diff > self.min_gap_seconds]

        findings = []
        for idx, row in hits.iterrows():
            d = int(diff.loc[idx])
            findings.append({
                "file": row.get("FilePath", "Unknown"),
                "reason": (
                    f"Modify time ({row['ModifyTime']}) is {d} seconds earlier than "
                    f"change time ({row['ChangeTime']}), ctime cannot be faked, likely timestomped"
                ),
                "score": self.score,
                "rule": self.name,
            })
        return findings


class RuleLinuxZeroedNanoseconds(BaseRule):
    name = "Zeroed Nanoseconds (Linux)"
    description = (
        "Detects files with zeroed nanoseconds on mtime, signature of "
        "touch command or utime() which lack nanosecond precision"
    )
    score = 30

    def analyze(self, df):
        if "ModifyTimeNs" not in df.columns or "ChangeTimeNs" not in df.columns:
            return []

        mask = _skip_mask(df)
        mtime_ns = pd.to_numeric(df["ModifyTimeNs"], errors="coerce").fillna(-1)
        ctime_ns = pd.to_numeric(df["ChangeTimeNs"], errors="coerce").fillna(0)

        mask &= (mtime_ns == 0) & (ctime_ns != 0)

        hits = df[mask]
        findings = []
        for idx, row in hits.iterrows():
            findings.append({
                "file": row.get("FilePath", "Unknown"),
                "reason": (
                    f"Modify time has zeroed nanoseconds but change time has "
                    f"nanosecond precision (ns={int(ctime_ns.loc[idx])}), likely set by touch or utime()"
                ),
                "score": self.score,
                "rule": self.name,
            })
        return findings


class RuleLinuxBirthtimeGap(BaseRule):
    name = "Birthtime Anomaly (Linux)"
    description = (
        "Detects files where birth time doesn't match change time, "
        "may indicate clock manipulation during file creation"
    )
    score = 35

    def __init__(self, min_gap_seconds=3600):
        self.min_gap_seconds = min_gap_seconds

    def analyze(self, df):
        if "BirthTime" not in df.columns or "ChangeTime" not in df.columns:
            return []

        mask = _skip_mask(df)
        mask &= df["BirthTime"].notna() & df["ChangeTime"].notna()
        mask &= df["BirthTime"].astype(str).str.strip() != ""

        sub = df[mask].copy()
        if sub.empty:
            return []

        diff = (sub["ChangeTime"] - sub["BirthTime"]).dt.total_seconds().abs()
        hits = sub[diff > self.min_gap_seconds]

        findings = []
        for idx, row in hits.iterrows():
            d = int(diff.loc[idx])
            findings.append({
                "file": row.get("FilePath", "Unknown"),
                "reason": (
                    f"Birth time ({row['BirthTime']}) differs from change time ({row['ChangeTime']}) "
                    f"by {d} seconds, possible clock manipulation during creation"
                ),
                "score": self.score,
                "rule": self.name,
            })
        return findings


class RuleLinuxLogClearing(BaseRule):
    name = "Log File Tampering (Linux)"
    description = "Detects signs of log file clearing or truncation"
    score = 45

    def analyze(self, log_entries):
        findings = []
        for entry in log_entries:
            line = entry.get("line", "")
            source = entry.get("source", "")

            # Detect log rotation/clearing commands
            if any(indicator in line.lower() for indicator in [
                "truncat", "logrotate", "> /var/log",
                "rm /var/log", "shred", "wipe",
            ]):
                findings.append({
                    "file": source,
                    "reason": f"Possible log tampering detected: {line.strip()[:200]}",
                    "score": self.score,
                    "rule": self.name,
                })
        return findings


class RuleLinuxClockJumpInLogs(BaseRule):
    name = "Clock Jump in Logs (Linux)"
    description = "Detects backwards time jumps in syslog/journal timestamps"
    score = 45

    def __init__(self, min_jump_minutes=5):
        self.min_jump_minutes = min_jump_minutes

    def analyze(self, log_entries):
        findings = []
        if len(log_entries) < 2:
            return findings

        # Group by source
        by_source = {}
        for entry in log_entries:
            src = entry.get("source", "unknown")
            ts = entry.get("timestamp")
            if ts:
                by_source.setdefault(src, []).append(entry)

        for source, entries in by_source.items():
            sorted_entries = sorted(entries, key=lambda x: x.get("line_num", 0))

            for i in range(1, len(sorted_entries)):
                prev_ts = sorted_entries[i - 1].get("timestamp")
                curr_ts = sorted_entries[i].get("timestamp")

                if prev_ts and curr_ts:
                    from datetime import timedelta
                    diff = prev_ts - curr_ts
                    if diff > timedelta(minutes=self.min_jump_minutes):
                        findings.append({
                            "file": source,
                            "reason": (
                                f"Log timestamp jumped backwards by "
                                f"{int(diff.total_seconds() / 60)} minutes"
                            ),
                            "score": self.score,
                            "rule": self.name,
                        })

        return findings
