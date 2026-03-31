import pandas as pd
from rules.rule_base import BaseRule
from datetime import timedelta


class RuleCreatedDuringClockChange(BaseRule):
    name = "File Created During Clock Manipulation"
    description = "Flags files created during a detected system clock change window"
    score = 50

    def __init__(self, min_jump_minutes=5):
        self.min_jump_minutes = min_jump_minutes
        self.bogus_windows = []

    def detect_clock_windows(self, events):
        """Find time windows where the system clock was manipulated.

        A clock change creates a pattern in event logs:
          record N: timestamp 2026-03-05 09:41:33 (normal)
          record N+1: timestamp 2019-01-01 09:41:55 (clock set back)
          ...
          record M: timestamp 2019-01-01 09:42:09 (still bogus)
          record M+1: timestamp 2026-03-05 09:42:10 (clock restored)

        The bogus window = timestamps between the backward jump and the forward jump.
        """
        if len(events) < 2:
            return

        sorted_events = sorted(events, key=lambda x: x["record_id"])
        in_bogus_window = False
        window_start = None

        for i in range(1, len(sorted_events)):
            prev = sorted_events[i - 1]
            curr = sorted_events[i]
            diff = prev["timestamp"] - curr["timestamp"]

            if not in_bogus_window:
                # Backward jump = clock set to past
                if diff > timedelta(minutes=self.min_jump_minutes):
                    in_bogus_window = True
                    window_start = curr["timestamp"]
            else:
                # Forward jump = clock restored
                forward = curr["timestamp"] - prev["timestamp"]
                if forward > timedelta(minutes=self.min_jump_minutes):
                    window_end = prev["timestamp"]
                    self.bogus_windows.append((window_start, window_end))
                    in_bogus_window = False
                    window_start = None

        # If still in bogus window at end of logs, close it
        if in_bogus_window and window_start:
            window_end = sorted_events[-1]["timestamp"]
            self.bogus_windows.append((window_start, window_end))

    def analyze_events(self, events):
        """Call this first to detect clock change windows from event logs."""
        self.detect_clock_windows(events)
        return len(self.bogus_windows)

    def analyze(self, df):
        """Then call this on MFT data to flag files created during those windows."""
        findings = []

        if not self.bogus_windows:
            return findings

        for _, row in df.iterrows():
            try:
                created = row["Created0x10"]
                if pd.isnull(created):
                    continue

                # Skip directories
                if str(row.get("IsDirectory", "")).strip().lower() in ("true", "1"):
                    continue

                for win_start, win_end in self.bogus_windows:
                    # Check if file creation falls within bogus time window
                    if win_start <= created.to_pydatetime() <= win_end:
                        parent = str(row.get("ParentPath", ""))
                        name = row.get("FileName", "Unknown")
                        full_path = f"{parent}\\{name}" if parent else name

                        findings.append({
                            "file": full_path,
                            "reason": (
                                f"File created at {created}, falls within detected clock "
                                f"manipulation window ({win_start} to {win_end})"
                            ),
                            "score": self.score,
                            "rule": self.name,
                        })
                        break  # Don't double-count across windows
            except Exception:
                continue

        return findings
