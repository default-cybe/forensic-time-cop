from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from datetime import datetime
from rules.rule_clock_jump_in_logs import RuleClockJumpInLogs
from rules.rule_record_sequence_gap import RuleRecordSequenceGap
from rules.rule_system_time_change import RuleSystemTimeChange


class LogAnalyzer:
    def __init__(self, evtx_paths, config=None):
        self.evtx_paths = evtx_paths
        self.config = config or {}
        rule_cfg = self.config.get("rules", {})

        self.rules = []

        if rule_cfg.get("clock_jump", {}).get("enabled", True):
            jump_min = rule_cfg.get("clock_jump", {}).get("min_jump_minutes", 5)
            r = RuleClockJumpInLogs(min_jump_minutes=jump_min)
            r.score = rule_cfg.get("clock_jump", {}).get("score", 45)
            self.rules.append(r)

        if rule_cfg.get("record_sequence_gap", {}).get("enabled", True):
            min_gap = rule_cfg.get("record_sequence_gap", {}).get("min_gap", 5)
            r = RuleRecordSequenceGap(min_gap=min_gap)
            r.score = rule_cfg.get("record_sequence_gap", {}).get("score", 45)
            self.rules.append(r)

        if rule_cfg.get("system_time_change", {}).get("enabled", True):
            r = RuleSystemTimeChange()
            r.score = rule_cfg.get("system_time_change", {}).get("score", 40)
            self.rules.append(r)

        self.log_clear_score = rule_cfg.get("log_clearing", {}).get("score", 50)
        self.log_clear_enabled = rule_cfg.get("log_clearing", {}).get("enabled", True)
        self.log_clear_events = []

    def parse_evtx(self, path):
        events = []
        try:
            with Evtx(path) as log:
                for record in log.records():
                    try:
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)
                        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

                        event_id = int(root.find(".//e:EventID", ns).text)
                        time_str = root.find(".//e:TimeCreated", ns).attrib.get("SystemTime", "")
                        record_id = int(root.find(".//e:EventRecordID", ns).text)

                        timestamp = datetime.fromisoformat(time_str.replace("Z", "+00:00"))

                        events.append({
                            "event_id": event_id,
                            "timestamp": timestamp,
                            "record_id": record_id,
                            "source": path,
                        })

                        # Log clearing events
                        if self.log_clear_enabled and event_id in [1102, 104]:
                            self.log_clear_events.append({
                                "file": path,
                                "reason": f"Event ID {event_id} detected, audit log was cleared at {timestamp}",
                                "score": self.log_clear_score,
                                "rule": "Log Clearing Detected",
                            })

                    except Exception:
                        continue
        except Exception as e:
            print(f"[!] Could not parse {path}: {e}")

        return events

    def run(self):
        all_findings = []
        self.all_events = []

        for path in self.evtx_paths:
            events = self.parse_evtx(path)
            self.all_events.extend(events)

        all_findings.extend(self.log_clear_events)

        for rule in self.rules:
            findings = rule.analyze(self.all_events)
            all_findings.extend(findings)

        return all_findings
