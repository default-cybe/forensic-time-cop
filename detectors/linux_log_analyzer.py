from rules.rule_linux_timestomp import (
    RuleTouchCommand,
    RuleUtimesSyscall,
    RuleLinuxClockChange,
)


class LinuxLogAnalyzer:
    def __init__(self, log_paths, config=None):
        self.log_paths = log_paths
        self.config = config or {}
        rule_cfg = self.config.get("rules", {})

        self.rules = []
        if rule_cfg.get("touch_command", {}).get("enabled", True):
            r = RuleTouchCommand()
            r.score = rule_cfg.get("touch_command", {}).get("score", 35)
            self.rules.append(r)
        if rule_cfg.get("utimes_syscall", {}).get("enabled", True):
            r = RuleUtimesSyscall()
            r.score = rule_cfg.get("utimes_syscall", {}).get("score", 40)
            self.rules.append(r)
        if rule_cfg.get("linux_clock_change", {}).get("enabled", True):
            r = RuleLinuxClockChange()
            r.score = rule_cfg.get("linux_clock_change", {}).get("score", 45)
            self.rules.append(r)

    def parse_log(self, path):
        entries = []
        try:
            with open(path, "r", errors="replace") as f:
                for line in f:
                    entries.append({
                        "line": line,
                        "source": path,
                    })
        except Exception as e:
            print(f"[!] Could not parse {path}: {e}")
        return entries

    def run(self):
        all_findings = []
        all_entries = []

        for path in self.log_paths:
            entries = self.parse_log(path)
            all_entries.extend(entries)

        for rule in self.rules:
            findings = rule.analyze(all_entries)
            all_findings.extend(findings)

        return all_findings
