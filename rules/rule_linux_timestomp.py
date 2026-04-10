import re
from rules.rule_base import BaseRule


class RuleTouchCommand(BaseRule):
    name = "Touch Command Detected (Linux)"
    description = "Detects touch command usage in audit/syslog, common timestomping method"
    score = 35

    TOUCH_PATTERN = re.compile(
        r'(touch\s+.*-[matrd]|'
        r'type=EXECVE.*touch\s+-[matrd]|'
        r'SYSCALL.*comm="touch")',
        re.IGNORECASE,
    )

    def analyze(self, log_entries):
        findings = []
        for entry in log_entries:
            line = entry.get("line", "")
            if self.TOUCH_PATTERN.search(line):
                findings.append({
                    "file": entry.get("source", "audit.log"),
                    "reason": f"Touch command with timestamp flags detected: {line.strip()[:200]}",
                    "score": self.score,
                    "rule": self.name,
                })
        return findings


class RuleUtimesSyscall(BaseRule):
    name = "Timestamp Syscall Detected (Linux)"
    description = "Detects utimes/utimensat/futimens syscalls in audit logs"
    score = 40

    SYSCALL_PATTERN = re.compile(r'(utimes|utimensat|futimens)', re.IGNORECASE)

    def analyze(self, log_entries):
        findings = []
        for entry in log_entries:
            line = entry.get("line", "")
            if self.SYSCALL_PATTERN.search(line):
                findings.append({
                    "file": entry.get("source", "audit.log"),
                    "reason": f"Timestamp modification syscall detected: {line.strip()[:200]}",
                    "score": self.score,
                    "rule": self.name,
                })
        return findings


class RuleLinuxClockChange(BaseRule):
    name = "Clock Change Detected (Linux)"
    description = "Detects system clock changes via date/timedatectl in logs"
    score = 45

    CLOCK_PATTERN = re.compile(
        r'(settimeofday|clock_settime|timedatectl\s+set-time|'
        r'date\s+-s\s|date\s+--set)',
        re.IGNORECASE,
    )

    def analyze(self, log_entries):
        findings = []
        for entry in log_entries:
            line = entry.get("line", "")
            if self.CLOCK_PATTERN.search(line):
                findings.append({
                    "file": entry.get("source", "syslog"),
                    "reason": f"System clock change detected: {line.strip()[:200]}",
                    "score": self.score,
                    "rule": self.name,
                })
        return findings
