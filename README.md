# Forensic Time Cop

Forensic Time Cop catches timestamp tampering and log clearing across Windows (NTFS) and Linux (ext4). It ships sixteen detection rules with configurable scoring, and you can run it three ways: from the CLI, as a small Flask web app, or as portable PyInstaller binaries that need nothing installed on the target.

A practical anti-forensics detection tool by Kaivalya Ahir.

## How it works

Modern filesystems keep two parallel sets of timestamps. One set is user-writable (NTFS `$STANDARD_INFORMATION`, Linux `mtime`/`atime`). The other is kernel-controlled (NTFS `$FILE_NAME`, Linux `ctime`). Anti-forensic tools only touch the writable set, so disagreement between the two sets reveals tampering. The same logic applies to event logs: clearing them leaves Event ID 1102/104 on Windows, and `truncate`/`shred` traces on Linux.

When an attacker rolls back the system clock instead of editing per-file timestamps, both sets agree internally. Per-file rules go quiet. Forensic Time Cop closes that gap by deriving clock-manipulation windows from log-timestamp jumps and flagging any file whose creation timestamp falls inside.

## Quick start

```bash
git clone https://github.com/<you>/forensic-time-cop
cd forensic-time-cop
pip install -r requirements.txt

# CLI on bundled test artifacts
python main.py tests/windows/mft_output.csv tests/windows
python main.py --os linux tests/ubuntu/linux_fs.csv tests/ubuntu/logs

# Web dashboard
python webapp/app.py
# open http://localhost:5000
```

Live collection on a target host:

```bash
python collect_and_zip.py            # auto-detects OS, builds zip
python main.py --live                # collect + analyze in one shot
```

Windows collection requires Administrator. Linux collection requires root.

## Build portable binaries

```bash
python build.py
```

Produces `dist/timecop`, `dist/timecop-collect`, `dist/timecop-webapp`. Single-file binaries, no Python required on target.

## Detection rules

### Windows

| Rule | Detects | Score |
|------|---------|-------|
| SI < FN Mismatch | SI Created earlier than FN Created | 40 |
| Zeroed Nanoseconds | `.0000000` subseconds on SI (tool signature) | 30 |
| SI Modified < SI Created | Modify time before creation time | 35 |
| Event Log Clearing | Event ID 1102, 104 | 50 |
| System Clock Jump | Backward jumps between EVTX records | 45 |
| Record Sequence Gap | Missing event record IDs | 45 |
| System Time Change | Event ID 4616 | 40 |
| File Created During Clock Manipulation | Cross-correlation with 4616 windows | 50 |

### Linux

| Rule | Detects | Score |
|------|---------|-------|
| mtime < ctime | mtime earlier than ctime (kernel-set) | 40 |
| Zeroed Nanoseconds | `mtime_ns=0` with `ctime_ns≠0` | 30 |
| Birthtime Anomaly | btime vs ctime gap (ext4, kernel 4.11+) | 35 |
| Touch Command | `touch -t/-d/-r` in audit or syslog | 35 |
| Timestamp Syscall | `utimensat`, `futimens`, `utimes` | 40 |
| Clock Change | `date -s`, `timedatectl set-time`, `settimeofday` | 45 |
| Log File Tampering | `truncate`, `shred`, `rm /var/log` | 45 |
| Clock Jump in Logs | Backward jumps in syslog/journal | 45 |
| File Created During Clock Manipulation | Cross-correlation with log windows | 50 |

Severity bands: HIGH is 70 or above, MEDIUM is 40 to 69, LOW is anything under 40. All scores and thresholds live in `config.yaml`.

## Project layout

```
forensic-time-cop/
  main.py                 CLI entry point
  collector.py            Windows artifact collector
  collector_linux.py      Linux artifact collector
  collect_and_zip.py      OS-aware wrapper, builds analysis zip
  mft_parser.py           Pure-Python NTFS MFT parser
  config.yaml             Rule scores, severity thresholds
  config_loader.py
  build.py                PyInstaller build wrapper
  detectors/              Per-artifact analyzers
  rules/                  Sixteen rule classes (BaseRule subclasses)
  scoring/                SuspicionScorer
  webapp/                 Flask app, templates, static
  tests/                  Sample artifacts (Windows + Linux)
```

## Configuration

`config.yaml` controls every rule. Disable a rule, change its score, adjust thresholds:

```yaml
rules:
  si_fn_mismatch:
    enabled: true
    score: 40
    min_gap_seconds: 3600
  zeroed_nanoseconds:
    enabled: true
    score: 30
```

Severity thresholds:

```yaml
scoring:
  high_threshold: 70
  medium_threshold: 40
```

## Output

CLI prints findings grouped by file with severity, score, triggered rules, and reasons. Web dashboard shows three tabs: simplified summary, detailed log of every reason, and Plotly visualizations (score histogram, severity donut, rule-trigger bar). JSON export from both:

```bash
python main.py tests/windows/mft_output.csv tests/windows --export report.json
```

## Test artifacts

`tests/windows/` contains a small MFT CSV with six timestomped files (`evil.exe`, `beacon.dll`, etc.) plus three EVTX files including a cleared Security log. `tests/ubuntu/` contains a synthetic Linux filesystem CSV plus matching `auth.log`, `syslog`, `kern.log`, `audit.log` exhibiting `date -s`, `touch -t`, and `truncate` patterns.

## Limitations

- Live memory not analyzed. Running malware that has not yet written to disk is invisible.
- Kernel rootkits hooking VFS/NTFS calls can fabricate consistent userspace observations.
- ext4 birthtime requires Linux 4.11+ and Python 3.12+. Otherwise that rule disables silently.
- The MFT parser handles a single Windows volume per invocation. Multi-disk hosts need per-volume runs.

## License

MIT.

## References

- Palmbach, D., Breitinger, F. (2020). *Artifacts for Detecting Timestamp Manipulation in NTFS on Windows and Their Reliability.* DFRWS EU.
- Carrier, B. (2005). *File System Forensic Analysis.* Addison-Wesley.
- MITRE ATT&CK T1070.006 (Timestomp), T1070.001 (Clear Event Logs).
- Eric Zimmerman, *MFTECmd.*
