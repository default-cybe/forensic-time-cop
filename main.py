import sys
import os
import json
import glob as globmod
from scoring.suspicion_scorer import SuspicionScorer
from config_loader import load_config


def find_evtx_files(folder):
    return globmod.glob(os.path.join(folder, "*.evtx"))


def find_log_files(folder):
    patterns = ["*.log", "auth.log*", "syslog*", "audit.log*"]
    files = []
    for p in patterns:
        files.extend(globmod.glob(os.path.join(folder, p)))
    return list(set(files))


def export_report(scored, output_path):
    report = {
        "tool": "Forensic Time Cop",
        "findings": scored,
        "total_files_flagged": len(scored),
        "high_severity": len([x for x in scored if x["severity"] == "HIGH"]),
        "medium_severity": len([x for x in scored if x["severity"] == "MEDIUM"]),
        "low_severity": len([x for x in scored if x["severity"] == "LOW"]),
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report exported to {output_path}")


def detect_os():
    if sys.platform == "win32":
        return "windows"
    return "linux"


def run_windows(positional, fullscan, config, export_path):
    from detectors.mft_analyzer import MFTAnalyzer
    from detectors.log_analyzer import LogAnalyzer
    from rules.rule_created_during_clock_change import RuleCreatedDuringClockChange

    all_findings = []
    clock_rule = RuleCreatedDuringClockChange()

    # MFT analysis
    mft_analyzer = None
    if positional:
        csv_path = positional[0]
        print(f"[*] Analyzing MFT: {csv_path}")
        mft_analyzer = MFTAnalyzer(csv_path, fullscan=fullscan, config=config)
        mft_findings = mft_analyzer.run()
        all_findings.extend(mft_findings)
        print(f"[+] MFT findings: {len(mft_findings)}")

    # Event log analysis
    all_events = []
    if len(positional) >= 2:
        evtx_folder = positional[1]
        evtx_files = find_evtx_files(evtx_folder)
        if evtx_files:
            print(f"[*] Analyzing {len(evtx_files)} event log(s)")
            log = LogAnalyzer(evtx_files, config=config)
            log_findings = log.run()
            all_findings.extend(log_findings)
            all_events = log.all_events
            print(f"[+] Log findings: {len(log_findings)}")
        else:
            print("[!] No .evtx files found")

    # Cross-correlate clock windows with file creation
    if all_events and mft_analyzer is not None:
        num_windows = clock_rule.analyze_events(all_events)
        if num_windows > 0:
            print(f"[*] Detected {num_windows} clock manipulation window(s)")
            clock_findings = clock_rule.analyze(mft_analyzer.df)
            all_findings.extend(clock_findings)
            print(f"[+] Files created during clock manipulation: {len(clock_findings)}")

    return all_findings


def run_linux(positional, fullscan, config, export_path):
    import re
    from datetime import datetime, timezone
    from detectors.linux_fs_analyzer import LinuxFSAnalyzer
    from detectors.linux_log_analyzer import LinuxLogAnalyzer
    from rules.rule_linux_fs import RuleLinuxLogClearing, RuleLinuxClockJumpInLogs
    from rules.rule_created_during_clock_change import RuleCreatedDuringClockChange

    all_findings = []
    fs = None
    entries = []

    # Linux filesystem analysis
    if positional:
        csv_path = positional[0]
        print(f"[*] Analyzing Linux filesystem: {csv_path}")
        fs = LinuxFSAnalyzer(csv_path, fullscan=fullscan, config=config)
        fs_findings = fs.run()
        all_findings.extend(fs_findings)
        print(f"[+] Filesystem findings: {len(fs_findings)}")

    # Linux log analysis (auditd/syslog)
    log_folder = positional[1] if len(positional) >= 2 else None
    if log_folder:
        log_files = find_log_files(log_folder)
        if log_files:
            print(f"[*] Analyzing {len(log_files)} Linux log file(s)")

            # Timestomping detection (touch, utimes, clock changes)
            linux_log = LinuxLogAnalyzer(log_files, config=config)
            log_findings = linux_log.run()
            all_findings.extend(log_findings)

            # Log tampering + clock jump detection on parsed entries
            log_clear_rule = RuleLinuxLogClearing()
            clock_jump_rule = RuleLinuxClockJumpInLogs()

            entries = []
            for lf in log_files:
                try:
                    with open(lf, "r", errors="replace") as f:
                        for i, line in enumerate(f):
                            entries.append({
                                "line": line,
                                "source": lf,
                                "line_num": i,
                            })
                except Exception:
                    continue

            all_findings.extend(log_clear_rule.analyze(entries))
            all_findings.extend(clock_jump_rule.analyze(entries))

            print(f"[+] Log findings: {len(log_findings)}")
        else:
            print("[!] No log files found")

    # Cross-correlate clock change windows with file creation (Linux)
    if fs is not None and fs.df is not None and entries:
        from datetime import timedelta
        clock_rule = RuleCreatedDuringClockChange()

        syslog_re = re.compile(r"^(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})")
        iso_re = re.compile(
            r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?"
        )
        year = datetime.now().year
        local_tz = datetime.now().astimezone().tzinfo

        # Parse every log line's timestamp (naive, local tz) in file order
        events = []
        for e in entries:
            line = e.get("line", "")
            ts = None
            im = iso_re.match(line)
            if im:
                try:
                    ts = datetime(
                        int(im.group(1)), int(im.group(2)), int(im.group(3)),
                        int(im.group(4)), int(im.group(5)), int(im.group(6)),
                        tzinfo=local_tz,
                    )
                except Exception:
                    ts = None
            if ts is None:
                m = syslog_re.match(line)
                if m:
                    try:
                        ts_str = f"{year} {m.group(1)} {m.group(2)} {m.group(3)}"
                        ts = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
                        ts = ts.replace(tzinfo=local_tz)
                    except Exception:
                        ts = None
            if ts is not None:
                events.append(ts)

        # Detect backward → forward jumps; window = [bogus_start, last_bogus_ts]
        in_bogus = False
        bogus_start = None
        last_bogus = None
        for i in range(1, len(events)):
            prev = events[i - 1]
            curr = events[i]
            if not in_bogus:
                if prev - curr > timedelta(minutes=5):
                    in_bogus = True
                    bogus_start = curr
                    last_bogus = curr
            else:
                # Forward jump back to real time = restore
                if curr - last_bogus > timedelta(minutes=5):
                    clock_rule.bogus_windows.append((bogus_start, last_bogus))
                    in_bogus = False
                    bogus_start = None
                    last_bogus = None
                else:
                    last_bogus = curr
        if in_bogus and bogus_start and last_bogus:
            clock_rule.bogus_windows.append((bogus_start, last_bogus))

        num_windows = len(clock_rule.bogus_windows)
        if num_windows > 0:
            print(f"[*] Detected {num_windows} clock manipulation window(s)")

            # Adapt Linux FS columns to what RuleCreatedDuringClockChange expects
            df = fs.df.copy()
            if "Created0x10" not in df.columns:
                if "BirthTime" in df.columns and df["BirthTime"].notna().any():
                    df["Created0x10"] = df["BirthTime"]
                elif "ModifyTime" in df.columns:
                    df["Created0x10"] = df["ModifyTime"]
            if "ParentPath" not in df.columns and "ParentDir" in df.columns:
                df["ParentPath"] = df["ParentDir"]
            if "FileName" not in df.columns and "FilePath" in df.columns:
                df["FileName"] = df["FilePath"].astype(str).str.rsplit("/", n=1).str[-1]

            clock_findings = clock_rule.analyze(df)
            all_findings.extend(clock_findings)
            print(f"[+] Files created during clock manipulation: {len(clock_findings)}")

    return all_findings


def main():
    if len(sys.argv) < 2:
        print(
            "Usage:\n"
            "  Windows: python main.py <mft.csv> [evtx_folder] [options]\n"
            "  Linux:   python main.py --os linux <fs.csv> [log_folder] [options]\n"
            "  Live:    python main.py --live [options]\n"
            "\nOptions:\n"
            "  --os windows|linux   Force OS mode (auto-detected if omitted)\n"
            "  --live               Auto-collect and analyze on current system\n"
            "  --fullscan           Scan all paths (skip system path filter)\n"
            "  --config config.yaml Use custom config\n"
            "  --export report.json Export JSON report"
        )
        sys.exit(1)

    args = sys.argv[1:]
    fullscan = "--fullscan" in args
    live_mode = "--live" in args
    config_path = None
    export_path = None
    target_os = None

    # Parse named args
    i = 0
    positional = []
    while i < len(args):
        if args[i] in ("--fullscan", "--live"):
            i += 1
        elif args[i] == "--os" and i + 1 < len(args):
            target_os = args[i + 1].lower()
            i += 2
        elif args[i] == "--config" and i + 1 < len(args):
            config_path = args[i + 1]
            i += 2
        elif args[i] == "--export" and i + 1 < len(args):
            export_path = args[i + 1]
            i += 2
        else:
            positional.append(args[i])
            i += 1

    # Auto-detect OS if not specified
    if target_os is None:
        target_os = detect_os()

    config = load_config(config_path)

    print(f"[*] Operating mode: {target_os.upper()}")

    # Live collection
    if live_mode:
        if target_os == "windows":
            from collector import collect
            print("[*] Live collection, extracting Windows artifacts")
            mft_csv, evtx_files = collect()
            if mft_csv:
                positional = [mft_csv, os.path.dirname(mft_csv)]
            else:
                print("[!] Collection failed")
                sys.exit(1)
        else:
            from collector_linux import collect
            print("[*] Live collection, extracting Linux artifacts")
            fs_csv, log_files = collect(fullscan=fullscan)
            if fs_csv:
                positional = [fs_csv, os.path.join("collected_artifacts", "logs")]
            else:
                print("[!] Collection failed")
                sys.exit(1)

    # Run analysis
    if target_os == "windows":
        all_findings = run_windows(positional, fullscan, config, export_path)
    else:
        all_findings = run_linux(positional, fullscan, config, export_path)

    # Score findings
    print(f"\n{'=' * 50}")
    if not all_findings:
        print("[+] No tampering detected.")
    else:
        scorer = SuspicionScorer(all_findings, config=config)
        scored = scorer.score_by_file()

        print(f"[!] Suspicious files found: {len(scored)}\n")
        for item in scored:
            print(f"  File     : {item['file']}")
            print(f"  Severity : {item['severity']}")
            print(f"  Score    : {item['total_score']}")
            print(f"  Rules    : {', '.join(item['rules_triggered'])}")
            print(f"  Reasons  :")
            for r in item["reasons"]:
                print(f"    - {r}")
            print()

        if export_path:
            export_report(scored, export_path)


if __name__ == "__main__":
    main()
