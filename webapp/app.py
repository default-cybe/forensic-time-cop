import os
import sys
import json
import tempfile

from flask import Flask, render_template, request, jsonify

# Handle both normal Python run and PyInstaller bundle
if getattr(sys, 'frozen', False):
    # Running as PyInstaller bundle
    bundle_dir = sys._MEIPASS
    template_dir = os.path.join(bundle_dir, 'webapp', 'templates')
    static_dir = os.path.join(bundle_dir, 'webapp', 'static')
    sys.path.insert(0, bundle_dir)
else:
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detectors.mft_analyzer import MFTAnalyzer
from detectors.log_analyzer import LogAnalyzer
from detectors.linux_fs_analyzer import LinuxFSAnalyzer
from detectors.linux_log_analyzer import LinuxLogAnalyzer
from scoring.suspicion_scorer import SuspicionScorer
from config_loader import load_config
from rules.rule_created_during_clock_change import RuleCreatedDuringClockChange
from rules.rule_linux_fs import RuleLinuxLogClearing, RuleLinuxClockJumpInLogs

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500MB max upload


@app.route("/")
def index():
    return render_template("index.html")


def analyze_windows(request_obj, config):
    """Run Windows analysis pipeline (MFT + EVTX)."""
    all_findings = []
    temp_files = []

    try:
        mft_file = request_obj.files.get("mft_csv")
        if not mft_file or not mft_file.filename:
            return {"error": "MFT CSV file is required"}, 400, temp_files

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
            mft_file.save(tmp.name)
            mft_path = tmp.name
            temp_files.append(mft_path)

        fullscan = request_obj.form.get("fullscan") == "true"
        mft = MFTAnalyzer(mft_path, fullscan=fullscan, config=config)
        mft_findings = mft.run()
        all_findings.extend(mft_findings)

        # EVTX files (optional)
        evtx_files = request_obj.files.getlist("evtx_files")
        if evtx_files and evtx_files[0].filename:
            evtx_paths = []
            temp_to_name = {}
            for evtx in evtx_files:
                with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
                    evtx.save(tmp.name)
                    evtx_paths.append(tmp.name)
                    temp_files.append(tmp.name)
                    temp_to_name[tmp.name] = evtx.filename

            log = LogAnalyzer(evtx_paths, config=config)
            log_findings = log.run()

            for finding in log_findings:
                finding["file"] = temp_to_name.get(finding["file"], finding["file"])
            all_findings.extend(log_findings)

            # Cross-correlate: files created during clock manipulation
            clock_rule = RuleCreatedDuringClockChange()
            num_windows = clock_rule.analyze_events(log.all_events)
            if num_windows > 0:
                clock_findings = clock_rule.analyze(mft.df)
                for finding in clock_findings:
                    finding["file"] = temp_to_name.get(finding["file"], finding["file"])
                all_findings.extend(clock_findings)

        return all_findings, 200, temp_files

    except Exception as e:
        return {"error": str(e)}, 500, temp_files


def analyze_linux(request_obj, config):
    """Run Linux analysis pipeline (FS CSV + log files)."""
    all_findings = []
    temp_files = []

    try:
        fs_file = request_obj.files.get("linux_csv")
        if not fs_file or not fs_file.filename:
            return {"error": "Linux filesystem CSV is required"}, 400, temp_files

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
            fs_file.save(tmp.name)
            fs_path = tmp.name
            temp_files.append(fs_path)

        fullscan = request_obj.form.get("fullscan") == "true"

        # Filesystem analysis
        fs_analyzer = LinuxFSAnalyzer(fs_path, fullscan=fullscan, config=config)
        fs_findings = fs_analyzer.run()
        all_findings.extend(fs_findings)

        # Log files (optional)
        log_files = request_obj.files.getlist("log_files")
        if log_files and log_files[0].filename:
            log_paths = []
            temp_to_name = {}
            for lf in log_files:
                with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp:
                    lf.save(tmp.name)
                    log_paths.append(tmp.name)
                    temp_files.append(tmp.name)
                    temp_to_name[tmp.name] = lf.filename

            # Timestomping detection (touch, utimes, clock changes)
            linux_log = LinuxLogAnalyzer(log_paths, config=config)
            log_findings = linux_log.run()

            for finding in log_findings:
                finding["file"] = temp_to_name.get(finding["file"], finding["file"])
            all_findings.extend(log_findings)

            # Log tampering + clock jump detection
            log_clear_rule = RuleLinuxLogClearing()
            clock_jump_rule = RuleLinuxClockJumpInLogs()

            entries = []
            for lp in log_paths:
                orig_name = temp_to_name.get(lp, lp)
                try:
                    with open(lp, "r", errors="replace") as f:
                        for i, line in enumerate(f):
                            entries.append({
                                "line": line,
                                "source": orig_name,
                                "line_num": i,
                            })
                except Exception:
                    continue

            all_findings.extend(log_clear_rule.analyze(entries))
            all_findings.extend(clock_jump_rule.analyze(entries))

            # Cross-correlate clock change windows with file creation
            import re
            from datetime import datetime, timedelta

            clock_rule = RuleCreatedDuringClockChange()
            syslog_re = re.compile(r"^(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})")
            iso_re = re.compile(
                r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?"
            )
            year = datetime.now().year
            local_tz = datetime.now().astimezone().tzinfo

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
                    if curr - last_bogus > timedelta(minutes=5):
                        clock_rule.bogus_windows.append((bogus_start, last_bogus))
                        in_bogus = False
                        bogus_start = None
                        last_bogus = None
                    else:
                        last_bogus = curr
            if in_bogus and bogus_start and last_bogus:
                clock_rule.bogus_windows.append((bogus_start, last_bogus))

            if clock_rule.bogus_windows:
                df = fs_analyzer.df.copy()
                if "Created0x10" not in df.columns:
                    if "BirthTime" in df.columns and df["BirthTime"].notna().any():
                        df["Created0x10"] = df["BirthTime"]
                    elif "ModifyTime" in df.columns:
                        df["Created0x10"] = df["ModifyTime"]
                if "ParentPath" not in df.columns and "ParentDir" in df.columns:
                    df["ParentPath"] = df["ParentDir"]
                if "FileName" not in df.columns and "FilePath" in df.columns:
                    df["FileName"] = df["FilePath"].astype(str).str.rsplit("/", n=1).str[-1]

                all_findings.extend(clock_rule.analyze(df))

        return all_findings, 200, temp_files

    except Exception as e:
        return {"error": str(e)}, 500, temp_files


@app.route("/analyze", methods=["POST"])
def analyze():
    config = load_config()
    os_mode = request.form.get("os_mode", "windows")

    if os_mode == "linux":
        result, status, temp_files = analyze_linux(request, config)
    else:
        result, status, temp_files = analyze_windows(request, config)

    try:
        if status != 200:
            return jsonify(result), status

        all_findings = result

        if not all_findings:
            return jsonify({
                "status": "clean",
                "message": "No tampering detected",
                "findings": [],
                "summary": {"high": 0, "medium": 0, "low": 0, "total": 0},
                "os_mode": os_mode,
            })

        scorer = SuspicionScorer(all_findings, config=config)
        scored = scorer.score_by_file()

        high = len([x for x in scored if x["severity"] == "HIGH"])
        med = len([x for x in scored if x["severity"] == "MEDIUM"])
        low = len([x for x in scored if x["severity"] == "LOW"])

        return jsonify({
            "status": "findings",
            "findings": scored,
            "summary": {
                "high": high,
                "medium": med,
                "low": low,
                "total": len(scored),
            },
            "os_mode": os_mode,
        })

    finally:
        for tmp_path in temp_files:
            try:
                os.remove(tmp_path)
            except OSError:
                pass


if __name__ == "__main__":
    app.run(debug=True, port=5000)
