"""
Forensic Time Cop: Quick Collect & Zip
Collects artifacts, filters to a time window, and zips for analysis.
Works on both Windows and Linux.

Usage:
  python collect_and_zip.py                          # Last 24 hours
  python collect_and_zip.py --hours 2                # Last 2 hours
  python collect_and_zip.py --since "2026-04-16 10:00"  # Since specific time
  python collect_and_zip.py --since "2026-04-16 10:00" --until "2026-04-16 14:00"
  python collect_and_zip.py --fullscan               # Include system paths
"""

import sys
import os
import csv
import zipfile
import argparse
from datetime import datetime, timezone, timedelta

# Determine platform
IS_WINDOWS = sys.platform == "win32"


def parse_time_window(args):
    """Parse time window from CLI args."""
    now = datetime.now(timezone.utc)

    if args.since:
        # Parse user-provided start time (assume local, convert to UTC)
        try:
            since = datetime.strptime(args.since, "%Y-%m-%d %H:%M")
        except ValueError:
            try:
                since = datetime.strptime(args.since, "%Y-%m-%d")
            except ValueError:
                print(f"[!] Cannot parse --since '{args.since}'. Use format: YYYY-MM-DD HH:MM")
                sys.exit(1)
        since = since.replace(tzinfo=timezone.utc)
    else:
        hours = args.hours or 24
        since = now - timedelta(hours=hours)

    if args.until:
        try:
            until = datetime.strptime(args.until, "%Y-%m-%d %H:%M")
        except ValueError:
            try:
                until = datetime.strptime(args.until, "%Y-%m-%d")
            except ValueError:
                print(f"[!] Cannot parse --until '{args.until}'. Use format: YYYY-MM-DD HH:MM")
                sys.exit(1)
        until = until.replace(tzinfo=timezone.utc)
    else:
        until = now

    return since, until


def filter_csv(input_path, output_path, since, until, time_columns):
    """Filter CSV rows to only those with any timestamp in the window."""
    kept = 0
    total = 0

    with open(input_path, "r", newline="", errors="replace") as fin:
        reader = csv.DictReader(fin)
        fieldnames = reader.fieldnames

        with open(output_path, "w", newline="") as fout:
            writer = csv.DictWriter(fout, fieldnames=fieldnames)
            writer.writeheader()

            for row in reader:
                total += 1
                in_window = False

                for col in time_columns:
                    val = row.get(col, "")
                    if not val:
                        continue
                    try:
                        # Handle various timestamp formats
                        ts = None
                        for fmt in [
                            "%Y-%m-%d %H:%M:%S.%f%z",
                            "%Y-%m-%d %H:%M:%S%z",
                            "%Y-%m-%dT%H:%M:%S.%f%z",
                            "%Y-%m-%dT%H:%M:%S%z",
                            "%Y-%m-%d %H:%M:%S.%f",
                            "%Y-%m-%d %H:%M:%S",
                        ]:
                            try:
                                ts = datetime.strptime(val.strip(), fmt)
                                break
                            except ValueError:
                                continue

                        if ts is None:
                            continue

                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)

                        if since <= ts <= until:
                            in_window = True
                            break
                    except Exception:
                        continue

                if in_window:
                    writer.writerow(row)
                    kept += 1

    return kept, total


def collect_windows(output_dir, since, until, fullscan):
    """Collect and filter Windows artifacts."""
    from collector import collect, is_admin

    if not is_admin():
        print("[!] Administrator privileges required")
        print("[!] Right-click terminal -> Run as Administrator")
        sys.exit(1)

    # Collect raw artifacts
    raw_dir = os.path.join(output_dir, "_raw")
    os.makedirs(raw_dir, exist_ok=True)

    print("[*] Collecting Windows artifacts...")
    mft_csv, evtx_files = collect(output_dir=raw_dir)

    files_to_zip = []

    # Copy full MFT CSV (no time filtering, need ALL timestamps for anomaly detection)
    if mft_csv and os.path.isfile(mft_csv):
        import shutil
        dest_csv = os.path.join(output_dir, "mft_output.csv")
        if mft_csv != dest_csv:
            shutil.copy2(mft_csv, dest_csv)
        size_mb = os.path.getsize(dest_csv) / (1024 * 1024)
        print(f"[+] MFT: full copy ({size_mb:.1f} MB), no time filter (need all timestamps for detection)")
        files_to_zip.append(("mft_output.csv", dest_csv))

    # Copy EVTX files (keep full, they're needed for log analysis)
    for evtx in evtx_files:
        if os.path.isfile(evtx):
            name = os.path.basename(evtx)
            dest = os.path.join(output_dir, name)
            if evtx != dest:
                import shutil
                shutil.copy2(evtx, dest)
            files_to_zip.append((name, dest))

    return files_to_zip


def collect_linux(output_dir, since, until, fullscan):
    """Collect and filter Linux artifacts."""
    from collector_linux import collect_fs_metadata, collect_logs, is_root

    if not is_root():
        print("[!] Root recommended for full collection")

    raw_dir = os.path.join(output_dir, "_raw")
    os.makedirs(raw_dir, exist_ok=True)

    # Collect filesystem metadata
    print("[*] Collecting Linux filesystem metadata...")
    raw_csv = collect_fs_metadata(raw_dir, fullscan=fullscan)

    files_to_zip = []

    # Copy full FS CSV (no time filtering, need all timestamps for anomaly detection)
    if raw_csv and os.path.isfile(raw_csv):
        import shutil
        dest_csv = os.path.join(output_dir, "linux_fs.csv")
        if raw_csv != dest_csv:
            shutil.copy2(raw_csv, dest_csv)
        size_mb = os.path.getsize(dest_csv) / (1024 * 1024)
        print(f"[+] Filesystem: full copy ({size_mb:.1f} MB), no time filter")
        files_to_zip.append(("linux_fs.csv", dest_csv))

    # Collect log files
    print("[*] Collecting log files...")
    log_files = collect_logs(raw_dir)

    log_out_dir = os.path.join(output_dir, "logs")
    os.makedirs(log_out_dir, exist_ok=True)

    for lf in log_files:
        if os.path.isfile(lf):
            name = os.path.basename(lf)
            dest = os.path.join(log_out_dir, name)
            if lf != dest:
                import shutil
                shutil.copy2(lf, dest)
            files_to_zip.append((f"logs/{name}", dest))

    return files_to_zip


def make_zip(output_dir, files_to_zip, since, until):
    """Create zip bundle."""
    ts_str = since.strftime("%Y%m%d_%H%M")
    zip_name = f"forensic_artifacts_{ts_str}.zip"
    zip_path = os.path.join(output_dir, zip_name)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, filepath in files_to_zip:
            if os.path.isfile(filepath):
                zf.write(filepath, arcname)

    size_mb = os.path.getsize(zip_path) / (1024 * 1024)
    print(f"\n[+] ZIP: {zip_path} ({size_mb:.1f} MB)")
    print(f"    Files: {len(files_to_zip)}")
    return zip_path


def cleanup_raw(output_dir):
    """Remove raw collection directory."""
    import shutil
    raw_dir = os.path.join(output_dir, "_raw")
    if os.path.isdir(raw_dir):
        shutil.rmtree(raw_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(
        description="Forensic Time Cop: Quick Collect & Zip",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python collect_and_zip.py                              # Last 24 hours
  python collect_and_zip.py --hours 2                    # Last 2 hours
  python collect_and_zip.py --since "2026-04-16 10:00"   # Since specific time
  python collect_and_zip.py --hours 1 --fullscan         # Last hour, all paths""",
    )
    parser.add_argument("--hours", type=float, help="Collect last N hours (default: 24)")
    parser.add_argument("--since", type=str, help="Start time: 'YYYY-MM-DD HH:MM'")
    parser.add_argument("--until", type=str, help="End time: 'YYYY-MM-DD HH:MM' (default: now)")
    parser.add_argument("--fullscan", action="store_true", help="Include system paths")
    parser.add_argument("--output", type=str, default="quick_collect", help="Output directory")
    parser.add_argument("--os", type=str, choices=["windows", "linux"],
                        help="Force OS (auto-detected if omitted)")

    args = parser.parse_args()

    since, until = parse_time_window(args)

    target_os = args.os
    if target_os is None:
        target_os = "windows" if IS_WINDOWS else "linux"

    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Forensic Time Cop: Quick Collect")
    print(f"[*] OS: {target_os.upper()}")
    print(f"[*] Window: {since.strftime('%Y-%m-%d %H:%M')} to {until.strftime('%Y-%m-%d %H:%M')} UTC")
    print()

    if target_os == "windows":
        files_to_zip = collect_windows(output_dir, since, until, args.fullscan)
    else:
        files_to_zip = collect_linux(output_dir, since, until, args.fullscan)

    if not files_to_zip:
        print("[!] No artifacts collected")
        sys.exit(1)

    zip_path = make_zip(output_dir, files_to_zip, since, until)
    cleanup_raw(output_dir)

    print(f"\n[*] Ready to analyze:")
    if target_os == "windows":
        print(f"    python main.py {output_dir}/mft_filtered.csv {output_dir}")
    else:
        print(f"    python main.py --os linux {output_dir}/linux_fs_filtered.csv {output_dir}/logs")
    print(f"\n    Or upload the zip contents to the web dashboard.")


if __name__ == "__main__":
    main()
