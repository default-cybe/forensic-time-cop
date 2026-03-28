"""
Forensic Time Cop: Linux Artifact Collector
Scans filesystem for timestamps + copies log files.
Requires: root for full scan + debugfs.
"""

import os
import sys
import csv
import shutil
import subprocess
from datetime import datetime, timezone

SKIP_DIRS = ["/proc", "/sys", "/dev", "/run", "/snap", "/boot/efi", "/mnt"]

SYSTEM_DIRS = ["/usr", "/lib", "/lib64", "/lib32", "/sbin", "/bin", "/boot"]

LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/audit/audit.log",
    "/var/log/kern.log",
    "/var/log/secure",
]


def is_root():
    return os.geteuid() == 0


def collect_fs_metadata(output_dir, scan_paths=None, fullscan=False):
    """Walk filesystem, dump timestamps to CSV (like MFT CSV but for Linux)."""
    csv_path = os.path.join(output_dir, "linux_fs.csv")

    if scan_paths is None:
        if fullscan:
            scan_paths = ["/"]
        else:
            scan_paths = ["/home", "/tmp", "/var/www", "/var/tmp", "/opt", "/srv"]

    count = 0
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "FilePath", "FileName", "ParentDir", "FileSize", "IsDirectory",
            "ModifyTime", "ModifyTimeNs",
            "ChangeTime", "ChangeTimeNs",
            "AccessTime", "AccessTimeNs",
            "BirthTime", "BirthTimeNs",
        ])

        for scan_path in scan_paths:
            if not os.path.isdir(scan_path):
                continue
            for root, dirs, files in os.walk(scan_path, followlinks=False):
                # Skip virtual/system filesystems
                if any(root.startswith(skip) for skip in SKIP_DIRS):
                    dirs.clear()
                    continue

                for name in files + [d for d in dirs]:
                    filepath = os.path.join(root, name)
                    try:
                        st = os.lstat(filepath)

                        mtime_ns = st.st_mtime_ns
                        ctime_ns = st.st_ctime_ns
                        atime_ns = st.st_atime_ns

                        # Birth time: available on ext4 with kernel 4.11+ / Python 3.12+
                        birthtime = getattr(st, "st_birthtime", 0)
                        birthtime_ns_raw = getattr(st, "st_birthtime_ns", 0)

                        writer.writerow([
                            filepath,
                            name,
                            root,
                            st.st_size,
                            os.path.isdir(filepath),
                            datetime.fromtimestamp(
                                mtime_ns / 1e9, tz=timezone.utc
                            ).isoformat(),
                            mtime_ns % 1_000_000_000,
                            datetime.fromtimestamp(
                                ctime_ns / 1e9, tz=timezone.utc
                            ).isoformat(),
                            ctime_ns % 1_000_000_000,
                            datetime.fromtimestamp(
                                atime_ns / 1e9, tz=timezone.utc
                            ).isoformat(),
                            atime_ns % 1_000_000_000,
                            datetime.fromtimestamp(
                                birthtime, tz=timezone.utc
                            ).isoformat() if birthtime else "",
                            birthtime_ns_raw % 1_000_000_000 if birthtime else "",
                        ])
                        count += 1
                    except (PermissionError, OSError, OverflowError):
                        continue

    print(f"  [+] Scanned {count} files -> {csv_path}")
    return csv_path


def collect_logs(output_dir):
    """Copy relevant log files."""
    log_dir = os.path.join(output_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    copied = []

    for log_path in LOG_FILES:
        if os.path.isfile(log_path):
            dest = os.path.join(log_dir, os.path.basename(log_path))
            try:
                shutil.copy2(log_path, dest)
                copied.append(dest)
                print(f"  [+] Copied {log_path} -> {dest}")
            except (PermissionError, OSError) as e:
                print(f"  [!] Cannot copy {log_path}: {e}")

    # Also try journalctl export
    journal_path = os.path.join(log_dir, "journal_export.log")
    try:
        result = subprocess.run(
            ["journalctl", "--no-pager", "-n", "10000", "--output=short-iso"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout:
            with open(journal_path, "w") as f:
                f.write(result.stdout)
            copied.append(journal_path)
            print(f"  [+] Exported journalctl -> {journal_path}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return copied


def collect(output_dir="collected_artifacts", scan_paths=None, fullscan=False):
    """Run full Linux artifact collection."""
    if sys.platform == "win32":
        print("[!] Linux collection cannot run on Windows")
        return None, []

    if not is_root():
        print("[!] Root privileges recommended for full collection")
        print("[!] Run: sudo python collector_linux.py")

    os.makedirs(output_dir, exist_ok=True)
    print(f"[*] Collecting Linux artifacts to: {os.path.abspath(output_dir)}")

    # Filesystem metadata
    print("\n[*] Scanning filesystem timestamps...")
    fs_csv = collect_fs_metadata(output_dir, scan_paths, fullscan)

    # Log files
    print("\n[*] Collecting log files...")
    log_files = collect_logs(output_dir)

    print(f"\n[*] Collection complete")
    print(f"    FS CSV:     {'OK' if fs_csv else 'FAILED'}")
    print(f"    Log files:  {len(log_files)} collected")

    return fs_csv, log_files


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "collected_artifacts"
    fullscan = "--fullscan" in sys.argv
    fs_csv, log_files = collect(output, fullscan=fullscan)

    if fs_csv:
        log_dir = os.path.join(output, "logs")
        print(f"\n[*] Ready to analyze. Run:")
        print(f"    python main.py --os linux {fs_csv} {log_dir}")
