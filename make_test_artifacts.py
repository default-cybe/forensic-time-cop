"""
Generate fake Linux forensic test artifacts (CSV + logs) for testing.
Run on any OS, no root needed. Creates a zip ready to upload to webapp.
"""

import csv
import os
import zipfile
from datetime import datetime, timezone, timedelta

OUT_DIR = "test_bundle"
CSV_PATH = os.path.join(OUT_DIR, "linux_fs.csv")
LOG_DIR = os.path.join(OUT_DIR, "logs")


def make_dirs():
    os.makedirs(LOG_DIR, exist_ok=True)


def make_fs_csv():
    """Generate a fake Linux filesystem CSV with mix of clean + stomped files."""
    now = datetime(2026, 4, 16, 5, 53, 22, 347448, tzinfo=timezone.utc)

    rows = []

    # --- Timestomped files (should trigger mtime < ctime + zeroed ns) ---
    stomped = [
        {
            "path": "/tmp/forensic_test/backdated.txt",
            "mtime": datetime(2020, 1, 1, 5, 0, 0, tzinfo=timezone.utc),
            "ctime": now,
            "mtime_ns": 0,
            "ctime_ns": 872178867,
        },
        {
            "path": "/tmp/forensic_test/suspicious.bin",
            "mtime": datetime(2019, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
            "ctime": now,
            "mtime_ns": 0,
            "ctime_ns": 467447060,
        },
        {
            "path": "/tmp/forensic_test/.secret_config",
            "mtime": datetime(2021, 3, 15, 12, 30, 0, tzinfo=timezone.utc),
            "ctime": now,
            "mtime_ns": 0,
            "ctime_ns": 908454786,
        },
        {
            "path": "/home/user/malware_dropper.sh",
            "mtime": datetime(2022, 8, 10, 3, 0, 0, tzinfo=timezone.utc),
            "ctime": now,
            "mtime_ns": 0,
            "ctime_ns": 551234567,
        },
        {
            "path": "/opt/backdoor/reverse_shell.py",
            "mtime": datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            "ctime": now,
            "mtime_ns": 0,
            "ctime_ns": 123456789,
        },
        {
            "path": "/var/www/html/webshell.php",
            "mtime": datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
            "ctime": now,
            "mtime_ns": 0,
            "ctime_ns": 999888777,
        },
    ]

    for s in stomped:
        name = os.path.basename(s["path"])
        parent = os.path.dirname(s["path"])
        rows.append([
            s["path"], name, parent, 1024, "False",
            s["mtime"].isoformat(), s["mtime_ns"],
            s["ctime"].isoformat(), s["ctime_ns"],
            s["mtime"].isoformat(), 0,
            "", "",
        ])

    # --- Clean files (should NOT trigger) ---
    clean_files = [
        "/home/user/documents/report.docx",
        "/home/user/documents/notes.txt",
        "/home/user/.bashrc",
        "/home/user/.profile",
        "/tmp/session_abc123",
        "/var/tmp/cache_data.bin",
        "/opt/myapp/config.ini",
        "/opt/myapp/app.py",
        "/srv/website/index.html",
        "/srv/website/style.css",
        "/home/user/photos/vacation.jpg",
        "/home/user/music/song.mp3",
    ]

    for i, path in enumerate(clean_files):
        t = now - timedelta(hours=i, minutes=30)
        ns = 123456789 + i * 111111
        name = os.path.basename(path)
        parent = os.path.dirname(path)
        rows.append([
            path, name, parent, 2048 + i * 100, "False",
            t.isoformat(), ns,
            t.isoformat(), ns,
            t.isoformat(), ns,
            "", "",
        ])

    # --- System files in skip paths (should be filtered out) ---
    system_files = [
        "/usr/bin/ls",
        "/usr/lib/libc.so",
        "/lib/x86_64-linux-gnu/ld-linux.so",
        "/sbin/init",
        "/bin/bash",
        "/boot/vmlinuz",
    ]

    for path in system_files:
        # Even if these have mtime < ctime, they should be skipped
        old_time = datetime(2018, 1, 1, tzinfo=timezone.utc)
        name = os.path.basename(path)
        parent = os.path.dirname(path)
        rows.append([
            path, name, parent, 4096, "False",
            old_time.isoformat(), 0,
            now.isoformat(), 555666777,
            old_time.isoformat(), 0,
            "", "",
        ])

    # --- Directories (should be skipped) ---
    dirs = ["/tmp/forensic_test", "/home/user", "/opt/myapp"]
    for path in dirs:
        name = os.path.basename(path)
        parent = os.path.dirname(path)
        rows.append([
            path, name, parent, 4096, "True",
            now.isoformat(), 0,
            now.isoformat(), 123456,
            now.isoformat(), 0,
            "", "",
        ])

    # --- Write CSV ---
    with open(CSV_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "FilePath", "FileName", "ParentDir", "FileSize", "IsDirectory",
            "ModifyTime", "ModifyTimeNs",
            "ChangeTime", "ChangeTimeNs",
            "AccessTime", "AccessTimeNs",
            "BirthTime", "BirthTimeNs",
        ])
        writer.writerows(rows)

    print(f"[+] CSV: {CSV_PATH} ({len(rows)} entries)")


def make_logs():
    """Generate fake log files with tampering evidence."""

    # syslog with clock change + touch commands
    syslog_content = """Apr 16 10:00:01 forensic-host systemd[1]: Started session 1
Apr 16 10:01:15 forensic-host sudo: attacker : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/date -s "2020-01-01 00:00:00"
Apr 16 10:01:16 forensic-host kernel: settimeofday called from process 1234
Jan  1 00:00:01 forensic-host systemd[1]: Started session 2
Jan  1 00:00:05 forensic-host sudo: attacker : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/touch -t 202001010000 /tmp/forensic_test/backdated.txt
Jan  1 00:00:10 forensic-host sudo: attacker : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/touch -t 201906150800 /tmp/forensic_test/suspicious.bin
Jan  1 00:05:22 forensic-host sudo: attacker : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/touch -d "2021-03-15 08:30:00" /tmp/forensic_test/.secret_config
Apr 16 10:05:30 forensic-host kernel: settimeofday called from process 1234
Apr 16 10:05:31 forensic-host systemd[1]: Time restored to normal
Apr 16 10:10:00 forensic-host systemd[1]: logrotate.service: Deactivated successfully.
Apr 16 10:15:00 forensic-host CRON[5678]: (root) CMD (test -x /usr/sbin/anacron)
Apr 16 10:20:00 forensic-host sshd[9012]: Accepted publickey for user from 192.168.1.100
"""

    # audit.log with utimensat syscalls
    audit_content = """type=SYSCALL msg=audit(1713250875.000:100): arch=c000003e syscall=280 success=yes exit=0 a0=ffffff9c comm="touch" exe="/usr/bin/touch" key="timestamp_change"
type=EXECVE msg=audit(1713250875.000:100): argc=4 a0="touch" a1="-t" a2="202001010000" a3="/tmp/forensic_test/backdated.txt"
type=SYSCALL msg=audit(1713250880.000:101): arch=c000003e syscall=280 success=yes exit=0 a0=ffffff9c comm="python3" exe="/usr/bin/python3" key="utimensat"
type=SYSCALL msg=audit(1713250885.000:102): arch=c000003e syscall=280 success=yes exit=0 a0=3 comm="malware" exe="/tmp/malware_dropper" key="futimens"
type=SYSCALL msg=audit(1713250890.000:103): arch=c000003e syscall=235 success=yes exit=0 comm="backdoor" exe="/opt/backdoor/reverse_shell.py" key="utimes"
"""

    # auth.log with suspicious activity
    auth_content = """Apr 16 09:50:00 forensic-host sshd[1001]: Accepted password for attacker from 10.0.0.5 port 44321 ssh2
Apr 16 09:50:05 forensic-host sudo: attacker : TTY=pts/1 ; PWD=/home/attacker ; USER=root ; COMMAND=/bin/bash
Apr 16 09:55:00 forensic-host sudo: attacker : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/timedatectl set-time "2020-01-01"
Apr 16 10:00:00 forensic-host sudo: attacker : TTY=pts/1 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/truncate -s 0 /var/log/auth.log
Apr 16 10:01:00 forensic-host sudo: attacker : TTY=pts/1 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/shred -zu /var/log/btmp
"""

    # kern.log, clean, no findings expected
    kern_content = """Apr 16 09:00:00 forensic-host kernel: [    0.000000] Linux version 5.15.0
Apr 16 09:00:01 forensic-host kernel: [    0.123456] Memory: 8192MB available
Apr 16 10:00:00 forensic-host kernel: [  3600.000000] eth0: link up
"""

    logs = {
        "syslog": syslog_content,
        "audit.log": audit_content,
        "auth.log": auth_content,
        "kern.log": kern_content,
    }

    for name, content in logs.items():
        path = os.path.join(LOG_DIR, name)
        with open(path, "w") as f:
            f.write(content.strip() + "\n")
        print(f"[+] Log: {path}")


def make_zip():
    """Bundle everything into a zip."""
    zip_path = "test_artifacts.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(OUT_DIR):
            for fname in files:
                full = os.path.join(root, fname)
                arcname = os.path.relpath(full, OUT_DIR)
                zf.write(full, arcname)
    print(f"\n[+] ZIP: {zip_path}")
    print(f"    Contains: linux_fs.csv + logs/")
    print(f"\n    Upload linux_fs.csv as Filesystem CSV")
    print(f"    Upload logs/* as Log Files")


if __name__ == "__main__":
    make_dirs()
    make_fs_csv()
    make_logs()
    make_zip()
    print("\n[*] Done! Transfer test_artifacts.zip to any machine and test.")
