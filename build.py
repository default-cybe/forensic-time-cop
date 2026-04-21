"""
Build portable Forensic Time Cop binary.
Run on each target OS to produce platform-specific executable.

Usage:
  pip install pyinstaller
  python build.py          # Builds for current OS
  python build.py --cli    # CLI only (smaller)
  python build.py --webapp # Webapp only
  python build.py --all    # Both CLI + webapp (default)
"""

import subprocess
import sys
import os
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SEP = os.pathsep  # ; on Windows, : on Linux


def data_path(src, dest="."):
    """Return absolute --add-data string."""
    return f"{os.path.join(BASE_DIR, src)}{SEP}{dest}"


def build_webapp():
    """Build webapp as single portable binary."""
    print("[*] Building webapp...")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", "timecop-webapp",
        "--add-data", data_path("webapp/templates", "webapp/templates"),
        "--add-data", data_path("webapp/static", "webapp/static"),
        "--add-data", data_path("config.yaml"),
        "--hidden-import", "detectors.mft_analyzer",
        "--hidden-import", "detectors.log_analyzer",
        "--hidden-import", "detectors.linux_fs_analyzer",
        "--hidden-import", "detectors.linux_log_analyzer",
        "--hidden-import", "rules.rule_si_fn_mismatch",
        "--hidden-import", "rules.rule_zeroed_nanoseconds",
        "--hidden-import", "rules.rule_birthtime_mtime_gap",
        "--hidden-import", "rules.rule_clock_jump_in_logs",
        "--hidden-import", "rules.rule_record_sequence_gap",
        "--hidden-import", "rules.rule_system_time_change",
        "--hidden-import", "rules.rule_created_during_clock_change",
        "--hidden-import", "rules.rule_linux_fs",
        "--hidden-import", "rules.rule_linux_timestomp",
        "--hidden-import", "rules.rule_base",
        "--hidden-import", "scoring.suspicion_scorer",
        "--hidden-import", "config_loader",
        "--distpath", os.path.join(BASE_DIR, "dist"),
        "--workpath", os.path.join(BASE_DIR, "build"),
        "--specpath", os.path.join(BASE_DIR, "build"),
        os.path.join(BASE_DIR, "webapp", "app.py"),
    ]

    subprocess.run(cmd, check=True, cwd=BASE_DIR)
    print("[+] Webapp binary: dist/timecop-webapp")


def build_cli():
    """Build CLI as single portable binary."""
    print("[*] Building CLI...")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", "timecop",
        "--add-data", data_path("config.yaml"),
        "--hidden-import", "detectors.mft_analyzer",
        "--hidden-import", "detectors.log_analyzer",
        "--hidden-import", "detectors.linux_fs_analyzer",
        "--hidden-import", "detectors.linux_log_analyzer",
        "--hidden-import", "rules.rule_si_fn_mismatch",
        "--hidden-import", "rules.rule_zeroed_nanoseconds",
        "--hidden-import", "rules.rule_birthtime_mtime_gap",
        "--hidden-import", "rules.rule_clock_jump_in_logs",
        "--hidden-import", "rules.rule_record_sequence_gap",
        "--hidden-import", "rules.rule_system_time_change",
        "--hidden-import", "rules.rule_created_during_clock_change",
        "--hidden-import", "rules.rule_linux_fs",
        "--hidden-import", "rules.rule_linux_timestomp",
        "--hidden-import", "rules.rule_base",
        "--hidden-import", "scoring.suspicion_scorer",
        "--hidden-import", "config_loader",
        "--hidden-import", "collector",
        "--hidden-import", "collector_linux",
        "--hidden-import", "mft_parser",
        "--distpath", os.path.join(BASE_DIR, "dist"),
        "--workpath", os.path.join(BASE_DIR, "build"),
        "--specpath", os.path.join(BASE_DIR, "build"),
        os.path.join(BASE_DIR, "main.py"),
    ]

    subprocess.run(cmd, check=True, cwd=BASE_DIR)
    print("[+] CLI binary: dist/timecop")


def build_collector():
    """Build quick collector as single portable binary."""
    print("[*] Building collector...")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", "timecop-collect",
        "--hidden-import", "collector",
        "--hidden-import", "collector_linux",
        "--hidden-import", "mft_parser",
        "--distpath", os.path.join(BASE_DIR, "dist"),
        "--workpath", os.path.join(BASE_DIR, "build"),
        "--specpath", os.path.join(BASE_DIR, "build"),
        os.path.join(BASE_DIR, "collect_and_zip.py"),
    ]

    subprocess.run(cmd, check=True, cwd=BASE_DIR)
    print("[+] Collector binary: dist/timecop-collect")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Build Forensic Time Cop binaries")
    parser.add_argument("--cli", action="store_true", help="Build CLI only")
    parser.add_argument("--webapp", action="store_true", help="Build webapp only")
    parser.add_argument("--collector", action="store_true", help="Build collector only")
    parser.add_argument("--all", action="store_true", help="Build everything (default)")
    args = parser.parse_args()

    # Check PyInstaller
    try:
        import PyInstaller
        print(f"[*] PyInstaller {PyInstaller.__version__}")
    except ImportError:
        print("[!] PyInstaller not installed. Run: pip install pyinstaller")
        sys.exit(1)

    # Default = all
    if not (args.cli or args.webapp or args.collector):
        args.all = True

    # Clean previous builds
    for d in ["build", "dist"]:
        full = os.path.join(BASE_DIR, d)
        if os.path.isdir(full):
            shutil.rmtree(full)

    if args.all or args.cli:
        build_cli()
    if args.all or args.webapp:
        build_webapp()
    if args.all or args.collector:
        build_collector()

    print(f"\n{'=' * 50}")
    print("[+] Build complete! Binaries in dist/")
    print()

    ext = ".exe" if sys.platform == "win32" else ""
    if args.all or args.webapp:
        print(f"    Webapp:    dist/timecop-webapp{ext}")
        print(f"               Run it, open http://localhost:5000")
    if args.all or args.cli:
        print(f"    CLI:       dist/timecop{ext}")
        print(f"               ./timecop <mft.csv> [evtx_folder]")
    if args.all or args.collector:
        print(f"    Collector: dist/timecop-collect{ext}")
        print(f"               ./timecop-collect --hours 2")


if __name__ == "__main__":
    main()
