"""
Forensic Time Cop: Live Artifact Collector
Auto-detects OS and extracts appropriate artifacts.
Windows: MFT + Event Logs (requires Admin + MFTECmd.exe)
Linux:   Filesystem timestamps + syslog/auditd (requires root)
"""

import os
import sys
import subprocess
import shutil
import ctypes
import glob as globmod


def is_admin():
    """Check if running with admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def find_mftecmd():
    """Search for MFTECmd.exe in common locations."""
    search_paths = [
        # Same directory as this script
        os.path.dirname(os.path.abspath(__file__)),
        # Tools subdirectory
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "Tools"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "Tools", "MFTECmd"),
        # Common forensic tool paths
        r"C:\Tools",
        r"C:\Tools\MFTECmd",
        r"C:\forensic-tools",
    ]

    # Check PATH first
    if shutil.which("MFTECmd.exe"):
        return shutil.which("MFTECmd.exe")
    if shutil.which("MFTECmd"):
        return shutil.which("MFTECmd")

    # Search known directories
    for path in search_paths:
        candidate = os.path.join(path, "MFTECmd.exe")
        if os.path.isfile(candidate):
            return candidate

    # Recursive search in script directory
    for match in globmod.glob(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "**", "MFTECmd.exe"
    ), recursive=True):
        return match

    return None


def export_event_logs(output_dir):
    """Export Windows event logs using wevtutil."""
    logs = ["Security", "System", "Application"]
    exported = []

    for log_name in logs:
        out_path = os.path.join(output_dir, f"{log_name}.evtx")
        try:
            subprocess.run(
                ["wevtutil", "epl", log_name, out_path, "/ow:true"],
                check=True,
                capture_output=True,
            )
            exported.append(out_path)
            print(f"  [+] Exported {log_name} -> {out_path}")
        except subprocess.CalledProcessError as e:
            print(f"  [!] Failed to export {log_name}: {e}")
        except FileNotFoundError:
            print("  [!] wevtutil not found, cannot export event logs")
            break

    return exported


def extract_mft(output_dir, mftecmd_path=None):
    """Extract and parse MFT. Uses MFTECmd if available, falls back to built-in parser."""
    mftecmd = mftecmd_path or find_mftecmd()

    if mftecmd:
        csv_path = os.path.join(output_dir, "mft_output.csv")
        try:
            print(f"  [*] Using MFTECmd: {mftecmd}")
            result = subprocess.run(
                [mftecmd, "-f", r"C:\$MFT", "--csv", output_dir, "--csvf", "mft_output.csv"],
                capture_output=True,
                text=True,
            )
            if os.path.isfile(csv_path):
                size_mb = os.path.getsize(csv_path) / (1024 * 1024)
                print(f"  [+] MFT extracted -> {csv_path} ({size_mb:.1f} MB)")
                return csv_path
            else:
                print(f"  [!] MFTECmd ran but no CSV produced")
                print(f"  [!] Falling back to built-in MFT parser...")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"  [!] MFTECmd failed: {e}")
            print(f"  [!] Falling back to built-in MFT parser...")

    # Built-in Python MFT parser, no external tools needed
    try:
        from mft_parser import parse_mft
        print("  [*] Using built-in MFT parser (no MFTECmd needed)")
        return parse_mft(output_dir)
    except Exception as e:
        print(f"  [!] Built-in MFT parser failed: {e}")
        return None


def collect(output_dir="collected_artifacts", mftecmd_path=None):
    """Run full artifact collection."""
    if sys.platform != "win32":
        print("[!] Live collection only works on Windows")
        return None, []

    if not is_admin():
        print("[!] Administrator privileges required for live collection")
        print("[!] Right-click terminal -> Run as Administrator")
        return None, []

    os.makedirs(output_dir, exist_ok=True)
    print(f"[*] Collecting artifacts to: {os.path.abspath(output_dir)}")

    # Extract MFT
    print("\n[*] Extracting MFT...")
    mft_csv = extract_mft(output_dir, mftecmd_path)

    # Export event logs
    print("\n[*] Exporting event logs...")
    evtx_files = export_event_logs(output_dir)

    print(f"\n[*] Collection complete")
    print(f"    MFT CSV:    {'OK' if mft_csv else 'FAILED'}")
    print(f"    Event logs:  {len(evtx_files)} exported")

    return mft_csv, evtx_files


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "collected_artifacts"
    mft_csv, evtx_files = collect(output)

    if mft_csv:
        print(f"\n[*] Ready to analyze. Run:")
        print(f"    python main.py {mft_csv} {output}")
