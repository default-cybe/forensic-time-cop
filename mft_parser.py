"""
Native Python MFT parser for Forensic Time Cop.
Reads raw NTFS $MFT directly from volume, no MFTECmd or .NET needed.
Requires Administrator privileges on Windows.

Produces CSV matching MFTECmd output format so existing analyzers work unchanged.
"""

import struct
import csv
import os
import sys
from datetime import datetime, timezone, timedelta

# NTFS epoch: January 1, 1601
NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_datetime(ft):
    """Convert NTFS FILETIME (100ns intervals since 1601-01-01) to datetime string."""
    if ft == 0 or ft < 0:
        return ""
    try:
        # ft is in 100ns units
        us = ft // 10  # microseconds
        leftover = ft % 10  # remaining 100ns digit
        delta = timedelta(microseconds=us)
        dt = NTFS_EPOCH + delta
        if dt.year < 1970 or dt.year > 2100:
            return ""
        # Format with 7-digit sub-second precision (100ns) like MFTECmd
        return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond:06d}{leftover}"
    except (OverflowError, OSError, ValueError):
        return ""


def _apply_fixup(data, record_size):
    """Apply NTFS fixup array to a record."""
    if len(data) < 48:
        return None
    fixup_offset = struct.unpack_from('<H', data, 0x04)[0]
    fixup_count = struct.unpack_from('<H', data, 0x06)[0]

    if fixup_count < 2 or fixup_offset + fixup_count * 2 > len(data):
        return None

    fixed = bytearray(data)
    for i in range(1, fixup_count):
        pos = i * 512 - 2
        if pos + 2 <= len(fixed) and fixup_offset + i * 2 + 2 <= len(data):
            val = struct.unpack_from('<H', data, fixup_offset + i * 2)[0]
            struct.pack_into('<H', fixed, pos, val)
    return bytes(fixed)


def _parse_data_runs(data, offset, length):
    """Parse NTFS data run list. Returns list of (cluster_offset, cluster_count)."""
    runs = []
    pos = offset
    end = offset + length
    current_lcn = 0

    while pos < end:
        header = data[pos]
        if header == 0:
            break
        pos += 1

        len_size = header & 0x0F
        off_size = (header >> 4) & 0x0F

        if len_size == 0 or pos + len_size + off_size > end:
            break

        # Read run length
        run_len = int.from_bytes(data[pos:pos + len_size], 'little', signed=False)
        pos += len_size

        # Read run offset (signed)
        if off_size > 0:
            run_off = int.from_bytes(data[pos:pos + off_size], 'little', signed=True)
            pos += off_size
            current_lcn += run_off
        else:
            # Sparse run
            current_lcn = 0

        if run_len > 0 and current_lcn > 0:
            runs.append((current_lcn, run_len))

    return runs


def _get_mft_runs(vol, boot):
    """Read MFT record 0 to get data runs for the full MFT file."""
    vol.seek(boot['mft_offset'])
    rec0 = vol.read(boot['record_size'])
    if rec0[:4] != b'FILE':
        return None

    rec0 = _apply_fixup(rec0, boot['record_size'])
    if not rec0:
        return None

    attr_offset = struct.unpack_from('<H', rec0, 0x14)[0]
    offset = attr_offset

    while offset + 8 < len(rec0):
        attr_type = struct.unpack_from('<I', rec0, offset)[0]
        if attr_type == 0xFFFFFFFF:
            break
        attr_len = struct.unpack_from('<I', rec0, offset + 4)[0]
        if attr_len == 0 or offset + attr_len > len(rec0):
            break

        if attr_type == 0x80:  # $DATA
            non_resident = struct.unpack_from('<B', rec0, offset + 8)[0]
            if non_resident:
                run_offset_rel = struct.unpack_from('<H', rec0, offset + 0x20)[0]
                alloc_size = struct.unpack_from('<Q', rec0, offset + 0x28)[0]
                runs = _parse_data_runs(rec0, offset + run_offset_rel,
                                        attr_len - run_offset_rel)
                return runs, alloc_size
        offset += attr_len

    return None


def read_mft(drive_letter='C', progress_cb=None):
    """
    Read all MFT records from raw NTFS volume.
    Returns list of parsed record dicts.
    """
    volume_path = f'\\\\.\\{drive_letter}:'

    with open(volume_path, 'rb') as vol:
        # Read boot sector
        boot_data = vol.read(512)

        if boot_data[3:7] != b'NTFS':
            raise ValueError(f"Volume {drive_letter}: is not NTFS")

        bps = struct.unpack_from('<H', boot_data, 0x0B)[0]
        spc = struct.unpack_from('<B', boot_data, 0x0D)[0]
        mft_cluster = struct.unpack_from('<Q', boot_data, 0x30)[0]
        rec_size_raw = struct.unpack_from('<b', boot_data, 0x40)[0]

        bytes_per_cluster = bps * spc
        mft_offset = mft_cluster * bytes_per_cluster

        if rec_size_raw > 0:
            record_size = rec_size_raw * bytes_per_cluster
        else:
            record_size = 2 ** abs(rec_size_raw)

        boot = {
            'bps': bps, 'spc': spc,
            'bytes_per_cluster': bytes_per_cluster,
            'mft_offset': mft_offset,
            'record_size': record_size,
        }

        print(f"  [*] NTFS volume {drive_letter}:")
        print(f"  [*] Cluster size: {bytes_per_cluster} bytes")
        print(f"  [*] MFT record size: {record_size} bytes")
        print(f"  [*] MFT start: cluster {mft_cluster} (offset {mft_offset})")

        # Get MFT data runs for non-contiguous reading
        run_info = _get_mft_runs(vol, boot)

        records = []
        record_idx = 0

        if run_info:
            runs, alloc_size = run_info
            total_records = alloc_size // record_size
            print(f"  [*] MFT size: ~{alloc_size // (1024*1024)} MB ({total_records} records)")
            print(f"  [*] Data runs: {len(runs)} extents")

            for lcn, count in runs:
                run_start = lcn * bytes_per_cluster
                run_bytes = count * bytes_per_cluster
                vol.seek(run_start)

                bytes_read = 0
                while bytes_read < run_bytes:
                    chunk = vol.read(record_size)
                    if len(chunk) < record_size:
                        break
                    bytes_read += record_size

                    parsed = _parse_record(chunk, record_size, record_idx)
                    if parsed:
                        records.append(parsed)

                    record_idx += 1
                    if record_idx % 100000 == 0:
                        msg = f"  [*] {record_idx} records scanned ({len(records)} active)..."
                        print(msg)
                        if progress_cb:
                            progress_cb(record_idx, len(records))
        else:
            # Fallback: sequential read from MFT start
            print("  [!] Could not parse MFT data runs, reading sequentially")
            vol.seek(mft_offset)
            fail_streak = 0

            while fail_streak < 100:
                chunk = vol.read(record_size)
                if len(chunk) < record_size:
                    break

                if chunk[:4] == b'FILE':
                    parsed = _parse_record(chunk, record_size, record_idx)
                    if parsed:
                        records.append(parsed)
                    fail_streak = 0
                else:
                    fail_streak += 1

                record_idx += 1
                if record_idx % 100000 == 0:
                    print(f"  [*] {record_idx} records scanned ({len(records)} active)...")

        print(f"  [+] Parsed {len(records)} active MFT records")
        return records


def _parse_record(data, record_size, expected_idx):
    """Parse a single MFT record and extract SI/FN timestamps."""
    if data[:4] != b'FILE':
        return None

    data = _apply_fixup(data, record_size)
    if not data:
        return None

    flags = struct.unpack_from('<H', data, 0x16)[0]
    if not (flags & 0x01):  # Not in use
        return None

    sequence = struct.unpack_from('<H', data, 0x10)[0]
    attr_offset = struct.unpack_from('<H', data, 0x14)[0]
    is_directory = bool(flags & 0x02)

    # MFT record number, use from record itself if available (Win10+)
    if len(data) >= 0x30:
        entry_number = struct.unpack_from('<I', data, 0x2C)[0]
    else:
        entry_number = expected_idx

    si_ts = None
    fn_ts = None
    fn_name = ""
    fn_parent = 0

    offset = attr_offset
    while offset + 16 < len(data):
        attr_type = struct.unpack_from('<I', data, offset)[0]
        if attr_type == 0xFFFFFFFF:
            break
        attr_len = struct.unpack_from('<I', data, offset + 4)[0]
        if attr_len < 16 or offset + attr_len > len(data):
            break

        non_resident = struct.unpack_from('<B', data, offset + 8)[0]

        if non_resident == 0:
            content_off = struct.unpack_from('<H', data, offset + 0x14)[0]
            content_size = struct.unpack_from('<I', data, offset + 0x10)[0]
            cs = offset + content_off

            if attr_type == 0x10 and content_size >= 32:  # $STANDARD_INFORMATION
                si_ts = struct.unpack_from('<4Q', data, cs)

            elif attr_type == 0x30 and content_size >= 66:  # $FILE_NAME
                parent_ref = struct.unpack_from('<Q', data, cs)[0] & 0x0000FFFFFFFFFFFF
                ts = struct.unpack_from('<4Q', data, cs + 8)
                name_len = struct.unpack_from('<B', data, cs + 64)[0]
                name_ns = struct.unpack_from('<B', data, cs + 65)[0]

                try:
                    name = data[cs + 66: cs + 66 + name_len * 2].decode('utf-16-le')
                except Exception:
                    name = ""

                # Prefer Win32 or Win32+DOS namespace over DOS-only
                if name_ns != 0x02 or not fn_name:
                    fn_ts = ts
                    fn_name = name
                    fn_parent = parent_ref

        offset += attr_len

    if not si_ts:
        return None

    return {
        'entry': entry_number,
        'sequence': sequence,
        'is_dir': is_directory,
        'name': fn_name,
        'parent_ref': fn_parent,
        'si_created': si_ts[0],
        'si_modified': si_ts[1],
        'si_mft_changed': si_ts[2],
        'si_accessed': si_ts[3],
        'fn_created': fn_ts[0] if fn_ts else 0,
        'fn_modified': fn_ts[1] if fn_ts else 0,
        'fn_mft_changed': fn_ts[2] if fn_ts else 0,
        'fn_accessed': fn_ts[3] if fn_ts else 0,
    }


def build_paths(records):
    """Resolve full parent paths from MFT entry references."""
    by_entry = {r['entry']: r for r in records}

    def resolve(entry_num, depth=0):
        if depth > 30 or entry_num not in by_entry:
            return "."
        r = by_entry[entry_num]
        if r['parent_ref'] == entry_num or r['entry'] == 5:
            return "."
        parent = resolve(r['parent_ref'], depth + 1)
        return f"{parent}\\{r['name']}"

    for r in records:
        r['parent_path'] = resolve(r['parent_ref'])


def export_csv(records, output_path):
    """Export to CSV matching MFTECmd column format."""
    build_paths(records)

    headers = [
        "EntryNumber", "SequenceNumber", "InUse", "ParentPath",
        "FileName", "Extension", "IsDirectory",
        "Created0x10", "Created0x30",
        "LastModified0x10", "LastModified0x30",
        "LastAccess0x10", "LastAccess0x30",
        "LastRecordChange0x10", "LastRecordChange0x30",
    ]

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()

        for r in records:
            name = r['name']
            ext = name.rsplit('.', 1)[1] if '.' in name else ''

            writer.writerow({
                "EntryNumber": r['entry'],
                "SequenceNumber": r['sequence'],
                "InUse": "True",
                "ParentPath": r.get('parent_path', '.'),
                "FileName": name,
                "Extension": ext,
                "IsDirectory": str(r['is_dir']),
                "Created0x10": filetime_to_datetime(r['si_created']),
                "Created0x30": filetime_to_datetime(r['fn_created']),
                "LastModified0x10": filetime_to_datetime(r['si_modified']),
                "LastModified0x30": filetime_to_datetime(r['fn_modified']),
                "LastAccess0x10": filetime_to_datetime(r['si_accessed']),
                "LastAccess0x30": filetime_to_datetime(r['fn_accessed']),
                "LastRecordChange0x10": filetime_to_datetime(r['si_mft_changed']),
                "LastRecordChange0x30": filetime_to_datetime(r['fn_mft_changed']),
            })

    return output_path


def parse_mft(output_dir, drive_letter='C'):
    """Main entry: read raw MFT from volume and export CSV."""
    records = read_mft(drive_letter)
    csv_path = os.path.join(output_dir, "mft_output.csv")
    print(f"  [*] Exporting {len(records)} records to CSV...")
    export_csv(records, csv_path)
    size_mb = os.path.getsize(csv_path) / (1024 * 1024)
    print(f"  [+] MFT CSV -> {csv_path} ({size_mb:.1f} MB)")
    return csv_path


if __name__ == "__main__":
    import ctypes
    if sys.platform != 'win32':
        print("[!] Windows only")
        sys.exit(1)
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[!] Run as Administrator")
        sys.exit(1)

    out = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out, exist_ok=True)
    parse_mft(out)
