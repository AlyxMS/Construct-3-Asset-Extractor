import struct
import sys
from pathlib import Path

def extract_assets(dat_path, out_dir):
    data = Path(dat_path).read_bytes()

    if data[:4] != b"c3ab":
        raise SystemExit("Not a c3ab file (bad magic)")

    # 8-byte big-endian pointer to the "fdir" directory block
    dir_off = struct.unpack_from(">Q", data, 4)[0]
    if data[dir_off:dir_off + 4] != b"fdir":
        raise SystemExit("'fdir' not found where expected")

    dir_size, file_count = struct.unpack_from(">II", data, dir_off + 8)

    entries_off = dir_off + 0x18          # skip 24-byte fdir header
    data_base = entries_off + dir_size    # file data starts here

    pos = entries_off
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    total = 0
    for i in range(file_count):
        offset, stored_size, real_size = struct.unpack_from(">QQQ", data, pos)
        flags = struct.unpack_from(">I", data, pos + 24)[0]
        name_len = data[pos + 28]

        name_start = pos + 29
        name = data[name_start:name_start + name_len].decode("utf-8")

        pos = name_start + name_len + 8   # skip 8 reserved bytes after name

        file_start = data_base + offset
        file_data = data[file_start:file_start + stored_size]
        total += stored_size

        if flags != 0 or stored_size != real_size:
            print(f"[!] {name}: flags={flags}, stored=0x{stored_size:x}, real=0x{real_size:x}")

        target = out / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(file_data)

        print(f"{i+1}/{file_count} {name}  offset=0x{offset:x}  size=0x{stored_size:x}")

    print()
    print(f"Directory bytes consumed: {pos - entries_off} / dir_size {dir_size}")
    print(f"Data bytes written:       {total} / data region {len(data) - data_base}")
    if pos - entries_off == dir_size and data_base + total == len(data):
        print("Format fully consistent - extraction complete.")
    else:
        print("[!] Sizes don't add up - there may be extra sections to investigate.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python unpack.py assets.dat output_folder")
        sys.exit(1)
    extract_assets(sys.argv[1], sys.argv[2])