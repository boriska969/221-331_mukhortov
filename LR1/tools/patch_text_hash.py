#!/usr/bin/env python3
"""Post-build step for PassManager.exe (LR1, pt. 5 of the task).

Computes SHA-256 over the .text section of the linked PE image and writes the digest
into the reference constant placed in .rdata after the marker "LR1TEXTHASH:".
The patch touches only the .rdata data bytes; the code in .text is not modified,
so the hash that is stored is exactly the hash that the program computes at run time.

Usage: patch_text_hash.py <path-to-exe>
"""
import hashlib
import struct
import sys
from pathlib import Path

MARKER = b"LR1TEXTHASH:"
HASH_LENGTH = 64


def find_text_section(data: bytearray):
    """Returns (virtual_size, raw_pointer) of the .text section of a PE32+ image."""
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise SystemExit("not a PE image")
    number_of_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    optional_header_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    section_table = e_lfanew + 24 + optional_header_size
    for index in range(number_of_sections):
        offset = section_table + index * 40
        name = bytes(data[offset:offset + 8])
        if name == b".text\0\0\0":
            virtual_size, _virtual_address, _raw_size, raw_pointer = struct.unpack_from(
                "<IIII", data, offset + 8)
            return virtual_size, raw_pointer
    raise SystemExit(".text section not found")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: patch_text_hash.py <exe>")
        return 2
    exe_path = Path(sys.argv[1])
    data = bytearray(exe_path.read_bytes())

    virtual_size, raw_pointer = find_text_section(data)
    text_bytes = bytes(data[raw_pointer:raw_pointer + virtual_size])
    if len(text_bytes) < virtual_size:
        # В памяти недостающие байты секции заполнены нулями.
        text_bytes += b"\0" * (virtual_size - len(text_bytes))
    digest = hashlib.sha256(text_bytes).hexdigest()

    position = data.find(MARKER)
    if position < 0 or data.find(MARKER, position + 1) >= 0:
        raise SystemExit("reference marker must occur exactly once")
    start = position + len(MARKER)
    data[start:start + HASH_LENGTH] = digest.encode("ascii")

    exe_path.write_bytes(bytes(data))
    print(f"patch_text_hash: .text size={virtual_size} sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
