from pathlib import Path
from typing import Dict

# First four bytes of a valid N64 ROM, per byte order. (Mirrors the table in
# core/media_identifier.py, which only detects the order — this module also
# enforces it.)
N64_MAGICS = {
    b'\x80\x37\x12\x40': 'z64_big_endian',
    b'\x37\x80\x40\x12': 'v64_byteswapped',
    b'\x40\x12\x37\x80': 'n64_little_endian_wordswapped',
}


def _to_big_endian(data: bytes, byte_order: str) -> bytes:
    """Normalize a header to z64 (big-endian) byte order.

    v64 swaps each 16-bit pair; .n64 reverses each 32-bit word. Both
    transforms are their own inverse, so the same operation converts back.
    """
    if byte_order == 'z64_big_endian':
        return data
    out = bytearray(len(data))
    if byte_order == 'v64_byteswapped':
        for i in range(0, len(data) - 1, 2):
            out[i] = data[i + 1]
            out[i + 1] = data[i]
        if len(data) % 2:
            out[-1] = data[-1]
        return bytes(out)
    # n64_little_endian_wordswapped: reverse each 32-bit word.
    for i in range(0, len(data) - 3, 4):
        out[i:i + 4] = data[i:i + 4][::-1]
    return bytes(out)


def parse_n64_header(path: str | Path) -> Dict[str, object]:
    data = Path(path).read_bytes()[:0x40]
    if len(data) < 0x40:
        return {'ok': False, 'reason': 'file shorter than N64 header'}
    byte_order = N64_MAGICS.get(data[:4])
    if byte_order is None:
        return {'ok': False, 'reason': 'not an N64 ROM (bad magic)', 'magic': data[:4].hex()}
    # Parse from the big-endian form so the fields are correct regardless of
    # the file's byte order.
    be = _to_big_endian(data, byte_order)
    title = be[0x20:0x34].decode('ascii', errors='ignore').strip('\x00 ').strip()
    return {'ok': True, 'byte_order': byte_order, 'title': title, 'clock_rate_raw': be[0x04:0x08].hex(), 'program_counter_raw': be[0x08:0x0C].hex(), 'release_raw': be[0x0C:0x10].hex(), 'crc1_raw': be[0x10:0x14].hex(), 'crc2_raw': be[0x14:0x18].hex(), 'country_code_raw': be[0x3E:0x3F].hex()}
