from pathlib import Path

from arc_emulator.systems.n64.header import parse_n64_header


def _canonical_header() -> bytes:
    """A 64-byte big-endian (z64) header with known field values."""
    h = bytearray(0x40)
    h[0x00:0x04] = b'\x80\x37\x12\x40'          # magic, z64 big-endian
    h[0x04:0x08] = bytes.fromhex('0000000f')    # clock rate
    h[0x08:0x0C] = bytes.fromhex('80000000')    # program counter
    h[0x0C:0x10] = bytes.fromhex('00000000')    # release
    h[0x10:0x14] = bytes.fromhex('12345678')    # crc1
    h[0x14:0x18] = bytes.fromhex('9abcdef0')    # crc2
    h[0x20:0x34] = b'TEST GAME' + b' ' * 11     # title, 20 bytes
    h[0x3E] = 0x45                               # country code 'E'
    return bytes(h)


def _swap16(data: bytes) -> bytes:
    out = bytearray(len(data))
    for i in range(0, len(data), 2):
        out[i], out[i + 1] = data[i + 1], data[i]
    return bytes(out)


def _swap32(data: bytes) -> bytes:
    out = bytearray(len(data))
    for i in range(0, len(data), 4):
        out[i:i + 4] = data[i:i + 4][::-1]
    return bytes(out)


EXPECTED = {
    'title': 'TEST GAME',
    'clock_rate_raw': '0000000f',
    'program_counter_raw': '80000000',
    'release_raw': '00000000',
    'crc1_raw': '12345678',
    'crc2_raw': '9abcdef0',
    'country_code_raw': '45',
}


def _check(path, byte_order):
    result = parse_n64_header(path)
    assert result['ok'] is True
    assert result['byte_order'] == byte_order
    for key, value in EXPECTED.items():
        assert result[key] == value, f'{key}: {result[key]!r} != {value!r}'


def test_z64_big_endian(tmp_path):
    p = tmp_path / 'test.z64'
    p.write_bytes(_canonical_header())
    _check(p, 'z64_big_endian')


def test_v64_byteswapped(tmp_path):
    p = tmp_path / 'test.v64'
    p.write_bytes(_swap16(_canonical_header()))
    _check(p, 'v64_byteswapped')


def test_n64_wordswapped(tmp_path):
    p = tmp_path / 'test.n64'
    p.write_bytes(_swap32(_canonical_header()))
    _check(p, 'n64_little_endian_wordswapped')


def test_rejects_bad_magic(tmp_path):
    p = tmp_path / 'junk.z64'
    p.write_bytes(b'NOT AN N64 ROM' * 8)  # 120 bytes, no valid magic
    result = parse_n64_header(p)
    assert result['ok'] is False
    assert 'bad magic' in result['reason']


def test_rejects_bad_magic_all_zeroes(tmp_path):
    p = tmp_path / 'zeroes.z64'
    p.write_bytes(b'\x00' * 0x40)
    result = parse_n64_header(p)
    assert result['ok'] is False


def test_rejects_short_file(tmp_path):
    p = tmp_path / 'short.z64'
    p.write_bytes(b'\x80\x37\x12\x40' + b'\x00' * 10)  # valid magic, too short
    result = parse_n64_header(p)
    assert result['ok'] is False
    assert 'shorter' in result['reason']
