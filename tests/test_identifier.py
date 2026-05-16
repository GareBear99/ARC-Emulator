from pathlib import Path
from arc_emulator.core.media_identifier import identify_media

def test_identify_n64(tmp_path: Path):
    p=tmp_path/'test.z64'; p.write_bytes(b'\x80\x37\x12\x40' + b'\x00'*100)
    info=identify_media(p)
    assert 'n64' in info['system_candidates']
    assert info['n64_byte_order']=='z64_big_endian'
