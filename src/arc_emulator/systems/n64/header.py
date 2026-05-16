from pathlib import Path
from typing import Dict

def parse_n64_header(path: str | Path) -> Dict[str, object]:
    data=Path(path).read_bytes()[:0x40]
    if len(data) < 0x40: return {'ok':False,'reason':'file shorter than N64 header'}
    title=data[0x20:0x34].decode('ascii',errors='ignore').strip('\x00 ').strip()
    return {'ok':True,'title':title,'clock_rate_raw':data[0x04:0x08].hex(),'program_counter_raw':data[0x08:0x0C].hex(),'release_raw':data[0x0C:0x10].hex(),'crc1_raw':data[0x10:0x14].hex(),'crc2_raw':data[0x14:0x18].hex(),'country_code_raw':data[0x3E:0x3F].hex()}
