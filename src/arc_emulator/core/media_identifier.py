from __future__ import annotations
from pathlib import Path
from typing import Dict
N64_EXTS={'.z64','.n64','.v64'}; GAMECUBE_EXTS={'.iso','.gcm','.rvz','.ciso'}; PS2_EXTS={'.iso','.bin','.img','.chd'}; PSP_EXTS={'.iso','.cso','.pbp'}
def identify_media(path: str | Path) -> Dict[str, object]:
    p=Path(path); suffix=p.suffix.lower(); size=p.stat().st_size if p.exists() else None
    candidates=[]
    if suffix in N64_EXTS: candidates.append('n64')
    if suffix in GAMECUBE_EXTS: candidates.append('gamecube')
    if suffix in PS2_EXTS: candidates.append('ps2')
    if suffix in PSP_EXTS: candidates.append('psp')
    n64_byte_order=None
    if p.exists() and suffix in N64_EXTS:
        head=p.read_bytes()[:4]
        table={b'\x80\x37\x12\x40':'z64_big_endian', b'\x37\x80\x40\x12':'v64_byteswapped', b'\x40\x12\x37\x80':'n64_little_endian_wordswapped'}
        n64_byte_order=table.get(head,'unknown')
    return {'path':str(p),'name':p.name,'extension':suffix,'size_bytes':size,'system_candidates':candidates or ['unknown'],'n64_byte_order':n64_byte_order}
