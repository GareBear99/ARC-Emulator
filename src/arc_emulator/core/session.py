from __future__ import annotations
import json, uuid
from pathlib import Path
from typing import Dict
from arc_emulator.arc.receipts import now_iso
SUPPORTED_SYSTEMS=['n64','gamecube','ps2','psp']
def create_session(store_root: str | Path, system: str, title: str='') -> Dict[str, str]:
    if system not in SUPPORTED_SYSTEMS: raise ValueError(f'Unsupported system: {system}')
    session_id=f'{system}-{uuid.uuid4().hex[:16]}'
    session={'schema':'arc.emulator.session.v1','session_id':session_id,'system':system,'title':title,'created_at':now_iso()}
    p=Path(store_root)/'sessions'/f'{session_id}.json'; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps(session,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return session
