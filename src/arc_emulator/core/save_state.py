from __future__ import annotations
from pathlib import Path
from typing import Any, Dict
from arc_emulator.arc.binary_store import BinaryStore
from arc_emulator.arc.receipts import save_state_receipt

def create_save_state(store: BinaryStore, session_id: str, system: str, state_file: str | Path, emulator_core_version: str='arc-emulator-v0.1.0') -> Dict[str, Any]:
    manifest=store.pack_file(state_file, kind='save_state', metadata={'session_id':session_id,'system':system,'emulator_core_version':emulator_core_version})
    receipt=store.write_receipt(save_state_receipt(session_id, system, manifest))
    return {'manifest':manifest,'receipt':receipt}
def verify_save_state(state_manifest_path: str | Path) -> Dict[str, Any]:
    import json
    manifest=json.loads(Path(state_manifest_path).read_text(encoding='utf-8'))
    required=['payload_sha256','manifest_sha256','merkle_root','chunk_hashes']
    missing=[x for x in required if x not in manifest]
    return {'ok':not missing,'missing':missing}
