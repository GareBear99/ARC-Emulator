from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict

def now_iso() -> str: return datetime.now(timezone.utc).isoformat()

def rom_pack_receipt(system: str, manifest: Dict[str, Any]) -> Dict[str, Any]:
    return {'event_type':'arc_emulator.rom_or_disc.packed','created_at':now_iso(),'system':system,'payload_sha256':manifest['payload_sha256'],'manifest_sha256':manifest['manifest_sha256'],'merkle_root':manifest['merkle_root'],'source_name':manifest.get('source_name'),'size_bytes':manifest.get('size_bytes')}

def session_receipt(session_id: str, system: str, title: str='') -> Dict[str, Any]:
    return {'event_type':'arc_emulator.session.created','created_at':now_iso(),'session_id':session_id,'system':system,'title':title}

def save_state_receipt(session_id: str, system: str, state_manifest: Dict[str, Any]) -> Dict[str, Any]:
    return {'event_type':'arc_emulator.save_state.created','created_at':now_iso(),'session_id':session_id,'system':system,'state_payload_sha256':state_manifest['payload_sha256'],'state_manifest_sha256':state_manifest['manifest_sha256'],'state_merkle_root':state_manifest['merkle_root']}
