from __future__ import annotations
from typing import Dict
from arc_emulator.arc.receipts import now_iso

def replay_plan(session_id: str, system: str) -> Dict[str, object]:
    return {'schema':'arc.emulator.replay_plan.v1','created_at':now_iso(),'session_id':session_id,'system':system,'input_timeline':[],'checkpoint_policy':{'state_hash_interval_frames':60,'render_hash_interval_frames':60,'audio_hash_interval_frames':60},'notes':['Deterministic replay plan scaffold. Actual emulation cores append input events and checkpoint hashes.']}
def input_event(frame: int, device: str, control: str, value: object) -> Dict[str, object]:
    return {'frame':frame,'device':device,'control':control,'value':value}
