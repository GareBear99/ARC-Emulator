from pathlib import Path
from arc_emulator.core.session import create_session

def test_create_session(tmp_path: Path):
    s=create_session(tmp_path,'n64','test')
    assert s['system']=='n64'
    assert s['session_id'].startswith('n64-')
