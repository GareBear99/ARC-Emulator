from pathlib import Path
from arc_emulator.arc.binary_store import BinaryStore

def test_pack_and_restore(tmp_path: Path):
    src=tmp_path/'sample.bin'; src.write_bytes(b'arc-emulator-test'*100)
    store=BinaryStore(tmp_path/'store')
    manifest=store.pack_file(src, kind='rom_or_disc', chunk_size=32)
    assert manifest['payload_sha256']; assert manifest['merkle_root']
    out=tmp_path/'restored.bin'; manifest_path=store.manifests/f"{manifest['manifest_sha256']}.json"
    result=store.restore_file(manifest_path, out)
    assert result['ok'] is True
    assert out.read_bytes()==src.read_bytes()
