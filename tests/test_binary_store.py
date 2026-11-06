import json
from pathlib import Path

from arc_emulator.arc.binary_store import (
    MAGIC,
    BinaryStore,
    canonical_json_bytes,
    make_envelope,
    parse_envelope,
    rebuild_envelope,
)
from arc_emulator.arc.crypto import sha256_bytes


def test_pack_and_restore(tmp_path: Path):
    src = tmp_path / 'sample.bin'
    src.write_bytes(b'arc-emulator-test' * 100)
    store = BinaryStore(tmp_path / 'store')
    manifest = store.pack_file(src, content_class='rom_or_disc', chunk_size=32)
    assert manifest['version'] == 5
    assert manifest['object_id'].startswith('arcbin:')
    assert manifest['content_class'] == 'rom_or_disc'
    assert manifest['codec'] == 'raw'
    assert manifest['envelope_sha256']
    assert manifest['merkle_root']
    assert manifest['chunks']
    assert all('store_path' in c for c in manifest['chunks'])
    out = tmp_path / 'restored.bin'
    manifest_path = store.manifests / f"{manifest['manifest_sha256']}.json"
    result = store.restore_file(manifest_path, out)
    assert result['ok'] is True
    assert result['restored_sha256'] == result['expected_sha256']
    assert out.read_bytes() == src.read_bytes()


def test_pack_envelope_roundtrip(tmp_path: Path):
    # The payload is wrapped in an ARC_APACHE_BIN envelope and the
    # ENVELOPE (not the raw payload) is chunked.
    src = tmp_path / 'sample.bin'
    src.write_bytes(b'envelope-test' * 10)
    store = BinaryStore(tmp_path / 'store')
    manifest = store.pack_file(src, content_class='rom_or_disc')
    envelope = rebuild_envelope(manifest, store.root)
    assert envelope.startswith(MAGIC)
    assert len(envelope) == manifest['envelope_size_bytes']
    assert sha256_bytes(envelope) == manifest['envelope_sha256']
    parsed = parse_envelope(envelope)
    assert parsed['payload'] == src.read_bytes()
    assert parsed['metadata']['content_class'] == 'rom_or_disc'
    assert parsed['metadata']['codec'] == 'raw'
    assert parsed['metadata']['payload_sha256'] == sha256_bytes(src.read_bytes())


def test_manifest_hash_v5_convention(tmp_path: Path):
    # The v5 manifest hash is computed with manifest_sha256 present and
    # null. The v1 convention (hash with the key removed) must NOT match.
    src = tmp_path / 'sample.bin'
    src.write_bytes(b'hash-convention' * 10)
    store = BinaryStore(tmp_path / 'store')
    manifest = store.pack_file(src, content_class='generic_blob')
    unsigned_v5 = dict(manifest)
    unsigned_v5['manifest_sha256'] = None
    assert sha256_bytes(canonical_json_bytes(unsigned_v5)) == manifest['manifest_sha256']
    unsigned_v1 = {k: v for k, v in manifest.items() if k != 'manifest_sha256'}
    assert sha256_bytes(canonical_json_bytes(unsigned_v1)) != manifest['manifest_sha256']


def test_canonical_json_ensure_ascii_false(tmp_path: Path):
    # v5 canonical JSON is UTF-8 as-is (ensure_ascii=False). A non-ASCII
    # source path must hash the raw UTF-8 bytes, not \uXXXX escapes.
    obj = {'source_path': '/tmp/café.z64', 'version': 5}
    raw = canonical_json_bytes(obj)
    assert 'café'.encode('utf-8') in raw
    assert b'\\u' not in raw
    assert raw == json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def test_store_layout_v5(tmp_path: Path):
    store = BinaryStore(tmp_path / 'store')
    store_json = json.loads((store.root / 'STORE.json').read_text(encoding='utf-8'))
    assert store_json['store_version'] == 5
    for rel in ['objects/sha256', 'manifests', 'receipts', 'sessions', 'streams', 'bundles', 'indexes', 'tmp']:
        assert (store.root / rel).is_dir()


def test_pack_empty_file(tmp_path: Path):
    # An empty payload still produces a non-empty envelope, so there is
    # always at least one chunk. (v1 produced zero chunks.)
    src = tmp_path / 'empty.bin'
    src.write_bytes(b'')
    store = BinaryStore(tmp_path / 'store')
    manifest = store.pack_file(src, content_class='generic_blob')
    assert len(manifest['chunks']) == 1
    out = tmp_path / 'restored.bin'
    manifest_path = store.manifests / f"{manifest['manifest_sha256']}.json"
    result = store.restore_file(manifest_path, out)
    assert result['ok'] is True
    assert out.read_bytes() == b''
