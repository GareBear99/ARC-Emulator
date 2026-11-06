import hashlib
import json
import struct
from pathlib import Path

import pytest

from arc_emulator.arc.binary_store import (
    MAGIC,
    BinaryStore,
    canonical_json_bytes,
    parse_envelope,
    rebuild_envelope,
    store_chunk,
)
from arc_emulator.arc.crypto import merkle_root, sha256_bytes
from arc_emulator.core.save_state import create_save_state, verify_save_state


def _resign(manifest):
    """Recompute manifest_sha256 after editing a manifest, so only the
    edited field can fail verification (isolates one check at a time).
    Uses the v5 convention: manifest_sha256 present and null."""
    m = dict(manifest)
    m['manifest_sha256'] = None
    m['manifest_sha256'] = sha256_bytes(canonical_json_bytes(m))
    return m


def _make_state(tmp_path, size=2500, session='n64-test123'):
    src = tmp_path / 'state.bin'
    src.write_bytes(b'STATE' * (size // 5))
    store = BinaryStore(tmp_path / 'store')
    out = create_save_state(store, session, 'n64', src)
    manifest = out['manifest']
    path = store.manifests / f"{manifest['manifest_sha256']}.json"
    return store, src, manifest, path


def _write_tampered(tmp_path, manifest, **changes):
    m = _resign({**manifest, **changes})
    p = tmp_path / 'tampered.json'
    p.write_text(json.dumps(m, indent=2, sort_keys=True))
    return p


def _tamper_envelope_payload(tmp_path, store, manifest):
    """Replace the stored envelope with one whose metadata payload hash is
    wrong, and re-sign the manifest to match. Only the payload check (and
    the envelope parse) should fail."""
    envelope = rebuild_envelope(manifest, store.root)
    parsed = parse_envelope(envelope)
    meta = dict(parsed['metadata'])
    meta['payload_sha256'] = '0' * 64
    mb = canonical_json_bytes(meta)
    payload = parsed['payload']
    tampered = MAGIC + struct.pack('>IQ', len(mb), len(payload)) + mb + payload + hashlib.sha256(payload).digest()
    chunk_size = manifest['chunk_size']
    chunks = []
    chunk_hashes = []
    for idx in range(0, len(tampered), chunk_size):
        chunk = tampered[idx:idx + chunk_size]
        h, rel = store_chunk(store.root, chunk)
        chunk_hashes.append(h)
        chunks.append({'index': len(chunks), 'sha256': h, 'size_bytes': len(chunk), 'store_path': rel})
    m = dict(manifest)
    m['chunks'] = chunks
    m['envelope_sha256'] = sha256_bytes(tampered)
    m['envelope_size_bytes'] = len(tampered)
    m['merkle_root'] = merkle_root(chunk_hashes)
    m = _resign(m)
    p = tmp_path / 'tampered-payload.json'
    p.write_text(json.dumps(m, indent=2, sort_keys=True))
    return p


def test_verify_valid_manifest_passes(tmp_path):
    _, _, _, path = _make_state(tmp_path)
    result = verify_save_state(path)
    assert result['ok'] is True
    assert result['missing'] == []
    assert result['failures'] == []
    assert result['checks']['payload_sha256'] is True
    assert result['checks']['merkle_root'] is True
    assert result['checks']['manifest_sha256'] is True
    assert result['checks']['chunks_present'] is True
    assert result['checks']['envelope_sha256'] is True
    assert result['checks']['envelope_parse'] is True


def test_verify_fails_tampered_envelope_sha256(tmp_path):
    store, _, manifest, _ = _make_state(tmp_path)
    tampered = _write_tampered(tmp_path, manifest, envelope_sha256='0' * 64)
    result = verify_save_state(tampered, store.root)
    assert result['ok'] is False
    assert result['checks']['envelope_sha256'] is False
    # Only the envelope check fails: the manifest itself is still intact
    # and the envelope payload is untouched.
    assert result['checks']['manifest_sha256'] is True
    assert result['checks']['merkle_root'] is True
    assert result['checks']['payload_sha256'] is True
    assert any('envelope hash mismatch' in f for f in result['failures'])


def test_verify_fails_tampered_envelope_payload(tmp_path):
    store, _, manifest, _ = _make_state(tmp_path)
    tampered = _tamper_envelope_payload(tmp_path, store, manifest)
    result = verify_save_state(tampered, store.root)
    assert result['ok'] is False
    assert result['checks']['payload_sha256'] is False
    assert result['checks']['envelope_parse'] is False
    # Everything else still matches: the tampered envelope was re-chunked
    # and the manifest re-signed around it.
    assert result['checks']['manifest_sha256'] is True
    assert result['checks']['envelope_sha256'] is True
    assert result['checks']['merkle_root'] is True
    assert any('payload hash mismatch' in f for f in result['failures'])


def test_verify_fails_deleted_chunk(tmp_path):
    store, _, manifest, path = _make_state(tmp_path)
    chunk = manifest['chunks'][0]
    obj = store.root / chunk['store_path']
    obj.unlink()
    result = verify_save_state(path)
    assert result['ok'] is False
    assert result['checks']['chunks_present'] is False
    assert any('missing from store' in f for f in result['failures'])


def test_verify_fails_tampered_chunk_content(tmp_path):
    store, _, manifest, path = _make_state(tmp_path)
    chunk = manifest['chunks'][0]
    obj = store.root / chunk['store_path']
    data = bytearray(obj.read_bytes())
    data[0] ^= 0xFF
    obj.write_bytes(bytes(data))  # same length, different bytes
    result = verify_save_state(path)
    assert result['ok'] is False
    assert any('content hash mismatch' in f for f in result['failures'])


def test_verify_fails_tampered_merkle_root(tmp_path):
    store, _, manifest, _ = _make_state(tmp_path)
    tampered = _write_tampered(tmp_path, manifest, merkle_root='0' * 64)
    result = verify_save_state(tampered, store.root)
    assert result['ok'] is False
    assert result['checks']['merkle_root'] is False
    assert result['checks']['manifest_sha256'] is True
    assert result['checks']['payload_sha256'] is True


def test_verify_fails_tampered_manifest_hash(tmp_path):
    store, _, manifest, _ = _make_state(tmp_path)
    # Edit a field WITHOUT re-signing: the manifest hash itself must catch it.
    m = dict(manifest)
    m['envelope_size_bytes'] = m['envelope_size_bytes'] + 1
    p = tmp_path / 'badhash.json'
    p.write_text(json.dumps(m, indent=2, sort_keys=True))
    result = verify_save_state(p, store.root)
    assert result['ok'] is False
    assert result['checks']['manifest_sha256'] is False


def test_verify_fails_missing_manifest(tmp_path):
    result = verify_save_state(tmp_path / 'does-not-exist.json')
    assert result['ok'] is False
    assert 'not found' in result['failures'][0]


def test_verify_fails_invalid_json(tmp_path):
    p = tmp_path / 'bad.json'
    p.write_text('{not json')
    result = verify_save_state(p)
    assert result['ok'] is False
    assert 'not valid JSON' in result['failures'][0]


def test_verify_fails_wrong_content_class(tmp_path):
    store = BinaryStore(tmp_path / 'store')
    src = tmp_path / 'game.z64'
    src.write_bytes(b'\x80\x37\x12\x40' + b'\x00' * 100)
    manifest = store.pack_file(src, content_class='rom_or_disc')
    path = store.manifests / f"{manifest['manifest_sha256']}.json"
    result = verify_save_state(path)
    assert result['ok'] is False
    assert result['checks']['content_class_is_save_state'] is False


def test_verify_multi_chunk_save_state(tmp_path):
    # 2.5 MB state file -> the envelope is ~2.5 MB -> 3 x 1 MB chunks
    # (odd count exercises Merkle pairing).
    store, src, manifest, path = _make_state(tmp_path, size=2_500_000)
    assert len(manifest['chunks']) == 3
    assert manifest['merkle_root'] == merkle_root([c['sha256'] for c in manifest['chunks']])
    result = verify_save_state(path)
    assert result['ok'] is True
    # Restore round-trips the whole payload.
    out = tmp_path / 'restored.bin'
    assert store.restore_file(path, out)['ok'] is True
    assert out.read_bytes() == src.read_bytes()


def test_merkle_root_odd_chunk_count(tmp_path):
    # The odd last node is duplicated when pairing, so the root must differ
    # from a naive pairwise hash of the raw list.
    h = [sha256_bytes(bytes([i])) for i in range(7)]
    lvl1 = [sha256_bytes(bytes.fromhex(h[i]) + bytes.fromhex(h[i + 1])) for i in (0, 2, 4)]
    lvl1.append(sha256_bytes(bytes.fromhex(h[6]) + bytes.fromhex(h[6])))
    lvl2 = [sha256_bytes(bytes.fromhex(lvl1[i]) + bytes.fromhex(lvl1[i + 1])) for i in (0, 2)]
    expected = sha256_bytes(bytes.fromhex(lvl2[0]) + bytes.fromhex(lvl2[1]))
    assert merkle_root(h) == expected
    assert merkle_root(h) != hashlib.sha256(
        bytes.fromhex(h[0]) + bytes.fromhex(h[1])
    ).hexdigest()
    # And a packed manifest's merkle root is the root of its chunk hashes.
    store = BinaryStore(tmp_path / 'store')
    src = tmp_path / 'data.bin'
    src.write_bytes(bytes(range(100)))
    manifest = store.pack_file(src, content_class='generic_blob', chunk_size=16)
    assert manifest['merkle_root'] == merkle_root([c['sha256'] for c in manifest['chunks']])


def test_verify_empty_state_file(tmp_path):
    store = BinaryStore(tmp_path / 'store')
    src = tmp_path / 'empty.bin'
    src.write_bytes(b'')
    out = create_save_state(store, 'n64-empty', 'n64', src)
    path = store.manifests / f"{out['manifest']['manifest_sha256']}.json"
    # The envelope is non-empty even for an empty payload: one chunk.
    assert len(out['manifest']['chunks']) == 1
    result = verify_save_state(path)
    assert result['ok'] is True
    restored = tmp_path / 'restored.bin'
    assert store.restore_file(path, restored)['ok'] is True
    assert restored.read_bytes() == b''
