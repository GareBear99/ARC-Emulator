import json
from pathlib import Path

from arc_emulator.arc.binary_store import BinaryStore
from arc_emulator.cli import main
from arc_emulator.core.save_state import create_save_state


def _run(argv, capsys):
    main(argv)
    return json.loads(capsys.readouterr().out)


def _make_state(tmp_path):
    src = tmp_path / 'state.bin'
    src.write_bytes(b'STATE' * 500)
    store = BinaryStore(tmp_path / 'store')
    out = create_save_state(store, 'n64-test123', 'n64', src)
    manifest_path = store.manifests / f"{out['manifest']['manifest_sha256']}.json"
    return store, src, out['manifest'], manifest_path


def test_cli_restore_roundtrip(tmp_path, capsys):
    _, src, _, manifest_path = _make_state(tmp_path)
    dest = tmp_path / 'restored.bin'
    result = _run(['restore', str(manifest_path), str(dest)], capsys)
    assert result['ok'] is True
    assert result['restored_sha256'] == result['expected_sha256']
    assert dest.read_bytes() == src.read_bytes()


def test_cli_restore_with_explicit_store(tmp_path, capsys):
    # Manifest copied outside the store: --store must locate the chunks.
    _, src, _, manifest_path = _make_state(tmp_path)
    copy = tmp_path / 'copy.json'
    copy.write_text(manifest_path.read_text(encoding='utf-8'))
    dest = tmp_path / 'restored.bin'
    result = _run(['restore', str(copy), str(dest), '--store', str(tmp_path / 'store')], capsys)
    assert result['ok'] is True
    assert dest.read_bytes() == src.read_bytes()


def test_cli_restore_missing_manifest(tmp_path, capsys):
    result = _run(['restore', str(tmp_path / 'nope.json'), str(tmp_path / 'out.bin')], capsys)
    assert result['ok'] is False
    assert 'not found' in result['error']


def test_cli_restore_missing_chunk(tmp_path, capsys):
    store, _, manifest, manifest_path = _make_state(tmp_path)
    chunk = manifest['chunks'][0]
    obj = store.root / chunk['store_path']
    obj.unlink()
    result = _run(['restore', str(manifest_path), str(tmp_path / 'out.bin')], capsys)
    assert result['ok'] is False
    assert 'missing chunk' in result['error']


def test_cli_verify_missing_manifest(tmp_path, capsys):
    result = _run(['verify-state', str(tmp_path / 'nope.json')], capsys)
    assert result['ok'] is False
    assert 'not found' in result['failures'][0]


def test_cli_verify_tampered_envelope(tmp_path, capsys):
    store, _, manifest, _ = _make_state(tmp_path)
    tampered = dict(manifest)
    tampered['envelope_sha256'] = '0' * 64
    p = tmp_path / 'tampered.json'
    p.write_text(json.dumps(tampered))
    result = _run(['verify-state', str(p), '--store', str(store.root)], capsys)
    assert result['ok'] is False
    assert result['checks']['envelope_sha256'] is False


def test_cli_identify_rejects_bad_magic(tmp_path, capsys):
    p = tmp_path / 'junk.z64'
    p.write_bytes(b'NOT AN N64 ROM' * 8)
    result = _run(['identify', str(p)], capsys)
    assert result['n64_header']['ok'] is False
    assert 'bad magic' in result['n64_header']['reason']


def test_cli_identify_valid_header(tmp_path, capsys):
    from tests.test_n64_header import _canonical_header
    p = tmp_path / 'test.z64'
    p.write_bytes(_canonical_header())
    result = _run(['identify', str(p)], capsys)
    assert result['n64_header']['ok'] is True
    assert result['n64_header']['title'] == 'TEST GAME'
    assert result['n64_header']['byte_order'] == 'z64_big_endian'
