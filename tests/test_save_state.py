import json
from pathlib import Path

import jsonschema
import pytest

from arc_emulator import __version__
from arc_emulator.arc.binary_store import BinaryStore
from arc_emulator.core.save_state import create_save_state

SCHEMAS = Path(__file__).resolve().parents[1] / 'schemas'


def _load_schema(name):
    return json.loads((SCHEMAS / name).read_text(encoding='utf-8'))


def _make_state(tmp_path):
    src = tmp_path / 'state.bin'
    src.write_bytes(b'STATE' * 500)
    store = BinaryStore(tmp_path / 'store')
    out = create_save_state(store, 'n64-test123', 'n64', src)
    return store, out['manifest']


def test_emulator_core_version_matches_package(tmp_path):
    _, manifest = _make_state(tmp_path)
    assert manifest['extra']['emulator_core_version'] == f'arc-emulator-v{__version__}'
    assert manifest['extra']['emulator_core_version'] == 'arc-emulator-v0.1.1'


def test_explicit_version_honored(tmp_path):
    src = tmp_path / 'state.bin'
    src.write_bytes(b'STATE' * 10)
    store = BinaryStore(tmp_path / 'store')
    out = create_save_state(store, 'n64-x', 'n64', src, emulator_core_version='arc-emulator-v9.9.9')
    assert out['manifest']['extra']['emulator_core_version'] == 'arc-emulator-v9.9.9'


def test_manifest_is_v5(tmp_path):
    _, manifest = _make_state(tmp_path)
    assert manifest['version'] == 5
    assert manifest['object_id'].startswith('arcbin:')
    assert manifest['content_class'] == 'save_state'
    assert manifest['codec'] == 'raw'
    assert manifest['extra']['session_id'] == 'n64-test123'
    assert manifest['extra']['system'] == 'n64'


def test_save_state_manifest_validates_against_save_state_schema(tmp_path):
    _, manifest = _make_state(tmp_path)
    jsonschema.validate(manifest, _load_schema('save_state.schema.json'))


def test_save_state_manifest_also_validates_against_rom_manifest_schema(tmp_path):
    # A save-state manifest is still a v5 binary manifest; the generic
    # schema must keep accepting it.
    _, manifest = _make_state(tmp_path)
    jsonschema.validate(manifest, _load_schema('rom_manifest.schema.json'))


def test_save_state_schema_rejects_rom_manifest(tmp_path):
    store = BinaryStore(tmp_path / 'store')
    src = tmp_path / 'game.z64'
    src.write_bytes(b'\x80\x37\x12\x40' + b'\x00' * 100)
    manifest = store.pack_file(src, content_class='rom_or_disc')
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(manifest, _load_schema('save_state.schema.json'))


def test_save_state_schema_rejects_missing_extra(tmp_path):
    _, manifest = _make_state(tmp_path)
    bad = dict(manifest)
    bad['extra'] = {'session_id': 'n64-test123'}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, _load_schema('save_state.schema.json'))
