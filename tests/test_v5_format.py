"""Pins for the ARC-Apache v5 manifest format, implemented in the
emulator's own code. These tests assert the interop-critical properties:
the v5 manifest-hash convention, the envelope, canonical JSON, the store
layout, and the v5 receipt shape. They do not import ARC-Apache."""
import json
from pathlib import Path

import jsonschema
import pytest

from arc_emulator.arc.binary_store import (
    MAGIC,
    BinaryStore,
    canonical_json_bytes,
    make_envelope,
    parse_envelope,
)
from arc_emulator.arc.crypto import sha256_bytes
from arc_emulator.arc.receipts import rom_pack_receipt

SCHEMAS = Path(__file__).resolve().parents[1] / 'schemas'


def _load_schema(name):
    return json.loads((SCHEMAS / name).read_text(encoding='utf-8'))


def _pack(tmp_path, data=b'v5-format' * 20):
    src = tmp_path / 'data.bin'
    src.write_bytes(data)
    store = BinaryStore(tmp_path / 'store')
    manifest = store.pack_file(src, content_class='rom_or_disc', codec='raw')
    return store, src, manifest


def test_manifest_validates_against_v5_schema(tmp_path):
    _, _, manifest = _pack(tmp_path)
    jsonschema.validate(manifest, _load_schema('rom_manifest.schema.json'))


def test_envelope_roundtrip_and_rejections(tmp_path):
    payload = b'envelope' * 10
    envelope = make_envelope(payload, content_class='generic_blob', codec='raw')
    parsed = parse_envelope(envelope)
    assert parsed['payload'] == payload
    assert parsed['metadata']['version'] == 5
    assert parsed['metadata']['payload_sha256'] == sha256_bytes(payload)
    # Wrong magic is rejected.
    with pytest.raises(ValueError, match='not an ARC-Apache binary envelope'):
        parse_envelope(b'NOTMAGIC' + envelope[len(MAGIC):])
    # A tampered footer is rejected.
    tampered = envelope[:-1] + bytes([envelope[-1] ^ 0xFF])
    with pytest.raises(ValueError, match='footer hash mismatch'):
        parse_envelope(tampered)
    # A truncated envelope is rejected.
    with pytest.raises(ValueError):
        parse_envelope(envelope[:-10])


def test_receipt_v5_shape_and_hash(tmp_path):
    store, _, manifest = _pack(tmp_path)
    receipt = store.write_receipt(rom_pack_receipt('n64', manifest))
    assert receipt['version'] == 5
    assert receipt['receipt_type'] == 'arc_emulator.rom_or_disc.packed'
    assert receipt['manifest_sha256'] == manifest['manifest_sha256']
    assert receipt['envelope_sha256'] == manifest['envelope_sha256']
    assert receipt['signature'] is None
    # The v5 receipt hash covers the receipt with receipt_sha256 AND
    # signature set to null (so a later signature does not change the ID).
    unsigned = dict(receipt)
    unsigned['receipt_sha256'] = None
    unsigned['signature'] = None
    assert sha256_bytes(canonical_json_bytes(unsigned)) == receipt['receipt_sha256']
    # The receipt file is stored under its own hash.
    assert (store.receipts / f"{receipt['receipt_sha256']}.json").exists()


def test_session_receipt_validates_against_schema(tmp_path):
    from arc_emulator.arc.receipts import session_receipt
    store = BinaryStore(tmp_path / 'store')
    receipt = store.write_receipt(session_receipt('n64-abc', 'n64', 'test'))
    assert receipt['version'] == 5
    jsonschema.validate(receipt, _load_schema('session_receipt.schema.json'))
