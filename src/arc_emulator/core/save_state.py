from __future__ import annotations
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

from arc_emulator import __version__
from arc_emulator.arc.binary_store import (
    BinaryStore,
    canonical_json_bytes,
    parse_envelope,
    store_root_for_manifest,
)
from arc_emulator.arc.crypto import merkle_root, sha256_bytes
from arc_emulator.arc.receipts import save_state_receipt

# v5 binary manifest required fields (ARC-Apache binary_manifest.schema.json).
REQUIRED_FIELDS = ['version', 'object_id', 'content_class', 'codec', 'envelope_sha256', 'envelope_size_bytes', 'chunk_size', 'chunks', 'merkle_root', 'manifest_sha256']


def create_save_state(store: BinaryStore, session_id: str, system: str, state_file: str | Path, emulator_core_version: str | None = None) -> Dict[str, Any]:
    if emulator_core_version is None:
        # Track the package version so the emitted version can never drift from it.
        emulator_core_version = f'arc-emulator-v{__version__}'
    manifest = store.pack_file(
        state_file,
        content_class='save_state',
        codec='raw',
        extra={'session_id': session_id, 'system': system, 'emulator_core_version': emulator_core_version},
    )
    receipt = store.write_receipt(save_state_receipt(session_id, system, manifest))
    return {'manifest': manifest, 'receipt': receipt}


def verify_save_state(state_manifest_path: str | Path, store_root: str | Path | None = None) -> Dict[str, Any]:
    """Actually verify a save-state manifest against the store.

    Recomputes the manifest hash (v5 null convention), checks every chunk
    object exists in the store and hashes to its recorded value, recomputes
    the envelope hash and the Merkle root from the chunk contents, checks
    the recorded envelope size, and parses the rebuilt envelope (which
    verifies the envelope magic, the footer, and the payload hash inside
    the envelope metadata). Returns {'ok', 'missing', 'checks',
    'failures'}; 'ok' is True only when every check passes. Never raises
    for a bad manifest — a bad manifest is a verification failure,
    reported as data.
    """
    checks: Dict[str, bool] = {}
    failures: List[str] = []

    def fail(name: str, msg: str) -> None:
        checks[name] = False
        failures.append(msg)

    try:
        manifest = json.loads(Path(state_manifest_path).read_text(encoding='utf-8'))
    except FileNotFoundError:
        msg = f'manifest not found: {state_manifest_path}'
        return {'ok': False, 'missing': [], 'checks': {}, 'failures': [msg], 'error': msg}
    except json.JSONDecodeError as exc:
        msg = f'manifest is not valid JSON: {exc}'
        return {'ok': False, 'missing': [], 'checks': {}, 'failures': [msg], 'error': msg}
    if not isinstance(manifest, dict):
        msg = 'manifest is not a JSON object'
        return {'ok': False, 'missing': [], 'checks': {}, 'failures': [msg], 'error': msg}

    missing = [x for x in REQUIRED_FIELDS if x not in manifest]
    checks['required_fields'] = not missing
    if missing:
        failures.append(f"missing fields: {', '.join(missing)}")

    if manifest.get('content_class') != 'save_state':
        fail('content_class_is_save_state', f"content_class is {manifest.get('content_class')!r}, expected 'save_state'")
    else:
        checks['content_class_is_save_state'] = True

    if 'manifest_sha256' in manifest:
        stored = manifest['manifest_sha256']
        unsigned = dict(manifest)
        unsigned['manifest_sha256'] = None
        recomputed = sha256_bytes(canonical_json_bytes(unsigned))
        if recomputed == stored:
            checks['manifest_sha256'] = True
        else:
            fail('manifest_sha256', 'manifest_sha256 does not match the manifest contents (manifest was altered)')
    else:
        fail('manifest_sha256', 'manifest_sha256 missing, cannot check manifest integrity')

    chunks = manifest.get('chunks')
    if not isinstance(chunks, list):
        fail('chunks_list', 'chunks is not a list')
        chunks = []

    root = store_root_for_manifest(state_manifest_path, store_root)
    if root is None:
        fail('store_located', 'could not locate the binary store for this manifest (pass --store)')
        checks['chunks_present'] = False
        checks['envelope_sha256'] = False
        checks['payload_sha256'] = False
        checks['merkle_root'] = False
        checks['envelope_size_bytes'] = False
        checks['envelope_parse'] = False
    else:
        envelope_bytes = bytearray()
        computed_hashes: List[str] = []
        all_present = True
        for i, chunk in enumerate(chunks):
            if not isinstance(chunk, dict) or not chunk.get('sha256'):
                all_present = False
                fail(f'chunk_{i}', f'chunk {i} has no sha256')
                continue
            h = chunk['sha256']
            store_path = chunk.get('store_path')
            if not store_path:
                all_present = False
                fail(f'chunk_{i}_store_path', f'chunk {i} has no store_path')
                continue
            obj = Path(root) / store_path
            if not obj.exists():
                all_present = False
                fail(f'chunk_{i}_present', f'chunk object missing from store: {h}')
                continue
            data = obj.read_bytes()
            actual = sha256_bytes(data)
            if actual != h:
                all_present = False
                fail(f'chunk_{i}_hash', f'chunk {i} content hash mismatch: recorded {h[:12]}..., actual {actual[:12]}...')
            if 'size_bytes' in chunk and chunk['size_bytes'] != len(data):
                all_present = False
                fail(f'chunk_{i}_size', f"chunk {i} size mismatch: manifest says {chunk['size_bytes']}, object is {len(data)}")
            if chunk.get('index') != i:
                all_present = False
                fail(f'chunk_{i}_index', f"chunk {i} index mismatch: manifest says {chunk.get('index')}")
            computed_hashes.append(actual)
            envelope_bytes.extend(data)
        checks['chunks_present'] = all_present
        if all_present:
            envelope = bytes(envelope_bytes)
            if sha256_bytes(envelope) == manifest.get('envelope_sha256'):
                checks['envelope_sha256'] = True
            else:
                fail('envelope_sha256', f"envelope hash mismatch: manifest says {manifest.get('envelope_sha256')}, recomputed {sha256_bytes(envelope)}")
            recomputed_root = merkle_root(computed_hashes)
            if recomputed_root == manifest.get('merkle_root'):
                checks['merkle_root'] = True
            else:
                fail('merkle_root', 'merkle_root does not match the chunk hashes')
            total = sum(c.get('size_bytes', 0) for c in chunks if isinstance(c, dict))
            if manifest.get('envelope_size_bytes') == len(envelope) == total:
                checks['envelope_size_bytes'] = True
            else:
                fail('envelope_size_bytes', f"envelope_size_bytes mismatch: manifest says {manifest.get('envelope_size_bytes')}, rebuilt envelope is {len(envelope)}, chunks total {total}")
            try:
                parsed = parse_envelope(envelope)
                checks['envelope_parse'] = True
                payload = parsed['payload']
                if sha256_bytes(payload) == parsed['metadata'].get('payload_sha256'):
                    checks['payload_sha256'] = True
                else:
                    fail('payload_sha256', f"payload hash mismatch: envelope metadata says {parsed['metadata'].get('payload_sha256')}, recomputed {sha256_bytes(payload)}")
            except Exception as exc:
                fail('envelope_parse', f'envelope parse failed: {exc}')
                fail('payload_sha256', f'payload hash could not be checked: envelope parse failed ({exc})')
        else:
            checks['envelope_sha256'] = False
            failures.append('envelope hash could not be recomputed: one or more chunks missing or corrupt')
            checks['payload_sha256'] = False
            failures.append('payload hash could not be recomputed: one or more chunks missing or corrupt')
            checks['merkle_root'] = False
            failures.append('merkle root could not be recomputed: one or more chunks missing or corrupt')
            checks['envelope_size_bytes'] = False
            failures.append('envelope size could not be checked: one or more chunks missing or corrupt')
            checks['envelope_parse'] = False
            failures.append('envelope could not be parsed: one or more chunks missing or corrupt')

    return {'ok': not failures, 'missing': missing, 'checks': checks, 'failures': failures}
