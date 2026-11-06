from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from arc_emulator.arc.binary_store import STORE_VERSION, utc_now


def now_iso() -> str:
    # Kept for the emulator's own records (session, replay plan), which are
    # not v5 manifests. v5 manifests and receipts use utc_now().
    return datetime.now(timezone.utc).isoformat()


def rom_pack_receipt(system: str, manifest: Dict[str, Any]) -> Dict[str, Any]:
    """v5 receipt for a packed ROM/disc image."""
    return {
        'version': STORE_VERSION,
        'receipt_type': 'arc_emulator.rom_or_disc.packed',
        'source': manifest.get('source_path'),
        'actor': 'arc-emulator',
        'policy_status': 'accepted',
        'system': system,
        'manifest_sha256': manifest['manifest_sha256'],
        'envelope_sha256': manifest['envelope_sha256'],
        'merkle_root': manifest['merkle_root'],
        'content_class': manifest.get('content_class'),
        'parent_receipts': [],
        'created_utc': utc_now(),
        'signature': None,
    }


def session_receipt(session_id: str, system: str, title: str = '') -> Dict[str, Any]:
    """v5 receipt for a session. Not manifest-bound (no manifest exists
    for a session), so it carries no manifest_sha256/envelope_sha256."""
    return {
        'version': STORE_VERSION,
        'receipt_type': 'arc_emulator.session.created',
        'source': session_id,
        'actor': 'arc-emulator',
        'policy_status': 'accepted',
        'session_id': session_id,
        'system': system,
        'title': title,
        'parent_receipts': [],
        'created_utc': utc_now(),
        'signature': None,
    }


def save_state_receipt(session_id: str, system: str, state_manifest: Dict[str, Any]) -> Dict[str, Any]:
    """v5 receipt for a created save state."""
    return {
        'version': STORE_VERSION,
        'receipt_type': 'arc_emulator.save_state.created',
        'source': state_manifest.get('source_path'),
        'actor': 'arc-emulator',
        'policy_status': 'accepted',
        'session_id': session_id,
        'system': system,
        'manifest_sha256': state_manifest['manifest_sha256'],
        'envelope_sha256': state_manifest['envelope_sha256'],
        'merkle_root': state_manifest['merkle_root'],
        'content_class': state_manifest.get('content_class'),
        'parent_receipts': [],
        'created_utc': utc_now(),
        'signature': None,
    }
