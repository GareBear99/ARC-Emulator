from __future__ import annotations

import hashlib
import json
import os
import struct
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .crypto import merkle_root, sha256_bytes, sha256_file

# ARC-Apache v5 binary-first store.
#
# The emulator implements the v5 manifest format in its own code. No
# ARC-Apache code is imported and there is no dependency on ARC-Apache.
# Format reference (read-only): ARC-Apache arc_apache/cli.py (VERSION = 5)
# and schemas/binary_manifest.schema.json.
#
# v5 essentials, all pinned by tests:
#   * every payload is wrapped in an ARC_APACHE_BIN envelope (magic +
#     metadata + payload + footer) and the ENVELOPE is chunked, not the
#     raw payload;
#   * manifest fields are version/object_id/content_class/codec/
#     envelope_sha256/envelope_size_bytes/chunk_size/chunks/merkle_root/
#     source_path/parents/created_utc/manifest_sha256 (+ optional
#     extra/encryption);
#   * the manifest hash is computed over the manifest with
#     manifest_sha256 set to null (NOT with the key removed) — the v1
#     convention (key removed) produces a different hash and will not
#     verify against ARC-Apache;
#   * canonical JSON uses ensure_ascii=False;
#   * chunk entries are {index, sha256, size_bytes, store_path}.

MAGIC = b"ARC_APACHE_BIN\0"
STORE_VERSION = 5
DEFAULT_CHUNK_SIZE = 1024 * 1024


def utc_now() -> str:
    """v5 timestamp: ISO 8601 UTC, no microseconds."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def canonical_json_bytes(obj: Any) -> bytes:
    # v5 canonical JSON: sorted keys, compact separators, UTF-8 as-is.
    # This MUST match ARC-Apache's canonical form or manifest/receipt
    # hashes will not interoperate.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(delete=False, dir=str(path.parent)) as f:
        tmp = Path(f.name)
        f.write(data)
    os.replace(tmp, path)


def write_json(path: Path, obj: Any) -> None:
    atomic_write(path, (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def ensure_store(store: str | Path) -> Path:
    """Create the v5 store layout (plus the emulator's sessions/ dir)."""
    store = Path(store)
    for rel in ["objects/sha256", "manifests", "receipts", "keys/public", "keys/private", "streams", "bundles", "indexes", "tmp"]:
        (store / rel).mkdir(parents=True, exist_ok=True)
    meta = store / "STORE.json"
    if not meta.exists():
        write_json(meta, {"store_version": STORE_VERSION, "created_utc": utc_now(), "doctrine": "binary-first cryptographic ARC memory store"})
    return store


def make_envelope(payload: bytes, *, content_class: str, codec: str, encryption: Dict[str, Any] | None = None) -> bytes:
    meta = {"version": STORE_VERSION, "content_class": content_class, "codec": codec, "encryption": encryption, "payload_sha256": sha256_bytes(payload)}
    mb = canonical_json_bytes(meta)
    # MAGIC + metadata length + payload length + metadata + payload + footer(payload hash bytes)
    return MAGIC + struct.pack(">IQ", len(mb), len(payload)) + mb + payload + hashlib.sha256(payload).digest()


def parse_envelope(envelope: bytes) -> Dict[str, Any]:
    if not envelope.startswith(MAGIC):
        raise ValueError("not an ARC-Apache binary envelope")
    off = len(MAGIC)
    meta_len, payload_len = struct.unpack(">IQ", envelope[off:off + 12])
    off += 12
    meta = json.loads(envelope[off:off + meta_len].decode("utf-8"))
    off += meta_len
    payload = envelope[off:off + payload_len]
    off += payload_len
    footer = envelope[off:off + 32]
    if len(footer) != 32:
        raise ValueError("missing envelope footer")
    if hashlib.sha256(payload).digest() != footer:
        raise ValueError("envelope footer hash mismatch")
    if meta.get("payload_sha256") != sha256_bytes(payload):
        raise ValueError("metadata payload hash mismatch")
    return {"metadata": meta, "payload": payload}


def store_chunk(store: str | Path, chunk: bytes) -> Tuple[str, str]:
    h = sha256_bytes(chunk)
    rel = Path("objects") / "sha256" / h[:2] / h[2:4] / f"{h}.bin"
    out = Path(store) / rel
    if not out.exists():
        atomic_write(out, chunk)
    return h, str(rel)


def pack_bytes(data: bytes, *, store: str | Path, content_class: str, codec: str, source_path: str | None, chunk_size: int, parents: List[str] | None = None, extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Pack raw bytes into the v5 store. Returns the v5 manifest."""
    store = ensure_store(store)
    envelope = make_envelope(data, content_class=content_class, codec=codec)
    payload_hash = sha256_bytes(envelope)
    chunks: List[Dict[str, Any]] = []
    chunk_hashes: List[str] = []
    for idx in range(0, len(envelope), chunk_size):
        chunk = envelope[idx:idx + chunk_size]
        h, rel = store_chunk(store, chunk)
        chunk_hashes.append(h)
        chunks.append({"index": len(chunks), "sha256": h, "size_bytes": len(chunk), "store_path": rel})
    manifest: Dict[str, Any] = {
        "version": STORE_VERSION,
        "object_id": f"arcbin:{payload_hash}",
        "content_class": content_class,
        "codec": codec,
        "envelope_sha256": payload_hash,
        "envelope_size_bytes": len(envelope),
        "chunk_size": chunk_size,
        "chunks": chunks,
        "merkle_root": merkle_root(chunk_hashes),
        "source_path": source_path,
        "parents": parents or [],
        "created_utc": utc_now(),
    }
    if extra:
        manifest["extra"] = extra
    # v5 manifest-hash convention: hash the manifest with manifest_sha256
    # present and null. (v1 hashed with the key removed — different hash.)
    unsigned = dict(manifest)
    unsigned["manifest_sha256"] = None
    manifest["manifest_sha256"] = sha256_bytes(canonical_json_bytes(unsigned))
    write_json(store / "manifests" / f"{manifest['manifest_sha256']}.json", manifest)
    return manifest


def rebuild_envelope(manifest: Dict[str, Any], store: str | Path) -> bytes:
    store = Path(store)
    return b"".join((store / ch["store_path"]).read_bytes() for ch in sorted(manifest["chunks"], key=lambda x: x["index"]))


def verify_manifest(manifest: Dict[str, Any], store: str | Path) -> Tuple[bool, List[str]]:
    """ARC-Apache-compatible manifest verification.

    Checks every chunk object (exists, hashes, sizes), the envelope hash,
    the Merkle root, the manifest hash (v5 null convention), and that the
    rebuilt bytes parse as a v5 envelope.
    """
    errors: List[str] = []
    store = Path(store)
    rebuilt = bytearray()
    chunk_hashes: List[str] = []
    for ch in sorted(manifest.get("chunks", []), key=lambda x: x["index"]):
        p = store / ch["store_path"]
        if not p.exists():
            errors.append(f"missing chunk: {p}")
            continue
        data = p.read_bytes()
        h = sha256_bytes(data)
        chunk_hashes.append(h)
        rebuilt.extend(data)
        if h != ch["sha256"]:
            errors.append(f"chunk sha256 mismatch: {p}")
        if len(data) != ch["size_bytes"]:
            errors.append(f"chunk size mismatch: {p}")
    if sha256_bytes(bytes(rebuilt)) != manifest.get("envelope_sha256"):
        errors.append("envelope_sha256 mismatch")
    if merkle_root(chunk_hashes) != manifest.get("merkle_root"):
        errors.append("merkle_root mismatch")
    expected = manifest.get("manifest_sha256")
    unsigned = dict(manifest)
    unsigned["manifest_sha256"] = None
    actual = sha256_bytes(canonical_json_bytes(unsigned))
    if actual != expected:
        errors.append("manifest_sha256 mismatch")
    try:
        parse_envelope(bytes(rebuilt))
    except Exception as e:
        errors.append(f"envelope parse failed: {e}")
    return not errors, errors


def store_root_for_manifest(manifest_path: str | Path, explicit: str | Path | None = None) -> Path | None:
    """Locate the binary store a manifest belongs to.

    Manifests live at <store>/manifests/<hash>.json, so the store root is
    normally the manifests directory's parent. An explicit root wins; a
    manifest copied elsewhere needs --store (or a sibling objects/ dir).
    Returns None when the store cannot be located.
    """
    if explicit:
        return Path(explicit)
    p = Path(manifest_path)
    if p.parent.name == 'manifests':
        return p.parent.parent
    if (p.parent / 'objects').is_dir():
        return p.parent
    return None


class BinaryStore:
    def __init__(self, root: str | Path):
        self.root = ensure_store(Path(root))
        self.objects = self.root / 'objects' / 'sha256'
        self.manifests = self.root / 'manifests'
        self.receipts = self.root / 'receipts'
        self.sessions = self.root / 'sessions'
        self.sessions.mkdir(parents=True, exist_ok=True)

    def _object_path(self, hex_hash: str) -> Path:
        return self.objects / hex_hash[:2] / hex_hash[2:4] / f'{hex_hash}.bin'

    def put_bytes(self, data: bytes) -> str:
        h = sha256_bytes(data)
        path = self._object_path(h)
        if not path.exists():
            atomic_write(path, data)
        return h

    def get_bytes(self, hex_hash: str) -> bytes:
        return self._object_path(hex_hash).read_bytes()

    def pack_file(self, path: str | Path, content_class: str = 'generic_blob', codec: str = 'raw', chunk_size: int = DEFAULT_CHUNK_SIZE, extra: Dict[str, Any] | None = None, source_path: str | None = None, parents: List[str] | None = None) -> Dict[str, Any]:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(path)
        data = path.read_bytes()
        return pack_bytes(data, store=self.root, content_class=content_class, codec=codec, source_path=source_path if source_path is not None else str(path), chunk_size=chunk_size, parents=parents, extra=extra)

    def restore_file(self, manifest_path: str | Path, output_path: str | Path) -> Dict[str, Any]:
        try:
            manifest = json.loads(Path(manifest_path).read_text(encoding='utf-8'))
        except FileNotFoundError:
            return {'ok': False, 'error': f'manifest not found: {manifest_path}'}
        except json.JSONDecodeError as exc:
            return {'ok': False, 'error': f'manifest is not valid JSON: {exc}'}
        if not isinstance(manifest, dict) or not isinstance(manifest.get('chunks'), list):
            return {'ok': False, 'error': 'manifest has no chunks list'}
        ok, errors = verify_manifest(manifest, self.root)
        if not ok:
            return {'ok': False, 'error': 'manifest verification failed: ' + '; '.join(errors)}
        try:
            parsed = parse_envelope(rebuild_envelope(manifest, self.root))
        except Exception as exc:
            return {'ok': False, 'error': f'envelope parse failed: {exc}'}
        payload = parsed['payload']
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(out, payload)
        restored = sha256_bytes(payload)
        return {'ok': restored == parsed['metadata'].get('payload_sha256'), 'restored_sha256': restored, 'expected_sha256': parsed['metadata'].get('payload_sha256')}

    def write_receipt(self, receipt: Dict[str, Any]) -> Dict[str, Any]:
        # v5 receipt identity: the hash covers the receipt with both
        # receipt_sha256 and signature set to null, so a receipt can be
        # (counter)signed later without changing its ID.
        receipt = dict(receipt)
        receipt.setdefault('version', STORE_VERSION)
        receipt.setdefault('signature', None)
        unsigned = dict(receipt)
        unsigned['receipt_sha256'] = None
        unsigned['signature'] = None
        receipt['receipt_sha256'] = sha256_bytes(canonical_json_bytes(unsigned))
        write_json(self.receipts / f"{receipt['receipt_sha256']}.json", receipt)
        return receipt
