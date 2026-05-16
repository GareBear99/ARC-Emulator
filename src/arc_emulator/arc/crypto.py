from __future__ import annotations
import hashlib
from pathlib import Path
from typing import Iterable, List

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        while True:
            b = f.read(chunk_size)
            if not b: break
            h.update(b)
    return h.hexdigest()

def merkle_root(hex_hashes: Iterable[str]) -> str:
    nodes: List[bytes] = [bytes.fromhex(h) for h in hex_hashes]
    if not nodes: return sha256_bytes(b'')
    while len(nodes) > 1:
        if len(nodes) % 2 == 1: nodes.append(nodes[-1])
        nodes = [hashlib.sha256(nodes[i] + nodes[i+1]).digest() for i in range(0, len(nodes), 2)]
    return nodes[0].hex()
