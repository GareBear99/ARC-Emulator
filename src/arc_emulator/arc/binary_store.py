from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List
from .crypto import sha256_bytes, sha256_file, merkle_root
DEFAULT_CHUNK_SIZE = 1024 * 1024

def canonical_json_bytes(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')

class BinaryStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.objects = self.root / 'objects' / 'sha256'
        self.manifests = self.root / 'manifests'
        self.receipts = self.root / 'receipts'
        self.sessions = self.root / 'sessions'
        for p in [self.objects, self.manifests, self.receipts, self.sessions]:
            p.mkdir(parents=True, exist_ok=True)
    def _object_path(self, hex_hash: str) -> Path:
        return self.objects / hex_hash[:2] / hex_hash[2:4] / f'{hex_hash}.bin'
    def put_bytes(self, data: bytes) -> str:
        h = sha256_bytes(data)
        path = self._object_path(h); path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists(): path.write_bytes(data)
        return h
    def get_bytes(self, hex_hash: str) -> bytes:
        return self._object_path(hex_hash).read_bytes()
    def pack_file(self, path: str | Path, kind: str='generic', chunk_size: int=DEFAULT_CHUNK_SIZE, metadata: Dict[str, Any] | None=None) -> Dict[str, Any]:
        path = Path(path)
        if not path.exists(): raise FileNotFoundError(path)
        chunks=[]; total=0; index=0
        with path.open('rb') as f:
            while True:
                data=f.read(chunk_size)
                if not data: break
                h=self.put_bytes(data); chunks.append({'index':index,'sha256':h,'size':len(data)})
                total += len(data); index += 1
        manifest={'schema':'arc.emulator.binary_manifest.v1','kind':kind,'source_name':path.name,'size_bytes':total,'payload_sha256':sha256_file(path),'chunk_size':chunk_size,'chunk_count':len(chunks),'chunk_hashes':chunks,'merkle_root':merkle_root([c['sha256'] for c in chunks]),'metadata':metadata or {}}
        manifest_hash=sha256_bytes(canonical_json_bytes(manifest)); manifest['manifest_sha256']=manifest_hash
        (self.manifests/f'{manifest_hash}.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n',encoding='utf-8')
        return manifest
    def restore_file(self, manifest_path: str | Path, output_path: str | Path) -> Dict[str, Any]:
        manifest=json.loads(Path(manifest_path).read_text(encoding='utf-8'))
        out=Path(output_path); out.parent.mkdir(parents=True, exist_ok=True)
        with out.open('wb') as f:
            for chunk in manifest['chunk_hashes']: f.write(self.get_bytes(chunk['sha256']))
        restored=sha256_file(out)
        return {'ok':restored==manifest['payload_sha256'],'restored_sha256':restored,'expected_sha256':manifest['payload_sha256']}
    def write_receipt(self, receipt: Dict[str, Any]) -> Dict[str, Any]:
        receipt=dict(receipt); receipt.setdefault('schema','arc.emulator.receipt.v1')
        rh=sha256_bytes(canonical_json_bytes(receipt)); receipt['receipt_sha256']=rh
        (self.receipts/f'{rh}.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n',encoding='utf-8')
        return receipt
