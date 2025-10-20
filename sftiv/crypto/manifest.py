from __future__ import annotations
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from sftiv.crypto.hashing import sha256_file

@dataclass
class Sha256Manifest:
    version: int
    filename: str
    size: int
    sha256: str
    created_at: int  # unix epoch seconds
    comment: Optional[str] = None

    def to_json_bytes(self) -> bytes:
        return json.dumps(asdict(self), separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @staticmethod
    def from_json_bytes(data: bytes) -> "Sha256Manifest":
        obj = json.loads(data.decode("utf-8"))
        return Sha256Manifest(
            version=int(obj["version"]),
            filename=str(obj["filename"]),
            size=int(obj["size"]),
            sha256=str(obj["sha256"]),
            created_at=int(obj["created_at"]),
            comment=obj.get("comment"),
        )

def create_manifest(input_path: str, comment: Optional[str] = None) -> Sha256Manifest:
    p = Path(input_path)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {input_path}")
    digest = sha256_file(str(p))
    return Sha256Manifest(
        version=1,
        filename=p.name,
        size=p.stat().st_size,
        sha256=digest,
        created_at=int(time.time()),
        comment=comment
    )

def write_manifest(manifest: Sha256Manifest, output_path: str) -> None:
    Path(output_path).write_bytes(manifest.to_json_bytes())

def read_manifest(path: str) -> Sha256Manifest:
    data = Path(path).read_bytes()
    return Sha256Manifest.from_json_bytes(data)
