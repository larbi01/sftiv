import hashlib
from pathlib import Path
from typing import Iterator

# CHUNK_SIZE balances memory and speed for large files (4 MiB).
CHUNK_SIZE = 4 * 1024 * 1024

def _read_in_chunks(path: Path, chunk_size: int = CHUNK_SIZE) -> Iterator[bytes]:
    """
    Stream the file in fixed-size chunks to avoid loading it all into memory.
    This is crucial for large files and prevents memory spikes.
    """
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk

def sha256_file(path_str: str) -> str:
    """
    Compute the SHA-256 digest (hex string) of a file located at `path_str`.

    Why sha256?
    - Widely used, collision-resistant for practical purposes.
    - Fast and available in Python's stdlib (hashlib).

    Returns:
        Hex-encoded string of the digest (64 hex chars).
    """
    path = Path(path_str)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path_str}")

    h = hashlib.sha256()
    for chunk in _read_in_chunks(path):
        h.update(chunk)
    return h.hexdigest()
