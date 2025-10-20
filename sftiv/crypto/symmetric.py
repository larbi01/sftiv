import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# header JSON contains: version, alg, nonce (base64), orig_name, orig_size

import base64

HEADER_STRUCT = struct.Struct(">I")  # 4-byte big-endian unsigned int
NONCE_SIZE = 12  # 96-bit nonce recommended for AES-GCM
KEY_SIZE = 32    # 256-bit key

@dataclass
class EnvelopeHeader:
    version: int
    alg: str
    nonce_b64: str
    orig_name: str
    orig_size: int

    def to_bytes(self) -> bytes:
        payload = {
            "version": self.version,
            "alg": self.alg,
            "nonce": self.nonce_b64,
            "orig_name": self.orig_name,
            "orig_size": self.orig_size,
        }
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return HEADER_STRUCT.pack(len(body)) + body

    @staticmethod
    def from_bytes(buf: bytes) -> Tuple["EnvelopeHeader", int]:
        # buf starts at the beginning of the envelope
        if len(buf) < HEADER_STRUCT.size:
            raise ValueError("Truncated envelope: missing header length")
        (hdr_len,) = HEADER_STRUCT.unpack_from(buf, 0)
        start = HEADER_STRUCT.size
        end = start + hdr_len
        if len(buf) < end:
            raise ValueError("Truncated envelope: incomplete header")
        raw = buf[start:end]
        data = json.loads(raw.decode("utf-8"))
        hdr = EnvelopeHeader(
            version=int(data["version"]),
            alg=str(data["alg"]),
            nonce_b64=str(data["nonce"]),
            orig_name=str(data.get("orig_name", "")),
            orig_size=int(data["orig_size"]),
        )
        return hdr, end  # return header and offset where ciphertext begins


# --------------------------
# Key management (filesystem)
# --------------------------

def key_generate(key_path: str) -> None:
    """
    Generate a fresh 256-bit key and store it at key_path in base64,
    with restrictive permissions (0600). Existing file will not be overwritten.
    """
    path = Path(key_path)
    if path.exists():
        raise FileExistsError(f"Key file already exists: {key_path}")

    key = os.urandom(KEY_SIZE)  # cryptographically secure RNG
    b64 = base64.b64encode(key)

    # Write atomically where possible
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("wb") as f:
        f.write(b64 + b"\n")
    os.replace(tmp, path)

    # Restrict permissions: owner read/write only
    os.chmod(path, 0o600)


def key_load(key_path: str) -> bytes:
    """
    Load a base64-encoded 256-bit key from disk and return raw bytes.
    """
    path = Path(key_path)
    if not path.is_file():
        raise FileNotFoundError(f"Key file not found: {key_path}")
    data = path.read_bytes().strip()
    key = base64.b64decode(data, validate=True)
    if len(key) != KEY_SIZE:
        raise ValueError("Invalid key size (expected 32 bytes)")
    return key


# --------------------------
# AES-GCM encrypt/decrypt
# --------------------------

def encrypt_file(input_path: str, output_path: str, key_path: str) -> None:
    """
    Read plaintext from input_path, encrypt with AES-256-GCM, write envelope to output_path.
    Envelope layout: [4B header_len][header JSON][ciphertext||tag]
    """
    key = key_load(key_path)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)

    in_p = Path(input_path)
    if not in_p.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    pt = in_p.read_bytes()

    # Associated Data could bind metadata
    aad = None

    ct = aesgcm.encrypt(nonce, pt, aad)  # returns ciphertext || auth_tag

    header = EnvelopeHeader(
        version=1,
        alg="AES-256-GCM",
        nonce_b64=base64.b64encode(nonce).decode("ascii"),
        orig_name=in_p.name,
        orig_size=len(pt),
    )

    out_p = Path(output_path)
    with out_p.open("wb") as f:
        f.write(header.to_bytes())
        f.write(ct)


def decrypt_file(input_path: str, output_path: str, key_path: str) -> None:
    """
    Read envelope from input_path, decrypt with AES-256-GCM, write plaintext to output_path.
    """
    key = key_load(key_path)
    data = Path(input_path).read_bytes()

    header, ct_offset = EnvelopeHeader.from_bytes(data)
    if header.alg != "AES-256-GCM" or header.version != 1:
        raise ValueError("Unsupported envelope format")

    nonce = base64.b64decode(header.nonce_b64, validate=True)
    if len(nonce) != NONCE_SIZE:
        raise ValueError("Invalid nonce length")

    ct = data[ct_offset:]

    aesgcm = AESGCM(key)
    aad = None
    pt = aesgcm.decrypt(nonce, ct, aad)  # verifies auth tag; raises on tamper

    # Optional sanity check
    if len(pt) != header.orig_size:
        raise ValueError("Size mismatch after decryption (possible corruption)")

    Path(output_path).write_bytes(pt)
