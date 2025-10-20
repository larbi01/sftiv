import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# --------------------------
# Key management (PEM files)
# --------------------------

def ed25519_keygen(priv_path: str, pub_path: str) -> None:
    """
    Create a new Ed25519 keypair and write:
      - private key (PEM, 0600)
      - public key (PEM, 0644)
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_p = Path(priv_path)
    pub_p = Path(pub_path)

    if priv_p.exists() or pub_p.exists():
        raise FileExistsError("Private or public key path already exists")

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # keep offline; 0600 perms
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # write atomically-ish
    tmp_priv = priv_p.with_suffix(priv_p.suffix + ".tmp")
    tmp_pub = pub_p.with_suffix(pub_p.suffix + ".tmp")
    tmp_priv.write_bytes(priv_bytes)
    tmp_pub.write_bytes(pub_bytes)
    os.replace(tmp_priv, priv_p)
    os.replace(tmp_pub, pub_p)

    os.chmod(priv_p, 0o600)  # owner read/write only
    os.chmod(pub_p, 0o644)   # public key can be world-readable

def _load_private_key(priv_path: str) -> ed25519.Ed25519PrivateKey:
    data = Path(priv_path).read_bytes()
    return serialization.load_pem_private_key(data, password=None)

def _load_public_key(pub_path: str) -> ed25519.Ed25519PublicKey:
    data = Path(pub_path).read_bytes()
    return serialization.load_pem_public_key(data)

# --------------------------
# Sign / verify (detached)
# --------------------------

def sign_bytes(priv_path: str, payload: bytes) -> str:
    """
    Returns signature as base64 string.
    """
    sk = _load_private_key(priv_path)
    sig = sk.sign(payload)
    return base64.b64encode(sig).decode("ascii")

def verify_bytes(pub_path: str, payload: bytes, sig_b64: str) -> bool:
    """
    Verify base64 signature; returns True/False.
    """
    pk = _load_public_key(pub_path)
    try:
        pk.verify(base64.b64decode(sig_b64, validate=True), payload)
        return True
    except Exception:
        return False
