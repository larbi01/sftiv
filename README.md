# SFTIV — Secure File Transfer & Integrity Verification (Python, WSL Ubuntu)

**SFTIV** is a minimal, real-world cybersecurity project that demonstrates:
- **Confidentiality:** AES-256-GCM encryption (symmetric key)
- **Integrity:** SHA-256 manifests (+ GCM tag during decrypt)
- **Authenticity:** Ed25519 signature over the manifest

> Tech: Python 3.10+, `cryptography`, `hashlib`, `socket`, `argparse` — no paid tools.

---

## ✨ What this shows (CIA triad)

- **Confidentiality:** plaintext is encrypted locally with AES-GCM; only key holders can decrypt.
- **Integrity:** tampering with the ciphertext fails GCM tag verification; plaintext integrity is verifiable with SHA-256.
- **Authenticity:** the sender signs the manifest (hash/size/filename) using Ed25519; the receiver verifies it with the public key.

---

## 🏗️ Architecture

Sender (Client) Receiver (Server)

plaintext ──sha256──┐
├─ manifest.json ──(sign with Ed25519)───────┐
plaintext ──AES-GCM──► envelope.enc ──TCP (length-prefixed)──► │
save to disk
decrypt with key
sha256(plaintext_out)
verify manifest
verify signature

**Transport wire format (simple & robust):**
1. **Header frame:** JSON → `{"version":1,"type":"envelope","size":...,"suggested_name":"..."}`  
2. **Data frame:** raw encrypted envelope bytes.  
Each frame is prefixed with an 8-byte big-endian length.

---

## 📁 Project structure

sftiv/
sftiv/
crypto/
hashing.py # SHA-256 (streaming)
symmetric.py # AES-256-GCM + self-describing envelope header
manifest.py # JSON manifest (version, file, size, sha256, timestamp)
signing.py # Ed25519 PEM keypair + sign/verify (base64 detached)
net/
framing.py # length-prefixed frames (8-byte big-endian)
server.py # TCP server: receive & store encrypted envelope
client.py # TCP client: send encrypted envelope
cli.py # unified CLI subcommands
tests/
run_e2e.py # minimal end-to-end happy path
samples/ # demo inputs/outputs (keys are gitignored for safety)
requirements.txt
README.md

---

## 🧰 Setup (WSL Ubuntu)

# 0) Open WSL Ubuntu
cd ~/

# 1) Python toolchain
sudo apt update && sudo apt -y install python3 python3-venv python3-pip

# 2) Clone and prepare venv
cd ~/projects
git clone https://github.com/larbi01/sftiv.git
cd sftiv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt  # or: pip install cryptography
If you didn’t commit requirements.txt, run pip install cryptography and then pip freeze > requirements.txt.

🚀 Quick start (local demo)

# 1) Generate AES key (base64, perms 0600)
python -m sftiv.cli keygen -o sftiv/samples/aes.key

# 2) Prepare a plaintext and encrypt
echo "hello secure world" > sftiv/samples/hello.txt
python -m sftiv.cli encrypt -k sftiv/samples/aes.key -i sftiv/samples/hello.txt -o sftiv/samples/hello.enc

# 3) Run the server (Terminal A)
python -m sftiv.cli server --bind 127.0.0.1 --port 5001 --outdir sftiv/samples/inbox

# 4) Send the encrypted envelope (Terminal B)
python -m sftiv.cli send --host 127.0.0.1 --port 5001 --file sftiv/samples/hello.enc --name hello.enc

# 5) Decrypt the received file
# replace <timestamp> with the file the server wrote (it prints it)
python -m sftiv.cli decrypt -k sftiv/samples/aes.key \
  -i sftiv/samples/inbox/<timestamp>_hello.enc \
  -o sftiv/samples/hello.out.txt

# 6) Integrity manifest + signature
python -m sftiv.cli manifest -i sftiv/samples/hello.txt -o sftiv/samples/hello.txt.sha256.json -m "demo"
python -m sftiv.cli sigkeygen --priv sftiv/samples/ed25519_priv.pem --pub sftiv/samples/ed25519_pub.pem
python -m sftiv.cli sign-manifest -p sftiv/samples/ed25519_priv.pem -m sftiv/samples/hello.txt.sha256.json -o sftiv/samples/hello.txt.sha256.json.sig

# Verify integrity & authenticity on the receiver side
python -m sftiv.cli verify -m sftiv/samples/hello.txt.sha256.json -f sftiv/samples/hello.out.txt
python -m sftiv.cli verify-signature --pub sftiv/samples/ed25519_pub.pem -m sftiv/samples/hello.txt.sha256.json -s sftiv/samples/hello.txt.sha256.json.sig
Expected outputs:

verify: [OK] Integrity verified …

verify-signature: [OK] Signature is VALID …

🔍 Negative tests (show security in action)
Tamper ciphertext → decrypt fails (GCM tag):

cp sftiv/samples/hello.enc sftiv/samples/hello.tampered.enc
python - <<'PY'
from pathlib import Path
p = Path("sftiv/samples/hello.tampered.enc")
b = bytearray(p.read_bytes()); b[-8] ^= 0xFF; p.write_bytes(bytes(b))
PY
python -m sftiv.cli decrypt -k sftiv/samples/aes.key -i sftiv/samples/hello.tampered.enc -o /tmp/x || true
Wrong AES key → decrypt fails.

Tamper manifest’s sha256 → signature invalid.

Truncate envelope → decrypt fails.

🔐 Security notes
Key hygiene: store AES keys with 0600 perms; rotate per policy.

Nonce safety: AES-GCM uses a fresh 96-bit random nonce per encryption; never reuse (key, nonce).

Manifest signing: we sign the parsed JSON (canonicalized) to ignore insignificant whitespace; data changes will break verification.

📜 License

This project is done by Larbi OUADEIH
