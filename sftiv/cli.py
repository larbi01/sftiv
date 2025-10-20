import argparse
import sys
from pathlib import Path

from sftiv.crypto.hashing import sha256_file
from sftiv.crypto.symmetric import key_generate, encrypt_file, decrypt_file
from sftiv.crypto.manifest import create_manifest, write_manifest, read_manifest
from sftiv.net.server import serve as serve_tcp
from sftiv.net.client import send_envelope
from sftiv.crypto.signing import ed25519_keygen, sign_bytes, verify_bytes


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sftiv",
        description="Secure File Transfer & Integrity Verification"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # hash
    p_hash = sub.add_parser("hash", help="Compute SHA-256 of a file")
    p_hash.add_argument("path", help="Path to the file to hash")

    # keygen
    p_key = sub.add_parser("keygen", help="Generate a 256-bit AES key (base64) with 0600 perms")
    p_key.add_argument("-o", "--out", required=True, help="Path to write the key file")

    # encrypt
    p_enc = sub.add_parser("encrypt", help="Encrypt file with AES-256-GCM")
    p_enc.add_argument("-k", "--key", required=True, help="Path to AES key file (base64)")
    p_enc.add_argument("-i", "--infile", required=True, help="Plaintext input file")
    p_enc.add_argument("-o", "--outfile", required=True, help="Output encrypted envelope")

    # decrypt
    p_dec = sub.add_parser("decrypt", help="Decrypt file previously encrypted with AES-GCM")
    p_dec.add_argument("-k", "--key", required=True, help="Path to AES key file (base64)")
    p_dec.add_argument("-i", "--infile", required=True, help="Envelope input file")
    p_dec.add_argument("-o", "--outfile", required=True, help="Decrypted output path")

    # manifest
    p_mani = sub.add_parser("manifest", help="Create a SHA-256 manifest JSON for a file")
    p_mani.add_argument("-i", "--infile", required=True, help="File to describe")
    p_mani.add_argument("-o", "--outfile", required=True, help="Manifest output path (.json)")
    p_mani.add_argument("-m", "--message", required=False, help="Optional comment")

    # verify
    p_ver = sub.add_parser("verify", help="Verify a file against a SHA-256 manifest JSON")
    p_ver.add_argument("-m", "--manifest", required=True, help="Path to manifest JSON")
    p_ver.add_argument("-f", "--file", required=True, help="Path to file to verify")

    # server
    p_srv = sub.add_parser("server", help="Run TCP server to receive encrypted envelopes")
    p_srv.add_argument("--bind", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    p_srv.add_argument("--port", type=int, default=5001, help="Port (default: 5001)")
    p_srv.add_argument("--outdir", required=True, help="Directory to save received envelopes")

    # send
    p_cli = sub.add_parser("send", help="Send an encrypted envelope to a server")
    p_cli.add_argument("--host", required=True, help="Server host")
    p_cli.add_argument("--port", type=int, default=5001, help="Server port (default: 5001)")
    p_cli.add_argument("--file", required=True, help="Path to encrypted envelope (.enc)")
    p_cli.add_argument("--name", required=False, help="Suggested name to save on server")

    # sigkeygen
    p_skg = sub.add_parser("sigkeygen", help="Generate Ed25519 keypair (PEM)")
    p_skg.add_argument("--priv", required=True, help="Private key PEM path")
    p_skg.add_argument("--pub", required=True, help="Public key PEM path")

    # sign-manifest
    p_sman = sub.add_parser("sign-manifest", help="Sign a manifest JSON and write a .sig file")
    p_sman.add_argument("-p", "--priv", required=True, help="Private key PEM")
    p_sman.add_argument("-m", "--manifest", required=True, help="Manifest JSON path")
    p_sman.add_argument("-o", "--out", required=True, help="Signature output (.sig)")

    # verify-signature
    p_vsig = sub.add_parser("verify-signature", help="Verify a manifest signature with a public key")
    p_vsig.add_argument("--pub", required=True, help="Public key PEM")
    p_vsig.add_argument("-m", "--manifest", required=True, help="Manifest JSON path")
    p_vsig.add_argument("-s", "--sig", required=True, help="Signature file (.sig)")

    return parser


def cmd_hash(args: argparse.Namespace) -> int:
    try:
        digest = sha256_file(args.path)
        print(digest)
        return 0
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[ERROR] Unexpected: {e}", file=sys.stderr)
        return 1


def cmd_keygen(args: argparse.Namespace) -> int:
    try:
        key_generate(args.out)
        print(f"[OK] Key generated at: {args.out}")
        return 0
    except FileExistsError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[ERROR] Unexpected: {e}", file=sys.stderr)
        return 1


def cmd_encrypt(args: argparse.Namespace) -> int:
    try:
        encrypt_file(args.infile, args.outfile, args.key)
        print(f"[OK] Encrypted: {args.infile} -> {args.outfile}")
        return 0
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[ERROR] Unexpected: {e}", file=sys.stderr)
        return 1


def cmd_decrypt(args: argparse.Namespace) -> int:
    try:
        decrypt_file(args.infile, args.outfile, args.key)
        print(f"[OK] Decrypted: {args.infile} -> {args.outfile}")
        return 0
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[ERROR] Unexpected: {e}", file=sys.stderr)
        return 1


def cmd_manifest(args: argparse.Namespace) -> int:
    try:
        mani = create_manifest(args.infile, comment=args.message)
        write_manifest(mani, args.outfile)
        print(f"[OK] Manifest written: {args.outfile}")
        print(f"  file={mani.filename} size={mani.size} sha256={mani.sha256}")
        return 0
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[ERROR] Unexpected: {e}", file=sys.stderr)
        return 1


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        mani = read_manifest(args.manifest)
        p = Path(args.file)
        if not p.is_file():
            print(f"[FAIL] File not found: {args.file}", file=sys.stderr)
            return 2

        digest = sha256_file(str(p))
        size = p.stat().st_size

        ok = True
        if digest != mani.sha256:
            print(f"[FAIL] SHA-256 mismatch:\n  expected={mani.sha256}\n  actual  ={digest}")
            ok = False
        if size != mani.size:
            print(f"[FAIL] Size mismatch:\n  expected={mani.size}\n  actual  ={size}")
            ok = False

        if ok:
            print(f"[OK] Integrity verified for {p.name}")
            return 0
        else:
            return 3
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[ERROR] Unexpected: {e}", file=sys.stderr)
        return 1


def cmd_server(args: argparse.Namespace) -> int:
    try:
        serve_tcp(args.bind, args.port, args.outdir)
        return 0
    except Exception as e:
        print(f"[ERROR] Server: {e}", file=sys.stderr)
        return 1


def cmd_send(args: argparse.Namespace) -> int:
    try:
        send_envelope(args.host, args.port, args.file, args.name)
        print(f"[OK] Sent: {args.file} -> {args.host}:{args.port}")
        return 0
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[ERROR] Unexpected: {e}", file=sys.stderr)
        return 1


def cmd_sigkeygen(args: argparse.Namespace) -> int:
    try:
        ed25519_keygen(args.priv, args.pub)
        print(f"[OK] Ed25519 keys generated:\n  priv={args.priv}\n  pub ={args.pub}")
        return 0
    except FileExistsError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[ERROR] Unexpected: {e}", file=sys.stderr)
        return 1


def cmd_sign_manifest(args: argparse.Namespace) -> int:
    try:
        mani = read_manifest(args.manifest)
        payload = mani.to_json_bytes()
        sig_b64 = sign_bytes(args.priv, payload)
        Path(args.out).write_text(sig_b64 + "\n", encoding="utf-8")
        print(f"[OK] Signature written: {args.out}")
        return 0
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[ERROR] Unexpected: {e}", file=sys.stderr)
        return 1


def cmd_verify_signature(args: argparse.Namespace) -> int:
    try:
        mani = read_manifest(args.manifest)
        payload = mani.to_json_bytes()
        sig_b64 = Path(args.sig).read_text(encoding="utf-8").strip()
        ok = verify_bytes(args.pub, payload, sig_b64)
        if ok:
            print("[OK] Signature is VALID for this manifest and public key")
            return 0
        else:
            print("[FAIL] Signature INVALID for this manifest/public key")
            return 3
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[ERROR] Unexpected: {e}", file=sys.stderr)
        return 1


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "hash": return cmd_hash(args)
    if args.command == "keygen": return cmd_keygen(args)
    if args.command == "encrypt": return cmd_encrypt(args)
    if args.command == "decrypt": return cmd_decrypt(args)
    if args.command == "manifest": return cmd_manifest(args)
    if args.command == "verify": return cmd_verify(args)
    if args.command == "server": return cmd_server(args)
    if args.command == "send": return cmd_send(args)
    if args.command == "sigkeygen": return cmd_sigkeygen(args)
    if args.command == "sign-manifest": return cmd_sign_manifest(args)
    if args.command == "verify-signature": return cmd_verify_signature(args)

    print("[ERROR] Unknown command", file=sys.stderr)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())

