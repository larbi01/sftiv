import os
import socket
import threading
from datetime import datetime
from pathlib import Path

from sftiv.crypto.hashing import sha256_file
from sftiv.net.framing import recv_json, recv_frame

def _safe_name(name: str) -> str:
    # Minimal sanitation to avoid path traversal; keep filenames simple.
    return "".join(c for c in name if c.isalnum() or c in ("-", "_", ".", " ")).strip() or "file.enc"

def _handle_client(conn: socket.socket, addr, outdir: Path) -> None:
    try:
        conn.settimeout(30.0)
        header = recv_json(conn)
        if header.get("version") != 1 or header.get("type") != "envelope":
            raise ValueError("Unsupported header")
        size = int(header["size"])
        suggested = _safe_name(str(header.get("suggested_name", "file.enc")))

        # Ensure unique filename
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        out_path = outdir / f"{ts}_{suggested}"

        # Receive envelope bytes and write to disk
        data = recv_frame(conn, max_len=size + 1024)  # soft check
        if len(data) != size:
            raise ValueError(f"Size mismatch: header={size} actual={len(data)}")

        outdir.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(data)

        digest = sha256_file(str(out_path))
        print(f"[RECV OK] {addr} -> {out_path} ({size} bytes) sha256={digest}")
    except Exception as e:
        print(f"[RECV ERR] {addr}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

def serve(bind_host: str, bind_port: int, outdir: str) -> None:
    outp = Path(outdir)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((bind_host, bind_port))
        s.listen(5)
        print(f"[LISTEN] {bind_host}:{bind_port} -> {outp.resolve()}")
        while True:
            conn, addr = s.accept()
            print(f"[ACCEPT] {addr}")
            t = threading.Thread(target=_handle_client, args=(conn, addr, outp), daemon=True)
            t.start()
