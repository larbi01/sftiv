import json
import socket
from pathlib import Path

from sftiv.net.framing import send_json, send_frame

def send_envelope(host: str, port: int, envelope_path: str, suggested_name: str | None = None) -> None:
    p = Path(envelope_path)
    if not p.is_file():
        raise FileNotFoundError(f"Envelope not found: {envelope_path}")
    data = p.read_bytes()
    header = {
        "version": 1,
        "type": "envelope",
        "size": len(data),
        "suggested_name": suggested_name or p.name,
    }
    with socket.create_connection((host, port), timeout=10.0) as sock:
        sock.settimeout(30.0)
        send_json(sock, header)
        send_frame(sock, data)
