import json
import socket
import struct
from typing import Tuple

_LEN = struct.Struct(">Q")  # 8-byte unsigned big-endian length

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes or raise ConnectionError on EOF/short read."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed during recv")
        buf.extend(chunk)
    return bytes(buf)

def send_frame(sock: socket.socket, data: bytes) -> None:
    """Send a single length-prefixed frame."""
    sock.sendall(_LEN.pack(len(data)))
    sock.sendall(data)

def recv_frame(sock: socket.socket, max_len: int = 1 << 30) -> bytes:
    """Receive a single length-prefixed frame (max_len default 1 GiB)."""
    (size,) = _LEN.unpack(_recv_exact(sock, _LEN.size))
    if size > max_len:
        raise ValueError(f"Incoming frame too large: {size} > {max_len}")
    return _recv_exact(sock, size)

def send_json(sock: socket.socket, obj: dict) -> None:
    send_frame(sock, json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

def recv_json(sock: socket.socket) -> dict:
    data = recv_frame(sock)
    return json.loads(data.decode("utf-8"))

