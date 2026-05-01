"""
network.py — TCP networking for ghostchat.

Wire framing
------------
Every payload (handshake bytes OR encrypted message) is wrapped in a
length-prefixed frame:

    [ 4-byte big-endian uint32 length ][ payload bytes ]

Encrypted chat message payload layout (from crypto.py):
    [ 12-byte nonce ][ ciphertext + 16-byte GCM tag ]

The RecvThread reads frames, decrypts them, deserialises JSON, and
dispatches to caller-supplied callbacks — keeping all blocking I/O off
the main (TUI) thread.
"""

import json
import socket
import struct
import threading
import time

from crypto import encrypt_message, decrypt_message

# Sanity cap: no single frame may exceed 10 MB
_MAX_FRAME = 10 * 1024 * 1024


# ---------------------------------------------------------------------------
# Low-level framing helpers
# ---------------------------------------------------------------------------

def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from *sock*; raise ConnectionError if closed."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed by peer")
        buf.extend(chunk)
    return bytes(buf)


def send_frame(sock: socket.socket, data: bytes) -> None:
    """Send *data* as a 4-byte-length-prefixed frame (atomic sendall)."""
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)


def recv_frame(sock: socket.socket) -> bytes:
    """Block until a complete length-prefixed frame is available."""
    raw_len = _recv_exactly(sock, 4)
    length = struct.unpack(">I", raw_len)[0]
    if length > _MAX_FRAME:
        raise ValueError(f"Frame length {length} exceeds safety limit")
    return _recv_exactly(sock, length)


# ---------------------------------------------------------------------------
# Encrypted message helpers (JSON payload)
# ---------------------------------------------------------------------------

def send_message(sock: socket.socket, aes_key: bytes, payload: dict) -> None:
    """Serialise *payload* to JSON, encrypt, and send as a framed message."""
    plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    encrypted = encrypt_message(aes_key, plaintext)
    send_frame(sock, encrypted)


def recv_message(sock: socket.socket, aes_key: bytes) -> dict:
    """Receive a framed message, decrypt, and return the parsed JSON dict."""
    frame = recv_frame(sock)
    plaintext = decrypt_message(aes_key, frame)
    return json.loads(plaintext.decode("utf-8"))


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

def host_listen(port: int, timeout: int = 300) -> tuple:
    """Bind to *port*, wait up to *timeout* seconds, accept one client.

    Returns
    -------
    (conn_socket, (remote_ip, remote_port))
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("", port))
    server.listen(1)
    server.settimeout(timeout)
    try:
        conn, addr = server.accept()
    finally:
        server.close()
    return conn, addr


def client_connect(host: str, port: int) -> socket.socket:
    """Connect to *host*:*port* and return the connected socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock


# ---------------------------------------------------------------------------
# Receive thread
# ---------------------------------------------------------------------------

class RecvThread(threading.Thread):
    """Background daemon thread that continuously reads encrypted frames.

    Parameters
    ----------
    sock          : connected socket to read from
    aes_key       : AES-256-GCM key (bytes); stored as a list[bytes] so the
                    caller can zero it out and we notice via reference.
    on_message    : callable(dict) — called with each decrypted JSON payload
    on_disconnect : callable()     — called once when the peer closes
    """

    def __init__(
        self,
        sock: socket.socket,
        aes_key_ref: list,      # list[bytes | None] — mutable reference
        on_message,
        on_disconnect,
    ) -> None:
        super().__init__(daemon=True, name="ghostchat-recv")
        self._sock = sock
        self._key_ref = aes_key_ref
        self._on_message = on_message
        self._on_disconnect = on_disconnect
        self._stopped = threading.Event()

    def run(self) -> None:
        while not self._stopped.is_set():
            try:
                key = self._key_ref[0]
                if key is None:
                    break
                frame = recv_frame(self._sock)
                plaintext = decrypt_message(key, frame)
                payload = json.loads(plaintext.decode("utf-8"))
                self._on_message(payload)
            except (ConnectionError, OSError):
                if not self._stopped.is_set():
                    self._on_disconnect()
                break
            except Exception:
                # Decryption failure or malformed JSON — skip silently
                continue

    def stop(self) -> None:
        """Signal the thread to exit (does not close the socket)."""
        self._stopped.set()
