"""
crypto.py — Cryptographic primitives for ghostchat.

Key exchange : X25519 ECDH
Key derivation: HKDF-SHA256 → 32-byte AES key
Encryption    : AES-256-GCM with random 12-byte nonce per message
Passphrase gate: Scrypt KDF + HMAC-SHA256 challenge-response

Nothing is written to disk. Callers are responsible for wiping key
material via wipe_buf() after use.
"""

import os
import hmac
import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Key generation & ECDH
# ---------------------------------------------------------------------------

def generate_keypair():
    """Generate an ephemeral X25519 keypair.

    Returns
    -------
    (private_key, public_bytes_32)
        private_key  : X25519PrivateKey object (never serialised to disk)
        public_bytes : 32-byte raw public key ready to send over the wire
    """
    private_key = X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes_raw()
    return private_key, public_bytes


def derive_shared_key(private_key, peer_public_bytes: bytes) -> bytes:
    """X25519 ECDH + HKDF-SHA256 → 32-byte AES-256-GCM key.

    The raw shared secret is overwritten with zeros immediately after
    HKDF derivation (best-effort; CPython may keep copies in the GC).
    """
    peer_pub = X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared_secret = private_key.exchange(peer_pub)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ghostchat-v1",
    )
    key = hkdf.derive(shared_secret)

    # Best-effort wipe of the raw shared secret
    wipe_buf(bytearray(shared_secret))
    return key


# ---------------------------------------------------------------------------
# AES-256-GCM per-message encryption
# ---------------------------------------------------------------------------

def encrypt_message(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt *plaintext* under *key* using AES-256-GCM.

    Returns  12-byte nonce  ||  ciphertext  ||  16-byte GCM tag
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct_and_tag


def decrypt_message(key: bytes, data: bytes) -> bytes:
    """Decrypt a frame produced by encrypt_message().

    data = nonce(12) || ciphertext || tag(16)
    Raises cryptography.exceptions.InvalidTag on authentication failure.
    """
    if len(data) < 12 + 16:
        raise ValueError("Frame too short to be a valid ciphertext")
    nonce = data[:12]
    ct_and_tag = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct_and_tag, None)


# ---------------------------------------------------------------------------
# Memory wipe helper
# ---------------------------------------------------------------------------

def wipe_buf(buf: bytearray) -> None:
    """Overwrite every byte of *buf* with zero in-place."""
    for i in range(len(buf)):
        buf[i] = 0


# ---------------------------------------------------------------------------
# Passphrase gate (optional shared secret verification)
# ---------------------------------------------------------------------------

def _derive_passphrase_key(passphrase: str, salt: bytes) -> bytes:
    """Scrypt KDF: passphrase string → 32-byte gate key."""
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))


def passphrase_handshake_host(
    send_raw,   # callable(bytes) → None
    recv_raw,   # callable()     → bytes
    passphrase: str,
) -> bool:
    """Host-side passphrase gate.

    Protocol:
      Host → Client : salt(16) || challenge(32)
      Client → Host : HMAC-SHA256(gate_key, challenge)
    Returns True if the client's HMAC is correct, False otherwise.
    """
    salt = os.urandom(16)
    challenge = os.urandom(32)
    send_raw(salt + challenge)

    gate_key = _derive_passphrase_key(passphrase, salt)
    expected = hmac.digest(gate_key, challenge, hashlib.sha256)

    response = recv_raw()
    result = hmac.compare_digest(response, expected)

    wipe_buf(bytearray(gate_key))
    return result


def passphrase_handshake_client(
    send_raw,
    recv_raw,
    passphrase: str,
) -> bool:
    """Client-side passphrase gate.

    Receives the host's challenge, responds with HMAC-SHA256.
    Always returns True; the host decides pass/fail.
    """
    data = recv_raw()
    if len(data) < 48:
        raise ValueError("Passphrase handshake packet too short")
    salt = data[:16]
    challenge = data[16:48]

    gate_key = _derive_passphrase_key(passphrase, salt)
    response = hmac.digest(gate_key, challenge, hashlib.sha256)
    send_raw(response)

    wipe_buf(bytearray(gate_key))
    return True  # Host validates; client's role is to respond
