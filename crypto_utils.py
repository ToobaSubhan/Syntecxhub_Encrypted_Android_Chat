"""
Shared encryption and framing helpers.
------------------------------------------
Both the server and the client import this file so they always agree on
the same key, the same encryption method, and the same way of marking
where one message ends and the next begins.

Encryption: AES-256-GCM
    - GCM gives you two things at once: the message is unreadable to
      anyone without the key, AND the receiver can tell if even one
      byte was changed in transit (it will refuse to decrypt).
    - Every message gets its own random 12-byte "nonce" (number used
      once). Reusing a nonce with the same key is the one mistake that
      breaks GCM's security, so we generate a fresh one every time.

Framing: a 4-byte length prefix
    - TCP only guarantees that bytes arrive in order, NOT that they
      arrive in the same chunks they were sent in. Two quick messages
      can arrive glued together, or one message can arrive in pieces.
    - To fix this, before sending a message we first send 4 bytes that
      say "the next message is N bytes long". The receiver reads those
      4 bytes first, then reads exactly that many bytes for the message.
"""

import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12  # bytes; the standard size for AES-GCM

# --- Pre-shared key -----------------------------------------------------
# PROTOTYPE ONLY: both sides hardcode the same 32-byte (256-bit) key.
# In a real product this key would never be hardcoded in source code -
# it would be entered by the user, exchanged through a secure channel,
# or negotiated with something like Diffie-Hellman key exchange.
# Hardcoding it here keeps the project focused on encryption/socket
# programming rather than key-distribution, which is its own hard problem.
PRESHARED_KEY = bytes.fromhex(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)
assert len(PRESHARED_KEY) == 32, "AES-256 needs a 32-byte key"


def encrypt(plaintext: bytes, key: bytes = PRESHARED_KEY) -> bytes:
    """Encrypt plaintext. Returns nonce + ciphertext (ciphertext includes
    the authentication tag at the end, which is how AES-GCM works)."""
    aesgcm = AESGCM(key)
    nonce = _random_nonce()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt(data: bytes, key: bytes = PRESHARED_KEY) -> bytes:
    """Reverse of encrypt(). Raises an exception if the key is wrong or
    the data was tampered with - that check is built into AES-GCM."""
    aesgcm = AESGCM(key)
    nonce, ciphertext = data[:NONCE_SIZE], data[NONCE_SIZE:]
    return aesgcm.decrypt(nonce, ciphertext, None)


def _random_nonce() -> bytes:
    import os
    return os.urandom(NONCE_SIZE)


# --- Message framing -----------------------------------------------------

def send_framed(sock, data: bytes) -> None:
    """Send data on sock, preceded by a 4-byte length so the receiver
    knows exactly how many bytes to read for this one message."""
    header = struct.pack(">I", len(data))  # ">I" = big-endian, 4-byte unsigned int
    sock.sendall(header + data)


def recv_exactly(sock, n: int) -> bytes:
    """Keep reading from sock until exactly n bytes have been collected.
    A single recv() call is not guaranteed to return all n bytes at once."""
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed before message finished")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_framed(sock):
    """Read one complete framed message from sock.
    Returns the message bytes, or None if the connection closed cleanly."""
    header = sock.recv(4)
    if not header:
        return None  # connection closed before any data came
    if len(header) < 4:
        header += recv_exactly(sock, 4 - len(header))
    (length,) = struct.unpack(">I", header)
    return recv_exactly(sock, length)
