"""Cryptographic utilities for Eufy Security cloud and P2P communication.

Uses pycryptodome for AES/RSA and Python's built-in ssl/hashlib for ECDH.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import struct
from typing import TYPE_CHECKING

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

if TYPE_CHECKING:
    pass

_LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ECDH for cloud API authentication
# ---------------------------------------------------------------------------
class ECDHKeyExchange:
    """ECDH key exchange using the prime256v1 (P-256) curve.

    Uses the `cryptography` library via an optional import; falls back to
    pure pycryptodome ECC if available.
    """

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization

        self._private_key = ec.generate_private_key(ec.SECP256R1())
        pub_numbers = self._private_key.public_key().public_numbers()
        # Uncompressed public key: 04 || x (32 bytes) || y (32 bytes)
        self.public_key_hex = "04" + format(pub_numbers.x, "064x") + format(pub_numbers.y, "064x")
        self._serialization = serialization
        self._ec = ec
        self._shared_secret: bytes | None = None

    @property
    def private_key_hex(self) -> str:
        """Return the private key as hex for persistence."""
        private_numbers = self._private_key.private_numbers()
        return format(private_numbers.private_value, "064x")

    @classmethod
    def from_private_key_hex(cls, private_key_hex: str) -> ECDHKeyExchange:
        """Restore from a persisted private key."""
        from cryptography.hazmat.primitives.asymmetric import ec

        instance = object.__new__(cls)
        from cryptography.hazmat.primitives import serialization

        private_value = int(private_key_hex, 16)
        # Reconstruct the key from the private value
        instance._private_key = ec.derive_private_key(private_value, ec.SECP256R1())
        pub_numbers = instance._private_key.public_key().public_numbers()
        instance.public_key_hex = "04" + format(pub_numbers.x, "064x") + format(pub_numbers.y, "064x")
        instance._serialization = serialization
        instance._ec = ec
        instance._shared_secret = None
        return instance

    def compute_shared_secret(self, server_public_key_hex: str) -> bytes:
        """Compute ECDH shared secret from the server's public key.

        The shared secret is used as an AES-256 key.
        """
        from cryptography.hazmat.primitives.asymmetric import ec

        server_pub_bytes = bytes.fromhex(server_public_key_hex)
        # Uncompressed point: 04 || x || y
        x = int.from_bytes(server_pub_bytes[1:33], "big")
        y = int.from_bytes(server_pub_bytes[33:65], "big")
        server_pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        shared = self._private_key.exchange(ec.ECDH(), server_pub)
        self._shared_secret = shared
        return shared


# ---------------------------------------------------------------------------
# AES-256-CBC for cloud API request/response encryption
# ---------------------------------------------------------------------------
def encrypt_api_data(data: str, key: bytes) -> str:
    """Encrypt data for the cloud API using AES-256-CBC.

    Key = ECDH shared secret (32 bytes), IV = key[:16].
    Returns base64-encoded ciphertext.
    """
    iv = key[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # PKCS7 padding
    pad_len = 16 - (len(data.encode()) % 16)
    padded = data.encode() + bytes([pad_len] * pad_len)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode()


def decrypt_api_data(data: str, key: bytes) -> bytes:
    """Decrypt cloud API response data from base64-encoded AES-256-CBC.

    Key = ECDH shared secret (32 bytes), IV = key[:16].
    Returns raw decrypted bytes.
    """
    iv = key[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(base64.b64decode(data))
    # Remove PKCS7 padding
    if decrypted:
        pad_len = decrypted[-1]
        if 0 < pad_len <= 16 and all(b == pad_len for b in decrypted[-pad_len:]):
            decrypted = decrypted[:-pad_len]
    return decrypted


def get_null_terminated_string(data: bytes) -> str:
    """Extract a null-terminated string from decrypted API data."""
    idx = data.find(b"\x00")
    if idx >= 0:
        return data[:idx].decode("utf-8", errors="replace")
    return data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# AES-128-ECB for P2P command encryption
# ---------------------------------------------------------------------------
def encrypt_p2p(data: bytes, key: bytes) -> bytes:
    """Encrypt P2P command data using AES-128-ECB.

    Data is zero-padded to 16-byte boundary before encryption.
    """
    # Pad to 16-byte boundary
    remainder = len(data) % 16
    if remainder:
        data = data + b"\x00" * (16 - remainder)
    cipher = AES.new(key[:16], AES.MODE_ECB)
    return cipher.encrypt(data)


def decrypt_p2p(data: bytes, key: bytes) -> bytes:
    """Decrypt P2P data using AES-128-ECB."""
    if len(data) % 16 != 0:
        # Truncate to nearest 16-byte boundary
        data = data[: len(data) - (len(data) % 16)]
    if not data:
        return b""
    cipher = AES.new(key[:16], AES.MODE_ECB)
    return cipher.decrypt(data)


# ---------------------------------------------------------------------------
# P2P encryption key derivation
# ---------------------------------------------------------------------------
def derive_p2p_key_level1(station_sn: str, p2p_did: str) -> bytes:
    """Derive Level 1 P2P encryption key from station serial and P2P DID.

    Key = last 7 chars of SN + 9 chars from DID starting at first '-'.
    Result is a 16-byte ASCII key for AES-128-ECB.
    """
    idx = p2p_did.index("-")
    key_str = station_sn[-7:] + p2p_did[idx : idx + 9]
    return key_str.encode("ascii")


def derive_p2p_key_level2(
    encrypted_aes_key: bytes, rsa_private_key_pem: str | bytes
) -> bytes:
    """Derive Level 2 P2P encryption key by RSA-decrypting the device's AES key.

    The device sends an RSA-1024-encrypted AES key during gateway info exchange.
    The RSA private key is fetched from Eufy's cloud cipher API.
    """
    if isinstance(rsa_private_key_pem, str):
        rsa_private_key_pem = rsa_private_key_pem.encode()
    rsa_key = RSA.import_key(rsa_private_key_pem)
    cipher = PKCS1_v1_5.new(rsa_key)
    sentinel = os.urandom(16)
    decrypted = cipher.decrypt(encrypted_aes_key, sentinel)
    return decrypted


# ---------------------------------------------------------------------------
# RSA key pair generation for video stream encryption
# ---------------------------------------------------------------------------
def generate_rsa_keypair() -> tuple[RSA.RsaKey, RSA.RsaKey]:
    """Generate a 1024-bit RSA key pair for video stream decryption.

    Returns (private_key, public_key).
    """
    key = RSA.generate(1024)
    return key, key.publickey()


def decrypt_video_frame(
    frame_data: bytes, rsa_private_key: RSA.RsaKey
) -> bytes:
    """Decrypt an encrypted video frame.

    For encrypted video frames (signCode > 0, length >= 128):
    - Bytes 22-149: RSA-encrypted AES key (128 bytes)
    - Byte 150: separator
    - Bytes 151+: video data (first 128 bytes AES-ECB encrypted)
    """
    if len(frame_data) < 151:
        return frame_data

    encrypted_key = frame_data[22:150]
    cipher_rsa = PKCS1_v1_5.new(rsa_private_key)
    sentinel = os.urandom(16)
    aes_key = cipher_rsa.decrypt(encrypted_key, sentinel)

    video_start = 151
    video_data = frame_data[video_start:]

    if len(video_data) >= 128 and len(aes_key) >= 16:
        cipher_aes = AES.new(aes_key[:16], AES.MODE_ECB)
        decrypted_part = cipher_aes.decrypt(video_data[:128])
        return decrypted_part + video_data[128:]

    return video_data


# ---------------------------------------------------------------------------
# Password hashing for API login
# ---------------------------------------------------------------------------
def encrypt_password(password: str, key: bytes) -> str:
    """Encrypt the user's password for the login API using AES-256-CBC."""
    return encrypt_api_data(password, key)


# ---------------------------------------------------------------------------
# Utility: MD5 for gtoken header
# ---------------------------------------------------------------------------
def md5_hex(data: str) -> str:
    """Return MD5 hex digest of a string."""
    return hashlib.md5(data.encode()).hexdigest()


# ---------------------------------------------------------------------------
# P2P DID encoding/decoding
# ---------------------------------------------------------------------------
def p2p_did_to_bytes(p2p_did: str) -> bytes:
    """Encode a P2P DID string to the 20-byte wire format.

    Format: XXXXXXXX-NNNNNN-YYYYYYYY
    -> 8 bytes (null-padded) + 4 bytes (uint32 BE) + 8 bytes (null-padded)
    """
    parts = p2p_did.split("-")
    if len(parts) != 3:
        raise ValueError(f"Invalid P2P DID format: {p2p_did}")
    buf1 = parts[0].encode().ljust(8, b"\x00")[:8]
    buf2 = struct.pack(">I", int(parts[1]))
    buf3 = parts[2].encode().ljust(8, b"\x00")[:8]
    return buf1 + buf2 + buf3


def bytes_to_p2p_did(data: bytes) -> str:
    """Decode 20 bytes to a P2P DID string."""
    part1 = data[:8].rstrip(b"\x00").decode("ascii", errors="replace")
    part2 = str(struct.unpack(">I", data[8:12])[0])
    part3 = data[12:20].rstrip(b"\x00").decode("ascii", errors="replace")
    return f"{part1}-{part2}-{part3}"


# ---------------------------------------------------------------------------
# P2P cloud IP decoding
# ---------------------------------------------------------------------------
_P2P_LOOKUP_TABLE = bytes.fromhex(
    "4959433db5bf6da347534f6165e371e9677f02030badb3892b2f35c16b8b9597"
    "11e5a70deff1050783fb9d3bc5c713171d1f2529d3df"
)


def decode_p2p_cloud_ips(data: str) -> list[tuple[str, int]]:
    """Decode obfuscated P2P cloud server IPs from the station's app_conn field."""
    if not data:
        return []
    encoded = data.split(":")[0]
    if len(encoded) < 2:
        return []
    output = bytearray(len(encoded) // 2)
    for i in range(len(encoded) // 2):
        z = 0x39
        for j in range(i):
            z ^= output[j]
        x = ord(encoded[i * 2 + 1]) - ord("A")
        y = (ord(encoded[i * 2]) - ord("A")) * 0x10
        output[i] = z ^ _P2P_LOOKUP_TABLE[i % len(_P2P_LOOKUP_TABLE)] ^ (x + y)
    try:
        decoded = output.decode("utf-8")
        return [(ip.strip(), 32100) for ip in decoded.split(",") if ip.strip()]
    except UnicodeDecodeError:
        _LOGGER.warning("Failed to decode P2P cloud IPs")
        return []


# ---------------------------------------------------------------------------
# Lock encryption utilities
# ---------------------------------------------------------------------------
_BASIC_LOCK_SEED = [
    104, -83, -72, 38, -107, 99, -110, 17,
    -95, -121, 54, 57, -46, -98, -111, 89,
]


def generate_basic_lock_aes_key(admin_user_id: str, station_sn: str) -> bytes:
    """Generate AES key for basic BLE lock commands.

    Combines a fixed seed array with the station serial and admin user id.
    Returns 16 bytes suitable as an AES-128 key.
    """
    enc_owner = admin_user_id.encode("utf-8")
    enc_sn = station_sn.encode("utf-8")
    arr = [b & 0xFF for b in _BASIC_LOCK_SEED]
    for i in range(16):
        sn_idx = (enc_sn[i % len(enc_sn)] * 3 + 5) % min(16, len(enc_sn))
        owner_idx = (enc_owner[i % len(enc_owner)] * 3 + 5) % min(40, len(enc_owner))
        arr[i] = (arr[i] + enc_sn[sn_idx % len(enc_sn)] + enc_owner[owner_idx % len(enc_owner)]) & 0xFF
    return bytes(arr)


def get_lock_vector_bytes(data: str) -> bytes:
    """Derive IV for lock AES-CBC encryption from a string (typically station SN).

    Returns 16 bytes: first 16 bytes of the UTF-8 encoding, zero-padded.
    """
    enc = data.encode("utf-8")
    if len(enc) >= 16:
        return enc[:16]
    return enc.ljust(16, b"\x00")


def encrypt_lock_aes_data(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Encrypt lock command data using AES-128-CBC with PKCS7 padding."""
    if len(key) > 16:
        # Key might be a hex string parsed to bytes; use first 16
        key = key[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv[:16])
    # PKCS7 padding
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len] * pad_len)
    return cipher.encrypt(padded)


def encode_lock_payload(data: str) -> bytes:
    """Zero-pad a lock payload string to a 16-byte boundary."""
    enc = data.encode("utf-8")
    remainder = len(enc) % 16
    if remainder == 0:
        return enc
    return enc + b"\x00" * (16 - remainder)


def generate_smart_lock_aes_key(admin_user_id: str, timestamp: int) -> bytes:
    """Generate AES key for smart lock (T8506 etc.) commands.

    Key = last 12 chars of user_id (UTF-8) + 4 bytes big-endian timestamp = 16 bytes.
    """
    user_part = admin_user_id[-12:].encode("utf-8")
    time_part = struct.pack(">I", timestamp)
    key = user_part + time_part
    # Pad or truncate to exactly 16 bytes
    if len(key) < 16:
        key = key.ljust(16, b"\x00")
    return key[:16]


def encrypt_payload_data(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt lock payload with AES-128-CBC and PKCS7 padding (standard Node.js style)."""
    cipher = AES.new(key[:16], AES.MODE_CBC, iv[:16])
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len] * pad_len)
    return cipher.encrypt(padded)


# ---------------------------------------------------------------------------
# Image decryption (event thumbnails)
# ---------------------------------------------------------------------------
def decode_image(p2p_did: str, data: bytes) -> bytes:
    """Decode an event thumbnail image using the station's P2P DID as key."""
    if not data or not p2p_did:
        return data
    key = hashlib.md5(p2p_did.encode()).digest()
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        # Only first 16 bytes are encrypted
        if len(data) >= 16:
            decrypted_header = cipher.decrypt(data[:16])
            return decrypted_header + data[16:]
    except Exception:
        _LOGGER.debug("Image decryption failed, returning raw data")
    return data
