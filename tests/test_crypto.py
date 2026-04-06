"""Tests for the crypto module."""

import struct
import pytest

from custom_components.eufy_security_advanced.lib.crypto import (
    ECDHKeyExchange,
    bytes_to_p2p_did,
    decode_p2p_cloud_ips,
    decrypt_api_data,
    decrypt_p2p,
    derive_p2p_key_level1,
    encrypt_api_data,
    encrypt_lock_aes_data,
    encrypt_p2p,
    encode_lock_payload,
    generate_basic_lock_aes_key,
    generate_smart_lock_aes_key,
    get_lock_vector_bytes,
    md5_hex,
    p2p_did_to_bytes,
)


class TestECDH:
    """Test ECDH key exchange."""

    def test_generate_keypair(self):
        ecdh = ECDHKeyExchange()
        assert ecdh.public_key_hex.startswith("04")
        assert len(ecdh.public_key_hex) == 130  # 04 + 64 hex chars x + 64 hex chars y

    def test_private_key_persistence(self):
        ecdh1 = ECDHKeyExchange()
        priv_hex = ecdh1.private_key_hex
        ecdh2 = ECDHKeyExchange.from_private_key_hex(priv_hex)
        assert ecdh1.public_key_hex == ecdh2.public_key_hex

    def test_shared_secret(self):
        ecdh1 = ECDHKeyExchange()
        ecdh2 = ECDHKeyExchange()
        secret1 = ecdh1.compute_shared_secret(ecdh2.public_key_hex)
        secret2 = ecdh2.compute_shared_secret(ecdh1.public_key_hex)
        assert secret1 == secret2
        assert len(secret1) == 32


class TestAESCloudEncryption:
    """Test AES-256-CBC cloud API encryption."""

    def test_encrypt_decrypt_roundtrip(self):
        key = b"\x01" * 32
        plaintext = "hello world"
        encrypted = encrypt_api_data(plaintext, key)
        decrypted = decrypt_api_data(encrypted, key)
        assert decrypted.decode("utf-8") == plaintext

    def test_encrypt_different_keys_differ(self):
        key1 = b"\x01" * 32
        key2 = b"\x02" * 32
        encrypted1 = encrypt_api_data("test", key1)
        encrypted2 = encrypt_api_data("test", key2)
        assert encrypted1 != encrypted2


class TestP2PEncryption:
    """Test AES-128-ECB P2P encryption."""

    def test_encrypt_decrypt_roundtrip(self):
        key = b"0123456789abcdef"
        data = b"test data here!!"  # 16 bytes exact
        encrypted = encrypt_p2p(data, key)
        decrypted = decrypt_p2p(encrypted, key)
        assert decrypted == data

    def test_encrypt_pads_to_16_bytes(self):
        key = b"0123456789abcdef"
        data = b"short"
        encrypted = encrypt_p2p(data, key)
        assert len(encrypted) == 16

    def test_empty_decrypt(self):
        key = b"0123456789abcdef"
        assert decrypt_p2p(b"", key) == b""


class TestP2PKeyDerivation:
    """Test P2P encryption key derivation."""

    def test_level1_key(self):
        key = derive_p2p_key_level1("T8010ABCDEFG", "ABCD1234-123456-EFGH5678")
        assert len(key) == 16
        # last 7 of "T8010ABCDEFG" = "ABCDEFG"
        # 9 chars from '-' in DID = "-123456-E"
        assert key == b"ABCDEFG-123456-E"

    def test_level1_key_format(self):
        key = derive_p2p_key_level1("T8010XYZTEST", "PREFIX00-999999-SUFFIX00")
        # last 7 of SN = "XYZTEST", first 9 from '-' = "-999999-S"
        assert key == b"XYZTEST-999999-S"


class TestP2PDID:
    """Test P2P DID encoding/decoding."""

    def test_encode_decode_roundtrip(self):
        did = "ABCD1234-123456-EFGH5678"
        encoded = p2p_did_to_bytes(did)
        assert len(encoded) == 20
        decoded = bytes_to_p2p_did(encoded)
        assert decoded == did

    def test_encode_format(self):
        encoded = p2p_did_to_bytes("TESTDID0-000001-SUFFIX00")
        # First 8 bytes: "TESTDID0"
        assert encoded[:8] == b"TESTDID0"
        # Bytes 8-12: uint32 BE = 1
        assert struct.unpack(">I", encoded[8:12])[0] == 1
        # Bytes 12-20: "SUFFIX00"
        assert encoded[12:20] == b"SUFFIX00"


class TestLockCrypto:
    """Test lock encryption utilities."""

    def test_basic_lock_key_length(self):
        key = generate_basic_lock_aes_key("admin123456789", "T8010ABCDEFG")
        assert len(key) == 16

    def test_basic_lock_key_deterministic(self):
        key1 = generate_basic_lock_aes_key("user1", "station1")
        key2 = generate_basic_lock_aes_key("user1", "station1")
        assert key1 == key2

    def test_basic_lock_key_differs(self):
        key1 = generate_basic_lock_aes_key("user1", "station1")
        key2 = generate_basic_lock_aes_key("user2", "station1")
        assert key1 != key2

    def test_lock_vector_bytes_short(self):
        iv = get_lock_vector_bytes("short")
        assert len(iv) == 16
        assert iv[:5] == b"short"
        assert iv[5:] == b"\x00" * 11

    def test_lock_vector_bytes_long(self):
        iv = get_lock_vector_bytes("this_is_a_long_string_more_than_16")
        assert len(iv) == 16

    def test_encode_lock_payload_padding(self):
        result = encode_lock_payload("hello")
        assert len(result) == 16  # Padded to 16
        assert result[:5] == b"hello"

    def test_encode_lock_payload_exact(self):
        data = "a" * 16
        result = encode_lock_payload(data)
        assert len(result) == 16

    def test_encrypt_lock_roundtrip(self):
        key = b"0123456789abcdef"
        iv = b"fedcba9876543210"
        from Crypto.Cipher import AES
        data = encode_lock_payload("test payload data")
        encrypted = encrypt_lock_aes_data(key, iv, data)
        # Decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        # Remove PKCS7 padding
        pad_len = decrypted[-1]
        decrypted = decrypted[:-pad_len]
        assert decrypted == data

    def test_smart_lock_key(self):
        key = generate_smart_lock_aes_key("admin_user_1234", 1704067200)
        assert len(key) == 16
        # Last 12 of user_id = "r_user_1234" (11 chars) ... actually:
        # "admin_user_1234"[-12:] = "in_user_1234" (12 chars)
        assert key[:12] == b"in_user_1234"


class TestMD5:
    def test_known_hash(self):
        assert md5_hex("") == "d41d8cd98f00b204e9800998ecf8427e"
        assert md5_hex("hello") == "5d41402abc4b2a76b9719d911017c592"
