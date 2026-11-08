"""Aes256 algorithm smoke test."""

from ratchetkit.algorithms.cipher.base import Aes256


def test_aes256_sizes():
    assert Aes256.key_size == 32
    assert Aes256.block_size == 16
    assert Aes256.nonce_size == 16


def test_aes256_encrypt_decrypt_roundtrip():
    key = b"\x11" * Aes256.key_size
    iv = b"\x22" * Aes256.iv_size()
    plain = b"hello ratchetkit"
    ct = Aes256.encrypt(key, iv, plain)
    assert ct != plain
    assert Aes256.decrypt(key, iv, ct) == plain
