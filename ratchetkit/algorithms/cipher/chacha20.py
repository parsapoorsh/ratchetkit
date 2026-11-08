"""ChaCha20 stream cipher algorithm."""
from __future__ import annotations


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from ratchetkit.algorithms.cipher.base import CipherAlgorithm


class ChaCha20(CipherAlgorithm):
    name = "chacha20"
    key_size = 32
    block_size = 1
    # cryptography ChaCha20 uses 16-byte nonce (4-byte counter + 12-byte nonce)
    nonce_size = 16
    algorithm = algorithms.ChaCha20

    @classmethod
    def encrypt(cls, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
        if len(key) != cls.key_size:
            raise ValueError(
                f"{cls.name} key must be {cls.key_size} bytes, got {len(key)}"
            )
        if len(iv) != cls.iv_size():
            raise ValueError(
                f"{cls.name} iv must be {cls.iv_size()} bytes, got {len(iv)}"
            )
        cipher = Cipher(cls.algorithm(key, iv), mode=None)
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

    @classmethod
    def decrypt(cls, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        if len(key) != cls.key_size:
            raise ValueError(
                f"{cls.name} key must be {cls.key_size} bytes, got {len(key)}"
            )
        if len(iv) != cls.iv_size():
            raise ValueError(
                f"{cls.name} iv must be {cls.iv_size()} bytes, got {len(iv)}"
            )
        cipher = Cipher(cls.algorithm(key, iv), mode=None)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
