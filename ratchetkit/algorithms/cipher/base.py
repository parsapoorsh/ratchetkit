"""Base class for pluggable symmetric ciphers."""
from __future__ import annotations


from abc import ABC
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, modes


class CipherAlgorithm(ABC):
    """Symmetric cipher used when deriving and applying MessageKeys.

    Block ciphers run in CTR. The nonce is the HMAC tag (SIV). Stream
    ciphers override encrypt / decrypt.
    """

    name: str
    key_size: int
    block_size: int
    nonce_size: int
    algorithm: Any  # hazmat algorithms.* class

    @classmethod
    def iv_size(cls) -> int:
        return cls.nonce_size

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
        cipher = Cipher(cls.algorithm(key), modes.CTR(iv))
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
        cipher = Cipher(cls.algorithm(key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
