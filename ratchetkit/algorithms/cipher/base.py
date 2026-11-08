"""Base class for pluggable symmetric ciphers."""
from __future__ import annotations


from abc import ABC
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import Camellia
except ImportError:  # pragma: no cover - older cryptography
    from cryptography.hazmat.primitives.ciphers.algorithms import Camellia


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


class Aes128(CipherAlgorithm):
    name = "aes128"
    key_size = 16
    block_size = 16
    nonce_size = 16
    algorithm = algorithms.AES


class Aes256(CipherAlgorithm):
    name = "aes256"
    key_size = 32
    block_size = 16
    nonce_size = 16
    algorithm = algorithms.AES


class Camellia128(CipherAlgorithm):
    name = "camellia128"
    key_size = 16
    block_size = 16
    nonce_size = 16
    algorithm = Camellia


class Camellia256(CipherAlgorithm):
    name = "camellia256"
    key_size = 32
    block_size = 16
    nonce_size = 16
    algorithm = Camellia
