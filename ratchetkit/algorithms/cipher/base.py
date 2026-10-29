"""Base class for pluggable symmetric ciphers."""
from __future__ import annotations


from abc import ABC
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, modes


class CipherAlgorithm(ABC):
    """Symmetric cipher used when deriving and applying MessageKeys.

    Block ciphers always run in CTR (single-use message keys). Stream
    ciphers (ChaCha20) take the IV as the nonce directly.
    """

    name: str
    key_size: int
    block_size: int
    nonce_size: int
    algorithm: Any  # hazmat algorithms.* class
    is_stream: bool = False

    @classmethod
    def iv_size(cls) -> int:
        if cls.is_stream:
            # cryptography ChaCha20 uses 16-byte nonce (4-byte counter + 12-byte nonce)
            return cls.nonce_size
        # Only CTR is used for block ciphers; IV length is the block size.
        return cls.block_size

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
        if cls.is_stream:
            cipher = Cipher(cls.algorithm(key, iv), mode=None)
        else:
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
        if cls.is_stream:
            cipher = Cipher(cls.algorithm(key, iv), mode=None)
        else:
            cipher = Cipher(cls.algorithm(key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
