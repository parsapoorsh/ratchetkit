"""Per-message cipher / MAC / IV material."""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.errors import InvalidMessage, SerializationError
from ratchetkit.kdf import Kdf
from ratchetkit.suite.registry import cipher_backend, hash_backend
from ratchetkit.packing import (
    encode_bytes,
    encode_u32,
    read_bytes,
    read_u32,
)
from ratchetkit.suite import KdfLabel

if TYPE_CHECKING:
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite


@dataclass(frozen=True)
class MessageKeys:
    """Derived single-use keys for one ratchet message.

    Encryption is stream-oriented only (ChaCha20 or block cipher in CTR).
    """

    cipher_key: bytes
    mac_key: bytes
    iv: bytes
    counter: int

    @classmethod
    def derive(cls, seed: bytes, counter: int, suite: CryptoSuite) -> MessageKeys:
        cipher = cipher_backend(suite.cipher)
        digest = hash_backend(suite.digest)
        key_size = cipher.key_size
        mac_size = digest.digest_size
        iv_size = cipher.iv_size()
        kdf = Kdf(suite.digest)
        material = kdf.hkdf(
            seed,
            key_size + mac_size + iv_size,
            salt=None,
            info=KdfLabel.MESSAGE_KEYS,
        )
        cipher_key = material[:key_size]
        offset = key_size
        mac_key = material[offset:offset + mac_size]
        offset += mac_size
        iv = material[offset:offset + iv_size]
        return cls(
            cipher_key=cipher_key,
            mac_key=mac_key,
            iv=iv,
            counter=counter,
        )

    def encrypt(self, plaintext: bytes, suite: CryptoSuite) -> bytes:
        return cipher_backend(suite.cipher).encrypt(self.cipher_key, self.iv, plaintext)

    def decrypt(self, ciphertext: bytes, suite: CryptoSuite) -> bytes:
        return cipher_backend(suite.cipher).decrypt(self.cipher_key, self.iv, ciphertext)

    def compute_mac(
        self,
        header: bytes,
        associated_data: bytes,
        ciphertext: bytes,
        suite: CryptoSuite,
    ) -> bytes:
        material = associated_data + header + ciphertext
        tag = Kdf(suite.digest).hmac_digest(self.mac_key, material)
        return tag[: suite.tag_size]

    def verify_mac(
        self,
        header: bytes,
        associated_data: bytes,
        ciphertext: bytes,
        mac: bytes,
        suite: CryptoSuite,
    ) -> None:
        expected = self.compute_mac(header, associated_data, ciphertext, suite)
        if not hmac.compare_digest(expected, mac):
            raise InvalidMessage("MAC verification failed")

    def to_bytes(self) -> bytes:
        return (
            encode_bytes(self.cipher_key)
            + encode_bytes(self.mac_key)
            + encode_bytes(self.iv)
            + encode_u32(self.counter)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> MessageKeys:
        cipher_key, offset = read_bytes(data, 0)
        mac_key, offset = read_bytes(data, offset)
        iv, offset = read_bytes(data, offset)
        counter, offset = read_u32(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in message keys")
        return cls(
            cipher_key=cipher_key,
            mac_key=mac_key,
            iv=iv,
            counter=counter,
        )
