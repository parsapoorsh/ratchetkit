"""Per-message cipher / MAC material (CTR-SIV: HMAC tag is the IV)."""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.errors import InvalidMessage, SerializationError
from ratchetkit.kdf import Kdf
from ratchetkit.packing import (
    encode_bytes,
    encode_u32,
    read_bytes,
    read_u32,
)
from ratchetkit.suite import KdfLabel
from ratchetkit.suite.registry import cipher_backend, hash_backend

if TYPE_CHECKING:
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite


@dataclass(frozen=True)
class MessageKeys:
    """Derived single-use keys for one ratchet message.

    HMAC over associated data, header, and plaintext is the CTR / ChaCha
    nonce (SIV). The tag is sent; no separate IV is derived.
    """

    cipher_key: bytes
    mac_key: bytes
    counter: int

    @classmethod
    def derive(cls, seed: bytes, counter: int, suite: CryptoSuite) -> MessageKeys:
        cipher = cipher_backend(suite.cipher)
        digest = hash_backend(suite.digest)
        key_size = cipher.key_size
        mac_size = digest.digest_size
        kdf = Kdf(suite.digest)
        material = kdf.hkdf(
            seed,
            key_size + mac_size,
            salt=None,
            info=KdfLabel.MESSAGE_KEYS,
        )
        return cls(
            cipher_key=material[:key_size],
            mac_key=material[key_size:key_size + mac_size],
            counter=counter,
        )

    def nonce(self, tag: bytes, suite: CryptoSuite) -> bytes:
        size = cipher_backend(suite.cipher).iv_size()
        if len(tag) >= size:
            return tag[:size]
        return tag + bytes(size - len(tag))

    def encrypt(self, plaintext: bytes, suite: CryptoSuite, tag: bytes) -> bytes:
        return cipher_backend(suite.cipher).encrypt(
            self.cipher_key,
            self.nonce(tag, suite),
            plaintext,
        )

    def decrypt(self, ciphertext: bytes, suite: CryptoSuite, tag: bytes) -> bytes:
        return cipher_backend(suite.cipher).decrypt(
            self.cipher_key,
            self.nonce(tag, suite),
            ciphertext,
        )

    def compute_mac(
        self,
        header: bytes,
        associated_data: bytes,
        data: bytes,
        suite: CryptoSuite,
    ) -> bytes:
        material = associated_data + header + data
        tag = Kdf(suite.digest).hmac_digest(self.mac_key, material)
        return tag[: suite.tag_size]

    def verify_mac(
        self,
        header: bytes,
        associated_data: bytes,
        data: bytes,
        mac: bytes,
        suite: CryptoSuite,
    ) -> None:
        expected = self.compute_mac(header, associated_data, data, suite)
        if not hmac.compare_digest(expected, mac):
            raise InvalidMessage("MAC verification failed")

    def to_bytes(self) -> bytes:
        return (
            encode_bytes(self.cipher_key)
            + encode_bytes(self.mac_key)
            + encode_u32(self.counter)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> MessageKeys:
        cipher_key, offset = read_bytes(data, 0)
        mac_key, offset = read_bytes(data, offset)
        counter, offset = read_u32(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in message keys")
        return cls(
            cipher_key=cipher_key,
            mac_key=mac_key,
            counter=counter,
        )
