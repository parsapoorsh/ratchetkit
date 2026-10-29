"""Key material: agreement and signing public keys / key pairs.

Agreement and signing share the same wire shape (alg id + bytes) via base
classes; concrete types pin the algorithm family so ids stay 1..N per enum.
"""
from __future__ import annotations


from dataclasses import dataclass

from ratchetkit.errors import SerializationError
from ratchetkit.packing import encode_bytes, encode_u32, read_bytes, read_u32
from ratchetkit.suite.algs import KeyExchangeAlg, SigningAlg


@dataclass(frozen=True)
class PublicKeyBase:
    """Opaque public key bytes plus a permanent algorithm id."""

    data: bytes

    def encode_body(self) -> bytes:
        return encode_u32(int(self.algorithm)) + encode_bytes(self.data)

    def to_bytes(self) -> bytes:
        return self.encode_body()

    @staticmethod
    def read_body(
        data: bytes | memoryview,
        offset: int = 0,
    ) -> tuple[int, bytes, int]:
        """Return ``(alg_id, key_data, next_offset)``."""
        alg_id, offset = read_u32(data, offset)
        key_data, offset = read_bytes(data, offset)
        return alg_id, key_data, offset

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PublicKeyBase):
            return NotImplemented
        if type(self) is not type(other):
            return NotImplemented
        return self.algorithm == other.algorithm and self.data == other.data

    def __hash__(self) -> int:
        return hash((type(self), int(self.algorithm), self.data))


@dataclass(frozen=True)
class PublicKey(PublicKeyBase):
    """Agreement (KEM / DH) public key."""

    algorithm: KeyExchangeAlg

    @classmethod
    def from_bytes(cls, data: bytes) -> PublicKey:
        alg_id, key_data, offset = cls.read_body(data)
        if offset != len(data):
            raise SerializationError("trailing bytes in public key")
        return cls(data=key_data, algorithm=KeyExchangeAlg.from_id(alg_id))


@dataclass(frozen=True)
class SigningPublicKey(PublicKeyBase):
    """Signature public key."""

    algorithm: SigningAlg

    @classmethod
    def from_bytes(cls, data: bytes) -> SigningPublicKey:
        alg_id, key_data, offset = cls.read_body(data)
        if offset != len(data):
            raise SerializationError("trailing bytes in signing public key")
        return cls(data=key_data, algorithm=SigningAlg.from_id(alg_id))


@dataclass(frozen=True)
class KeyPairBase:
    """Private key material; public half is derived from the matching backend."""

    private: bytes

    def encode_body(self) -> bytes:
        return encode_u32(int(self.algorithm)) + encode_bytes(self.private)

    def to_bytes(self) -> bytes:
        return self.encode_body()

    @staticmethod
    def read_body(
        data: bytes | memoryview,
        offset: int = 0,
    ) -> tuple[int, bytes, int]:
        """Return ``(alg_id, private, next_offset)``."""
        alg_id, offset = read_u32(data, offset)
        private, offset = read_bytes(data, offset)
        return alg_id, private, offset

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KeyPairBase):
            return NotImplemented
        if type(self) is not type(other):
            return NotImplemented
        return self.algorithm == other.algorithm and self.private == other.private

    def __hash__(self) -> int:
        return hash((type(self), int(self.algorithm), self.private))


@dataclass(frozen=True)
class KeyPair(KeyPairBase):
    """Agreement (KEM / DH) private key; ``public`` via KEM ``derive_public``."""

    algorithm: KeyExchangeAlg

    @property
    def public(self) -> PublicKey:
        # Import here so suite.backends can load KEM modules that import KeyPair.
        from ratchetkit.suite.registry import key_exchange_backend

        data = key_exchange_backend(self.algorithm)().derive_public(self.private)
        return PublicKey(data=data, algorithm=self.algorithm)

    @classmethod
    def from_bytes(cls, data: bytes) -> KeyPair:
        alg_id, private, offset = cls.read_body(data)
        if offset != len(data):
            raise SerializationError("trailing bytes in key pair")
        return cls(private=private, algorithm=KeyExchangeAlg.from_id(alg_id))


@dataclass(frozen=True)
class SigningKeyPair(KeyPairBase):
    """Signing private key; ``public`` via signing ``derive_public``."""

    algorithm: SigningAlg

    @property
    def public(self) -> SigningPublicKey:
        from ratchetkit.suite.registry import signing_backend

        data = signing_backend(self.algorithm)().derive_public(self.private)
        return SigningPublicKey(data=data, algorithm=self.algorithm)

    @classmethod
    def from_bytes(cls, data: bytes) -> SigningKeyPair:
        alg_id, private, offset = cls.read_body(data)
        if offset != len(data):
            raise SerializationError("trailing bytes in signing key pair")
        return cls(private=private, algorithm=SigningAlg.from_id(alg_id))
