"""Key material: agreement and signing public keys / key pairs.

Agreement and signing share the same wire shape via base classes; concrete
types pin the algorithm family. A key pair always carries its public half
(set when the key is generated), so no backend lookup is needed on access.
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

    def to_bytes(self) -> bytes:
        return encode_u32(int(self.algorithm)) + encode_bytes(self.data)

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
    """Private key material plus the matching public key (no runtime derive)."""

    private: bytes

    def to_bytes(self) -> bytes:
        return (
            encode_u32(int(self.public.algorithm))
            + encode_bytes(self.private)
            + encode_bytes(self.public.data)
        )

    @staticmethod
    def read_body(
        data: bytes | memoryview,
        offset: int = 0,
    ) -> tuple[int, bytes, bytes, int]:
        """Return ``(alg_id, private, public_data, next_offset)``."""
        alg_id, offset = read_u32(data, offset)
        private, offset = read_bytes(data, offset)
        public_data, offset = read_bytes(data, offset)
        return alg_id, private, public_data, offset

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KeyPairBase):
            return NotImplemented
        if type(self) is not type(other):
            return NotImplemented
        return (
            self.private == other.private
            and self.public == other.public
        )

    def __hash__(self) -> int:
        return hash((type(self), self.private, self.public))


@dataclass(frozen=True)
class KeyPair(KeyPairBase):
    """Agreement (KEM / DH) key pair."""

    public: PublicKey

    @property
    def algorithm(self) -> KeyExchangeAlg:
        return self.public.algorithm

    @classmethod
    def from_bytes(cls, data: bytes) -> KeyPair:
        alg_id, private, public_data, offset = cls.read_body(data)
        if offset != len(data):
            raise SerializationError("trailing bytes in key pair")
        algorithm = KeyExchangeAlg.from_id(alg_id)
        return cls(
            private=private,
            public=PublicKey(data=public_data, algorithm=algorithm),
        )


@dataclass(frozen=True)
class SigningKeyPair(KeyPairBase):
    """Signing key pair."""

    public: SigningPublicKey

    @property
    def algorithm(self) -> SigningAlg:
        return self.public.algorithm

    @classmethod
    def from_bytes(cls, data: bytes) -> SigningKeyPair:
        alg_id, private, public_data, offset = cls.read_body(data)
        if offset != len(data):
            raise SerializationError("trailing bytes in signing key pair")
        algorithm = SigningAlg.from_id(alg_id)
        return cls(
            private=private,
            public=SigningPublicKey(data=public_data, algorithm=algorithm),
        )
