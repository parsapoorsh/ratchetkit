"""Triple Ratchet (classical + sparse PQ) crypto suite."""
from __future__ import annotations


from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ratchetkit.algorithms.kem.base import KemBackend
from ratchetkit.errors import SerializationError
from ratchetkit.packing import (
    ConstructorId,
    encode_u32,
    expect_constructor,
    pack_constructor,
    read_u32,
)
from ratchetkit.suite.algs import (
    DEFAULT_SCKA_CHUNKS,
    CipherAlg,
    HashAlg,
    KeyExchangeAlg,
    SigningAlg,
)
from ratchetkit.suite.double import CryptoSuiteDoubleRatchet
from ratchetkit.suite.registry import key_exchange_backend

if TYPE_CHECKING:
    from ratchetkit.keys.identity import IdentityKeyPair
    from ratchetkit.keys.prekey import (
        OneTimePreKey,
        PreKeyBundle,
        SignedPqPreKey,
        SignedPreKey,
    )
from ratchetkit.handshake.pqxdh import PostQuantumExtendedDiffieHellman


@dataclass(frozen=True, kw_only=True)
class CryptoSuiteTripleRatchet(CryptoSuiteDoubleRatchet):
    """Classical Double Ratchet plus required Sparse PQ Ratchet half.

    ``pq_key_exchange`` and ``scka_chunks`` are required (no optional PQ).
    Handshakes use PQXDH (classical X3DH DH + signed PQ prekey).
    """

    pq_key_exchange: KeyExchangeAlg
    scka_chunks: int = DEFAULT_SCKA_CHUNKS
    pq_kem: KemBackend = field(init=False, repr=False, compare=False)

    CONSTRUCTOR_ID = ConstructorId.SUITE_TRIPLE

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.scka_chunks < 1:
            raise ValueError("scka_chunks must be at least 1")
        object.__setattr__(
            self,
            "pq_kem",
            key_exchange_backend(self.pq_key_exchange)(),
        )

    def handshake(self) -> PostQuantumExtendedDiffieHellman:
        """PQXDH handshake for this suite (classical DH + PQ KEM)."""
        from ratchetkit.handshake.pqxdh import PostQuantumExtendedDiffieHellman

        return PostQuantumExtendedDiffieHellman(self, self.pq_kem)

    def generate_pq_prekey(
        self,
        key_id: int,
        identity: IdentityKeyPair,
    ) -> SignedPqPreKey:
        """Generate a signed PQ prekey with this suite's ``pq_kem``."""
        from ratchetkit.keys.prekey import SignedPqPreKey

        return SignedPqPreKey.generate(key_id, identity, self.pq_kem)

    def create_bundle(
        self,
        identity: IdentityKeyPair,
        signed_prekey: SignedPreKey,
        one_time_prekey: OneTimePreKey | None = None,
        pq_prekey: SignedPqPreKey | None = None,
    ) -> PreKeyBundle:
        """Publish a PQXDH prekey bundle (requires ``pq_prekey`` private stay local)."""
        if pq_prekey is None:
            raise ValueError(
                "CryptoSuiteTripleRatchet.create_bundle requires pq_prekey "
                "(use suite.generate_pq_prekey(key_id, identity))"
            )
        return self.handshake().create_bundle(
            identity,
            signed_prekey,
            one_time_prekey,
            pq_prekey,
        )

    def to_bytes(self) -> bytes:
        return (
            pack_constructor(self.CONSTRUCTOR_ID)
            + encode_u32(int(self.digest))
            + encode_u32(int(self.cipher))
            + encode_u32(int(self.key_exchange))
            + encode_u32(int(self.signing))
            + encode_u32(self.tag_size)
            + encode_u32(int(self.pq_key_exchange))
            + encode_u32(self.scka_chunks)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> CryptoSuiteTripleRatchet:
        offset = expect_constructor(data, cls.CONSTRUCTOR_ID)
        digest_id, offset = read_u32(data, offset)
        cipher_id, offset = read_u32(data, offset)
        kx_id, offset = read_u32(data, offset)
        signing_id, offset = read_u32(data, offset)
        tag_size, offset = read_u32(data, offset)
        pq_id, offset = read_u32(data, offset)
        chunks, offset = read_u32(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in triple suite")
        return cls(
            digest=HashAlg.from_id(digest_id),
            cipher=CipherAlg.from_id(cipher_id),
            key_exchange=KeyExchangeAlg.from_id(kx_id),
            signing=SigningAlg.from_id(signing_id),
            tag_size=tag_size,
            pq_key_exchange=KeyExchangeAlg.from_id(pq_id),
            scka_chunks=chunks,
        )
