"""Triple Ratchet (classical + sparse PQ) crypto suite."""
from __future__ import annotations


from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ratchetkit.algorithms.kem.base import KemBackend
from ratchetkit.errors import SerializationError
from ratchetkit.handshake.message import InitialMessagePQXDH, InitialMessageX3DH
from ratchetkit.handshake.pqxdh import PostQuantumExtendedDiffieHellman
from ratchetkit.handshake.x3dh import ExtendedTripleDiffieHellmanResult
from ratchetkit.keys.keypair import PublicKey
from ratchetkit.packing import (
    ConstructorId,
    encode_u32,
    read_u32,
)
from ratchetkit.ratchet.message.triple import TripleRatchetMessage
from ratchetkit.ratchet.protocol.triple import TripleRatchet
from ratchetkit.suite.algs import (
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


@dataclass(frozen=True, kw_only=True)
class CryptoSuiteTripleRatchet(CryptoSuiteDoubleRatchet):
    """Classical Double Ratchet plus required Sparse PQ Ratchet half.

    ``pq_key_exchange`` and ``scka_chunks`` are required (no optional PQ).
    Handshakes use PQXDH (classical X3DH DH + signed PQ prekey).
    """

    pq_key_exchange: KeyExchangeAlg
    scka_chunks: int
    pq_kem: KemBackend = field(init=False, repr=False, compare=False)

    InitialMessage = InitialMessagePQXDH
    Message = TripleRatchetMessage
    Ratchet = TripleRatchet

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

        return SignedPqPreKey.generate(key_id, identity, self, self.pq_kem)

    def create_bundle(
        self,
        identity: IdentityKeyPair,
        signed_prekey: SignedPreKey,
        pq_prekey: SignedPqPreKey,
        one_time_prekey: OneTimePreKey | None = None,
    ) -> PreKeyBundle:
        """Publish a PQXDH prekey bundle (``pq_prekey`` private stays local)."""
        return self.handshake().create_bundle(
            identity,
            signed_prekey,
            pq_prekey,
            one_time_prekey,
        )

    def respond_handshake(
        self,
        our_identity: IdentityKeyPair,
        our_signed_prekey: SignedPreKey,
        initial: InitialMessageX3DH,
        our_one_time_prekey: OneTimePreKey | None = None,
        our_pq_prekey: SignedPqPreKey | None = None,
    ) -> bytes:
        """Finish PQXDH; ``our_pq_prekey`` is required."""
        if our_pq_prekey is None:
            raise ValueError(
                "accept on a Triple suite requires our_pq_prekey"
            )
        if not isinstance(initial, InitialMessagePQXDH):
            raise ValueError(
                "accept on a Triple suite requires InitialMessagePQXDH"
            )
        return self.handshake().respond(
            our_identity,
            our_signed_prekey,
            initial,
            our_pq_prekey,
            our_one_time_prekey,
        )

    def open_initiate(
        self,
        result: ExtendedTripleDiffieHellmanResult,
        their_bundle: PreKeyBundle,
    ) -> TripleRatchet:
        """Alice: open a Triple Ratchet from the handshake result."""
        if result.ratchet_key is None:
            raise ValueError("handshake result missing ratchet key")
        return TripleRatchet.initiate(
            self,
            result.shared_secret,
            result.ratchet_key,
            their_bundle.signed_prekey,
            self.pq_kem,
            n_chunks=self.scka_chunks,
        )

    def open_accept(
        self,
        shared_secret: bytes,
        initial: InitialMessageX3DH,
        message: TripleRatchetMessage,
        our_signed_prekey: SignedPreKey,
    ) -> TripleRatchet:
        """Bob: open a Triple Ratchet after handshake respond."""
        if initial.ratchet_public is None:
            raise ValueError("initial message missing ratchet public")
        their_ratchet = PublicKey(initial.ratchet_public, self.kem.algorithm)
        return TripleRatchet.accept(
            self,
            shared_secret,
            their_ratchet,
            our_signed_prekey.key_pair,
            self.pq_kem,
            n_chunks=self.scka_chunks,
        )

    def load_ratchet(self, data: bytes) -> TripleRatchet:
        """Restore Triple Ratchet state saved by ``Ratchet.to_bytes``."""
        return TripleRatchet.from_bytes(data, self)

    def to_bytes(self) -> bytes:
        return (
            self.constructor_pack()
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
        offset = cls.constructor_expect(data)
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
