"""Classical Double Ratchet crypto suite (base for Triple as well)."""
from __future__ import annotations


from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ratchetkit.algorithms.kem.base import KemBackend
from ratchetkit.algorithms.signing.base import SigningBackend
from ratchetkit.errors import SerializationError
from ratchetkit.packing import (
    Constructor,
    ConstructorId,
    encode_u32,
    read_u32,
)
from ratchetkit.suite.algs import (
    DEFAULT_TAG_SIZE,
    MIN_CIPHER_KEY_BYTES,
    MIN_TAG_SIZE,
    CipherAlg,
    HashAlg,
    KeyExchangeAlg,
    SigningAlg,
)
from ratchetkit.suite.registry import (
    cipher_backend,
    hash_backend,
    key_exchange_backend,
    signing_backend,
)

if TYPE_CHECKING:
    from ratchetkit.keys.identity import IdentityKeyPair
    from ratchetkit.keys.prekey import (
        OneTimePreKey,
        PreKeyBundle,
        SignedPqPreKey,
        SignedPreKey,
    )
from ratchetkit.handshake.x3dh import ExtendedTripleDiffieHellman


@dataclass(frozen=True, kw_only=True)
class CryptoSuiteDoubleRatchet(Constructor):
    """Primitives for X3DH and classical Double Ratchet sessions.

    Agreement and signing are separate: ``key_exchange`` / ``kem`` for
    confidentiality, ``signing`` / ``signer`` for identity authenticity.

    Sizes live on the algorithm classes::

        hash_backend(suite.digest).digest_size
        cipher_backend(suite.cipher).key_size

    Suite dumps write each algorithm as its permanent ``IntEnum`` id (u32).
    """

    digest: HashAlg
    cipher: CipherAlg
    key_exchange: KeyExchangeAlg
    signing: SigningAlg
    tag_size: int = DEFAULT_TAG_SIZE
    kem: KemBackend = field(init=False, repr=False, compare=False)
    signer: SigningBackend = field(init=False, repr=False, compare=False)

    CONSTRUCTOR_ID = ConstructorId.SUITE_DOUBLE

    def __post_init__(self) -> None:
        key_size = cipher_backend(self.cipher).key_size
        if key_size < MIN_CIPHER_KEY_BYTES:
            raise ValueError(
                f"cipher {self.cipher.name!r} key size {key_size} "
                f"is below the {MIN_CIPHER_KEY_BYTES}-byte minimum "
                "(use AES-256, Camellia-256, or ChaCha20)"
            )
        digest_size = hash_backend(self.digest).digest_size
        if self.tag_size < MIN_TAG_SIZE or self.tag_size > digest_size:
            raise ValueError(
                f"tag_size {self.tag_size} out of range "
                f"[{MIN_TAG_SIZE}, {digest_size}] for digest "
                f"{self.digest.name!r}"
            )
        object.__setattr__(
            self,
            "kem",
            key_exchange_backend(self.key_exchange)(),
        )
        object.__setattr__(
            self,
            "signer",
            signing_backend(self.signing)(),
        )

    def handshake(self) -> ExtendedTripleDiffieHellman:
        """Classical X3DH handshake for this suite."""
        from ratchetkit.handshake.x3dh import ExtendedTripleDiffieHellman

        return ExtendedTripleDiffieHellman(self)

    def create_bundle(
        self,
        identity: IdentityKeyPair,
        signed_prekey: SignedPreKey,
        one_time_prekey: OneTimePreKey | None = None,
        pq_prekey: SignedPqPreKey | None = None,
    ) -> PreKeyBundle:
        """Publish a classical X3DH prekey bundle (``pq_prekey`` must be None)."""
        if pq_prekey is not None:
            raise ValueError(
                "CryptoSuiteDoubleRatchet.create_bundle does not take a PQ prekey"
            )
        return self.handshake().create_bundle(
            identity,
            signed_prekey,
            one_time_prekey,
        )

    def to_bytes(self) -> bytes:
        return (
            self.constructor_pack()
            + encode_u32(int(self.digest))
            + encode_u32(int(self.cipher))
            + encode_u32(int(self.key_exchange))
            + encode_u32(int(self.signing))
            + encode_u32(self.tag_size)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> CryptoSuiteDoubleRatchet:
        offset = cls.constructor_expect(data)
        digest_id, offset = read_u32(data, offset)
        cipher_id, offset = read_u32(data, offset)
        kx_id, offset = read_u32(data, offset)
        signing_id, offset = read_u32(data, offset)
        tag_size, offset = read_u32(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in double suite")
        return cls(
            digest=HashAlg.from_id(digest_id),
            cipher=CipherAlg.from_id(cipher_id),
            key_exchange=KeyExchangeAlg.from_id(kx_id),
            signing=SigningAlg.from_id(signing_id),
            tag_size=tag_size,
        )
