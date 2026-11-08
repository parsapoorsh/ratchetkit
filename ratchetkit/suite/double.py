"""Classical Double Ratchet crypto suite (base for Triple as well)."""
from __future__ import annotations


from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ratchetkit.algorithms.kem.base import KemBackend
from ratchetkit.algorithms.signing.base import SigningBackend
from ratchetkit.errors import SerializationError
from ratchetkit.handshake.message import InitialMessageX3DH
from ratchetkit.handshake.x3dh import ExtendedTripleDiffieHellman
from ratchetkit.keys.keypair import PublicKey
from ratchetkit.packing import (
    Constructor,
    ConstructorId,
    encode_u32,
    read_u32,
)
from ratchetkit.ratchet.message.double import DoubleRatchetMessage
from ratchetkit.ratchet.protocol.double import DoubleRatchet
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
        SignedPreKey,
    )
    from ratchetkit.ratchet.message.base import RatchetMessage
    from ratchetkit.session import Session


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

    InitialMessage = InitialMessageX3DH
    Message = DoubleRatchetMessage
    Ratchet = DoubleRatchet

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
        return ExtendedTripleDiffieHellman(self)

    def initiate(
        self,
        our_identity: IdentityKeyPair,
        their_bundle: PreKeyBundle,
    ) -> tuple[Session, InitialMessageX3DH]:
        """Alice: handshake + open a session."""
        from ratchetkit.session import Session

        result = self.handshake().initiate(our_identity, their_bundle)
        if result.ratchet_key is None:
            raise ValueError("handshake result missing ratchet key")
        ratchet = self.Ratchet.initiate(
            self,
            result.shared_secret,
            result.ratchet_key,
            their_bundle.signed_prekey,
        )
        associated = (
            our_identity.signing.public.data + their_bundle.identity_signing.data
        )
        session = Session(
            suite=self,
            ratchet=ratchet,
            associated_data=associated,
        )
        return session, result.initial_message

    def accept(
        self,
        our_identity: IdentityKeyPair,
        our_signed_prekey: SignedPreKey,
        initial: InitialMessageX3DH,
        message: RatchetMessage,
        our_one_time_prekey: OneTimePreKey | None = None,
        associated_data: bytes = b"",
    ) -> tuple[Session, bytes]:
        """Bob: finish handshake, open a session, decrypt the first message.

        ``associated_data`` is extra AD for the first message only; it is
        appended to the handshake identity AD (same rule as Session.decrypt).
        """
        from ratchetkit.session import Session

        if not isinstance(message, self.Message):
            raise TypeError(
                f"{type(self).__name__} requires {self.Message.__name__}"
            )
        shared = self.handshake().respond(
            our_identity,
            our_signed_prekey,
            initial,
            our_one_time_prekey,
        )
        if initial.ratchet_public is None:
            raise ValueError("initial message missing ratchet public")
        their_ratchet = PublicKey(initial.ratchet_public, self.kem.algorithm)
        first_header = None
        if not self.kem.supports_dh:
            first_header = message.ratchet_public
        ratchet = self.Ratchet.accept(
            self,
            shared,
            their_ratchet,
            our_signed_prekey.key_pair,
            first_header=first_header,
        )
        associated = (
            initial.identity_signing.data + our_identity.signing.public.data
        )
        session = Session(
            suite=self,
            ratchet=ratchet,
            associated_data=associated,
        )
        return session, session.decrypt(message, associated_data)

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
