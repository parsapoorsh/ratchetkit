"""Classical Double Ratchet crypto suite (base for Triple as well)."""
from __future__ import annotations


from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ratchetkit.algorithms.kem.base import KemBackend
from ratchetkit.algorithms.signing.base import SigningBackend
from ratchetkit.errors import SerializationError
from ratchetkit.handshake.message import InitialMessageX3DH
from ratchetkit.handshake.x3dh import (
    ExtendedTripleDiffieHellman,
    ExtendedTripleDiffieHellmanResult,
)
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
        SignedPqPreKey,
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
        """Classical X3DH handshake for this suite."""
        from ratchetkit.handshake.x3dh import ExtendedTripleDiffieHellman

        return ExtendedTripleDiffieHellman(self)

    def create_bundle(
        self,
        identity: IdentityKeyPair,
        signed_prekey: SignedPreKey,
        one_time_prekey: OneTimePreKey | None = None,
    ) -> PreKeyBundle:
        """Publish a classical X3DH prekey bundle."""
        return self.handshake().create_bundle(
            identity,
            signed_prekey,
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
        """Finish the suite handshake; returns the shared secret."""
        return self.handshake().respond(
            our_identity,
            our_signed_prekey,
            initial,
            our_one_time_prekey,
        )

    def open_initiate(
        self,
        result: ExtendedTripleDiffieHellmanResult,
        their_bundle: PreKeyBundle,
    ) -> DoubleRatchet:
        """Alice: open a Double Ratchet from the handshake result."""
        if result.ratchet_key is None:
            raise ValueError("handshake result missing ratchet key")
        return DoubleRatchet.initiate(
            self,
            result.shared_secret,
            result.ratchet_key,
            their_bundle.signed_prekey,
        )

    def open_accept(
        self,
        shared_secret: bytes,
        initial: InitialMessageX3DH,
        message: DoubleRatchetMessage,
        our_signed_prekey: SignedPreKey,
    ) -> DoubleRatchet:
        """Bob: open a Double Ratchet after handshake respond."""
        if initial.ratchet_public is None:
            raise ValueError("initial message missing ratchet public")
        their_ratchet = PublicKey(initial.ratchet_public, self.kem.algorithm)
        first_header = None
        if not self.kem.supports_dh:
            first_header = message.ratchet_public
        return DoubleRatchet.accept(
            self,
            shared_secret,
            their_ratchet,
            our_signed_prekey.key_pair,
            first_header=first_header,
        )

    def load_ratchet(self, data: bytes) -> DoubleRatchet:
        """Restore ratchet state saved by ``Ratchet.to_bytes``."""
        return DoubleRatchet.from_bytes(data, self)

    def initiate(
        self,
        our_identity: IdentityKeyPair,
        their_bundle: PreKeyBundle,
    ) -> tuple[Session, InitialMessageX3DH]:
        """Alice: handshake + open a session."""
        from ratchetkit.session import Session

        result = self.handshake().initiate(our_identity, their_bundle)
        ratchet = self.open_initiate(result, their_bundle)
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
        our_pq_prekey: SignedPqPreKey | None = None,
    ) -> tuple[Session, bytes]:
        """Bob: finish handshake, open a session, decrypt the first message.

        ``associated_data`` is extra AD for the first message only; it is
        appended to the handshake identity AD (same rule as Session.decrypt).

        Triple / PQXDH sessions require ``our_pq_prekey`` matching the bundle.
        """
        from ratchetkit.session import Session

        if not isinstance(message, self.Message):
            raise TypeError(
                f"{type(self).__name__} requires {self.Message.__name__}"
            )
        shared = self.respond_handshake(
            our_identity,
            our_signed_prekey,
            initial,
            our_one_time_prekey,
            our_pq_prekey,
        )
        ratchet = self.open_accept(
            shared,
            initial,
            message,
            our_signed_prekey,
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
