"""Classical Double Ratchet crypto suite (base for Triple as well)."""
from __future__ import annotations


from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ratchetkit.algorithms.kem.base import KemBackend
from ratchetkit.algorithms.signing.base import SigningBackend
from ratchetkit.errors import InvalidKey, InvalidSignature, SerializationError
from ratchetkit.handshake.message import InitialMessagePQXDH, InitialMessageX3DH
from ratchetkit.kdf import Kdf
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.keypair import PublicKey
from ratchetkit.keys.prekey import OneTimePreKey, PreKeyBundle, SignedPreKey
from ratchetkit.packing import (
    Constructor,
    ConstructorId,
    encode_u32,
    read_u32,
)
from ratchetkit.ratchet.message.base import RatchetMessage
from ratchetkit.ratchet.message.double import DoubleRatchetMessage
from ratchetkit.ratchet.protocol.double import DoubleRatchet
from ratchetkit.suite import KdfLabel
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

    def create_bundle(
        self,
        identity: IdentityKeyPair,
        signed_prekey: SignedPreKey,
        one_time_prekey: OneTimePreKey | None = None,
    ) -> PreKeyBundle:
        bundle = PreKeyBundle.from_local(identity, signed_prekey, one_time_prekey)
        bundle.verify(self)
        return bundle

    def initiate(
        self,
        our_identity: IdentityKeyPair,
        their_bundle: PreKeyBundle,
    ) -> tuple[Session, InitialMessageX3DH]:
        """Alice: X3DH + open a Double Ratchet session."""
        from ratchetkit.session import Session

        their_bundle.verify(self)
        if their_bundle.pq_prekey is not None:
            raise InvalidKey("X3DH cannot use a PQ prekey bundle")

        secrets: list[bytes] = []
        kem_ciphertexts: list[bytes] = []
        ephemeral = self.kem.generate_keypair()

        if self.kem.supports_dh:
            if our_identity.agreement is None:
                raise InvalidKey("DH suite requires identity agreement key")
            if their_bundle.identity_agreement is None:
                raise InvalidKey("bundle missing identity agreement key")
            secrets.append(
                self.kem.dh(our_identity.agreement, their_bundle.signed_prekey)
            )
            secrets.append(
                self.kem.dh(ephemeral, their_bundle.identity_agreement)
            )
            secrets.append(
                self.kem.dh(ephemeral, their_bundle.signed_prekey)
            )
            if their_bundle.one_time_prekey is not None:
                secrets.append(
                    self.kem.dh(ephemeral, their_bundle.one_time_prekey)
                )
        else:
            if their_bundle.one_time_prekey is None:
                raise InvalidKey(
                    "KEM suites require a one-time prekey for forward secrecy"
                )
            secret, ct = self.kem.encapsulate(their_bundle.signed_prekey)
            secrets.append(secret)
            kem_ciphertexts.append(ct)
            secret, ct = self.kem.encapsulate(their_bundle.one_time_prekey)
            secrets.append(secret)
            kem_ciphertexts.append(ct)

        shared = self.handshake_secret(secrets, KdfLabel.X3DH)
        ratchet_key = self.kem.generate_keypair()
        identity_agreement = (
            our_identity.agreement.public
            if our_identity.agreement is not None
            else None
        )
        to_sign = InitialMessageX3DH.signed_material(
            identity_agreement_data=(
                identity_agreement.data if identity_agreement is not None else b""
            ),
            ephemeral_public=ephemeral.public.data,
            signed_prekey_public=their_bundle.signed_prekey.data,
            kem_ciphertexts=kem_ciphertexts,
            ratchet_public=ratchet_key.public.data,
        )
        signature = self.signer.sign(
            our_identity.signing,
            to_sign,
            hash_backend(self.digest),
        )
        initial = InitialMessageX3DH(
            identity_signing=our_identity.signing.public,
            identity_agreement=identity_agreement,
            ephemeral_public=ephemeral.public,
            kem_ciphertexts=tuple(kem_ciphertexts),
            signed_prekey_id=their_bundle.signed_prekey_id,
            one_time_prekey_id=their_bundle.one_time_prekey_id,
            signature=signature,
            ratchet_public=ratchet_key.public.data,
        )
        ratchet = DoubleRatchet.initiate(
            self,
            shared,
            ratchet_key,
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
        return session, initial

    def accept(
        self,
        our_identity: IdentityKeyPair,
        our_signed_prekey: SignedPreKey,
        initial: InitialMessageX3DH,
        message: RatchetMessage,
        our_one_time_prekey: OneTimePreKey | None = None,
        associated_data: bytes = b"",
    ) -> tuple[Session, bytes]:
        """Bob: finish X3DH, open a session, decrypt the first message."""
        from ratchetkit.session import Session

        if not isinstance(message, DoubleRatchetMessage):
            raise TypeError(
                f"{type(self).__name__} requires DoubleRatchetMessage"
            )
        if isinstance(initial, InitialMessagePQXDH):
            raise InvalidKey("X3DH cannot accept a PQXDH initial message")
        if initial.signed_prekey_id != our_signed_prekey.key_id:
            raise InvalidKey("signed prekey id mismatch")
        if our_one_time_prekey is not None:
            if initial.one_time_prekey_id != our_one_time_prekey.key_id:
                raise InvalidKey("one-time prekey id mismatch")
        elif initial.one_time_prekey_id is not None:
            raise InvalidKey("one-time prekey was used but not provided")
        self.validate_initial_algorithms(initial)
        agreement_data = (
            initial.identity_agreement.data
            if initial.identity_agreement is not None
            else b""
        )
        to_verify = InitialMessageX3DH.signed_material(
            identity_agreement_data=agreement_data,
            ephemeral_public=initial.ephemeral_public.data,
            signed_prekey_public=our_signed_prekey.key_pair.public.data,
            kem_ciphertexts=initial.kem_ciphertexts,
            ratchet_public=initial.ratchet_public or b"",
        )
        self.signer.verify(
            initial.identity_signing,
            to_verify,
            initial.signature,
            hash_backend(self.digest),
        )

        secrets: list[bytes] = []
        if self.kem.supports_dh:
            if our_identity.agreement is None:
                raise InvalidKey("DH suite requires identity agreement key")
            if initial.identity_agreement is None:
                raise InvalidKey("initial message missing identity agreement key")
            secrets.append(
                self.kem.dh(
                    our_signed_prekey.key_pair,
                    initial.identity_agreement,
                )
            )
            secrets.append(
                self.kem.dh(
                    our_identity.agreement,
                    initial.ephemeral_public,
                )
            )
            secrets.append(
                self.kem.dh(
                    our_signed_prekey.key_pair,
                    initial.ephemeral_public,
                )
            )
            if our_one_time_prekey is not None:
                secrets.append(
                    self.kem.dh(
                        our_one_time_prekey.key_pair,
                        initial.ephemeral_public,
                    )
                )
        else:
            if our_one_time_prekey is None:
                raise InvalidKey(
                    "KEM suites require a one-time prekey for forward secrecy"
                )
            cts = list(initial.kem_ciphertexts)
            if len(cts) < 2:
                raise InvalidKey("KEM initial message missing SPK/OPK ciphertexts")
            secrets.append(
                self.kem.decapsulate(our_signed_prekey.key_pair, cts[0])
            )
            secrets.append(
                self.kem.decapsulate(our_one_time_prekey.key_pair, cts[1])
            )
        shared = self.handshake_secret(secrets, KdfLabel.X3DH)
        if initial.ratchet_public is None:
            raise ValueError("initial message missing ratchet public")
        their_ratchet = PublicKey(initial.ratchet_public, self.kem.algorithm)
        first_header = None
        if not self.kem.supports_dh:
            first_header = message.ratchet_public
        ratchet = DoubleRatchet.accept(
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

    def validate_initial_algorithms(self, initial_message: InitialMessageX3DH) -> None:
        if initial_message.identity_signing.algorithm != self.signing:
            raise InvalidKey(
                f"initial message identity signing algorithm "
                f"{initial_message.identity_signing.algorithm!r} "
                f"does not match suite {self.signing!r}"
            )
        expected = self.kem.algorithm
        checks = [
            ("ephemeral", initial_message.ephemeral_public.algorithm),
        ]
        if initial_message.identity_agreement is not None:
            checks.append(
                ("identity agreement", initial_message.identity_agreement.algorithm)
            )
        for label, algorithm in checks:
            if algorithm != expected:
                raise InvalidKey(
                    f"initial message {label} algorithm {algorithm!r} "
                    f"does not match suite {expected!r}"
                )

    def handshake_secret(self, secrets: list[bytes], info: bytes) -> bytes:
        if not secrets:
            raise InvalidKey("no handshake secrets to combine")
        for index, secret in enumerate(secrets):
            if not isinstance(secret, (bytes, bytearray)) or not secret:
                raise InvalidKey(f"handshake secret {index} is empty")
            if not any(secret):
                raise InvalidKey(f"handshake secret {index} is all zeros")
        size = hash_backend(self.digest).digest_size
        prefix = b"\xff" * size
        ikm = prefix + b"".join(bytes(s) for s in secrets)
        return Kdf(self.digest).hkdf(ikm, size, salt=None, info=info)

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
