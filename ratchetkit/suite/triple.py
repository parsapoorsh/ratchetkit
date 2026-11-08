"""Triple Ratchet (classical + sparse PQ) crypto suite."""
from __future__ import annotations


from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ratchetkit.algorithms.kem.base import KemBackend
from ratchetkit.errors import InvalidKey, SerializationError
from ratchetkit.handshake.message import InitialMessagePQXDH, InitialMessageX3DH
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.keypair import PublicKey
from ratchetkit.keys.prekey import (
    OneTimePreKey,
    PreKeyBundle,
    SignedPqPreKey,
    SignedPreKey,
)
from ratchetkit.suite import KdfLabel
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
from ratchetkit.suite.registry import hash_backend, key_exchange_backend

if TYPE_CHECKING:
    from ratchetkit.ratchet.message.base import RatchetMessage
    from ratchetkit.session import Session


@dataclass(frozen=True, kw_only=True)
class CryptoSuiteTripleRatchet(CryptoSuiteDoubleRatchet):
    """Classical Double Ratchet plus required Sparse PQ Ratchet half.

    ``pq_key_exchange`` and ``scka_chunks`` are required (no optional PQ).
    Handshakes use PQXDH (classical X3DH DH + signed PQ prekey).
    """

    pq_key_exchange: KeyExchangeAlg
    scka_chunks: int
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

    def create_bundle(
        self,
        identity: IdentityKeyPair,
        signed_prekey: SignedPreKey,
        pq_prekey: SignedPqPreKey,
        one_time_prekey: OneTimePreKey | None = None,
    ) -> PreKeyBundle:
        if pq_prekey.key_pair.public.algorithm != self.pq_kem.algorithm:
            raise InvalidKey(
                f"PQ prekey algorithm {pq_prekey.key_pair.public.algorithm!r} "
                f"does not match pq_kem {self.pq_kem.algorithm!r}"
            )
        bundle = PreKeyBundle.from_local(
            identity,
            signed_prekey,
            one_time_prekey,
            pq_prekey,
        )
        bundle.verify(self)
        return bundle

    def initiate(
        self,
        our_identity: IdentityKeyPair,
        their_bundle: PreKeyBundle,
    ) -> tuple[Session, InitialMessageX3DH]:
        from ratchetkit.session import Session

        if not self.kem.supports_dh:
            raise InvalidKey(
                "PQXDH requires a DH-capable classical key_exchange "
                f"(got {self.kem.algorithm!r})"
            )
        their_bundle.verify(self)
        if their_bundle.pq_prekey is None or their_bundle.pq_prekey_id is None:
            raise InvalidKey("PQXDH requires a PQ prekey on the bundle")
        if their_bundle.pq_prekey.algorithm != self.pq_kem.algorithm:
            raise InvalidKey(
                f"bundle PQ prekey algorithm {their_bundle.pq_prekey.algorithm!r} "
                f"does not match pq_kem {self.pq_kem.algorithm!r}"
            )
        if our_identity.agreement is None:
            raise InvalidKey("DH suite requires identity agreement key")
        if their_bundle.identity_agreement is None:
            raise InvalidKey("bundle missing identity agreement key")

        ephemeral = self.kem.generate_keypair()
        secrets: list[bytes] = [
            self.kem.dh(our_identity.agreement, their_bundle.signed_prekey),
            self.kem.dh(ephemeral, their_bundle.identity_agreement),
            self.kem.dh(ephemeral, their_bundle.signed_prekey),
        ]
        if their_bundle.one_time_prekey is not None:
            secrets.append(
                self.kem.dh(ephemeral, their_bundle.one_time_prekey)
            )
        pq_secret, pq_ciphertext = self.pq_kem.encapsulate(their_bundle.pq_prekey)
        secrets.append(pq_secret)
        shared = self.handshake_secret(secrets, KdfLabel.PQXDH)
        ratchet_key = self.kem.generate_keypair()
        identity_agreement = our_identity.agreement.public
        to_sign = InitialMessagePQXDH.signed_material(
            identity_agreement_data=identity_agreement.data,
            ephemeral_public=ephemeral.public.data,
            signed_prekey_public=their_bundle.signed_prekey.data,
            kem_ciphertexts=[],
            ratchet_public=ratchet_key.public.data,
            pq_ciphertext=pq_ciphertext,
        )
        signature = self.signer.sign(
            our_identity.signing,
            to_sign,
            hash_backend(self.digest),
        )
        initial = InitialMessagePQXDH(
            identity_signing=our_identity.signing.public,
            identity_agreement=identity_agreement,
            ephemeral_public=ephemeral.public,
            kem_ciphertexts=(),
            signed_prekey_id=their_bundle.signed_prekey_id,
            one_time_prekey_id=their_bundle.one_time_prekey_id,
            signature=signature,
            ratchet_public=ratchet_key.public.data,
            pq_prekey_id=their_bundle.pq_prekey_id,
            pq_ciphertext=pq_ciphertext,
        )
        ratchet = TripleRatchet.initiate(
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

    def generate_pq_prekey(
        self,
        key_id: int,
        identity: IdentityKeyPair,
    ) -> SignedPqPreKey:
        """Generate a signed PQ prekey with this suite's ``pq_kem``."""
        return SignedPqPreKey.generate(key_id, identity, self, self.pq_kem)

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
        """Bob: PQXDH respond + Triple Ratchet. ``our_pq_prekey`` is required."""
        from ratchetkit.session import Session

        if our_pq_prekey is None:
            raise ValueError(
                "accept on a Triple suite requires our_pq_prekey"
            )
        if not isinstance(message, TripleRatchetMessage):
            raise TypeError(
                f"{type(self).__name__} requires TripleRatchetMessage"
            )
        if not isinstance(initial, InitialMessagePQXDH):
            raise ValueError(
                "accept on a Triple suite requires InitialMessagePQXDH"
            )
        if not initial.pq_ciphertext:
            raise InvalidKey("PQXDH initial message missing pq_ciphertext")
        if our_pq_prekey.key_pair.public.algorithm != self.pq_kem.algorithm:
            raise InvalidKey(
                f"local PQ prekey algorithm "
                f"{our_pq_prekey.key_pair.public.algorithm!r} "
                f"does not match pq_kem {self.pq_kem.algorithm!r}"
            )
        if our_identity.agreement is None:
            raise InvalidKey("DH suite requires identity agreement key")
        if initial.identity_agreement is None:
            raise InvalidKey("initial message missing identity agreement key")
        if initial.signed_prekey_id != our_signed_prekey.key_id:
            raise InvalidKey("signed prekey id mismatch")
        if our_one_time_prekey is not None:
            if initial.one_time_prekey_id != our_one_time_prekey.key_id:
                raise InvalidKey("one-time prekey id mismatch")
        elif initial.one_time_prekey_id is not None:
            raise InvalidKey("one-time prekey was used but not provided")
        if initial.pq_prekey_id != our_pq_prekey.key_id:
            raise InvalidKey("PQ prekey id mismatch")
        self.validate_initial_algorithms(initial)
        to_verify = InitialMessagePQXDH.signed_material(
            identity_agreement_data=initial.identity_agreement.data,
            ephemeral_public=initial.ephemeral_public.data,
            signed_prekey_public=our_signed_prekey.key_pair.public.data,
            kem_ciphertexts=initial.kem_ciphertexts,
            ratchet_public=initial.ratchet_public or b"",
            pq_ciphertext=initial.pq_ciphertext,
        )
        self.signer.verify(
            initial.identity_signing,
            to_verify,
            initial.signature,
            hash_backend(self.digest),
        )
        secrets: list[bytes] = [
            self.kem.dh(
                our_signed_prekey.key_pair,
                initial.identity_agreement,
            ),
            self.kem.dh(
                our_identity.agreement,
                initial.ephemeral_public,
            ),
            self.kem.dh(
                our_signed_prekey.key_pair,
                initial.ephemeral_public,
            ),
        ]
        if our_one_time_prekey is not None:
            secrets.append(
                self.kem.dh(
                    our_one_time_prekey.key_pair,
                    initial.ephemeral_public,
                )
            )
        secrets.append(
            self.pq_kem.decapsulate(
                our_pq_prekey.key_pair,
                initial.pq_ciphertext,
            )
        )
        shared = self.handshake_secret(secrets, KdfLabel.PQXDH)
        if initial.ratchet_public is None:
            raise ValueError("initial message missing ratchet public")
        their_ratchet = PublicKey(initial.ratchet_public, self.kem.algorithm)
        ratchet = TripleRatchet.accept(
            self,
            shared,
            their_ratchet,
            our_signed_prekey.key_pair,
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
