"""Signed prekeys, one-time prekeys, and published bundles."""
from __future__ import annotations


import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.errors import InvalidSignature, SerializationError
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.keypair import (
    KeyPair,
    PublicKey,
    SigningPublicKey,
)
from ratchetkit.packing import (
    Constructor,
    ConstructorId,
    encode_u32,
    read_u32,
)
from ratchetkit.suite.algs import KeyExchangeAlg, SigningAlg
from ratchetkit.suite.registry import hash_backend

if TYPE_CHECKING:
    from ratchetkit.algorithms.kem.base import KemBackend
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite


@dataclass
class SignedPreKey:
    key_pair: KeyPair
    signature: bytes

    @staticmethod
    def signed_material(public: PublicKey) -> bytes:
        """Transcript bytes covered by the SPK signature.

        Binds the algorithm id to the key bytes so a peer cannot relabel
        the same point as a different primitive.
        """
        return encode_u32(int(public.algorithm)) + public.data

    @classmethod
    def generate(cls, identity: IdentityKeyPair) -> SignedPreKey:
        suite = identity.require_suite()
        pair = suite.kem.generate_keypair()
        signature = suite.signer.sign(
            identity.signing,
            cls.signed_material(pair.public),
            hash_backend(suite.digest),
        )
        return cls(key_pair=pair, signature=signature)


@dataclass
class OneTimePreKey:
    key_pair: KeyPair

    @classmethod
    def generate(
        cls,
        suite: CryptoSuite | None = None,
        identity: IdentityKeyPair | None = None,
    ) -> OneTimePreKey:
        if suite is None:
            if identity is None:
                raise ValueError("need suite or identity")
            suite = identity.require_suite()
        return cls(key_pair=suite.kem.generate_keypair())


@dataclass
class SignedPqPreKey:
    """Long-lived post-quantum KEM prekey signed by the identity key.

    Used by PQXDH (classical X3DH DH secrets + one PQ encapsulation). The KEM
    backend is typically ML-KEM-768/1024 and may differ from the classical
    ``suite.kem`` used for identity / signed prekey.
    """

    key_pair: KeyPair
    signature: bytes

    @staticmethod
    def signed_material(public: PublicKey) -> bytes:
        """Transcript bytes covered by the PQ prekey signature."""
        return encode_u32(int(public.algorithm)) + public.data

    @classmethod
    def generate(
        cls,
        identity: IdentityKeyPair,
        pq_kem: KemBackend | None = None,
    ) -> SignedPqPreKey:
        suite = identity.require_suite()
        if pq_kem is None:
            from ratchetkit.suite.triple import CryptoSuiteTripleRatchet

            if isinstance(suite, CryptoSuiteTripleRatchet):
                pq_kem = suite.pq_kem
            else:
                raise ValueError(
                    "pq_kem is required when the suite has no pq_key_exchange"
                )
        pair = pq_kem.generate_keypair()
        signature = suite.signer.sign(
            identity.signing,
            cls.signed_material(pair.public),
            hash_backend(suite.digest),
        )
        return cls(key_pair=pair, signature=signature)


@dataclass(frozen=True)
class PreKeyBundle(Constructor):
    """Public material a peer publishes for X3DH / PQXDH initiation."""

    identity_signing: SigningPublicKey
    identity_agreement: PublicKey | None
    signed_prekey: PublicKey
    signed_prekey_signature: bytes
    one_time_prekey: PublicKey
    pq_prekey: PublicKey | None = None
    pq_prekey_signature: bytes | None = None

    def verify(self, suite: CryptoSuite) -> None:
        if self.identity_signing.algorithm != suite.signing:
            raise InvalidSignature(
                f"identity signing algorithm {self.identity_signing.algorithm!r} "
                f"does not match suite {suite.signing!r}"
            )
        expected_kx = suite.kem.algorithm
        if self.signed_prekey.algorithm != expected_kx:
            raise InvalidSignature(
                f"signed prekey algorithm {self.signed_prekey.algorithm!r} "
                f"does not match suite {expected_kx!r}"
            )
        if (
            self.identity_agreement is not None
            and self.identity_agreement.algorithm != expected_kx
        ):
            raise InvalidSignature(
                f"identity agreement algorithm "
                f"{self.identity_agreement.algorithm!r} "
                f"does not match suite {expected_kx!r}"
            )
        if self.one_time_prekey.algorithm != expected_kx:
            raise InvalidSignature(
                f"one-time prekey algorithm {self.one_time_prekey.algorithm!r} "
                f"does not match suite {expected_kx!r}"
            )
        try:
            suite.signer.verify(
                self.identity_signing,
                SignedPreKey.signed_material(self.signed_prekey),
                self.signed_prekey_signature,
                hash_backend(suite.digest),
            )
        except InvalidSignature:
            raise
        except Exception as exc:
            raise InvalidSignature("signed prekey verification failed") from exc

        has_pq = self.pq_prekey is not None or self.pq_prekey_signature is not None
        if has_pq:
            if self.pq_prekey is None or self.pq_prekey_signature is None:
                raise InvalidSignature("incomplete PQ prekey on bundle")
            try:
                suite.signer.verify(
                    self.identity_signing,
                    SignedPqPreKey.signed_material(self.pq_prekey),
                    self.pq_prekey_signature,
                    hash_backend(suite.digest),
                )
            except InvalidSignature:
                raise
            except Exception as exc:
                raise InvalidSignature("PQ prekey verification failed") from exc

    @classmethod
    def from_local(
        cls,
        identity: IdentityKeyPair,
        signed_prekey: SignedPreKey,
        one_time_prekey: OneTimePreKey,
        pq_prekey: SignedPqPreKey | None = None,
    ) -> PreKeyBundle:
        return cls(
            identity_signing=identity.signing.public,
            identity_agreement=(
                identity.agreement.public if identity.agreement is not None else None
            ),
            signed_prekey=signed_prekey.key_pair.public,
            signed_prekey_signature=signed_prekey.signature,
            one_time_prekey=one_time_prekey.key_pair.public,
            pq_prekey=(
                pq_prekey.key_pair.public if pq_prekey is not None else None
            ),
            pq_prekey_signature=(
                pq_prekey.signature if pq_prekey is not None else None
            ),
        )

    CONSTRUCTOR_ID = ConstructorId.PREKEY_BUNDLE

    def to_bytes(self) -> bytes:
        parts = [
            self.constructor_pack(),
            self.encode_field(self.identity_signing.data),
            encode_u32(int(self.identity_signing.algorithm)),
        ]
        if self.identity_agreement is not None:
            parts.extend(
                [
                    b"\x01",
                    self.encode_field(self.identity_agreement.data),
                    encode_u32(int(self.identity_agreement.algorithm)),
                ]
            )
        else:
            parts.append(b"\x00")
        parts.extend(
            [
                self.encode_field(self.signed_prekey.data),
                encode_u32(int(self.signed_prekey.algorithm)),
                self.encode_field(self.signed_prekey_signature),
                self.encode_field(self.one_time_prekey.data),
                encode_u32(int(self.one_time_prekey.algorithm)),
            ]
        )
        if self.pq_prekey is None:
            parts.append(b"\x00")
        else:
            parts.extend(
                [
                    b"\x01",
                    self.encode_field(self.pq_prekey.data),
                    encode_u32(int(self.pq_prekey.algorithm)),
                    self.encode_field(self.pq_prekey_signature or b""),
                ]
            )
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> PreKeyBundle:
        view = memoryview(data)
        if not view:
            raise SerializationError("empty prekey bundle")
        offset = cls.constructor_expect(view)

        identity_data, offset = cls.read_field(view, offset)
        identity_alg_id, offset = read_u32(view, offset)
        has_agreement = view[offset]
        offset += 1
        identity_agreement = None
        if has_agreement:
            agreement_data, offset = cls.read_field(view, offset)
            agreement_alg_id, offset = read_u32(view, offset)
            identity_agreement = PublicKey(
                agreement_data,
                KeyExchangeAlg.from_id(agreement_alg_id),
            )
        spk_data, offset = cls.read_field(view, offset)
        spk_alg_id, offset = read_u32(view, offset)
        signature, offset = cls.read_field(view, offset)
        opk_data, offset = cls.read_field(view, offset)
        opk_alg_id, offset = read_u32(view, offset)
        one_time = PublicKey(opk_data, KeyExchangeAlg.from_id(opk_alg_id))
        pq_prekey = None
        pq_prekey_signature = None
        # Older bundles omit the PQ flag entirely (end of blob).
        if offset < len(view):
            has_pq = view[offset]
            offset += 1
            if has_pq:
                pq_data, offset = cls.read_field(view, offset)
                pq_alg_id, offset = read_u32(view, offset)
                pq_prekey_signature, offset = cls.read_field(view, offset)
                pq_prekey = PublicKey(pq_data, KeyExchangeAlg.from_id(pq_alg_id))
        if offset != len(view):
            raise SerializationError("trailing bytes in prekey bundle")
        return cls(
            identity_signing=SigningPublicKey(
                identity_data,
                SigningAlg.from_id(identity_alg_id),
            ),
            identity_agreement=identity_agreement,
            signed_prekey=PublicKey(spk_data, KeyExchangeAlg.from_id(spk_alg_id)),
            signed_prekey_signature=signature,
            one_time_prekey=one_time,
            pq_prekey=pq_prekey,
            pq_prekey_signature=pq_prekey_signature,
        )

    @staticmethod
    def encode_field(value: bytes) -> bytes:
        if len(value) > 0xFFFF:
            raise SerializationError("field too large")
        return struct.pack(">H", len(value)) + value

    @staticmethod
    def read_field(view: memoryview, offset: int) -> tuple[bytes, int]:
        if offset + 2 > len(view):
            raise SerializationError("truncated prekey bundle field")
        length = struct.unpack_from(">H", view, offset)[0]
        offset += 2
        if offset + length > len(view):
            raise SerializationError("truncated prekey bundle field body")
        value = bytes(view[offset:offset + length])
        return value, offset + length
