"""ECDSA signatures on NIST curves."""
from __future__ import annotations


from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ratchetkit.errors import InvalidSignature
from ratchetkit.algorithms.signing.base import SigningBackend
from ratchetkit.keys.keypair import SigningKeyPair, SigningPublicKey
from ratchetkit.suite.algs import SigningAlg

if TYPE_CHECKING:
    from ratchetkit.algorithms.hash.base import HashAlgorithm
    from ratchetkit.keys.keypair import SigningPublicKey


class EcdsaBackend(SigningBackend):
    """ECDSA on a fixed NIST curve."""

    algorithm: SigningAlg
    curve: ec.EllipticCurve

    def generate_keypair(self) -> SigningKeyPair:
        raw = ec.generate_private_key(self.curve)
        byte_length = (self.curve.key_size + 7) // 8
        private = raw.private_numbers().private_value.to_bytes(byte_length, "big")
        return SigningKeyPair(
            private=private,
            public=SigningPublicKey(self.derive_public(private), self.algorithm),
        )

    def derive_public(self, private: bytes) -> bytes:
        key = ec.derive_private_key(int.from_bytes(private, "big"), self.curve)
        return key.public_key().public_bytes(
            Encoding.X962,
            PublicFormat.UncompressedPoint,
        )

    def sign(
        self,
        private: SigningKeyPair,
        message: bytes,
        digest: type[HashAlgorithm],
    ) -> bytes:
        key = ec.derive_private_key(
            int.from_bytes(private.private, "big"),
            self.curve,
        )
        return key.sign(message, ec.ECDSA(digest.hazmat()))

    def verify(
        self,
        public: SigningPublicKey,
        message: bytes,
        signature: bytes,
        digest: type[HashAlgorithm],
    ) -> None:
        key = ec.EllipticCurvePublicKey.from_encoded_point(self.curve, public.data)
        try:
            key.verify(signature, message, ec.ECDSA(digest.hazmat()))
        except Exception as exc:
            raise InvalidSignature("ECDSA verification failed") from exc


class EcdsaSecp256r1(EcdsaBackend):
    algorithm = SigningAlg.ECDSA_SECP256R1
    curve = ec.SECP256R1()


class EcdsaSecp384r1(EcdsaBackend):
    algorithm = SigningAlg.ECDSA_SECP384R1
    curve = ec.SECP384R1()


class EcdsaSecp521r1(EcdsaBackend):
    algorithm = SigningAlg.ECDSA_SECP521R1
    curve = ec.SECP521R1()
