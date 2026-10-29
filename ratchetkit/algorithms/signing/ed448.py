"""Ed448 signatures."""
from __future__ import annotations


from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ratchetkit.errors import InvalidSignature
from ratchetkit.algorithms.signing.base import SigningBackend
from ratchetkit.keys.keypair import SigningKeyPair, SigningPublicKey
from ratchetkit.suite.algs import SigningAlg

if TYPE_CHECKING:
    from ratchetkit.algorithms.hash.base import HashAlgorithm
    from ratchetkit.keys.keypair import SigningPublicKey


class Ed448(SigningBackend):
    algorithm = SigningAlg.ED448

    def generate_keypair(self) -> SigningKeyPair:
        private = ed448.Ed448PrivateKey.generate()
        return SigningKeyPair(
            private=private.private_bytes(
                Encoding.Raw,
                PrivateFormat.Raw,
                NoEncryption(),
            ),
            algorithm=self.algorithm,
        )

    def derive_public(self, private: bytes) -> bytes:
        key = ed448.Ed448PrivateKey.from_private_bytes(private)
        return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(
        self,
        private: SigningKeyPair,
        message: bytes,
        digest: type[HashAlgorithm],
    ) -> bytes:
        key = ed448.Ed448PrivateKey.from_private_bytes(private.private)
        return key.sign(message)

    def verify(
        self,
        public: SigningPublicKey,
        message: bytes,
        signature: bytes,
        digest: type[HashAlgorithm],
    ) -> None:
        key = ed448.Ed448PublicKey.from_public_bytes(public.data)
        try:
            key.verify(signature, message)
        except Exception as exc:
            raise InvalidSignature("Ed448 verification failed") from exc
