"""Ed25519 signatures."""
from __future__ import annotations


from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ed25519
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


class Ed25519(SigningBackend):
    algorithm = SigningAlg.ED25519

    def generate_keypair(self) -> SigningKeyPair:
        private = ed25519.Ed25519PrivateKey.generate()
        return SigningKeyPair(
            private=private.private_bytes(
                Encoding.Raw,
                PrivateFormat.Raw,
                NoEncryption(),
            ),
            algorithm=self.algorithm,
        )

    def derive_public(self, private: bytes) -> bytes:
        key = ed25519.Ed25519PrivateKey.from_private_bytes(private)
        return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(
        self,
        private: SigningKeyPair,
        message: bytes,
        digest: type[HashAlgorithm],
    ) -> bytes:
        key = ed25519.Ed25519PrivateKey.from_private_bytes(private.private)
        return key.sign(message)

    def verify(
        self,
        public: SigningPublicKey,
        message: bytes,
        signature: bytes,
        digest: type[HashAlgorithm],
    ) -> None:
        key = ed25519.Ed25519PublicKey.from_public_bytes(public.data)
        try:
            key.verify(signature, message)
        except Exception as exc:
            raise InvalidSignature("Ed25519 verification failed") from exc
