"""RSA-PSS signatures."""
from __future__ import annotations


from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ratchetkit.errors import InvalidKey, InvalidSignature
from ratchetkit.algorithms.signing.base import SigningBackend
from ratchetkit.keys.keypair import SigningKeyPair, SigningPublicKey, SigningPublicKey
from ratchetkit.suite.algs import SigningAlg

if TYPE_CHECKING:
    from ratchetkit.algorithms.hash.base import HashAlgorithm
    from ratchetkit.keys.keypair import SigningPublicKey


class RsaPssBackend(SigningBackend):
    """RSA-PSS on a fixed modulus size."""

    algorithm: SigningAlg
    key_size: int

    def generate_keypair(self) -> SigningKeyPair:
        raw = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
        )
        private = raw.private_bytes(
            Encoding.DER,
            PrivateFormat.PKCS8,
            NoEncryption(),
        )
        return SigningKeyPair(
            private=private,
            public=SigningPublicKey(self.derive_public(private), self.algorithm),
        )

    def derive_public(self, private: bytes) -> bytes:
        key = serialization.load_der_private_key(private, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise InvalidKey("expected RSA private key")
        return key.public_key().public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(
        self,
        private: SigningKeyPair,
        message: bytes,
        digest: type[HashAlgorithm],
    ) -> bytes:
        key = serialization.load_der_private_key(private.private, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise InvalidKey("expected RSA private key")
        algorithm = digest.hazmat()
        hasher = hashes.Hash(algorithm)
        hasher.update(message)
        return key.sign(
            hasher.finalize(),
            padding.PSS(
                mgf=padding.MGF1(algorithm),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(algorithm),
        )

    def verify(
        self,
        public: SigningPublicKey,
        message: bytes,
        signature: bytes,
        digest: type[HashAlgorithm],
    ) -> None:
        key = serialization.load_der_public_key(public.data)
        if not isinstance(key, rsa.RSAPublicKey):
            raise InvalidKey("expected RSA public key")
        algorithm = digest.hazmat()
        hasher = hashes.Hash(algorithm)
        hasher.update(message)
        try:
            key.verify(
                signature,
                hasher.finalize(),
                padding.PSS(
                    mgf=padding.MGF1(algorithm),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                utils.Prehashed(algorithm),
            )
        except Exception as exc:
            raise InvalidSignature("RSA-PSS verification failed") from exc


class RsaPss2048(RsaPssBackend):
    algorithm = SigningAlg.RSA_PSS_2048
    key_size = 2048


class RsaPss3072(RsaPssBackend):
    algorithm = SigningAlg.RSA_PSS_3072
    key_size = 3072


class RsaPss4096(RsaPssBackend):
    algorithm = SigningAlg.RSA_PSS_4096
    key_size = 4096
