"""ML-DSA signatures (FIPS 204)."""
from __future__ import annotations


from typing import TYPE_CHECKING, Any

from ratchetkit.errors import InvalidSignature
from ratchetkit.algorithms.signing.base import SigningBackend
from ratchetkit.keys.keypair import SigningKeyPair, SigningPublicKey
from ratchetkit.suite.algs import SigningAlg

if TYPE_CHECKING:
    from ratchetkit.algorithms.hash.base import HashAlgorithm
    from ratchetkit.keys.keypair import SigningPublicKey


class MldsaBackend(SigningBackend):
    """ML-DSA pure signatures; private stored as FIPS seed."""

    algorithm: SigningAlg
    dsa_private_cls: Any
    dsa_public_cls: Any

    def generate_keypair(self) -> SigningKeyPair:
        raw = self.dsa_private_cls.generate()
        private = raw.private_bytes_raw()
        return SigningKeyPair(
            private=private,
            public=SigningPublicKey(self.derive_public(private), self.algorithm),
        )

    def derive_public(self, private: bytes) -> bytes:
        key = self.dsa_private_cls.from_seed_bytes(private)
        return key.public_key().public_bytes_raw()

    def sign(
        self,
        private: SigningKeyPair,
        message: bytes,
        digest: type[HashAlgorithm],
    ) -> bytes:
        # ML-DSA is a pure signature scheme; digest is unused (suite still has one).
        key = self.dsa_private_cls.from_seed_bytes(private.private)
        return key.sign(message)

    def verify(
        self,
        public: SigningPublicKey,
        message: bytes,
        signature: bytes,
        digest: type[HashAlgorithm],
    ) -> None:
        key = self.dsa_public_cls.from_public_bytes(public.data)
        try:
            key.verify(signature, message)
        except Exception as exc:
            raise InvalidSignature(
                f"{self.algorithm.name} ML-DSA verification failed"
            ) from exc


class Mldsa65(MldsaBackend):
    algorithm = SigningAlg.MLDSA65

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.mldsa import (
            MLDSA65PrivateKey,
            MLDSA65PublicKey,
        )

        self.dsa_private_cls = MLDSA65PrivateKey
        self.dsa_public_cls = MLDSA65PublicKey


class Mldsa87(MldsaBackend):
    algorithm = SigningAlg.MLDSA87

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.mldsa import (
            MLDSA87PrivateKey,
            MLDSA87PublicKey,
        )

        self.dsa_private_cls = MLDSA87PrivateKey
        self.dsa_public_cls = MLDSA87PublicKey
