"""Signature backend interface (identity / prekey authenticity)."""
from __future__ import annotations


from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ratchetkit.algorithms.hash.base import HashAlgorithm
    from ratchetkit.keys.keypair import SigningKeyPair, SigningPublicKey
    from ratchetkit.suite.algs import SigningAlg


class SigningBackend(ABC):
    """Sign / verify only. Separate from KEM/DH agreement keys."""

    algorithm: SigningAlg

    @abstractmethod
    def generate_keypair(self) -> SigningKeyPair:
        ...

    @abstractmethod
    def derive_public(self, private: bytes) -> bytes:
        """Public key bytes matching the given private/seed material."""

    @abstractmethod
    def sign(
        self,
        private: SigningKeyPair,
        message: bytes,
        digest: type[HashAlgorithm],
    ) -> bytes:
        ...

    @abstractmethod
    def verify(
        self,
        public: SigningPublicKey,
        message: bytes,
        signature: bytes,
        digest: type[HashAlgorithm],
    ) -> None:
        """Raise :class:`~ratchetkit.errors.InvalidSignature` on failure."""
