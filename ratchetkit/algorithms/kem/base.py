"""KEM / DH backend interface (agreement only)."""
from __future__ import annotations


from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ratchetkit.keys.keypair import KeyPair, PublicKey
    from ratchetkit.suite.algs import KeyExchangeAlg


class KemBackend(ABC):
    """Key encapsulation / DH for agreement keys. No signing."""

    algorithm: KeyExchangeAlg
    supports_dh: bool = False

    @abstractmethod
    def generate_keypair(self) -> KeyPair:
        ...

    @abstractmethod
    def derive_public(self, private: bytes) -> bytes:
        """Public key bytes matching the given private/seed material."""

    @abstractmethod
    def encapsulate(self, their_public: PublicKey) -> tuple[bytes, bytes]:
        """Return ``(shared_secret, ciphertext)``."""

    @abstractmethod
    def decapsulate(self, our_private: KeyPair, ciphertext: bytes) -> bytes:
        ...

    def dh(self, our_private: KeyPair, their_public: PublicKey) -> bytes:
        """Optional mutual DH. Only implemented by DH-capable backends."""
        raise NotImplementedError(
            f"{self.algorithm.name} does not support mutual DH"
        )
