"""Ratchet engine ABC: encrypt / decrypt / serialize / trial-clone."""
from __future__ import annotations


from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ratchetkit.ratchet.message.base import RatchetMessage
    from ratchetkit.suite import CryptoSuite


class Ratchet(ABC):
    """Stateful ratchet half used by :class:`~ratchetkit.session.Session`."""

    suite: CryptoSuite

    @abstractmethod
    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes = b"",
    ) -> RatchetMessage:
        """Encrypt one plaintext; advances send-side ratchet state."""

    @abstractmethod
    def decrypt(
        self,
        message: RatchetMessage,
        associated_data: bytes = b"",
    ) -> bytes:
        """Decrypt one message; commits state only after MAC success."""

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Serialize ratchet state (secret key material)."""

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes, suite: CryptoSuite) -> Ratchet:
        """Deserialize ratchet state for this concrete type."""

    @abstractmethod
    def clone(self) -> Ratchet:
        """Trial-decrypt copy of mutable state (no deepcopy)."""

    @abstractmethod
    def adopt(self, other: Ratchet) -> None:
        """Replace live state with a successful trial-decrypt clone."""
