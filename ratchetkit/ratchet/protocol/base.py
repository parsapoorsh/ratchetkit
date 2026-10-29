"""Ratchet engine ABC: encrypt / decrypt / serialize."""
from __future__ import annotations


from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic, TypeVar

from ratchetkit.ratchet.message.base import RatchetMessage

if TYPE_CHECKING:
    from typing import Self

    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite


M = TypeVar("M", bound=RatchetMessage)


class Ratchet(ABC, Generic[M]):
    """Stateful ratchet half used by :class:`~ratchetkit.session.Session`."""

    suite: CryptoSuite

    @abstractmethod
    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes = b"",
    ) -> M:
        """Encrypt one plaintext; advances send-side ratchet state."""

    @abstractmethod
    def decrypt(
        self,
        message: M,
        associated_data: bytes = b"",
    ) -> bytes:
        """Decrypt one message; commits state only after MAC success."""

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Serialize ratchet state (secret key material)."""

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes, suite: CryptoSuite) -> Self:
        """Deserialize ratchet state for this concrete type."""
