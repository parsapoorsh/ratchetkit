"""Ratchet message ABC."""
from __future__ import annotations


from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet


class RatchetMessage(ABC):
    """Wire message: header material + ciphertext + MAC."""

    @abstractmethod
    def header_bytes(self) -> bytes:
        """Bytes authenticated under the MAC (no ciphertext/MAC body)."""

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Full on-wire encoding."""

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes, suite: CryptoSuiteDoubleRatchet) -> RatchetMessage:
        """Parse a full on-wire blob of this concrete type."""

    # Concrete types expose ``ciphertext`` and ``mac`` as dataclass fields.
