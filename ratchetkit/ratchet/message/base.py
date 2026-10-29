"""Ratchet message ABC and shared wire-field helpers."""
from __future__ import annotations


import struct
from abc import ABC, abstractmethod

from ratchetkit.errors import SerializationError


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
    def from_bytes(cls, data: bytes) -> RatchetMessage:
        """Parse a full on-wire blob of this concrete type."""

    # Concrete types expose ``ciphertext`` and ``mac`` as dataclass fields.

    @staticmethod
    def encode_field(value: bytes) -> bytes:
        if len(value) > 0xFFFF:
            raise SerializationError("field too large")
        return struct.pack(">H", len(value)) + value

    @staticmethod
    def read_field(view: memoryview, offset: int) -> tuple[bytes, int]:
        if offset + 2 > len(view):
            raise SerializationError("truncated ratchet message field")
        length = struct.unpack_from(">H", view, offset)[0]
        offset += 2
        if offset + length > len(view):
            raise SerializationError("truncated ratchet message field body")
        value = bytes(view[offset:offset + length])
        return value, offset + length
