"""Classical Double Ratchet message encoding."""
from __future__ import annotations


import struct
from dataclasses import dataclass

from ratchetkit.errors import SerializationError
from ratchetkit.packing import (
    ConstructorId,
    expect_constructor,
    pack_constructor,
)
from ratchetkit.ratchet.message.base import RatchetMessage


@dataclass
class DoubleRatchetMessage(RatchetMessage):
    """Double Ratchet ciphertext with header and MAC tag."""

    ratchet_public: bytes
    previous_counter: int
    counter: int
    ciphertext: bytes
    mac: bytes

    CONSTRUCTOR_ID = ConstructorId.DOUBLE_RATCHET_MESSAGE

    def header_bytes(self) -> bytes:
        return (
            self.encode_field(self.ratchet_public)
            + struct.pack(">II", self.previous_counter, self.counter)
        )

    def to_bytes(self) -> bytes:
        return (
            pack_constructor(self.CONSTRUCTOR_ID)
            + self.header_bytes()
            + self.encode_field(self.ciphertext)
            + self.encode_field(self.mac)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> DoubleRatchetMessage:
        view = memoryview(data)
        if not view:
            raise SerializationError("empty ratchet message")
        offset = expect_constructor(view, cls.CONSTRUCTOR_ID)

        ratchet_public, offset = cls.read_field(view, offset)
        if offset + 8 > len(view):
            raise SerializationError("truncated ratchet message counters")
        previous_counter, counter = struct.unpack_from(">II", view, offset)
        offset += 8
        ciphertext, offset = cls.read_field(view, offset)
        mac, offset = cls.read_field(view, offset)
        if offset != len(view):
            raise SerializationError("trailing bytes in ratchet message")
        return cls(
            ratchet_public=ratchet_public,
            previous_counter=previous_counter,
            counter=counter,
            ciphertext=ciphertext,
            mac=mac,
        )
