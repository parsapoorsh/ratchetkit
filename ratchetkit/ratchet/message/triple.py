"""Triple Ratchet (hybrid) message encoding."""
from __future__ import annotations


import struct
from dataclasses import dataclass

from ratchetkit.errors import SerializationError
from ratchetkit.packing import (
    Constructor,
    ConstructorId,
    encode_bytes16,
    read_bytes16,
)
from ratchetkit.ratchet.message.base import RatchetMessage
from ratchetkit.ratchet.message.double import DoubleRatchetMessage
from ratchetkit.ratchet.spqr import SpqrHeader


@dataclass
class TripleRatchetMessage(RatchetMessage, Constructor):
    """Composite header (EC Double Ratchet + SPQR) + ciphertext + MAC."""

    ec_message: DoubleRatchetMessage
    spqr_header: SpqrHeader
    ciphertext: bytes
    mac: bytes

    CONSTRUCTOR_ID = ConstructorId.TRIPLE_RATCHET_MESSAGE

    def header_bytes(self) -> bytes:
        return (
            encode_bytes16(self.ec_message.header_bytes())
            + encode_bytes16(self.spqr_header.header_bytes())
        )

    def to_bytes(self) -> bytes:
        return (
            self.constructor_pack()
            + self.header_bytes()
            + encode_bytes16(self.ciphertext)
            + encode_bytes16(self.mac)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> TripleRatchetMessage:
        if not data:
            raise SerializationError("empty triple ratchet message")
        view = memoryview(data)
        offset = cls.constructor_expect(view)
        ec_raw, offset = read_bytes16(view, offset)
        spqr_raw, offset = read_bytes16(view, offset)
        ciphertext, offset = read_bytes16(view, offset)
        mac, offset = read_bytes16(view, offset)
        if offset != len(view):
            raise SerializationError("trailing bytes in triple ratchet message")

        ratchet_public, pos = read_bytes16(ec_raw, 0)
        if pos + 8 > len(ec_raw):
            raise SerializationError("truncated EC counters in triple header")
        previous_counter, counter = struct.unpack_from(">II", ec_raw, pos)
        ec_message = DoubleRatchetMessage(
            ratchet_public=ratchet_public,
            previous_counter=previous_counter,
            counter=counter,
            ciphertext=b"",
            mac=b"",
        )
        spqr_header = SpqrHeader.from_bytes(spqr_raw)
        return cls(
            ec_message=ec_message,
            spqr_header=spqr_header,
            ciphertext=ciphertext,
            mac=mac,
        )
