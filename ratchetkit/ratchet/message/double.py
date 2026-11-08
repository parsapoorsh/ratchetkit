"""Classical Double Ratchet message encoding."""
from __future__ import annotations


from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.errors import SerializationError
from ratchetkit.packing import encode_varint, read_varint
from ratchetkit.ratchet.header import RatchetHeader
from ratchetkit.ratchet.message.base import RatchetMessage

if TYPE_CHECKING:
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite


@dataclass
class DoubleRatchetMessage(RatchetMessage):
    """Double Ratchet ciphertext with header and MAC tag."""

    ratchet_public: bytes
    previous_counter: int
    counter: int
    ciphertext: bytes
    mac: bytes

    def header_bytes(self) -> bytes:
        return (
            self.ratchet_public
            + encode_varint(self.previous_counter)
            + encode_varint(self.counter)
        )

    def to_bytes(self) -> bytes:
        return self.header_bytes() + self.ciphertext + self.mac

    @classmethod
    def read_header(
        cls,
        data: bytes | memoryview,
        offset: int,
        suite: CryptoSuite,
    ) -> tuple[DoubleRatchetMessage, int]:
        kem = suite.kem
        if kem.supports_dh:
            size = kem.public_size
            if size < 1 or offset + size > len(data):
                raise SerializationError("truncated ratchet public")
            ratchet_public = bytes(data[offset:offset + size])
            offset += size
        else:
            start = offset
            _public, _ct, offset = RatchetHeader.read_kem(data, offset)
            ratchet_public = bytes(data[start:offset])
        previous_counter, offset = read_varint(data, offset)
        counter, offset = read_varint(data, offset)
        return cls(
            ratchet_public=ratchet_public,
            previous_counter=previous_counter,
            counter=counter,
            ciphertext=b"",
            mac=b"",
        ), offset

    @classmethod
    def from_bytes(cls, data: bytes, suite: CryptoSuite) -> DoubleRatchetMessage:
        if not data:
            raise SerializationError("empty ratchet message")
        message, offset = cls.read_header(data, 0, suite)
        tag_size = suite.tag_size
        if offset + tag_size > len(data):
            raise SerializationError("truncated ratchet message tag")
        message.mac = bytes(data[len(data) - tag_size:])
        message.ciphertext = bytes(data[offset:len(data) - tag_size])
        return message
