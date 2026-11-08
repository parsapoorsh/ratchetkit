"""Triple Ratchet (hybrid) message encoding."""
from __future__ import annotations


from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.errors import SerializationError
from ratchetkit.ratchet.message.base import RatchetMessage
from ratchetkit.ratchet.message.double import DoubleRatchetMessage
from ratchetkit.ratchet.spqr import SpqrHeader

if TYPE_CHECKING:
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet


@dataclass
class TripleRatchetMessage(RatchetMessage):
    """Composite header (EC Double Ratchet + SPQR) + ciphertext + MAC."""

    ec_message: DoubleRatchetMessage
    spqr_header: SpqrHeader
    ciphertext: bytes
    mac: bytes

    def header_bytes(self) -> bytes:
        return self.ec_message.header_bytes() + self.spqr_header.header_bytes()

    def to_bytes(self) -> bytes:
        return self.header_bytes() + self.ciphertext + self.mac

    @classmethod
    def from_bytes(cls, data: bytes, suite: CryptoSuiteDoubleRatchet) -> TripleRatchetMessage:
        if not data:
            raise SerializationError("empty triple ratchet message")
        ec_message, offset = DoubleRatchetMessage.read_header(data, 0, suite)
        spqr_header, offset = SpqrHeader.read(data, offset)
        tag_size = suite.tag_size
        if offset + tag_size > len(data):
            raise SerializationError("truncated triple ratchet message tag")
        return cls(
            ec_message=ec_message,
            spqr_header=spqr_header,
            ciphertext=bytes(data[offset:len(data) - tag_size]),
            mac=bytes(data[len(data) - tag_size:]),
        )
