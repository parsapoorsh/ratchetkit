"""Double Ratchet safety limits (from libsignal consts.rs)."""
from __future__ import annotations


from dataclasses import dataclass

from ratchetkit.errors import SerializationError
from ratchetkit.packing import encode_u32, read_u32


@dataclass(frozen=True)
class RatchetLimits:
    MAX_FORWARD_JUMPS: int = 25_000
    MAX_MESSAGE_KEYS: int = 2_000
    MAX_RECEIVER_CHAINS: int = 5

    def to_bytes(self) -> bytes:
        return (
            encode_u32(self.MAX_FORWARD_JUMPS)
            + encode_u32(self.MAX_MESSAGE_KEYS)
            + encode_u32(self.MAX_RECEIVER_CHAINS)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> RatchetLimits:
        forward, offset = read_u32(data, 0)
        message_keys, offset = read_u32(data, offset)
        receiver_chains, offset = read_u32(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in ratchet limits")
        return cls(
            MAX_FORWARD_JUMPS=forward,
            MAX_MESSAGE_KEYS=message_keys,
            MAX_RECEIVER_CHAINS=receiver_chains,
        )
