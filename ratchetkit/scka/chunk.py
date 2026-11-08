"""Chunk framing for sparse continuous key-agreement payloads.

Payloads (ML-KEM public keys / ciphertexts) are split into indexed chunks so
each application message carries a fixed-size piece. Reconstruction requires
all ``n_chunks`` distinct indices (systematic identity code). Full Reed-Solomon
erasure coding can replace this later without changing the SCKA interface.
"""
from __future__ import annotations


import math

from ratchetkit.errors import InvalidMessage, SerializationError
from ratchetkit.packing import (
    encode_bytes16,
    encode_u8,
    encode_u16,
    encode_u32,
    read_bytes16,
    read_u8,
    read_u16,
    read_u32,
)


class ChunkCodec:
    """Split a byte string into ``n_chunks`` equal-width pieces (zero-padded)."""

    def __init__(self, n_chunks: int):
        if n_chunks < 1:
            raise ValueError("n_chunks must be at least 1")
        self.n_chunks = n_chunks

    def split(self, payload: bytes) -> list[bytes]:
        if self.n_chunks == 1:
            return [payload]
        width = math.ceil(len(payload) / self.n_chunks)
        if width == 0:
            width = 1
        padded = payload + bytes(width * self.n_chunks - len(payload))
        return [padded[i * width:(i + 1) * width] for i in range(self.n_chunks)]

    def join(self, chunks: dict[int, bytes], payload_len: int) -> bytes:
        if len(chunks) < self.n_chunks:
            raise InvalidMessage(
                f"need {self.n_chunks} chunks, have {len(chunks)}"
            )
        ordered = []
        for index in range(self.n_chunks):
            if index not in chunks:
                raise InvalidMessage(f"missing chunk index {index}")
            ordered.append(chunks[index])
        blob = b"".join(ordered)
        if payload_len > len(blob):
            raise InvalidMessage("payload length exceeds reconstructed blob")
        return blob[:payload_len]


class ChunkFrame:
    """Wire format for one SCKA chunk (or ack-only) message body."""

    FLAG_PAYLOAD = 0x01
    FLAG_ACK_ONLY = 0x02

    def __init__(
        self,
        flags: int,
        key_epoch: int,
        chunk_index: int,
        ack_count: int,
        payload_len: int,
        data: bytes,
    ):
        self.flags = flags
        self.key_epoch = key_epoch
        self.chunk_index = chunk_index
        self.ack_count = ack_count
        self.payload_len = payload_len
        self.data = data

    def to_bytes(self) -> bytes:
        return (
            encode_u8(self.flags & 0xFF)
            + encode_u32(self.key_epoch)
            + encode_u16(self.chunk_index)
            + encode_u16(self.ack_count)
            + encode_u16(self.payload_len)
            + encode_bytes16(self.data)
        )

    @classmethod
    def read(
        cls,
        data: bytes | memoryview,
        offset: int = 0,
    ) -> tuple[ChunkFrame, int]:
        flags, offset = read_u8(data, offset)
        key_epoch, offset = read_u32(data, offset)
        chunk_index, offset = read_u16(data, offset)
        ack_count, offset = read_u16(data, offset)
        payload_len, offset = read_u16(data, offset)
        body, offset = read_bytes16(data, offset)
        frame = cls(
            flags=flags,
            key_epoch=key_epoch,
            chunk_index=chunk_index,
            ack_count=ack_count,
            payload_len=payload_len,
            data=body,
        )
        return frame, offset

    @classmethod
    def from_bytes(cls, raw: bytes) -> ChunkFrame:
        if not raw:
            raise SerializationError("truncated SCKA chunk frame")
        frame, offset = cls.read(raw, 0)
        if offset != len(raw):
            raise SerializationError("trailing bytes in SCKA chunk frame")
        return frame
