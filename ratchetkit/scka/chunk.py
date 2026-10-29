"""Chunk framing for sparse continuous key-agreement payloads.

Payloads (ML-KEM public keys / ciphertexts) are split into indexed chunks so
each application message carries a fixed-size piece. Reconstruction requires
all ``n_chunks`` distinct indices (systematic identity code). Full Reed-Solomon
erasure coding can replace this later without changing the SCKA interface.
"""
from __future__ import annotations


import math
import struct

from ratchetkit.errors import InvalidMessage, SerializationError
from ratchetkit.packing import (
    Constructor,
    ConstructorId,
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


class ChunkFrame(Constructor):
    """Wire format for one SCKA chunk (or ack-only) message body."""

    CONSTRUCTOR_ID = ConstructorId.CHUNK_FRAME
    FLAG_PAYLOAD = 0x01
    FLAG_ACK_ONLY = 0x02

    def __init__(
        self,
        flags: int,
        key_epoch: int,
        chunk_index: int,
        n_chunks: int,
        ack_count: int,
        payload_len: int,
        data: bytes,
    ):
        self.flags = flags
        self.key_epoch = key_epoch
        self.chunk_index = chunk_index
        self.n_chunks = n_chunks
        self.ack_count = ack_count
        self.payload_len = payload_len
        self.data = data

    def to_bytes(self) -> bytes:
        if len(self.data) > 0xFFFF:
            raise SerializationError("chunk data too large")
        return (
            self.constructor_pack()
            + bytes([self.flags & 0xFF])
            + struct.pack(
                ">IHHHH",
                self.key_epoch & 0xFFFFFFFF,
                self.chunk_index & 0xFFFF,
                self.n_chunks & 0xFFFF,
                self.ack_count & 0xFFFF,
                self.payload_len & 0xFFFF,
            )
            + struct.pack(">H", len(self.data))
            + self.data
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> ChunkFrame:
        # constructor(4) + flags(1) + IHHHH(12) + data_len(2)
        if len(raw) < 4 + 1 + 12 + 2:
            raise SerializationError("truncated SCKA chunk frame")
        offset = cls.constructor_expect(raw)
        flags = raw[offset]
        offset += 1
        key_epoch, chunk_index, n_chunks, ack_count, payload_len = struct.unpack_from(
            ">IHHHH",
            raw,
            offset,
        )
        offset += 12
        data_len = struct.unpack_from(">H", raw, offset)[0]
        offset += 2
        if offset + data_len != len(raw):
            raise SerializationError("SCKA chunk frame length mismatch")
        return cls(
            flags=flags,
            key_epoch=key_epoch,
            chunk_index=chunk_index,
            n_chunks=n_chunks,
            ack_count=ack_count,
            payload_len=payload_len,
            data=raw[offset:offset + data_len],
        )
