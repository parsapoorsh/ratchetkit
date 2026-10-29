"""MTProto-style 4-byte constructor IDs for on-wire types."""

from __future__ import annotations

import struct
from enum import IntEnum

from ratchetkit.errors import SerializationError

# Big-endian u32 on the wire (project convention). MTProto uses LE; same idea.
CONSTRUCTOR_SIZE = 4


class ConstructorId(IntEnum):
    """Unique constructor for each packable object."""

    PREKEY_BUNDLE = 0x524B0010
    INITIAL_MESSAGE_X3DH = 0x524B0011
    INITIAL_MESSAGE_PQXDH = 0x524B0015
    DOUBLE_RATCHET_MESSAGE = 0x524B0012
    TRIPLE_RATCHET_MESSAGE = 0x524B0013
    CHUNK_FRAME = 0x524B0014
    SESSION = 0x524B0020
    SUITE_DOUBLE = 0x524B0021
    SUITE_TRIPLE = 0x524B0022
    DOUBLE_RATCHET = 0x524B0023
    TRIPLE_RATCHET = 0x524B0024
    SPQR = 0x524B0025
    SCKA = 0x524B0026


def pack_constructor(constructor_id: ConstructorId | int) -> bytes:
    return struct.pack(">I", int(constructor_id))


def read_constructor(
    data: bytes | memoryview,
    offset: int = 0,
) -> tuple[ConstructorId, int]:
    if offset + CONSTRUCTOR_SIZE > len(data):
        raise SerializationError("truncated constructor id")
    raw = struct.unpack_from(">I", data, offset)[0]
    try:
        return ConstructorId(raw), offset + CONSTRUCTOR_SIZE
    except ValueError as exc:
        raise SerializationError(f"unknown constructor id 0x{raw:08X}") from exc


def expect_constructor(
    data: bytes | memoryview,
    expected: ConstructorId,
    offset: int = 0,
) -> int:
    """Read constructor at offset; raise if it is not ``expected``."""
    got, next_offset = read_constructor(data, offset)
    if got is not expected:
        raise SerializationError(
            f"expected constructor 0x{int(expected):08X}, got 0x{int(got):08X}"
        )
    return next_offset


def encode_bytes(value: bytes) -> bytes:
    """Length-prefixed bytes (u32 big-endian). Used by session-state blobs."""
    if len(value) > 0xFFFFFFFF:
        raise SerializationError("field too large")
    return struct.pack(">I", len(value)) + value


def read_bytes(
    data: bytes | memoryview,
    offset: int,
) -> tuple[bytes, int]:
    if offset + 4 > len(data):
        raise SerializationError("truncated field length")
    length = struct.unpack_from(">I", data, offset)[0]
    offset += 4
    if offset + length > len(data):
        raise SerializationError("truncated field body")
    return bytes(data[offset:offset + length]), offset + length


def encode_str(value: str) -> bytes:
    return encode_bytes(value.encode("ascii"))


def read_str(
    data: bytes | memoryview,
    offset: int,
) -> tuple[str, int]:
    raw, offset = read_bytes(data, offset)
    try:
        return raw.decode("ascii"), offset
    except UnicodeDecodeError as exc:
        raise SerializationError("non-ascii string field") from exc


def encode_u32(value: int) -> bytes:
    if value < 0 or value > 0xFFFFFFFF:
        raise SerializationError("u32 out of range")
    return struct.pack(">I", value)


def read_u32(
    data: bytes | memoryview,
    offset: int,
) -> tuple[int, int]:
    if offset + 4 > len(data):
        raise SerializationError("truncated u32")
    return struct.unpack_from(">I", data, offset)[0], offset + 4


def encode_u8(value: int) -> bytes:
    if value < 0 or value > 0xFF:
        raise SerializationError("u8 out of range")
    return bytes([value])


def read_u8(
    data: bytes | memoryview,
    offset: int,
) -> tuple[int, int]:
    if offset >= len(data):
        raise SerializationError("truncated u8")
    return int(data[offset]), offset + 1


def encode_bool(value: bool) -> bytes:
    return b"\x01" if value else b"\x00"


def read_bool(
    data: bytes | memoryview,
    offset: int,
) -> tuple[bool, int]:
    flag, offset = read_u8(data, offset)
    if flag not in (0, 1):
        raise SerializationError("invalid bool flag")
    return bool(flag), offset


def encode_optional_bytes(value: bytes | None) -> bytes:
    if value is None:
        return encode_bool(False)
    return encode_bool(True) + encode_bytes(value)


def read_optional_bytes(
    data: bytes | memoryview,
    offset: int,
) -> tuple[bytes | None, int]:
    present, offset = read_bool(data, offset)
    if not present:
        return None, offset
    return read_bytes(data, offset)
