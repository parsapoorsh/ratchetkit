"""Ratchet header payload encoding (DH public or KEM public+CT)."""
from __future__ import annotations


import struct

from ratchetkit.errors import SerializationError


class RatchetHeader:
    """Encode / decode the opaque ``ratchet_public`` field on messages."""

    @staticmethod
    def encode_dh(public: bytes) -> bytes:
        return public

    @staticmethod
    def encode_kem(public: bytes, ciphertext: bytes) -> bytes:
        if len(public) > 0xFFFF or len(ciphertext) > 0xFFFF:
            raise SerializationError("KEM header field too large")
        return (
            struct.pack(">H", len(public))
            + public
            + struct.pack(">H", len(ciphertext))
            + ciphertext
        )

    @staticmethod
    def decode_kem(data: bytes) -> tuple[bytes, bytes]:
        if len(data) < 4:
            raise SerializationError("truncated KEM header")
        pub_len = struct.unpack_from(">H", data, 0)[0]
        offset = 2
        if offset + pub_len + 2 > len(data):
            raise SerializationError("truncated KEM header public")
        public = data[offset:offset + pub_len]
        offset += pub_len
        ct_len = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        if offset + ct_len > len(data):
            raise SerializationError("truncated KEM header ciphertext")
        ciphertext = data[offset:offset + ct_len]
        return public, ciphertext

    @staticmethod
    def chain_id(header: bytes, is_kem: bool) -> bytes:
        """Stable id for the receiving chain keyed by this header."""
        if not is_kem:
            return header
        # Chain identity is the encapsulation CT (unique per send chain).
        return RatchetHeader.decode_kem(header)[1]
