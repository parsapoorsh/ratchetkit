"""Initial handshake messages carried from initiator to responder."""
from __future__ import annotations


import struct
from dataclasses import dataclass

from ratchetkit.errors import SerializationError
from ratchetkit.suite.algs import KeyExchangeAlg, SigningAlg
from ratchetkit.keys.keypair import PublicKey, SigningPublicKey
from ratchetkit.packing import (
    Constructor,
    encode_u32,
    read_u32,
    ConstructorId,
)


@dataclass
class InitialMessageX3DH(Constructor):
    """First message of a classical X3DH handshake (public half only)."""

    identity_signing: SigningPublicKey
    identity_agreement: PublicKey | None
    ephemeral_public: PublicKey
    # For KEM-only suites: encapsulations to SPK / OPK (optional trailing).
    kem_ciphertexts: tuple[bytes, ...]
    signed_prekey_id: int
    one_time_prekey_id: int | None
    signature: bytes
    # Optional first ratchet public used to seed the Double Ratchet.
    ratchet_public: bytes | None = None

    CONSTRUCTOR_ID = ConstructorId.INITIAL_MESSAGE_X3DH

    @staticmethod
    def signed_material(
        identity_agreement_data: bytes,
        ephemeral_public: bytes,
        signed_prekey_public: bytes,
        kem_ciphertexts: list[bytes] | tuple[bytes, ...],
        ratchet_public: bytes,
        pq_ciphertext: bytes | None = None,
    ) -> bytes:
        """Bytes covered by the initiator signature on the initial message.

        Includes the initiator identity-agreement public key so a MitM cannot
        swap it without breaking the signature. PQXDH also binds the PQ
        ciphertext when present.
        """
        material = (
            identity_agreement_data
            + ephemeral_public
            + signed_prekey_public
            + b"".join(kem_ciphertexts)
            + ratchet_public
        )
        if pq_ciphertext is not None:
            material = material + pq_ciphertext
        return material

    def encode_body(self) -> bytes:
        """Serialize fields after the constructor id."""
        parts = [
            self.encode_field(self.identity_signing.data),
            encode_u32(int(self.identity_signing.algorithm)),
        ]
        if self.identity_agreement is not None:
            parts.extend(
                [
                    b"\x01",
                    self.encode_field(self.identity_agreement.data),
                    encode_u32(int(self.identity_agreement.algorithm)),
                ]
            )
        else:
            parts.append(b"\x00")
        parts.extend(
            [
                self.encode_field(self.ephemeral_public.data),
                encode_u32(int(self.ephemeral_public.algorithm)),
                bytes([len(self.kem_ciphertexts)]),
            ]
        )
        for ct in self.kem_ciphertexts:
            parts.append(self.encode_field(ct))
        parts.append(struct.pack(">I", self.signed_prekey_id))
        if self.one_time_prekey_id is None:
            parts.append(b"\x00")
        else:
            parts.extend([b"\x01", struct.pack(">I", self.one_time_prekey_id)])
        parts.append(self.encode_field(self.signature))
        if self.ratchet_public is None:
            parts.append(b"\x00")
        else:
            parts.extend([b"\x01", self.encode_field(self.ratchet_public)])
        return b"".join(parts)

    def to_bytes(self) -> bytes:
        return self.constructor_pack() + self.encode_body()

    @classmethod
    def decode_body(cls, view: memoryview, offset: int) -> tuple[dict, int]:
        """Parse X3DH fields starting at ``offset``; return kwargs and new offset."""
        identity_data, offset = cls.read_field(view, offset)
        identity_alg_id, offset = read_u32(view, offset)
        has_agreement = view[offset]
        offset += 1
        identity_agreement = None
        if has_agreement:
            agreement_data, offset = cls.read_field(view, offset)
            agreement_alg_id, offset = read_u32(view, offset)
            identity_agreement = PublicKey(
                agreement_data,
                KeyExchangeAlg.from_id(agreement_alg_id),
            )
        ephemeral_data, offset = cls.read_field(view, offset)
        ephemeral_alg_id, offset = read_u32(view, offset)
        ct_count = view[offset]
        offset += 1
        ciphertexts = []
        for _ in range(ct_count):
            ct, offset = cls.read_field(view, offset)
            ciphertexts.append(ct)
        if offset + 4 > len(view):
            raise SerializationError("truncated signed prekey id")
        signed_prekey_id = struct.unpack_from(">I", view, offset)[0]
        offset += 4
        has_opk = view[offset]
        offset += 1
        one_time_prekey_id = None
        if has_opk:
            if offset + 4 > len(view):
                raise SerializationError("truncated one-time prekey id")
            one_time_prekey_id = struct.unpack_from(">I", view, offset)[0]
            offset += 4
        signature, offset = cls.read_field(view, offset)
        if offset >= len(view):
            raise SerializationError("truncated initial message ratchet flag")
        has_ratchet = view[offset]
        offset += 1
        ratchet_public = None
        if has_ratchet:
            ratchet_public, offset = cls.read_field(view, offset)
        fields = dict(
            identity_signing=SigningPublicKey(
                identity_data,
                SigningAlg.from_id(identity_alg_id),
            ),
            identity_agreement=identity_agreement,
            ephemeral_public=PublicKey(
                ephemeral_data,
                KeyExchangeAlg.from_id(ephemeral_alg_id),
            ),
            kem_ciphertexts=tuple(ciphertexts),
            signed_prekey_id=signed_prekey_id,
            one_time_prekey_id=one_time_prekey_id,
            signature=signature,
            ratchet_public=ratchet_public,
        )
        return fields, offset

    @classmethod
    def from_bytes(cls, data: bytes) -> InitialMessageX3DH:
        view = memoryview(data)
        if not view:
            raise SerializationError("empty initial message")
        offset = cls.constructor_expect(view)
        fields, offset = cls.decode_body(view, offset)
        if offset != len(view):
            raise SerializationError("trailing bytes in initial message")
        return cls(**fields)

    @staticmethod
    def encode_field(value: bytes) -> bytes:
        if len(value) > 0xFFFF:
            raise SerializationError("field too large")
        return struct.pack(">H", len(value)) + value

    @staticmethod
    def read_field(view: memoryview, offset: int) -> tuple[bytes, int]:
        if offset + 2 > len(view):
            raise SerializationError("truncated initial message field")
        length = struct.unpack_from(">H", view, offset)[0]
        offset += 2
        if offset + length > len(view):
            raise SerializationError("truncated initial message field body")
        value = bytes(view[offset : offset + length])
        return value, offset + length


@dataclass
class InitialMessagePQXDH(InitialMessageX3DH):
    """First message of a PQXDH handshake (X3DH fields + PQ encapsulation)."""

    pq_prekey_id: int = 0
    pq_ciphertext: bytes = b""

    CONSTRUCTOR_ID = ConstructorId.INITIAL_MESSAGE_PQXDH

    def __post_init__(self) -> None:
        if not self.pq_ciphertext:
            raise ValueError("InitialMessagePQXDH requires pq_ciphertext")

    def encode_body(self) -> bytes:
        return (
            super().encode_body()
            + struct.pack(">I", self.pq_prekey_id)
            + self.encode_field(self.pq_ciphertext)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> InitialMessagePQXDH:
        view = memoryview(data)
        if not view:
            raise SerializationError("empty initial message")
        offset = cls.constructor_expect(view)
        fields, offset = cls.decode_body(view, offset)
        if offset + 4 > len(view):
            raise SerializationError("truncated PQ prekey id")
        pq_prekey_id = struct.unpack_from(">I", view, offset)[0]
        offset += 4
        pq_ciphertext, offset = cls.read_field(view, offset)
        if offset != len(view):
            raise SerializationError("trailing bytes in PQXDH initial message")
        return cls(
            **fields,
            pq_prekey_id=pq_prekey_id,
            pq_ciphertext=pq_ciphertext,
        )
