"""Chunked ML-KEM Sparse Continuous Key Agreement (SCKA).

Alternating KEM ping-pong with payloads split across ``n_chunks`` application
messages (Signal DR §5.1 interface; chunk amortization from ePrint 2025/078).

Turn discipline (like the classical DH ratchet):
  - Alice starts as the CKA *sender* (advertises a public key).
  - Bob becomes sender after fully receiving Alice's payload (encapsulates).
  - Roles swap after each completed exchange so both sides share one secret
    per epoch - never two concurrent encapsulations into the same epoch.
"""
from __future__ import annotations


import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ratchetkit.errors import InvalidKey, InvalidMessage, SerializationError
from ratchetkit.keys.keypair import KeyPair, PublicKey
from ratchetkit.packing import (
    Constructor,
    ConstructorId,
    encode_bool,
    encode_bytes,
    encode_optional_bytes,
    encode_u32,
    read_bool,
    read_bytes,
    read_optional_bytes,
    read_u32,
)
from ratchetkit.scka.chunk import ChunkCodec, ChunkFrame

if TYPE_CHECKING:
    from ratchetkit.algorithms.kem.base import KemBackend


@dataclass
class SckaKey:
    """Shared secret emitted by the SCKA for a numbered epoch."""

    epoch: int
    key: bytes


@dataclass
class SckaSendResult:
    msg: bytes
    # CKA epoch currently being exchanged (tCurr); may lead tS.
    cka_epoch: int
    # Chunks sent so far for the active outbound payload (cS).
    chunks_sent: int
    # Fresh shared secret to mix into the root (sender-side, once per epoch).
    mix_key: SckaKey | None


@dataclass
class SckaRecvResult:
    # CKA epoch after processing this frame (tCurr).
    cka_epoch: int
    # Chunks held for the current inbound payload (cR).
    chunks_recv: int
    # Reconstructed shared secret to mix into the root (once per epoch).
    mix_key: SckaKey | None


@dataclass
class ChunkedKemScka(Constructor):
    """Alternating KEM SCKA with fixed-width chunk amortization.

    Epoch 0 is the handshake secret. Epochs 1, 2, ... are produced one at a time
    by a single encapsulator; the peer reconstructs the same secret from the
    chunked ciphertext.

    Sender mixes the shared secret as soon as encapsulate succeeds (paper TR
    KDF1 at CKA-Send), while still drip-feeding chunks. Receiver mixes only
    after reconstructing all ``n_chunks`` pieces. ``peer_ack`` carries how many
    chunks the peer has stored so SPQR can activate tS early (cAck+1 >= n).
    """

    kem: KemBackend
    n_chunks: int
    # True while this party should be drip-feeding a CKA payload.
    is_cka_sender: bool = False
    our_key: KeyPair | None = None
    their_public: PublicKey | None = None
    # Last CKA epoch whose secret has been mixed (or handshake 0).
    epoch: int = 0
    send_chunks: list[bytes] | None = None
    send_chunk_index: int = 0
    send_payload_len: int = 0
    send_key_epoch: int = 0
    pending_send_secret: bytes | None = None
    # Secret produced by prepare_outbound; returned once as mix_key on first send.
    pending_mix_secret: bytes | None = None
    recv_chunks: dict[int, bytes] = field(default_factory=dict)
    recv_payload_len: int = 0
    recv_key_epoch: int = 0
    peer_ack: int = 0
    codec: ChunkCodec = field(init=False)

    def __post_init__(self) -> None:
        if self.n_chunks < 1:
            raise ValueError("n_chunks must be at least 1")
        self.codec = ChunkCodec(self.n_chunks)

    def clone(self) -> ChunkedKemScka:
        """Trial-decrypt copy via constructor (no deepcopy)."""
        return ChunkedKemScka(
            kem=self.kem,
            n_chunks=self.n_chunks,
            is_cka_sender=self.is_cka_sender,
            our_key=self.our_key,
            their_public=self.their_public,
            epoch=self.epoch,
            send_chunks=(
                list(self.send_chunks) if self.send_chunks is not None else None
            ),
            send_chunk_index=self.send_chunk_index,
            send_payload_len=self.send_payload_len,
            send_key_epoch=self.send_key_epoch,
            pending_send_secret=self.pending_send_secret,
            pending_mix_secret=self.pending_mix_secret,
            recv_chunks=dict(self.recv_chunks),
            recv_payload_len=self.recv_payload_len,
            recv_key_epoch=self.recv_key_epoch,
            peer_ack=self.peer_ack,
        )

    @classmethod
    def init_alice(cls, kem: KemBackend, n_chunks: int = 8) -> ChunkedKemScka:
        # Alice opens the first CKA transmission.
        return cls(kem=kem, n_chunks=n_chunks, is_cka_sender=True)

    @classmethod
    def init_bob(cls, kem: KemBackend, n_chunks: int = 8) -> ChunkedKemScka:
        return cls(kem=kem, n_chunks=n_chunks, is_cka_sender=False)

    def send(self) -> SckaSendResult:
        if self.is_cka_sender and self.send_chunks is None:
            self.prepare_outbound()

        if self.send_chunks is None:
            # Not our CKA turn (or nothing to send): ack-only.
            return SckaSendResult(
                msg=self.ack_frame().to_bytes(),
                cka_epoch=self.epoch,
                chunks_sent=0,
                mix_key=None,
            )

        # Emit mix_key once when the sender first starts drip-feeding a secret.
        mix_key = None
        if self.pending_mix_secret is not None:
            mix_key = SckaKey(self.send_key_epoch, self.pending_mix_secret)
            self.epoch = self.send_key_epoch
            self.pending_mix_secret = None

        index = self.send_chunk_index
        frame = ChunkFrame(
            flags=ChunkFrame.FLAG_PAYLOAD,
            key_epoch=self.send_key_epoch,
            chunk_index=index,
            n_chunks=self.n_chunks,
            ack_count=len(self.recv_chunks),
            payload_len=self.send_payload_len,
            data=self.send_chunks[index],
        )
        self.send_chunk_index = index + 1
        chunks_sent = self.send_chunk_index
        cka_epoch = self.send_key_epoch

        if self.send_chunk_index >= self.n_chunks:
            self.pending_send_secret = None
            self.send_chunks = None
            self.send_chunk_index = 0
            # Finished distributing; wait for peer to become CKA sender.
            self.is_cka_sender = False

        return SckaSendResult(
            msg=frame.to_bytes(),
            cka_epoch=cka_epoch,
            chunks_sent=chunks_sent,
            mix_key=mix_key,
        )

    def receive(self, msg: bytes) -> SckaRecvResult:
        frame = ChunkFrame.from_bytes(msg)
        self.peer_ack = max(self.peer_ack, frame.ack_count)

        if frame.flags & ChunkFrame.FLAG_ACK_ONLY and not (
            frame.flags & ChunkFrame.FLAG_PAYLOAD
        ):
            return SckaRecvResult(
                cka_epoch=self.epoch,
                chunks_recv=len(self.recv_chunks),
                mix_key=None,
            )

        if not (frame.flags & ChunkFrame.FLAG_PAYLOAD):
            raise InvalidMessage("SCKA frame missing payload flag")
        if frame.n_chunks != self.n_chunks:
            raise InvalidMessage("SCKA n_chunks mismatch")

        if frame.key_epoch < self.recv_key_epoch:
            return SckaRecvResult(
                cka_epoch=self.epoch,
                chunks_recv=len(self.recv_chunks),
                mix_key=None,
            )

        if frame.key_epoch != self.recv_key_epoch or not self.recv_chunks:
            if frame.key_epoch != self.recv_key_epoch:
                self.recv_chunks = {}
            self.recv_key_epoch = frame.key_epoch
            self.recv_payload_len = frame.payload_len

        if frame.chunk_index not in self.recv_chunks:
            self.recv_chunks[frame.chunk_index] = frame.data

        mix_key = None
        if len(self.recv_chunks) >= self.n_chunks:
            payload = self.codec.join(self.recv_chunks, self.recv_payload_len)
            self.recv_chunks = {}
            secret = self.consume_payload(payload)
            if secret is not None:
                mix_key = SckaKey(frame.key_epoch, secret)
                self.epoch = frame.key_epoch
            # Peer finished their CKA payload; it is now our turn to send.
            self.is_cka_sender = True

        return SckaRecvResult(
            cka_epoch=max(self.epoch, frame.key_epoch),
            chunks_recv=len(self.recv_chunks),
            mix_key=mix_key,
        )

    def prepare_outbound(self) -> None:
        if self.their_public is None:
            # Advertise a fresh encapsulation key (bootstrap or next round key).
            self.our_key = self.kem.generate_keypair()
            payload = self.encode_bootstrap(self.our_key.public.data)
            # Bootstrap alone does not produce a shared secret.
            self.arm_send(payload, key_epoch=self.epoch + 1, secret=None)
            return

        secret, ciphertext = self.kem.encapsulate(self.their_public)
        if not any(secret):
            raise InvalidKey("SCKA encapsulate produced all-zero secret")
        # Fresh local key for the peer's next encapsulation.
        self.our_key = self.kem.generate_keypair()
        payload = self.encode_exchange(ciphertext, self.our_key.public.data)
        self.arm_send(payload, key_epoch=self.epoch + 1, secret=secret)

    def arm_send(
        self,
        payload: bytes,
        key_epoch: int,
        secret: bytes | None,
    ) -> None:
        self.send_chunks = self.codec.split(payload)
        self.send_chunk_index = 0
        self.send_payload_len = len(payload)
        self.send_key_epoch = key_epoch
        self.pending_send_secret = secret
        # Emit as mix_key on the first drip chunk (paper: KDF1 at CKA-Send).
        self.pending_mix_secret = secret
        self.peer_ack = 0

    def consume_payload(self, payload: bytes) -> bytes | None:
        kind, body = self.decode_payload(payload)
        if kind == 0:
            public = self.read_length_prefixed(body)
            self.their_public = PublicKey(public, self.kem.algorithm)
            return None
        if kind == 1:
            ciphertext, rest = self.read_length_prefixed_rest(body)
            peer_public, _ = self.read_length_prefixed_rest(rest)
            if self.our_key is None:
                raise InvalidKey("SCKA decapsulate without local private key")
            try:
                secret = self.kem.decapsulate(self.our_key, ciphertext)
            except Exception as exc:
                raise InvalidKey("SCKA KEM decapsulation failed") from exc
            if not any(secret):
                raise InvalidKey("SCKA shared secret is all zeros")
            self.their_public = PublicKey(peer_public, self.kem.algorithm)
            return secret
        raise InvalidMessage(f"unknown SCKA payload kind {kind}")

    def ack_frame(self) -> ChunkFrame:
        return ChunkFrame(
            flags=ChunkFrame.FLAG_ACK_ONLY,
            key_epoch=self.epoch,
            chunk_index=0,
            n_chunks=self.n_chunks,
            ack_count=len(self.recv_chunks),
            payload_len=0,
            data=b"",
        )

    @staticmethod
    def encode_bootstrap(public: bytes) -> bytes:
        return bytes([0]) + struct.pack(">H", len(public)) + public

    @staticmethod
    def encode_exchange(ciphertext: bytes, public: bytes) -> bytes:
        return (
            bytes([1])
            + struct.pack(">H", len(ciphertext))
            + ciphertext
            + struct.pack(">H", len(public))
            + public
        )

    @staticmethod
    def decode_payload(payload: bytes) -> tuple[int, bytes]:
        if not payload:
            raise InvalidMessage("empty SCKA payload")
        return payload[0], payload[1:]

    @staticmethod
    def read_length_prefixed(body: bytes) -> bytes:
        value, rest = ChunkedKemScka.read_length_prefixed_rest(body)
        if rest:
            raise InvalidMessage("trailing bytes in SCKA field")
        return value

    @staticmethod
    def read_length_prefixed_rest(body: bytes) -> tuple[bytes, bytes]:
        if len(body) < 2:
            raise InvalidMessage("truncated SCKA length prefix")
        length = struct.unpack_from(">H", body, 0)[0]
        if 2 + length > len(body):
            raise InvalidMessage("truncated SCKA field")
        return body[2:2 + length], body[2 + length:]

    CONSTRUCTOR_ID = ConstructorId.SCKA

    def to_bytes(self) -> bytes:
        send_chunks_blob = None
        if self.send_chunks is not None:
            parts = [encode_u32(len(self.send_chunks))]
            for chunk in self.send_chunks:
                parts.append(encode_bytes(chunk))
            send_chunks_blob = b"".join(parts)

        recv_parts = [encode_u32(len(self.recv_chunks))]
        for index in sorted(self.recv_chunks):
            recv_parts.append(encode_u32(index))
            recv_parts.append(encode_bytes(self.recv_chunks[index]))
        recv_blob = b"".join(recv_parts)

        our_key = None
        if self.our_key is not None:
            our_key = self.our_key.to_bytes()
        their_public = None
        if self.their_public is not None:
            their_public = self.their_public.to_bytes()

        return b"".join(
            [
                self.constructor_pack(),
                encode_u32(self.n_chunks),
                encode_bool(self.is_cka_sender),
                encode_optional_bytes(our_key),
                encode_optional_bytes(their_public),
                encode_u32(self.epoch),
                encode_optional_bytes(send_chunks_blob),
                encode_u32(self.send_chunk_index),
                encode_u32(self.send_payload_len),
                encode_u32(self.send_key_epoch),
                encode_optional_bytes(self.pending_send_secret),
                encode_optional_bytes(self.pending_mix_secret),
                encode_bytes(recv_blob),
                encode_u32(self.recv_payload_len),
                encode_u32(self.recv_key_epoch),
                encode_u32(self.peer_ack),
            ]
        )

    @classmethod
    def from_bytes(cls, data: bytes, kem: KemBackend) -> ChunkedKemScka:
        offset = cls.constructor_expect(data)
        n_chunks, offset = read_u32(data, offset)
        is_cka_sender, offset = read_bool(data, offset)
        our_key_blob, offset = read_optional_bytes(data, offset)
        their_public_blob, offset = read_optional_bytes(data, offset)
        epoch, offset = read_u32(data, offset)
        send_chunks_blob, offset = read_optional_bytes(data, offset)
        send_chunk_index, offset = read_u32(data, offset)
        send_payload_len, offset = read_u32(data, offset)
        send_key_epoch, offset = read_u32(data, offset)
        pending_send_secret, offset = read_optional_bytes(data, offset)
        pending_mix_secret, offset = read_optional_bytes(data, offset)
        recv_blob, offset = read_bytes(data, offset)
        recv_payload_len, offset = read_u32(data, offset)
        recv_key_epoch, offset = read_u32(data, offset)
        peer_ack, offset = read_u32(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in SCKA")

        our_key = None
        if our_key_blob is not None:
            our_key = KeyPair.from_bytes(our_key_blob)
        their_public = None
        if their_public_blob is not None:
            their_public = PublicKey.from_bytes(their_public_blob)

        send_chunks = None
        if send_chunks_blob is not None:
            count, pos = read_u32(send_chunks_blob, 0)
            send_chunks = []
            for _ in range(count):
                chunk, pos = read_bytes(send_chunks_blob, pos)
                send_chunks.append(chunk)
            if pos != len(send_chunks_blob):
                raise SerializationError("trailing bytes in SCKA send chunks")

        recv_count, pos = read_u32(recv_blob, 0)
        recv_chunks: dict[int, bytes] = {}
        for _ in range(recv_count):
            index, pos = read_u32(recv_blob, pos)
            chunk, pos = read_bytes(recv_blob, pos)
            recv_chunks[index] = chunk
        if pos != len(recv_blob):
            raise SerializationError("trailing bytes in SCKA recv chunks")

        return cls(
            kem=kem,
            n_chunks=n_chunks,
            is_cka_sender=is_cka_sender,
            our_key=our_key,
            their_public=their_public,
            epoch=epoch,
            send_chunks=send_chunks,
            send_chunk_index=send_chunk_index,
            send_payload_len=send_payload_len,
            send_key_epoch=send_key_epoch,
            pending_send_secret=pending_send_secret,
            pending_mix_secret=pending_mix_secret,
            recv_chunks=recv_chunks,
            recv_payload_len=recv_payload_len,
            recv_key_epoch=recv_key_epoch,
            peer_ack=peer_ack,
        )
