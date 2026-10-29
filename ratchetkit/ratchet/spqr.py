"""Sparse Post-Quantum Ratchet (Signal Double Ratchet specification §5)."""
from __future__ import annotations

from ratchetkit.suite.registry import hash_backend


import hmac
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.errors import (
    DuplicateMessage,
    InvalidMessage,
    SerializationError,
    TooFarInFuture,
    TooManySkippedKeys,
)
from ratchetkit.kdf import Kdf
from ratchetkit.keys.chain import ChainKey
from ratchetkit.keys.message import MessageKeys
from ratchetkit.packing import (
    Constructor,
    ConstructorId,
    encode_bool,
    encode_bytes,
    encode_u32,
    encode_u8,
    read_bool,
    read_bytes,
    read_u32,
    read_u8,
)
from ratchetkit.ratchet.limits import RatchetLimits
from ratchetkit.scka.kem_scka import ChunkedKemScka
from ratchetkit.suite import KdfLabel

if TYPE_CHECKING:
    from ratchetkit.algorithms.kem.base import KemBackend
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite


# Direction constants (spec A2B / B2A).
DIR_A2B = 0
DIR_B2A = 1

SPQR_INFO_INIT = b"SPQR v1 Chain Start"
SPQR_INFO_EPOCH = b"SPQR v1 Chain Add Epoch"


@dataclass
class EpochChains:
    """Send and receive chain keys for one SCKA epoch."""

    send: ChainKey | None
    receive: ChainKey | None

    def to_bytes(self) -> bytes:
        parts = []
        if self.send is None:
            parts.append(encode_bool(False))
        else:
            parts.append(encode_bool(True))
            parts.append(encode_bytes(self.send.to_bytes()))
        if self.receive is None:
            parts.append(encode_bool(False))
        else:
            parts.append(encode_bool(True))
            parts.append(encode_bytes(self.receive.to_bytes()))
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes, suite: CryptoSuite) -> EpochChains:
        has_send, offset = read_bool(data, 0)
        send = None
        if has_send:
            send_blob, offset = read_bytes(data, offset)
            send = ChainKey.from_bytes(send_blob, suite)
        has_recv, offset = read_bool(data, offset)
        receive = None
        if has_recv:
            recv_blob, offset = read_bytes(data, offset)
            receive = ChainKey.from_bytes(recv_blob, suite)
        if offset != len(data):
            raise SerializationError("trailing bytes in epoch chains")
        return cls(send=send, receive=receive)


@dataclass
class SpqrHeader:
    """Sparse PQ ratchet header: SCKA body + epoch/period counters.

    Layout mirrors paper TR hQ fields used for skip bookkeeping:
    ``t_s`` (sending key epoch), ``i_s_prev2`` / ``i_s_prev`` (periods in
    the two prior sending epochs), and ``counter`` (period in ``t_s``).
    """

    scka_msg: bytes
    counter: int
    t_s: int = 0
    previous_counter: int = 0
    previous2_counter: int = 0

    def to_bytes(self) -> bytes:
        if len(self.scka_msg) > 0xFFFF:
            raise InvalidMessage("SCKA header too large")
        return (
            struct.pack(">H", len(self.scka_msg))
            + self.scka_msg
            + struct.pack(
                ">IIII",
                self.t_s & 0xFFFFFFFF,
                self.previous2_counter & 0xFFFFFFFF,
                self.previous_counter & 0xFFFFFFFF,
                self.counter & 0xFFFFFFFF,
            )
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> SpqrHeader:
        # len(2) + body + t_s/prev2/prev/counter (16)
        if len(data) < 2 + 16:
            raise InvalidMessage("truncated SPQR header")
        length = struct.unpack_from(">H", data, 0)[0]
        offset = 2
        if offset + length + 16 > len(data):
            raise InvalidMessage("truncated SPQR header body")
        scka_msg = data[offset:offset + length]
        offset += length
        t_s, previous2_counter, previous_counter, counter = struct.unpack_from(
            ">IIII",
            data,
            offset,
        )
        return cls(
            scka_msg=scka_msg,
            counter=counter,
            t_s=t_s,
            previous_counter=previous_counter,
            previous2_counter=previous2_counter,
        )

    def header_bytes(self) -> bytes:
        return self.to_bytes()


class SparsePostQuantumRatchet(Constructor):
    """Secure messaging ratchet driven by an SCKA (DR §5 / ePrint 2025/078).

    Scheduling (paper Table 1):
      t_curr  - CKA epoch currently being exchanged (may lead t_s)
      t_s     - epoch under which we encrypt outgoing messages
      t_r     - epoch under which we decrypt incoming messages
    Keys for epoch e are mixed into the root as soon as SCKA produces them
    (sender at first drip chunk; receiver after full reconstruction), but
    ``t_s`` only advances once the peer is known to hold enough chunks
    (cAck + 1 >= n_chunks) or once reconstruction finishes on our side.
    """

    def __init__(
        self,
        suite: CryptoSuite,
        root_key: bytes,
        scka: ChunkedKemScka,
        direction: int,
        chains: dict[int, EpochChains] | None = None,
        # Highest epoch whose SCKA secret has been mixed into the root.
        mixed_epoch: int = 0,
        # Paper tS / tR / tCurr.
        t_s: int = 0,
        t_r: int = 0,
        t_curr: int = 0,
        # Periods of the last two sealed sending epochs (iS-1, iS-2).
        previous_counter: int = 0,
        previous2_counter: int = 0,
        skipped: dict[tuple[int, int], MessageKeys] | None = None,
        skipped_order: list[tuple[int, int]] | None = None,
        limits: RatchetLimits | None = None,
    ):
        self.suite = suite
        self.root_key = root_key
        self.scka = scka
        self.direction = direction
        self.chains = chains if chains is not None else {}
        self.mixed_epoch = mixed_epoch
        self.t_s = t_s
        self.t_r = t_r
        self.t_curr = t_curr
        self.previous_counter = previous_counter
        self.previous2_counter = previous2_counter
        self.skipped = skipped if skipped is not None else {}
        self.limits = limits or RatchetLimits()
        self.kdf = Kdf(suite.digest)
        if skipped_order is not None:
            self.skipped_order = list(skipped_order)
        else:
            self.skipped_order = list(self.skipped.keys())

    # Back-compat aliases used by compromise tests / examples.
    @property
    def epoch(self) -> int:
        return self.mixed_epoch

    @property
    def sending_epoch(self) -> int:
        return self.t_s

    @property
    def receiving_epoch(self) -> int:
        return self.t_r

    @classmethod
    def initiate(
        cls,
        suite: CryptoSuite,
        shared_secret: bytes,
        pq_kem: KemBackend,
        n_chunks: int = 8,
        limits: RatchetLimits | None = None,
    ) -> SparsePostQuantumRatchet:
        """Alice: initialize SPQR from a shared secret."""
        root, ck_send, ck_recv = cls.kdf_init(suite, shared_secret)
        scka = ChunkedKemScka.init_alice(pq_kem, n_chunks=n_chunks)
        ratchet = cls(
            suite=suite,
            root_key=root,
            scka=scka,
            direction=DIR_A2B,
            limits=limits,
        )
        ratchet.chains[0] = EpochChains(
            send=ChainKey(ck_send, 0, suite),
            receive=ChainKey(ck_recv, 0, suite),
        )
        return ratchet

    @classmethod
    def accept(
        cls,
        suite: CryptoSuite,
        shared_secret: bytes,
        pq_kem: KemBackend,
        n_chunks: int = 8,
        limits: RatchetLimits | None = None,
    ) -> SparsePostQuantumRatchet:
        """Bob: initialize SPQR (send/recv chain seeds swapped)."""
        root, ck_a, ck_b = cls.kdf_init(suite, shared_secret)
        # Spec: Bob gets CKr, CKs reordered relative to Alice.
        ck_send, ck_recv = ck_b, ck_a
        scka = ChunkedKemScka.init_bob(pq_kem, n_chunks=n_chunks)
        ratchet = cls(
            suite=suite,
            root_key=root,
            scka=scka,
            direction=DIR_B2A,
            limits=limits,
        )
        ratchet.chains[0] = EpochChains(
            send=ChainKey(ck_send, 0, suite),
            receive=ChainKey(ck_recv, 0, suite),
        )
        return ratchet

    @staticmethod
    def kdf_init(suite: CryptoSuite, sk: bytes) -> tuple[bytes, bytes, bytes]:
        size = hash_backend(suite.digest).digest_size
        kdf = Kdf(suite.digest)
        material = kdf.hkdf(
            sk,
            size * 3,
            salt=bytes(size),
            info=SPQR_INFO_INIT + KdfLabel.SPQR_INIT,
        )
        return material[:size], material[size:size * 2], material[size * 2:]

    def kdf_rk(self, scka_out: bytes) -> tuple[bytes, bytes, bytes]:
        size = hash_backend(self.suite.digest).digest_size
        material = self.kdf.hkdf(
            scka_out,
            size * 3,
            salt=self.root_key,
            info=SPQR_INFO_EPOCH + KdfLabel.SPQR_EPOCH,
        )
        return material[:size], material[size:size * 2], material[size * 2:]

    def install_epoch(self, key_epoch: int, key: bytes) -> None:
        """Mix SCKA secret into root and stage send/recv chains for ``key_epoch``.

        Does not advance ``t_s`` / ``t_r``; callers activate those once the peer
        can decrypt (ack threshold or full reconstruction).
        """
        if key_epoch != self.mixed_epoch + 1:
            raise InvalidMessage(
                f"SCKA epoch jump: have {self.mixed_epoch}, got {key_epoch}"
            )
        root, ck_send, ck_recv = self.kdf_rk(key)
        if self.direction == DIR_B2A:
            ck_send, ck_recv = ck_recv, ck_send
        self.root_key = root
        self.chains[key_epoch] = EpochChains(
            send=ChainKey(ck_send, 0, self.suite),
            receive=ChainKey(ck_recv, 0, self.suite),
        )
        self.mixed_epoch = key_epoch
        self.t_curr = max(self.t_curr, key_epoch)
        self.clear_old_epochs(key_epoch)

    def clear_old_epochs(self, current: int) -> None:
        """Drop chains and skipped keys older than current - 2 (two prior epochs)."""
        # Keep current and the two previous epochs for skip recovery (iS-1, iS-2).
        stale = [ep for ep in self.chains if ep < current - 2]
        for ep in stale:
            del self.chains[ep]
        stale_skip = [key for key in self.skipped if key[0] < current - 2]
        for key in stale_skip:
            self.skipped.pop(key, None)
            if key in self.skipped_order:
                self.skipped_order.remove(key)

    def activate_send_epoch(self, target: int) -> None:
        """Advance t_s to ``target`` (paper: start using next KS)."""
        if target <= self.t_s:
            return
        if target not in self.chains or self.chains[target].send is None:
            raise InvalidMessage(
                f"SPQR cannot activate send epoch {target}: chain missing"
            )
        # Seal prior sending chain and shift period history (iS -> iS-1 -> iS-2).
        # previous_counter is the last counter used on the sealed chain (PN),
        # matching Double Ratchet / libsignal semantics.
        old = self.chains.get(self.t_s)
        if old is not None and old.send is not None:
            index = old.send.index
            sealed_last = index - 1 if index > 0 else 0
            self.previous2_counter = self.previous_counter
            self.previous_counter = sealed_last
            old.send = None
        self.t_s = target

    def try_activate_send_from_ack(self) -> None:
        """Paper TR-Send: if t_s < t_curr and cAck+1 >= n_chunks, start using KS."""
        if self.t_s >= self.t_curr:
            return
        if self.t_curr not in self.chains:
            return
        # peer_ack is chunks the peer has stored of our outbound payload.
        if self.scka.peer_ack + 1 < self.scka.n_chunks:
            return
        self.activate_send_epoch(self.t_curr)

    def send_key(self) -> tuple[MessageKeys, SpqrHeader]:
        """Advance SCKA + send chain; return message keys and SPQR header."""
        result = self.scka.send()
        if result.mix_key is not None:
            self.install_epoch(result.mix_key.epoch, result.mix_key.key)

        # t_curr tracks the CKA epoch being exchanged (may lead t_s).
        if result.cka_epoch > self.t_curr:
            self.t_curr = result.cka_epoch

        # Early activation: peer has acknowledged enough chunks (cAck+1 >= n).
        self.try_activate_send_from_ack()

        chains = self.chains.get(self.t_s)
        if chains is None or chains.send is None:
            raise InvalidMessage("SPQR missing sending chain for epoch")

        keys = chains.send.message_keys()
        header = SpqrHeader(
            scka_msg=result.msg,
            counter=keys.counter,
            t_s=self.t_s,
            previous_counter=self.previous_counter,
            previous2_counter=self.previous2_counter,
        )
        chains.send = chains.send.next_chain_key()
        return keys, header

    def receive_key(self, header: SpqrHeader) -> MessageKeys:
        """Advance SCKA + receive chain for ``header``; return message keys.

        Does not verify MAC or decrypt. Standalone decrypt does both after this;
        Triple hybrid verifies a combined MAC instead.

        ``header.t_s`` is the epoch under which the peer encrypted (paper t in
        hQ). We may skip sealed epochs using ``previous_counter`` /
        ``previous2_counter`` (iS-1 / iS-2) when the peer advanced.
        """
        msg_epoch = header.t_s
        if msg_epoch > self.t_r + 2:
            raise TooFarInFuture(
                self.t_r,
                msg_epoch,
                2,
            )

        recv = self.scka.receive(header.scka_msg)
        if recv.mix_key is not None:
            self.install_epoch(recv.mix_key.epoch, recv.mix_key.key)
            # We reconstructed the peer's CKA payload: start using it for send.
            # Paper TR-Rec lines 34-36: tS <- tCurr when cR >= n_chunk.
            if self.t_s < recv.mix_key.epoch:
                self.activate_send_epoch(recv.mix_key.epoch)

        if recv.cka_epoch > self.t_curr:
            self.t_curr = recv.cka_epoch

        # Peer encrypts under a key we already mixed as sender: activate t_s.
        if msg_epoch > self.t_s and msg_epoch <= self.mixed_epoch:
            self.activate_send_epoch(msg_epoch)

        # Peer ack of our outbound chunks may unlock early t_s (cAck+1 >= n).
        self.try_activate_send_from_ack()

        # Advance t_r toward msg_epoch, storing skipped keys on sealed chains.
        # PN is inclusive last counter; skip through PN+1 exclusive (DR style).
        if msg_epoch > self.t_r:
            jump = msg_epoch - self.t_r
            if jump >= 2:
                # Seal t_r fully via iS-2, then t_r+1 via iS-1.
                old = self.chains.get(self.t_r)
                if old is not None and old.receive is not None:
                    self.skip_in_epoch(
                        self.t_r,
                        old.receive,
                        header.previous2_counter + 1,
                    )
                    old.receive = None
                mid = self.t_r + 1
                mid_chain = self.chains.get(mid)
                if mid_chain is not None and mid_chain.receive is not None:
                    self.skip_in_epoch(
                        mid,
                        mid_chain.receive,
                        header.previous_counter + 1,
                    )
                    mid_chain.receive = None
            else:
                old = self.chains.get(self.t_r)
                if old is not None and old.receive is not None:
                    self.skip_in_epoch(
                        self.t_r,
                        old.receive,
                        header.previous_counter + 1,
                    )
                    old.receive = None
            self.t_r = msg_epoch

        skipped = self.skipped.get((msg_epoch, header.counter))
        if skipped is not None:
            self.skipped.pop((msg_epoch, header.counter), None)
            if (msg_epoch, header.counter) in self.skipped_order:
                self.skipped_order.remove((msg_epoch, header.counter))
            return skipped

        chains = self.chains.get(msg_epoch)
        if chains is None or chains.receive is None:
            raise InvalidMessage("SPQR missing receiving chain for epoch")

        if header.counter < chains.receive.index:
            raise DuplicateMessage(chains.receive.index, header.counter)

        chains.receive = self.skip_in_epoch(
            msg_epoch,
            chains.receive,
            header.counter,
        )
        keys = chains.receive.message_keys()
        chains.receive = chains.receive.next_chain_key()
        return keys

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes = b"",
    ) -> tuple[SpqrHeader, bytes, bytes]:
        """Return (header, ciphertext, mac)."""
        keys, header = self.send_key()
        ciphertext = keys.encrypt(plaintext, self.suite)
        mac = self.compute_mac(
            keys,
            header.header_bytes(),
            associated_data,
            ciphertext,
        )
        return header, ciphertext, mac

    def decrypt(
        self,
        header: SpqrHeader,
        ciphertext: bytes,
        mac: bytes,
        associated_data: bytes = b"",
    ) -> bytes:
        trial = self.clone()
        plaintext = trial.apply_decrypt(header, ciphertext, mac, associated_data)
        self.adopt(trial)
        return plaintext

    def apply_decrypt(
        self,
        header: SpqrHeader,
        ciphertext: bytes,
        mac: bytes,
        associated_data: bytes = b"",
    ) -> bytes:
        keys = self.receive_key(header)
        self.verify_mac(keys, header, ciphertext, mac, associated_data)
        return keys.decrypt(ciphertext, self.suite)

    def skip_in_epoch(
        self,
        epoch: int,
        chain: ChainKey,
        until_counter: int,
    ) -> ChainKey:
        if until_counter < chain.index:
            raise DuplicateMessage(chain.index, until_counter)
        jump = until_counter - chain.index
        if jump > self.limits.MAX_FORWARD_JUMPS:
            raise TooFarInFuture(chain.index, until_counter, self.limits.MAX_FORWARD_JUMPS)
        current = chain
        while current.index < until_counter:
            keys = current.message_keys()
            self.store_skipped(epoch, keys)
            current = current.next_chain_key()
        return current

    def store_skipped(self, epoch: int, keys: MessageKeys) -> None:
        key = (epoch, keys.counter)
        if key in self.skipped:
            return
        if len(self.skipped) >= self.limits.MAX_MESSAGE_KEYS:
            raise TooManySkippedKeys(len(self.skipped) + 1, self.limits.MAX_MESSAGE_KEYS)
        self.skipped[key] = keys
        self.skipped_order.append(key)

    def compute_mac(
        self,
        keys: MessageKeys,
        header: bytes,
        associated_data: bytes,
        ciphertext: bytes,
    ) -> bytes:
        material = associated_data + header + ciphertext
        tag = self.kdf.hmac_digest(keys.mac_key, material)
        return tag[: self.suite.tag_size]

    def verify_mac(
        self,
        keys: MessageKeys,
        header: SpqrHeader,
        ciphertext: bytes,
        mac: bytes,
        associated_data: bytes,
    ) -> None:
        expected = self.compute_mac(
            keys,
            header.header_bytes(),
            associated_data,
            ciphertext,
        )
        if not hmac.compare_digest(expected, mac):
            raise InvalidMessage("SPQR MAC verification failed")

    def clone(self) -> SparsePostQuantumRatchet:
        """Trial-decrypt copy via ``__init__`` (no deepcopy)."""
        chains = {
            epoch: EpochChains(send=ec.send, receive=ec.receive)
            for epoch, ec in self.chains.items()
        }
        return SparsePostQuantumRatchet(
            suite=self.suite,
            root_key=self.root_key,
            scka=self.scka.clone(),
            direction=self.direction,
            chains=chains,
            mixed_epoch=self.mixed_epoch,
            t_s=self.t_s,
            t_r=self.t_r,
            t_curr=self.t_curr,
            previous_counter=self.previous_counter,
            previous2_counter=self.previous2_counter,
            skipped=dict(self.skipped),
            skipped_order=self.skipped_order,
            limits=self.limits,
        )

    def adopt(self, other: SparsePostQuantumRatchet) -> None:
        self.root_key = other.root_key
        self.scka = other.scka
        self.direction = other.direction
        self.chains = other.chains
        self.mixed_epoch = other.mixed_epoch
        self.t_s = other.t_s
        self.t_r = other.t_r
        self.t_curr = other.t_curr
        self.previous_counter = other.previous_counter
        self.previous2_counter = other.previous2_counter
        self.skipped = other.skipped
        self.skipped_order = other.skipped_order

    CONSTRUCTOR_ID = ConstructorId.SPQR

    def to_bytes(self) -> bytes:
        chain_parts = [encode_u32(len(self.chains))]
        for epoch in sorted(self.chains):
            chain_parts.append(encode_u32(epoch))
            chain_parts.append(encode_bytes(self.chains[epoch].to_bytes()))

        skipped_parts = [encode_u32(len(self.skipped_order))]
        for epoch, counter in self.skipped_order:
            keys = self.skipped[(epoch, counter)]
            skipped_parts.append(encode_u32(epoch))
            skipped_parts.append(encode_u32(counter))
            skipped_parts.append(encode_bytes(keys.to_bytes()))

        return b"".join(
            [
                self.constructor_pack(),
                encode_bytes(self.root_key),
                encode_u8(self.direction),
                encode_u32(self.mixed_epoch),
                encode_u32(self.t_s),
                encode_u32(self.t_r),
                encode_u32(self.t_curr),
                encode_u32(self.previous_counter),
                encode_u32(self.previous2_counter),
                encode_bytes(self.limits.to_bytes()),
                encode_bytes(self.scka.to_bytes()),
                encode_bytes(b"".join(chain_parts)),
                encode_bytes(b"".join(skipped_parts)),
            ]
        )

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        suite: CryptoSuite,
        pq_kem: KemBackend,
    ) -> SparsePostQuantumRatchet:
        offset = cls.constructor_expect(data)
        root_key, offset = read_bytes(data, offset)
        direction, offset = read_u8(data, offset)
        mixed_epoch, offset = read_u32(data, offset)
        t_s, offset = read_u32(data, offset)
        t_r, offset = read_u32(data, offset)
        t_curr, offset = read_u32(data, offset)
        previous_counter, offset = read_u32(data, offset)
        previous2_counter, offset = read_u32(data, offset)
        limits_blob, offset = read_bytes(data, offset)
        scka_blob, offset = read_bytes(data, offset)
        chains_blob, offset = read_bytes(data, offset)
        skipped_blob, offset = read_bytes(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in SPQR")

        chain_count, pos = read_u32(chains_blob, 0)
        chains: dict[int, EpochChains] = {}
        for _ in range(chain_count):
            chain_epoch, pos = read_u32(chains_blob, pos)
            epoch_blob, pos = read_bytes(chains_blob, pos)
            chains[chain_epoch] = EpochChains.from_bytes(epoch_blob, suite)
        if pos != len(chains_blob):
            raise SerializationError("trailing bytes in SPQR chains")

        skipped_count, pos = read_u32(skipped_blob, 0)
        skipped: dict[tuple[int, int], MessageKeys] = {}
        skipped_order: list[tuple[int, int]] = []
        for _ in range(skipped_count):
            skip_epoch, pos = read_u32(skipped_blob, pos)
            counter, pos = read_u32(skipped_blob, pos)
            keys_blob, pos = read_bytes(skipped_blob, pos)
            keys = MessageKeys.from_bytes(keys_blob)
            if keys.counter != counter:
                raise SerializationError("SPQR skipped key counter mismatch")
            key = (skip_epoch, counter)
            skipped[key] = keys
            skipped_order.append(key)
        if pos != len(skipped_blob):
            raise SerializationError("trailing bytes in SPQR skipped keys")

        ratchet = cls(
            suite=suite,
            root_key=root_key,
            scka=ChunkedKemScka.from_bytes(scka_blob, pq_kem),
            direction=direction,
            chains=chains,
            mixed_epoch=mixed_epoch,
            t_s=t_s,
            t_r=t_r,
            t_curr=t_curr,
            previous_counter=previous_counter,
            previous2_counter=previous2_counter,
            skipped=skipped,
            limits=RatchetLimits.from_bytes(limits_blob),
        )
        ratchet.skipped_order = skipped_order
        return ratchet
