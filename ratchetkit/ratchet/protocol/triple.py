"""Triple Ratchet: classical Double Ratchet + Sparse PQ Ratchet (DR §6)."""
from __future__ import annotations

from ratchetkit.suite.registry import hash_backend


import hmac
from typing import TYPE_CHECKING

from ratchetkit.errors import InvalidMessage, SerializationError
from ratchetkit.kdf import Kdf
from ratchetkit.keys.keypair import KeyPair, PublicKey
from ratchetkit.keys.message import MessageKeys
from ratchetkit.packing import (
    Constructor,
    ConstructorId,
    encode_bytes,
    expect_constructor,
    pack_constructor,
    read_bytes,
)
from ratchetkit.ratchet.limits import RatchetLimits
from ratchetkit.ratchet.message import TripleRatchetMessage
from ratchetkit.ratchet.protocol.base import Ratchet
from ratchetkit.ratchet.protocol.double import DoubleRatchet
from ratchetkit.ratchet.spqr import SparsePostQuantumRatchet
from ratchetkit.suite import KdfLabel

if TYPE_CHECKING:
    from ratchetkit.algorithms.kem.base import KemBackend
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite
    from ratchetkit.suite.triple import CryptoSuiteTripleRatchet


TR_INFO_SPLIT = b"TR v1 SK split"
TR_INFO_HYBRID = b"TR v1 hybrid mk"


class TripleRatchet(Ratchet, Constructor):
    """Hybrid secure messaging: EC Double Ratchet ∥ Sparse PQ Ratchet.

    Owns composition only: split handshake SK, drive both leaf ratchets via
    their ``send_key`` / ``receive_key``, then KDF_HYBRID before AEAD
    (Signal Double Ratchet specification §6 / ePrint 2025/078 hybrid idea).
    """

    def __init__(
        self,
        suite: CryptoSuite,
        ec: DoubleRatchet,
        spqr: SparsePostQuantumRatchet,
    ):
        self.suite = suite
        self.ec = ec
        self.spqr = spqr
        self.kdf = Kdf(suite.digest)

    @classmethod
    def initiate(
        cls,
        suite: CryptoSuite,
        shared_secret: bytes,
        our_ratchet_key: KeyPair,
        their_ratchet_public: PublicKey,
        pq_kem: KemBackend,
        n_chunks: int = 8,
        limits: RatchetLimits | None = None,
    ) -> TripleRatchet:
        sk_ec, sk_scka = cls.split_sk(suite, shared_secret)
        ec = DoubleRatchet.initiate(
            suite,
            sk_ec,
            our_ratchet_key,
            their_ratchet_public,
        )
        if limits is not None:
            ec.limits = limits
            ec.skipped.limits = limits
        spqr = SparsePostQuantumRatchet.initiate(
            suite,
            sk_scka,
            pq_kem,
            n_chunks=n_chunks,
            limits=limits,
        )
        return cls(suite=suite, ec=ec, spqr=spqr)

    @classmethod
    def accept(
        cls,
        suite: CryptoSuite,
        shared_secret: bytes,
        their_ratchet_public: PublicKey,
        our_ratchet_key: KeyPair,
        pq_kem: KemBackend,
        n_chunks: int = 8,
        limits: RatchetLimits | None = None,
        first_header: bytes | None = None,
    ) -> TripleRatchet:
        sk_ec, sk_scka = cls.split_sk(suite, shared_secret)
        ec = DoubleRatchet.accept(
            suite,
            sk_ec,
            their_ratchet_public,
            our_ratchet_key,
            first_header=first_header,
        )
        if limits is not None:
            ec.limits = limits
            ec.skipped.limits = limits
        spqr = SparsePostQuantumRatchet.accept(
            suite,
            sk_scka,
            pq_kem,
            n_chunks=n_chunks,
            limits=limits,
        )
        return cls(suite=suite, ec=ec, spqr=spqr)

    @staticmethod
    def split_sk(suite: CryptoSuite, sk: bytes) -> tuple[bytes, bytes]:
        """Expand handshake SK into SKec and SKscka (spec §7.1)."""
        size = hash_backend(suite.digest).digest_size
        kdf = Kdf(suite.digest)
        material = kdf.hkdf(
            sk,
            size * 2,
            salt=bytes(size),
            info=TR_INFO_SPLIT + KdfLabel.TR_SPLIT,
        )
        return material[:size], material[size:]

    def hybrid_message_key(self, ec_mk: bytes, pq_mk: bytes) -> bytes:
        """KDF_HYBRID(ec_mk, pq_mk) -> seed for MessageKeys.derive."""
        size = hash_backend(self.suite.digest).digest_size
        return self.kdf.hkdf(
            ec_mk,
            size,
            salt=pq_mk,
            info=TR_INFO_HYBRID + KdfLabel.TR_HYBRID,
        )

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes = b"",
    ) -> TripleRatchetMessage:
        ec_keys, ec_header = self.ec.send_key()
        pq_keys, spqr_header = self.spqr.send_key()
        seed = self.hybrid_message_key(ec_keys.cipher_key, pq_keys.cipher_key)
        hybrid = MessageKeys.derive(seed, ec_keys.counter, self.suite)
        ciphertext = hybrid.encrypt(plaintext, self.suite)
        message = TripleRatchetMessage(
            ec_message=ec_header,
            spqr_header=spqr_header,
            ciphertext=ciphertext,
            mac=b"",
        )
        message.mac = self.compute_mac(
            hybrid,
            message.header_bytes(),
            associated_data,
            ciphertext,
        )
        return message

    def decrypt(
        self,
        message: TripleRatchetMessage,
        associated_data: bytes = b"",
    ) -> bytes:
        trial = self.clone()
        plaintext = trial.apply_decrypt(message, associated_data)
        self.adopt(trial)
        return plaintext

    def apply_decrypt(
        self,
        message: TripleRatchetMessage,
        associated_data: bytes = b"",
    ) -> bytes:
        ec_keys = self.ec.receive_key(message.ec_message)
        pq_keys = self.spqr.receive_key(message.spqr_header)
        seed = self.hybrid_message_key(ec_keys.cipher_key, pq_keys.cipher_key)
        hybrid = MessageKeys.derive(seed, ec_keys.counter, self.suite)
        self.verify_mac(
            hybrid,
            message.header_bytes(),
            associated_data,
            message.ciphertext,
            message.mac,
        )
        return hybrid.decrypt(message.ciphertext, self.suite)

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
        header: bytes,
        associated_data: bytes,
        ciphertext: bytes,
        mac: bytes,
    ) -> None:
        expected = self.compute_mac(keys, header, associated_data, ciphertext)
        if not hmac.compare_digest(expected, mac):
            raise InvalidMessage("Triple Ratchet MAC verification failed")

    def clone(self) -> TripleRatchet:
        """Trial-decrypt copy via ``__init__`` (no deepcopy)."""
        return TripleRatchet(
            suite=self.suite,
            ec=self.ec.clone(),
            spqr=self.spqr.clone(),
        )

    def adopt(self, other: TripleRatchet) -> None:
        self.ec = other.ec
        self.spqr = other.spqr

    CONSTRUCTOR_ID = ConstructorId.TRIPLE_RATCHET

    def to_bytes(self) -> bytes:
        return (
            self.constructor_pack()
            + encode_bytes(self.ec.to_bytes())
            + encode_bytes(self.spqr.to_bytes())
        )

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        suite: CryptoSuiteTripleRatchet,
    ) -> TripleRatchet:
        offset = cls.constructor_expect(data)
        ec_blob, offset = read_bytes(data, offset)
        spqr_blob, offset = read_bytes(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in triple ratchet")
        return cls(
            suite=suite,
            ec=DoubleRatchet.from_bytes(ec_blob, suite),
            spqr=SparsePostQuantumRatchet.from_bytes(
                spqr_blob,
                suite,
                suite.pq_kem,
            ),
        )

