"""Triple Ratchet: classical Double Ratchet + Sparse PQ Ratchet (DR §6)."""
from __future__ import annotations


from typing import TYPE_CHECKING

from ratchetkit.errors import SerializationError
from ratchetkit.kdf import Kdf
from ratchetkit.keys.keypair import KeyPair, PublicKey
from ratchetkit.keys.message import MessageKeys
from ratchetkit.packing import (
    Constructor,
    ConstructorId,
    encode_bytes,
    read_bytes,
)
from ratchetkit.ratchet.limits import RatchetLimits
from ratchetkit.ratchet.message import DoubleRatchetMessage, TripleRatchetMessage
from ratchetkit.ratchet.protocol.base import Ratchet
from ratchetkit.ratchet.protocol.double import DoubleRatchet
from ratchetkit.ratchet.spqr import SparsePostQuantumRatchet
from ratchetkit.suite import KdfLabel
from ratchetkit.suite.registry import hash_backend

if TYPE_CHECKING:
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite
    from ratchetkit.suite.triple import CryptoSuiteTripleRatchet


class TripleRatchet(Ratchet[TripleRatchetMessage], Constructor):
    """Hybrid secure messaging: EC Double Ratchet ∥ Sparse PQ Ratchet.

    Owns composition: split handshake SK, advance the EC leaf and SPQR leaf,
    then KDF_HYBRID before AEAD (Signal Double Ratchet specification §6 /
    ePrint 2025/078 hybrid idea).
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
        suite: CryptoSuiteTripleRatchet,
        shared_secret: bytes,
        our_ratchet_key: KeyPair,
        their_ratchet_public: PublicKey,
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
            suite.pq_kem,
            n_chunks=suite.scka_chunks,
            limits=limits,
        )
        return cls(suite=suite, ec=ec, spqr=spqr)

    @classmethod
    def accept(
        cls,
        suite: CryptoSuiteTripleRatchet,
        shared_secret: bytes,
        their_ratchet_public: PublicKey,
        our_ratchet_key: KeyPair,
        first_header: bytes | None = None,
        limits: RatchetLimits | None = None,
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
            suite.pq_kem,
            n_chunks=suite.scka_chunks,
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
            info=KdfLabel.TR_SPLIT,
        )
        return material[:size], material[size:]

    def hybrid_message_key(self, ec_mk: bytes, pq_mk: bytes) -> bytes:
        """KDF_HYBRID(ec_mk, pq_mk) -> seed for MessageKeys.derive."""
        size = hash_backend(self.suite.digest).digest_size
        return self.kdf.hkdf(
            ec_mk,
            size,
            salt=pq_mk,
            info=KdfLabel.TR_HYBRID,
        )

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes = b"",
    ) -> TripleRatchetMessage:
        ec_keys, header, previous_counter = self.ec.take_send_keys()
        ec_header = DoubleRatchetMessage(
            ratchet_public=header,
            previous_counter=previous_counter,
            counter=ec_keys.counter,
            ciphertext=b"",
            mac=b"",
        )

        pq_keys, spqr_header = self.spqr.send_key()
        seed = self.hybrid_message_key(ec_keys.cipher_key, pq_keys.cipher_key)
        hybrid = MessageKeys.derive(seed, ec_keys.counter, self.suite)
        message = TripleRatchetMessage(
            ec_message=ec_header,
            spqr_header=spqr_header,
            ciphertext=b"",
            mac=b"",
        )
        message.mac = hybrid.compute_mac(
            message.header_bytes(),
            associated_data,
            plaintext,
            self.suite,
        )
        message.ciphertext = hybrid.encrypt(plaintext, self.suite, message.mac)
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
        ec_message = message.ec_message
        ec_keys = self.ec.take_keys(
            ec_message.ratchet_public,
            ec_message.counter,
            ec_message.previous_counter,
        )
        pq_keys = self.spqr.receive_key(message.spqr_header)
        seed = self.hybrid_message_key(ec_keys.cipher_key, pq_keys.cipher_key)
        hybrid = MessageKeys.derive(seed, ec_keys.counter, self.suite)
        plaintext = hybrid.decrypt(message.ciphertext, self.suite, message.mac)
        hybrid.verify_mac(
            message.header_bytes(),
            associated_data,
            plaintext,
            message.mac,
            self.suite,
        )
        return plaintext

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

