"""Double Ratchet encrypt / decrypt with DH or KEM ratchet steps."""
from __future__ import annotations


import hmac
from typing import TYPE_CHECKING

from ratchetkit.errors import DuplicateMessage, InvalidKey, InvalidMessage, SerializationError
from ratchetkit.kdf import Kdf
from ratchetkit.keys.keypair import KeyPair, PublicKey
from ratchetkit.keys.message import MessageKeys
from ratchetkit.keys.root import RootKey
from ratchetkit.packing import (
    Constructor,
    ConstructorId,
    encode_bytes,
    encode_optional_bytes,
    encode_u32,
    read_bytes,
    read_optional_bytes,
    read_u32,
)
from ratchetkit.ratchet.chains import ReceiverChain, SenderChain
from ratchetkit.ratchet.header import RatchetHeader
from ratchetkit.ratchet.limits import RatchetLimits
from ratchetkit.ratchet.message import DoubleRatchetMessage
from ratchetkit.ratchet.protocol.base import Ratchet
from ratchetkit.ratchet.skipped import SkippedMessageKeys

if TYPE_CHECKING:
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite


class DoubleRatchet(Ratchet, Constructor):
    """Stateful Double Ratchet session half.

    Decrypt mutates state only after MAC verification succeeds, matching
    libsignal's trial-session pattern (clone, try, commit on success).
    """

    def __init__(
        self,
        suite: CryptoSuite,
        root_key: RootKey,
        sender_chain: SenderChain | None = None,
        receiver_chains: list[ReceiverChain] | None = None,
        previous_counter: int = 0,
        skipped: SkippedMessageKeys | None = None,
        limits: RatchetLimits | None = None,
        our_ratchet_key: KeyPair | None = None,
        sender_header: bytes | None = None,
        their_kem_public: PublicKey | None = None,
    ):
        self.suite = suite
        self.root_key = root_key
        self.sender_chain = sender_chain
        self.receiver_chains = receiver_chains or []
        self.previous_counter = previous_counter
        self.limits = limits or RatchetLimits()
        self.skipped = skipped or SkippedMessageKeys(self.limits)
        self.kdf = Kdf(suite.digest)
        self.our_ratchet_key = our_ratchet_key
        self.sender_header = sender_header
        self.their_kem_public = their_kem_public

    @property
    def is_kem(self) -> bool:
        return not self.suite.kem.supports_dh

    @classmethod
    def initiate(
        cls,
        suite: CryptoSuite,
        shared_secret: bytes,
        our_ratchet_key: KeyPair,
        their_ratchet_public: PublicKey,
    ) -> DoubleRatchet:
        """Alice: seed sending chain against Bob's signed prekey public."""
        root = RootKey(shared_secret, suite)
        if suite.kem.supports_dh:
            root, chain = root.create_chain(
                their_ratchet_public,
                our_ratchet_key,
            )
            sender_header = RatchetHeader.encode_dh(our_ratchet_key.public.data)
            their_kem = None
        else:
            root, chain, ct = root.create_chain_send(their_ratchet_public)
            sender_header = RatchetHeader.encode_kem(our_ratchet_key.public.data, ct)
            their_kem = their_ratchet_public
        return cls(
            suite=suite,
            root_key=root,
            sender_chain=SenderChain(our_ratchet_key, chain),
            our_ratchet_key=our_ratchet_key,
            sender_header=sender_header,
            their_kem_public=their_kem,
        )

    @classmethod
    def accept(
        cls,
        suite: CryptoSuite,
        shared_secret: bytes,
        their_ratchet_public: PublicKey,
        our_ratchet_key: KeyPair,
        first_header: bytes | None = None,
    ) -> DoubleRatchet:
        """Bob: seed receiving chain under Alice's first ratchet material."""
        root = RootKey(shared_secret, suite)
        if suite.kem.supports_dh:
            root, recv_chain = root.create_chain(
                their_ratchet_public,
                our_ratchet_key,
            )
            remote_id = their_ratchet_public
            their_kem = None
        else:
            if first_header is None:
                raise InvalidMessage("KEM accept requires first encapsulation header")
            remote_public, ct = RatchetHeader.decode_kem(first_header)
            # Header public must match the signed initial ratchet public.
            if their_ratchet_public.data and remote_public != their_ratchet_public.data:
                raise InvalidMessage(
                    "KEM header public does not match initial ratchet public"
                )
            root, recv_chain = root.create_chain_recv(our_ratchet_key, ct)
            remote_id = PublicKey(
                RatchetHeader.chain_id(first_header, is_kem=True),
                suite.kem.algorithm,
            )
            their_kem = PublicKey(remote_public, suite.kem.algorithm)

        return cls(
            suite=suite,
            root_key=root,
            sender_chain=None,
            receiver_chains=[ReceiverChain(remote_id, recv_chain)],
            our_ratchet_key=our_ratchet_key,
            their_kem_public=their_kem,
        )

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes = b"",
    ) -> DoubleRatchetMessage:
        if self.sender_chain is None:
            self.ensure_sender_chain()

        assert self.sender_chain is not None
        assert self.sender_header is not None
        chain = self.sender_chain.chain_key
        keys = chain.message_keys()
        ciphertext = keys.encrypt(plaintext, self.suite)
        message = DoubleRatchetMessage(
            ratchet_public=self.sender_header,
            previous_counter=self.previous_counter,
            counter=keys.counter,
            ciphertext=ciphertext,
            mac=b"",
        )
        message.mac = self.compute_mac(
            keys,
            message.header_bytes(),
            associated_data,
            ciphertext,
        )
        self.sender_chain.chain_key = chain.next_chain_key()
        return message

    def decrypt(
        self,
        message: DoubleRatchetMessage,
        associated_data: bytes = b"",
    ) -> bytes:
        """Decrypt; commit ratchet state only after MAC verification succeeds.

        Matches libsignal: try on a cloned session, keep the clone only on
        success so forged headers/counters cannot desync the live state.
        """
        trial = self.clone()
        plaintext = trial.apply_decrypt(message, associated_data)
        self.adopt(trial)
        return plaintext

    def apply_decrypt(
        self,
        message: DoubleRatchetMessage,
        associated_data: bytes = b"",
    ) -> bytes:
        """Mutating decrypt for a trial clone only. Prefer :meth:`decrypt`."""
        try:
            chain_id = RatchetHeader.chain_id(message.ratchet_public, self.is_kem)
        except Exception as exc:
            raise InvalidMessage("malformed ratchet header") from exc

        skipped = self.skipped.peek(chain_id, message.counter)
        if skipped is not None:
            self.verify_mac(skipped, message, associated_data)
            self.skipped.take(chain_id, message.counter)
            return skipped.decrypt(message.ciphertext, self.suite)

        chain = self.find_receiver_chain(chain_id)
        if chain is None:
            try:
                chain = self.ratchet_step(
                    message.ratchet_public,
                    message.previous_counter,
                )
            except InvalidKey as exc:
                # Bad remote public / failed DH must not leak as a raw crypto error.
                raise InvalidMessage("ratchet step rejected remote key material") from exc

        if message.counter < chain.chain_key.index:
            raise DuplicateMessage(chain.chain_key.index, message.counter)

        chain.chain_key = self.skipped.skip_in_chain(
            chain_id,
            chain.chain_key,
            message.counter,
        )
        keys = chain.chain_key.message_keys()
        self.verify_mac(keys, message, associated_data)
        plaintext = keys.decrypt(message.ciphertext, self.suite)
        chain.chain_key = chain.chain_key.next_chain_key()
        return plaintext

    def clone(self) -> DoubleRatchet:
        """Trial-decrypt copy via ``__init__`` (no deepcopy).

        Mutable containers get new wrappers; immutable key material and the
        suite are shared. ChainKey / KeyPair objects are not mutated in place.
        """
        sender = None
        if self.sender_chain is not None:
            sender = SenderChain(
                self.sender_chain.ratchet_key,
                self.sender_chain.chain_key,
            )
        receivers = [
            ReceiverChain(chain.ratchet_public, chain.chain_key)
            for chain in self.receiver_chains
        ]
        return DoubleRatchet(
            suite=self.suite,
            root_key=self.root_key,
            sender_chain=sender,
            receiver_chains=receivers,
            previous_counter=self.previous_counter,
            skipped=self.skipped.clone(),
            limits=self.limits,
            our_ratchet_key=self.our_ratchet_key,
            sender_header=self.sender_header,
            their_kem_public=self.their_kem_public,
        )

    def adopt(self, other: DoubleRatchet) -> None:
        """Replace live state with a successful trial decrypt state."""
        self.root_key = other.root_key
        self.sender_chain = other.sender_chain
        self.receiver_chains = other.receiver_chains
        self.previous_counter = other.previous_counter
        self.skipped = other.skipped
        self.our_ratchet_key = other.our_ratchet_key
        self.sender_header = other.sender_header
        self.their_kem_public = other.their_kem_public

    CONSTRUCTOR_ID = ConstructorId.DOUBLE_RATCHET

    def to_bytes(self) -> bytes:
        sender = None
        if self.sender_chain is not None:
            sender = self.sender_chain.to_bytes()
        our_key = None
        if self.our_ratchet_key is not None:
            our_key = self.our_ratchet_key.to_bytes()
        their_kem = None
        if self.their_kem_public is not None:
            their_kem = self.their_kem_public.to_bytes()
        parts = [
            self.constructor_pack(),
            encode_bytes(self.root_key.to_bytes()),
            encode_u32(self.previous_counter),
            encode_bytes(self.limits.to_bytes()),
            encode_optional_bytes(sender),
            encode_u32(len(self.receiver_chains)),
        ]
        for chain in self.receiver_chains:
            parts.append(encode_bytes(chain.to_bytes()))
        parts.append(encode_bytes(self.skipped.to_bytes()))
        parts.append(encode_optional_bytes(our_key))
        parts.append(encode_optional_bytes(self.sender_header))
        parts.append(encode_optional_bytes(their_kem))
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes, suite: CryptoSuite) -> DoubleRatchet:
        offset = cls.constructor_expect(data)
        root_blob, offset = read_bytes(data, offset)
        previous_counter, offset = read_u32(data, offset)
        limits_blob, offset = read_bytes(data, offset)
        sender_blob, offset = read_optional_bytes(data, offset)
        receiver_count, offset = read_u32(data, offset)
        receivers = []
        for _ in range(receiver_count):
            chain_blob, offset = read_bytes(data, offset)
            receivers.append(ReceiverChain.from_bytes(chain_blob, suite))
        skipped_blob, offset = read_bytes(data, offset)
        our_key_blob, offset = read_optional_bytes(data, offset)
        sender_header, offset = read_optional_bytes(data, offset)
        their_kem_blob, offset = read_optional_bytes(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in double ratchet")

        sender = None
        if sender_blob is not None:
            sender = SenderChain.from_bytes(sender_blob, suite)
        our_key = None
        if our_key_blob is not None:
            our_key = KeyPair.from_bytes(our_key_blob)
        their_kem = None
        if their_kem_blob is not None:
            their_kem = PublicKey.from_bytes(their_kem_blob)
        return cls(
            suite=suite,
            root_key=RootKey.from_bytes(root_blob, suite),
            sender_chain=sender,
            receiver_chains=receivers,
            previous_counter=previous_counter,
            skipped=SkippedMessageKeys.from_bytes(skipped_blob),
            limits=RatchetLimits.from_bytes(limits_blob),
            our_ratchet_key=our_key,
            sender_header=sender_header,
            their_kem_public=their_kem,
        )

    def find_receiver_chain(self, ratchet_id: bytes) -> ReceiverChain | None:
        for chain in self.receiver_chains:
            if chain.ratchet_id == ratchet_id:
                return chain
        return None

    def ratchet_step(
        self,
        header: bytes,
        previous_counter: int = 0,
    ) -> ReceiverChain:
        # Double Ratchet: before installing a new remote chain, skip any
        # remaining keys on the current receive chain through PN.
        self.skip_previous_chain(previous_counter)

        if self.sender_chain is not None:
            # libsignal: previous_counter = sender_index.saturating_sub(1)
            index = self.sender_chain.chain_key.index
            self.previous_counter = index - 1 if index > 0 else 0
        if self.is_kem:
            return self.kem_ratchet(header)
        return self.dh_ratchet(PublicKey(header, self.suite.kem.algorithm))

    def skip_previous_chain(self, previous_counter: int) -> None:
        """Cache message keys on the newest receiver chain through PN inclusive."""
        if not self.receiver_chains:
            return
        old = self.receiver_chains[0]
        # PN is the last counter sent on the peer's previous sending chain.
        target = previous_counter + 1
        if target <= old.chain_key.index:
            return
        old.chain_key = self.skipped.skip_in_chain(
            old.ratchet_id,
            old.chain_key,
            target,
        )

    def dh_ratchet(self, their_public: PublicKey) -> ReceiverChain:
        our_key = self.our_ratchet_key
        if our_key is None:
            our_key = self.suite.kem.generate_keypair()
            self.our_ratchet_key = our_key

        self.root_key, recv_ck = self.root_key.create_chain(
            their_public,
            our_key,
        )
        receiver = ReceiverChain(their_public, recv_ck)
        self.push_receiver(receiver)

        new_local = self.suite.kem.generate_keypair()
        self.root_key, send_ck = self.root_key.create_chain(
            their_public,
            new_local,
        )
        self.sender_chain = SenderChain(new_local, send_ck)
        self.sender_header = RatchetHeader.encode_dh(new_local.public.data)
        self.our_ratchet_key = new_local
        return receiver

    def kem_ratchet(self, header: bytes) -> ReceiverChain:
        remote_public, ct = RatchetHeader.decode_kem(header)
        our_key = self.our_ratchet_key
        if our_key is None:
            raise InvalidMessage("KEM ratchet missing local private key")

        self.root_key, recv_ck = self.root_key.create_chain_recv(our_key, ct)
        chain_id = PublicKey(
            RatchetHeader.chain_id(header, is_kem=True),
            self.suite.kem.algorithm,
        )
        receiver = ReceiverChain(chain_id, recv_ck)
        self.push_receiver(receiver)
        self.their_kem_public = PublicKey(remote_public, self.suite.kem.algorithm)

        new_local = self.suite.kem.generate_keypair()
        self.root_key, send_ck, send_ct = self.root_key.create_chain_send(
            self.their_kem_public
        )
        self.sender_chain = SenderChain(new_local, send_ck)
        self.sender_header = RatchetHeader.encode_kem(new_local.public.data, send_ct)
        self.our_ratchet_key = new_local
        return receiver

    def push_receiver(self, receiver: ReceiverChain) -> None:
        self.receiver_chains.insert(0, receiver)
        while len(self.receiver_chains) > self.limits.MAX_RECEIVER_CHAINS:
            self.receiver_chains.pop()

    def ensure_sender_chain(self) -> None:
        if self.sender_chain is not None:
            return
        if not self.is_kem:
            if not self.receiver_chains:
                raise InvalidMessage("cannot encrypt before ratchet is initialized")
            their_public = self.receiver_chains[0].ratchet_public
            new_local = self.suite.kem.generate_keypair()
            self.root_key, send_ck = self.root_key.create_chain(
                their_public,
                new_local,
            )
            self.sender_chain = SenderChain(new_local, send_ck)
            self.sender_header = RatchetHeader.encode_dh(new_local.public.data)
            self.our_ratchet_key = new_local
            return

        if self.their_kem_public is None:
            raise InvalidMessage("KEM send missing remote public")
        new_local = self.suite.kem.generate_keypair()
        self.root_key, send_ck, ct = self.root_key.create_chain_send(
            self.their_kem_public
        )
        self.sender_chain = SenderChain(new_local, send_ck)
        self.sender_header = RatchetHeader.encode_kem(new_local.public.data, ct)
        self.our_ratchet_key = new_local

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
        message: DoubleRatchetMessage,
        associated_data: bytes,
    ) -> None:
        expected = self.compute_mac(
            keys,
            message.header_bytes(),
            associated_data,
            message.ciphertext,
        )
        if not hmac.compare_digest(expected, message.mac):
            raise InvalidMessage("MAC verification failed")
