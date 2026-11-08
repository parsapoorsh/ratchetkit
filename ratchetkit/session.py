"""High-level Session: suite handshake wired into the matching ratchet."""
from __future__ import annotations


from ratchetkit.errors import SerializationError
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import (
    OneTimePreKey,
    PreKeyBundle,
    SignedPqPreKey,
    SignedPreKey,
)
from ratchetkit.packing import (
    Constructor,
    ConstructorId,
    encode_bytes,
    read_bytes,
)
from ratchetkit.ratchet.message import RatchetMessage
from ratchetkit.ratchet.protocol import Ratchet
from ratchetkit.suite.double import CryptoSuiteDoubleRatchet
from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite
from ratchetkit.suite.triple import CryptoSuiteTripleRatchet
from ratchetkit.handshake.message import InitialMessageX3DH


class Session(Constructor):
    """Conversation session: encrypt / decrypt + binary persistence.

    ``CryptoSuiteDoubleRatchet`` uses classical X3DH + Double Ratchet.
    ``CryptoSuiteTripleRatchet`` uses PQXDH + Triple Ratchet.
    """

    CONSTRUCTOR_ID = ConstructorId.SESSION

    def __init__(
        self,
        suite: CryptoSuite,
        ratchet: Ratchet,
        associated_data: bytes = b"",
    ):
        self.suite = suite
        self.ratchet = ratchet
        self.associated_data = associated_data

    @classmethod
    def initiate(
        cls,
        our_identity: IdentityKeyPair,
        their_bundle: PreKeyBundle,
    ) -> tuple[Session, InitialMessageX3DH]:
        """Alice: suite handshake + open the suite's ratchet."""
        suite = our_identity.require_suite()
        result = suite.handshake().initiate(our_identity, their_bundle)
        ratchet = suite.open_initiate(result, their_bundle)
        associated = (
            our_identity.signing.public.data + their_bundle.identity_signing.data
        )
        session = cls(
            suite=suite,
            ratchet=ratchet,
            associated_data=associated,
        )
        return session, result.initial_message

    @classmethod
    def accept(
        cls,
        our_identity: IdentityKeyPair,
        our_signed_prekey: SignedPreKey,
        initial: InitialMessageX3DH,
        message: RatchetMessage,
        our_one_time_prekey: OneTimePreKey | None = None,
        associated_data: bytes = b"",
        our_pq_prekey: SignedPqPreKey | None = None,
    ) -> tuple[Session, bytes]:
        """Bob: finish handshake, open matching ratchet, decrypt first message.

        ``associated_data`` is extra AD for the first message only; it is
        appended to the handshake identity AD (same rule as :meth:`decrypt`).

        Triple / PQXDH sessions require ``our_pq_prekey`` matching the bundle.
        """
        suite = our_identity.require_suite()
        if not isinstance(message, suite.Message):
            raise TypeError(
                f"{type(suite).__name__} requires {suite.Message.__name__}"
            )
        shared = suite.respond_handshake(
            our_identity,
            our_signed_prekey,
            initial,
            our_one_time_prekey,
            our_pq_prekey,
        )
        ratchet = suite.open_accept(
            shared,
            initial,
            message,
            our_signed_prekey,
        )
        associated = (
            initial.identity_signing.data + our_identity.signing.public.data
        )
        session = cls(
            suite=suite,
            ratchet=ratchet,
            associated_data=associated,
        )
        return session, session.decrypt(message, associated_data)

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes = b"",
    ) -> RatchetMessage:
        """Encrypt plaintext; returns a ratchet message (caller serializes).

        ``associated_data`` is extra AD authenticated with the MAC (appended to
        the session handshake AD). Both sides must pass the same bytes.
        """
        return self.ratchet.encrypt(
            plaintext,
            self.associated_data + associated_data,
        )

    def decrypt(
        self,
        message: RatchetMessage,
        associated_data: bytes = b"",
    ) -> bytes:
        """Decrypt a ratchet message; returns plaintext bytes.

        ``associated_data`` must match the extra AD used at encrypt time.
        """
        if not isinstance(message, self.suite.Message):
            raise TypeError(
                f"{type(self.suite).__name__} requires {self.suite.Message.__name__}"
            )
        return self.ratchet.decrypt(
            message,
            self.associated_data + associated_data,
        )

    def to_bytes(self) -> bytes:
        """Serialize full session state (suite + ratchet + AD).

        The blob includes the crypto suite, so ``from_bytes`` does not need a
        separate suite argument. Treat the result as secret key material.
        """
        return (
            self.constructor_pack()
            + encode_bytes(self.suite.to_bytes())
            + encode_bytes(self.associated_data)
            + encode_bytes(self.ratchet.to_bytes())
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Session:
        """Restore a session from :meth:`to_bytes` output."""
        offset = cls.constructor_expect(data)
        suite_blob, offset = read_bytes(data, offset)
        associated_data, offset = read_bytes(data, offset)
        ratchet_blob, offset = read_bytes(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in session")

        suite_id, _ = Constructor.constructor_read(suite_blob, 0)
        if suite_id is ConstructorId.SUITE_TRIPLE:
            suite: CryptoSuite = CryptoSuiteTripleRatchet.from_bytes(suite_blob)
        elif suite_id is ConstructorId.SUITE_DOUBLE:
            suite = CryptoSuiteDoubleRatchet.from_bytes(suite_blob)
        else:
            raise SerializationError(
                f"session suite constructor 0x{int(suite_id):08X} not supported"
            )
        return cls(
            suite=suite,
            ratchet=suite.load_ratchet(ratchet_blob),
            associated_data=associated_data,
        )
