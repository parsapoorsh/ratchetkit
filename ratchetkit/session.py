"""High-level Session: X3DH/PQXDH handshake wired into Double or Triple Ratchet."""
from __future__ import annotations


from ratchetkit.errors import SerializationError
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.keypair import PublicKey
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
from ratchetkit.ratchet.message import (
    DoubleRatchetMessage,
    RatchetMessage,
    TripleRatchetMessage,
)
from ratchetkit.ratchet.protocol import DoubleRatchet, Ratchet, TripleRatchet
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
        """Alice: suite handshake + open a Double or Triple Ratchet."""
        suite = our_identity.require_suite()
        result = suite.handshake().initiate(our_identity, their_bundle)
        assert result.ratchet_key is not None

        if isinstance(suite, CryptoSuiteTripleRatchet):
            ratchet: Ratchet = TripleRatchet.initiate(
                suite,
                result.shared_secret,
                result.ratchet_key,
                their_bundle.signed_prekey,
                suite.pq_kem,
                n_chunks=suite.scka_chunks,
            )
        else:
            ratchet = DoubleRatchet.initiate(
                suite,
                result.shared_secret,
                result.ratchet_key,
                their_bundle.signed_prekey,
            )

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
        shared = suite.handshake().respond(
            our_identity,
            our_signed_prekey,
            initial,
            our_one_time_prekey,
            our_pq_prekey,
        )
        if initial.ratchet_public is None:
            raise ValueError("initial message missing ratchet public")

        their_ratchet = PublicKey(initial.ratchet_public, suite.kem.algorithm)
        first_header = None
        if not suite.kem.supports_dh:
            if isinstance(message, TripleRatchetMessage):
                first_header = message.ec_message.ratchet_public
            else:
                assert isinstance(message, DoubleRatchetMessage)
                first_header = message.ratchet_public

        if isinstance(suite, CryptoSuiteTripleRatchet):
            ratchet: Ratchet = TripleRatchet.accept(
                suite,
                shared,
                their_ratchet,
                our_signed_prekey.key_pair,
                suite.pq_kem,
                n_chunks=suite.scka_chunks,
                first_header=first_header,
            )
        else:
            ratchet = DoubleRatchet.accept(
                suite,
                shared,
                their_ratchet,
                our_signed_prekey.key_pair,
                first_header=first_header,
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
        ad = self.associated_data + associated_data
        if isinstance(self.ratchet, TripleRatchet):
            if not isinstance(message, TripleRatchetMessage):
                raise TypeError("triple session requires TripleRatchetMessage")
            return self.ratchet.decrypt(message, ad)
        if isinstance(message, TripleRatchetMessage):
            raise TypeError("double session requires DoubleRatchetMessage")
        return self.ratchet.decrypt(message, ad)

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
            if not isinstance(suite, CryptoSuiteTripleRatchet):
                raise SerializationError("triple suite decode failed")
            ratchet: Ratchet = TripleRatchet.from_bytes(ratchet_blob, suite)
        elif suite_id is ConstructorId.SUITE_DOUBLE:
            suite = CryptoSuiteDoubleRatchet.from_bytes(suite_blob)
            ratchet = DoubleRatchet.from_bytes(ratchet_blob, suite)
        else:
            raise SerializationError(
                f"session suite constructor 0x{int(suite_id):08X} not supported"
            )
        return cls(
            suite=suite,
            ratchet=ratchet,
            associated_data=associated_data,
        )
