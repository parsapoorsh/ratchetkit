"""Conversation session: encrypt / decrypt + binary persistence."""
from __future__ import annotations


from ratchetkit.errors import SerializationError
from ratchetkit.packing import (
    Constructor,
    ConstructorId,
    encode_bytes,
    read_bytes,
)
from ratchetkit.ratchet.message import RatchetMessage
from ratchetkit.ratchet.protocol import Ratchet
from ratchetkit.ratchet.protocol.double import DoubleRatchet
from ratchetkit.ratchet.protocol.triple import TripleRatchet
from ratchetkit.suite.double import CryptoSuiteDoubleRatchet
from ratchetkit.suite.triple import CryptoSuiteTripleRatchet


class Session(Constructor):
    """Live ratchet half: encrypt, decrypt, and persist.

    Opened by ``suite.initiate`` / ``suite.accept``. Restored with
    :meth:`from_bytes`.
    """

    CONSTRUCTOR_ID = ConstructorId.SESSION

    def __init__(
        self,
        suite: CryptoSuiteDoubleRatchet,
        ratchet: Ratchet,
        associated_data: bytes = b"",
    ):
        self.suite = suite
        self.ratchet = ratchet
        self.associated_data = associated_data

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
            suite: CryptoSuiteDoubleRatchet = CryptoSuiteTripleRatchet.from_bytes(suite_blob)
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
