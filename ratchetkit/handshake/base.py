"""Shared base for X3DH / PQXDH handshakes."""
from __future__ import annotations


from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.errors import InvalidKey
from ratchetkit.kdf import Kdf
from ratchetkit.suite.registry import hash_backend

if TYPE_CHECKING:
    from ratchetkit.handshake.message import InitialMessageX3DH
    from ratchetkit.keys.identity import IdentityKeyPair
    from ratchetkit.keys.keypair import KeyPair
    from ratchetkit.keys.prekey import (
        OneTimePreKey,
        PreKeyBundle,
        SignedPqPreKey,
        SignedPreKey,
    )
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite


@dataclass
class HandshakeResult:
    """Outcome of :meth:`Handshake.initiate` (shared secret + first wire msg)."""

    shared_secret: bytes
    initial_message: InitialMessageX3DH
    # Initiator-side ratchet key used to seed the Double Ratchet sending chain.
    ratchet_key: KeyPair | None = None


class Handshake(ABC):
    """Bundle publish / initiate / respond for a key-agreement protocol.

    Subclasses supply protocol-specific secret collection and the HKDF
    ``info`` label via :attr:`kdf_info`.
    """

    # HKDF info bound into :meth:`derive_secret` (e.g. KdfLabel.X3DH).
    kdf_info: bytes

    def __init__(self, suite: CryptoSuite):
        self.suite = suite
        self.kdf = Kdf(suite.digest)
        self.kem = suite.kem

    @abstractmethod
    def create_bundle(
        self,
        identity: IdentityKeyPair,
        signed_prekey: SignedPreKey,
        one_time_prekey: OneTimePreKey | None = None,
        pq_prekey: SignedPqPreKey | None = None,
    ) -> PreKeyBundle:
        """Build and verify a publishable prekey bundle for this protocol."""

    @abstractmethod
    def initiate(
        self,
        our_identity: IdentityKeyPair,
        their_bundle: PreKeyBundle,
    ) -> HandshakeResult:
        """Alice: derive shared secret and produce the signed initial message."""

    @abstractmethod
    def respond(
        self,
        our_identity: IdentityKeyPair,
        our_signed_prekey: SignedPreKey,
        initial_message: InitialMessageX3DH,
        our_one_time_prekey: OneTimePreKey | None = None,
        our_pq_prekey: SignedPqPreKey | None = None,
    ) -> bytes:
        """Bob: verify initiator and derive the matching shared secret."""

    def validate_initial_algorithms(self, initial_message: InitialMessageX3DH) -> None:
        """Reject initiator keys whose algorithms do not match this suite."""
        if initial_message.identity_signing.algorithm != self.suite.signing:
            raise InvalidKey(
                f"initial message identity signing algorithm "
                f"{initial_message.identity_signing.algorithm!r} "
                f"does not match suite {self.suite.signing!r}"
            )
        expected = self.kem.algorithm
        checks = [
            ("ephemeral", initial_message.ephemeral_public.algorithm),
        ]
        if initial_message.identity_agreement is not None:
            checks.append(
                ("identity agreement", initial_message.identity_agreement.algorithm)
            )
        for label, algorithm in checks:
            if algorithm != expected:
                raise InvalidKey(
                    f"initial message {label} algorithm {algorithm!r} "
                    f"does not match suite {expected!r}"
                )

    def sign_initial_material(
        self,
        our_identity: IdentityKeyPair,
        material: bytes,
    ) -> bytes:
        """Sign initiator material with the local identity signing key."""
        return self.suite.signer.sign(
            our_identity.signing,
            material,
            hash_backend(self.suite.digest),
        )

    def derive_secret(self, secrets: list[bytes]) -> bytes:
        """HKDF-combine DH/KEM secrets with this protocol's ``kdf_info`` label."""
        name = type(self).__name__
        if not secrets:
            raise InvalidKey(f"no {name} secrets to combine")
        for index, secret in enumerate(secrets):
            if not isinstance(secret, (bytes, bytearray)) or not secret:
                raise InvalidKey(f"{name} secret {index} is empty")
            if not any(secret):
                raise InvalidKey(f"{name} secret {index} is all zeros")
        size = hash_backend(self.suite.digest).digest_size
        prefix = b"\xff" * size
        ikm = prefix + b"".join(bytes(s) for s in secrets)
        return self.kdf.hkdf(
            ikm,
            size,
            salt=None,
            info=self.kdf_info,
        )
