"""Long-lived identity key pair (signing + optional DH)."""
from __future__ import annotations


from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.keys.keypair import KeyPair, SigningKeyPair

if TYPE_CHECKING:
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite


@dataclass
class IdentityKeyPair:
    """Account identity: signing key, plus DH key when the suite supports it.

    ``suite`` is the crypto this identity was minted for; handshake APIs
    take it from here so callers do not pass the suite again.

    Signing and agreement are separate key pairs (separate algorithms).
    """

    signing: SigningKeyPair
    agreement: KeyPair | None = None
    suite: CryptoSuite | None = None

    @classmethod
    def generate(cls, suite: CryptoSuite) -> IdentityKeyPair:
        signing = suite.signer.generate_keypair()
        agreement = suite.kem.generate_keypair() if suite.kem.supports_dh else None
        return cls(signing=signing, agreement=agreement, suite=suite)

    def require_suite(self) -> CryptoSuite:
        if self.suite is None:
            raise ValueError("identity has no suite; use IdentityKeyPair.generate")
        return self.suite
