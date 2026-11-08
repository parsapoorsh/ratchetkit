"""Long-lived identity key pair (signing + optional DH)."""
from __future__ import annotations


from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.keys.keypair import KeyPair, SigningKeyPair

if TYPE_CHECKING:
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet


@dataclass
class IdentityKeyPair:
    """Account identity: signing key, plus DH key when the suite supports it.

    Signing and agreement are separate key pairs (separate algorithms).
    """

    signing: SigningKeyPair
    agreement: KeyPair | None = None

    @classmethod
    def generate(cls, suite: CryptoSuiteDoubleRatchet) -> IdentityKeyPair:
        signing = suite.signer.generate_keypair()
        agreement = suite.kem.generate_keypair() if suite.kem.supports_dh else None
        return cls(signing=signing, agreement=agreement)
