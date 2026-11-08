"""Shared NIST elliptic-curve ECDH (agreement only)."""
from __future__ import annotations


from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ratchetkit.errors import InvalidKey
from ratchetkit.algorithms.kem.base import KemBackend
from ratchetkit.keys.keypair import KeyPair, PublicKey

if TYPE_CHECKING:
    from ratchetkit.suite.algs import KeyExchangeAlg


class EcKem(KemBackend):
    """NIST elliptic-curve ECDH-as-KEM backend base."""

    algorithm: KeyExchangeAlg
    curve: ec.EllipticCurve
    supports_dh = True

    def generate_keypair(self) -> KeyPair:
        raw = ec.generate_private_key(self.curve)
        byte_length = (self.curve.key_size + 7) // 8
        private = raw.private_numbers().private_value.to_bytes(byte_length, "big")
        return KeyPair(
            private=private,
            public=PublicKey(self.derive_public(private), self.algorithm),
        )

    def derive_public(self, private: bytes) -> bytes:
        key = ec.derive_private_key(int.from_bytes(private, "big"), self.curve)
        return key.public_key().public_bytes(
            Encoding.X962,
            PublicFormat.UncompressedPoint,
        )

    def encapsulate(self, their_public: PublicKey) -> tuple[bytes, bytes]:
        ephemeral = self.generate_keypair()
        secret = self.dh(ephemeral, their_public)
        return secret, ephemeral.public.data

    def decapsulate(self, our_private: KeyPair, ciphertext: bytes) -> bytes:
        return self.dh(
            our_private,
            PublicKey(ciphertext, self.algorithm),
        )

    def dh(self, our_private: KeyPair, their_public: PublicKey) -> bytes:
        try:
            private = ec.derive_private_key(
                int.from_bytes(our_private.private, "big"),
                self.curve,
            )
            public = ec.EllipticCurvePublicKey.from_encoded_point(
                self.curve,
                their_public.data,
            )
            shared = private.exchange(ec.ECDH(), public)
        except Exception as exc:
            raise InvalidKey(
                f"{self.algorithm.name} ECDH failed (invalid public key)"
            ) from exc
        if not any(shared):
            raise InvalidKey(
                f"{self.algorithm.name} ECDH produced an all-zero shared secret"
            )
        return shared
