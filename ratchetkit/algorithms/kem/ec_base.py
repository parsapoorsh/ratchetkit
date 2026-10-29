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
        private = self.encode_private(raw)
        return KeyPair(
            private=private,
            public=PublicKey(self.derive_public(private), self.algorithm),
        )

    def derive_public(self, private: bytes) -> bytes:
        return self.encode_public(self.decode_private(private).public_key())

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
            private = self.decode_private(our_private.private)
            public = self.decode_public(their_public.data)
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

    @staticmethod
    def encode_public(key: ec.EllipticCurvePublicKey) -> bytes:
        return key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def encode_private(self, key: ec.EllipticCurvePrivateKey) -> bytes:
        numbers = key.private_numbers()
        byte_length = (self.curve.key_size + 7) // 8
        return numbers.private_value.to_bytes(byte_length, "big")

    def decode_private(self, data: bytes) -> ec.EllipticCurvePrivateKey:
        value = int.from_bytes(data, "big")
        return ec.derive_private_key(value, self.curve)

    def decode_public(self, data: bytes) -> ec.EllipticCurvePublicKey:
        return ec.EllipticCurvePublicKey.from_encoded_point(self.curve, data)
