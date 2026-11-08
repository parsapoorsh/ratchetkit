"""Shared RSA-OAEP encapsulation (agreement only)."""
from __future__ import annotations


import os
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ratchetkit.errors import InvalidKey
from ratchetkit.algorithms.kem.base import KemBackend
from ratchetkit.keys.keypair import KeyPair, PublicKey

if TYPE_CHECKING:
    from ratchetkit.suite.algs import KeyExchangeAlg


class RsaKem(KemBackend):
    """RSA-OAEP encapsulation backend base."""

    algorithm: KeyExchangeAlg
    key_size: int
    supports_dh = False
    secret_size = 32

    def generate_keypair(self) -> KeyPair:
        raw = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
        )
        private = raw.private_bytes(
            Encoding.DER,
            PrivateFormat.PKCS8,
            NoEncryption(),
        )
        return KeyPair(
            private=private,
            public=PublicKey(self.derive_public(private), self.algorithm),
        )

    def derive_public(self, private: bytes) -> bytes:
        key = serialization.load_der_private_key(private, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise InvalidKey("expected RSA private key")
        return key.public_key().public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        )

    def encapsulate(self, their_public: PublicKey) -> tuple[bytes, bytes]:
        loaded = serialization.load_der_public_key(their_public.data)
        if not isinstance(loaded, rsa.RSAPublicKey):
            raise InvalidKey("expected RSA public key")
        secret = os.urandom(self.secret_size)
        ciphertext = loaded.encrypt(
            secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return secret, ciphertext

    def decapsulate(self, our_private: KeyPair, ciphertext: bytes) -> bytes:
        loaded = serialization.load_der_private_key(
            our_private.private,
            password=None,
        )
        if not isinstance(loaded, rsa.RSAPrivateKey):
            raise InvalidKey("expected RSA private key")
        try:
            return loaded.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:
            raise InvalidKey("RSA-OAEP decapsulation failed") from exc
