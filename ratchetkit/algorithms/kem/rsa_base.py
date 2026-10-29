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
        private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
        )
        return KeyPair(
            private=self.encode_private(private),
            algorithm=self.algorithm,
        )

    def derive_public(self, private: bytes) -> bytes:
        return self.encode_public(self.decode_private(private).public_key())

    def encapsulate(self, their_public: PublicKey) -> tuple[bytes, bytes]:
        public = self.decode_public(their_public.data)
        secret = os.urandom(self.secret_size)
        ciphertext = public.encrypt(
            secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return secret, ciphertext

    def decapsulate(self, our_private: KeyPair, ciphertext: bytes) -> bytes:
        private = self.decode_private(our_private.private)
        try:
            return private.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:
            raise InvalidKey("RSA-OAEP decapsulation failed") from exc

    @staticmethod
    def encode_public(key: rsa.RSAPublicKey) -> bytes:
        return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    @staticmethod
    def encode_private(key: rsa.RSAPrivateKey) -> bytes:
        return key.private_bytes(
            Encoding.DER,
            PrivateFormat.PKCS8,
            NoEncryption(),
        )

    @staticmethod
    def decode_public(data: bytes) -> rsa.RSAPublicKey:
        key = serialization.load_der_public_key(data)
        if not isinstance(key, rsa.RSAPublicKey):
            raise InvalidKey("expected RSA public key")
        return key

    @staticmethod
    def decode_private(data: bytes) -> rsa.RSAPrivateKey:
        key = serialization.load_der_private_key(data, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise InvalidKey("expected RSA private key")
        return key
