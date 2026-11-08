"""Hash algorithms for HKDF, HMAC, and signature digests."""
from __future__ import annotations


import hashlib
from abc import ABC, abstractmethod
from typing import Any

from cryptography.hazmat.primitives import hashes


class HashAlgorithm(ABC):
    """Hashlib-compatible digest used for HKDF, HMAC, and signature digests."""

    name: str
    digest_size: int

    @classmethod
    @abstractmethod
    def new(cls, data: bytes = b"") -> Any:
        """Return a hashlib-style digest object."""

    @classmethod
    @abstractmethod
    def constructor(cls):
        """Return the hashlib constructor (for hmac / HKDF)."""

    @classmethod
    @abstractmethod
    def hazmat(cls) -> hashes.HashAlgorithm:
        """cryptography.hazmat hash for ECDSA / RSA-PSS."""


class Sha256(HashAlgorithm):
    name = "sha256"
    digest_size = 32

    @classmethod
    def new(cls, data: bytes = b""):
        return hashlib.sha256(data)

    @classmethod
    def constructor(cls):
        return hashlib.sha256

    @classmethod
    def hazmat(cls) -> hashes.HashAlgorithm:
        return hashes.SHA256()


class Sha384(HashAlgorithm):
    name = "sha384"
    digest_size = 48

    @classmethod
    def new(cls, data: bytes = b""):
        return hashlib.sha384(data)

    @classmethod
    def constructor(cls):
        return hashlib.sha384

    @classmethod
    def hazmat(cls) -> hashes.HashAlgorithm:
        return hashes.SHA384()


class Sha512(HashAlgorithm):
    name = "sha512"
    digest_size = 64

    @classmethod
    def new(cls, data: bytes = b""):
        return hashlib.sha512(data)

    @classmethod
    def constructor(cls):
        return hashlib.sha512

    @classmethod
    def hazmat(cls) -> hashes.HashAlgorithm:
        return hashes.SHA512()


class Sha3256(HashAlgorithm):
    name = "sha3_256"
    digest_size = 32

    @classmethod
    def new(cls, data: bytes = b""):
        return hashlib.sha3_256(data)

    @classmethod
    def constructor(cls):
        return hashlib.sha3_256

    @classmethod
    def hazmat(cls) -> hashes.HashAlgorithm:
        return hashes.SHA3_256()


class Blake2b(HashAlgorithm):
    name = "blake2b"
    digest_size = 64

    @classmethod
    def new(cls, data: bytes = b""):
        return hashlib.blake2b(data)

    @classmethod
    def constructor(cls):
        return hashlib.blake2b

    @classmethod
    def hazmat(cls) -> hashes.HashAlgorithm:
        return hashes.BLAKE2b(64)
