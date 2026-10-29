"""SHA-512 hash algorithm."""
from __future__ import annotations


import hashlib

from cryptography.hazmat.primitives import hashes

from ratchetkit.algorithms.hash.base import HashAlgorithm


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
