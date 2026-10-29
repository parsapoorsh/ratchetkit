"""SHA3-256 hash algorithm."""
from __future__ import annotations


import hashlib

from cryptography.hazmat.primitives import hashes

from ratchetkit.algorithms.hash.base import HashAlgorithm


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
