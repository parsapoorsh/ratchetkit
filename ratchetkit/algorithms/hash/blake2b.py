"""BLAKE2b hash algorithm (64-byte digest)."""
from __future__ import annotations


import hashlib

from cryptography.hazmat.primitives import hashes

from ratchetkit.algorithms.hash.base import HashAlgorithm


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
