"""SHA-256 hash algorithm."""
from __future__ import annotations


import hashlib

from cryptography.hazmat.primitives import hashes

from ratchetkit.algorithms.hash.base import HashAlgorithm


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
