"""SHA-384 hash algorithm."""
from __future__ import annotations


import hashlib

from cryptography.hazmat.primitives import hashes

from ratchetkit.algorithms.hash.base import HashAlgorithm


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
