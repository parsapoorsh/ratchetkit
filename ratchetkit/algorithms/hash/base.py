"""Base class for pluggable hash algorithms."""
from __future__ import annotations


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
