"""HKDF and HMAC helpers over pluggable hash algorithm classes."""

from __future__ import annotations

import hmac
from typing import TYPE_CHECKING

from ratchetkit.suite import HashAlg

if TYPE_CHECKING:
    from ratchetkit.algorithms.hash.base import HashAlgorithm


class Kdf:
    """Domain-separated HKDF / HMAC using a suite hash class."""

    def __init__(self, digest: HashAlg | type[HashAlgorithm]):
        if isinstance(digest, HashAlg):
            self.hash_cls = digest.impl
        else:
            self.hash_cls = digest

    def hmac_digest(self, key: bytes, data: bytes) -> bytes:
        """HMAC over ``data`` using the suite digest."""
        return hmac.new(key, data, self.hash_cls.constructor()).digest()

    def hkdf(
        self,
        ikm: bytes,
        length: int,
        salt: bytes | None = None,
        info: bytes = b"",
    ) -> bytes:
        """HKDF-Extract + Expand (RFC 5869).

        ``info`` is raw bytes (use :class:`~ratchetkit.suite.KdfLabel` constants).
        """
        factory = self.hash_cls.constructor()
        hash_len = self.hash_cls.digest_size

        if salt is None:
            salt = bytes(hash_len)

        prk = hmac.new(salt, ikm, factory).digest()

        if length < 0:
            raise ValueError("hkdf length must be non-negative")
        if length > 255 * hash_len:
            raise ValueError("hkdf length exceeds maximum for this digest")

        okm = bytearray()
        previous = b""
        counter = 1
        while len(okm) < length:
            previous = hmac.new(
                prk,
                previous + info + bytes([counter]),
                factory,
            ).digest()
            okm.extend(previous)
            counter += 1

        return bytes(okm[:length])
