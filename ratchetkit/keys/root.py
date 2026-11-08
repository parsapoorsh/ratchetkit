"""Root key: DH/KEM ratchet step into a new root + chain key."""
from __future__ import annotations


from typing import TYPE_CHECKING

from ratchetkit.errors import InvalidKey, SerializationError
from ratchetkit.kdf import Kdf
from ratchetkit.keys.chain import ChainKey
from ratchetkit.packing import encode_bytes, read_bytes
from ratchetkit.suite import KdfLabel
from ratchetkit.suite.registry import HASH

if TYPE_CHECKING:
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite


class RootKey:
    """Root key advanced on each DH/KEM ratchet step."""

    def __init__(self, key: bytes, suite: CryptoSuite):
        expected = HASH[suite.digest].digest_size
        if not isinstance(key, (bytes, bytearray)) or len(key) != expected:
            raise InvalidKey(
                f"root key must be {expected} bytes, got "
                f"{len(key) if isinstance(key, (bytes, bytearray)) else type(key).__name__}"
            )
        if not any(key):
            raise InvalidKey("root key must not be all zeros")
        self.key = bytes(key)
        self.suite = suite
        self.kdf = Kdf(suite.digest)

    def create_chain_from_secret(self, shared: bytes) -> tuple[RootKey, ChainKey]:
        """Advance root using an already-computed shared secret.

        Rejects empty or all-zero DH/KEM outputs (low-order points, failed
        agreement) so they cannot collapse the root chain (spec §8.3).
        """
        if not isinstance(shared, (bytes, bytearray)) or not shared:
            raise InvalidKey("DH/KEM shared secret is missing or empty")
        if not any(shared):
            raise InvalidKey("DH/KEM shared secret is all zeros")
        size = HASH[self.suite.digest].digest_size
        material = self.kdf.hkdf(
            bytes(shared),
            size + size,
            salt=self.key,
            info=KdfLabel.ROOT_CHAIN,
        )
        root = material[:size]
        chain = material[size:]
        return (
            RootKey(root, self.suite),
            ChainKey(chain, 0, self.suite),
        )

    def to_bytes(self) -> bytes:
        return encode_bytes(self.key)

    @classmethod
    def from_bytes(cls, data: bytes, suite: CryptoSuite) -> RootKey:
        key, offset = read_bytes(data, 0)
        if offset != len(data):
            raise SerializationError("trailing bytes in root key")
        return cls(key, suite)
