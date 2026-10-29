"""Chain key: HMAC stepping and message-key seed derivation."""
from __future__ import annotations

from ratchetkit.suite.registry import hash_backend


from typing import TYPE_CHECKING

from ratchetkit.errors import InvalidKey, SerializationError
from ratchetkit.kdf import Kdf
from ratchetkit.keys.message import MessageKeys
from ratchetkit.packing import encode_bytes, encode_u32, read_bytes, read_u32
from ratchetkit.suite import ChainKeySeed

if TYPE_CHECKING:
    from ratchetkit.suite import CryptoSuite


class ChainKey:
    """Symmetric ratchet chain key (HMAC with ChainKeySeed).

    Spec KDF_CK must fail when the chain key is missing; we also require the
    suite digest length so a truncated/empty key cannot advance the chain.
    """

    def __init__(self, key: bytes, index: int, suite: CryptoSuite):
        expected = hash_backend(suite.digest).digest_size
        if not isinstance(key, (bytes, bytearray)) or len(key) != expected:
            raise InvalidKey(
                f"chain key must be {expected} bytes, got "
                f"{len(key) if isinstance(key, (bytes, bytearray)) else type(key).__name__}"
            )
        if not any(key):
            raise InvalidKey("chain key must not be all zeros")
        if index < 0:
            raise InvalidKey("chain index must be non-negative")
        self.key = bytes(key)
        self.index = index
        self.suite = suite
        self.kdf = Kdf(suite.digest)

    def next_chain_key(self) -> ChainKey:
        next_key = self.kdf.hmac_digest(self.key, ChainKeySeed.CHAIN_KEY_SEED)
        return ChainKey(next_key, self.index + 1, self.suite)

    def message_keys(self) -> MessageKeys:
        seed = self.kdf.hmac_digest(self.key, ChainKeySeed.MESSAGE_KEY_SEED)
        return MessageKeys.derive(seed, self.index, self.suite)

    def to_bytes(self) -> bytes:
        return encode_bytes(self.key) + encode_u32(self.index)

    @classmethod
    def from_bytes(cls, data: bytes, suite: CryptoSuite) -> ChainKey:
        key, offset = read_bytes(data, 0)
        index, offset = read_u32(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in chain key")
        return cls(key, index, suite)
