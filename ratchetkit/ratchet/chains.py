"""Sender and receiver chain bookkeeping."""
from __future__ import annotations


from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.errors import SerializationError
from ratchetkit.keys.chain import ChainKey
from ratchetkit.keys.keypair import KeyPair, PublicKey
from ratchetkit.packing import encode_bytes, read_bytes

if TYPE_CHECKING:
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite


@dataclass
class SenderChain:
    """Our current sending chain: ratchet key pair + chain key."""

    ratchet_key: KeyPair
    chain_key: ChainKey

    def to_bytes(self) -> bytes:
        return (
            encode_bytes(self.ratchet_key.to_bytes())
            + encode_bytes(self.chain_key.to_bytes())
        )

    @classmethod
    def from_bytes(cls, data: bytes, suite: CryptoSuite) -> SenderChain:
        key_blob, offset = read_bytes(data, 0)
        chain_blob, offset = read_bytes(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in sender chain")
        return cls(
            ratchet_key=KeyPair.from_bytes(key_blob),
            chain_key=ChainKey.from_bytes(chain_blob, suite),
        )


@dataclass
class ReceiverChain:
    """A remote ratchet public key paired with its receiving chain key."""

    ratchet_public: PublicKey
    chain_key: ChainKey

    @property
    def ratchet_id(self) -> bytes:
        return self.ratchet_public.data

    def to_bytes(self) -> bytes:
        return (
            encode_bytes(self.ratchet_public.to_bytes())
            + encode_bytes(self.chain_key.to_bytes())
        )

    @classmethod
    def from_bytes(cls, data: bytes, suite: CryptoSuite) -> ReceiverChain:
        public_blob, offset = read_bytes(data, 0)
        chain_blob, offset = read_bytes(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in receiver chain")
        return cls(
            ratchet_public=PublicKey.from_bytes(public_blob),
            chain_key=ChainKey.from_bytes(chain_blob, suite),
        )
