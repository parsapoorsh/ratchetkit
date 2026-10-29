"""Skipped message-key cache for out-of-order delivery."""
from __future__ import annotations


from typing import TYPE_CHECKING

from ratchetkit.errors import (
    DuplicateMessage,
    SerializationError,
    TooFarInFuture,
    TooManySkippedKeys,
)
from ratchetkit.keys.message import MessageKeys
from ratchetkit.packing import (
    encode_bytes,
    encode_u32,
    read_bytes,
    read_u32,
)
from ratchetkit.ratchet.limits import RatchetLimits

if TYPE_CHECKING:
    from ratchetkit.keys.chain import ChainKey


class SkippedMessageKeys:
    """Map of (ratchet_id, counter) -> MessageKeys with a hard size cap.

    Exceeding the cap raises :class:`TooManySkippedKeys` rather than silently
    dropping older keys (which would make delayed messages permanently
    undecryptable). Spec §3.1: MKSKIPPED raises if too many elements are stored.
    """

    def __init__(
        self,
        limits: RatchetLimits | None = None,
        entries: dict[tuple[bytes, int], MessageKeys] | None = None,
        order: list[tuple[bytes, int]] | None = None,
    ):
        self.limits = limits or RatchetLimits()
        self.entries: dict[tuple[bytes, int], MessageKeys] = (
            dict(entries) if entries is not None else {}
        )
        self.order: list[tuple[bytes, int]] = (
            list(order) if order is not None else []
        )

    def clone(self) -> SkippedMessageKeys:
        """Trial-decrypt copy: new dict/list, shared MessageKeys values."""
        return SkippedMessageKeys(
            limits=self.limits,
            entries=self.entries,
            order=self.order,
        )

    def store(self, ratchet_id: bytes, keys: MessageKeys) -> None:
        key = (ratchet_id, keys.counter)
        if key in self.entries:
            return
        if len(self.entries) >= self.limits.MAX_MESSAGE_KEYS:
            raise TooManySkippedKeys(len(self.entries) + 1, self.limits.MAX_MESSAGE_KEYS)
        self.entries[key] = keys
        self.order.append(key)

    def peek(self, ratchet_id: bytes, counter: int) -> MessageKeys | None:
        """Return a cached key without consuming it (MAC check first)."""
        return self.entries.get((ratchet_id, counter))

    def take(self, ratchet_id: bytes, counter: int) -> MessageKeys | None:
        """Remove and return a cached key. Call only after MAC verification."""
        key = (ratchet_id, counter)
        keys = self.entries.pop(key, None)
        if keys is not None and key in self.order:
            self.order.remove(key)
        return keys

    def skip_in_chain(
        self,
        ratchet_id: bytes,
        chain: ChainKey,
        until_counter: int,
    ) -> ChainKey:
        """Advance ``chain`` up to (but not including) ``until_counter``, storing keys."""
        if until_counter < chain.index:
            raise DuplicateMessage(chain.index, until_counter)
        jump = until_counter - chain.index
        if jump > self.limits.MAX_FORWARD_JUMPS:
            raise TooFarInFuture(chain.index, until_counter, self.limits.MAX_FORWARD_JUMPS)

        current = chain
        while current.index < until_counter:
            keys = current.message_keys()
            self.store(ratchet_id, keys)
            current = current.next_chain_key()
        return current

    def to_bytes(self) -> bytes:
        parts = [encode_bytes(self.limits.to_bytes()), encode_u32(len(self.order))]
        for ratchet_id, counter in self.order:
            keys = self.entries[(ratchet_id, counter)]
            parts.append(encode_bytes(ratchet_id))
            parts.append(encode_u32(counter))
            parts.append(encode_bytes(keys.to_bytes()))
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> SkippedMessageKeys:
        limits_blob, offset = read_bytes(data, 0)
        count, offset = read_u32(data, offset)
        skipped = cls(limits=RatchetLimits.from_bytes(limits_blob))
        for _ in range(count):
            ratchet_id, offset = read_bytes(data, offset)
            counter, offset = read_u32(data, offset)
            keys_blob, offset = read_bytes(data, offset)
            keys = MessageKeys.from_bytes(keys_blob)
            if keys.counter != counter:
                raise SerializationError("skipped key counter mismatch")
            key = (ratchet_id, counter)
            skipped.entries[key] = keys
            skipped.order.append(key)
        if offset != len(data):
            raise SerializationError("trailing bytes in skipped message keys")
        return skipped
