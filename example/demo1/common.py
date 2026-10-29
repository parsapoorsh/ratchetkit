"""Unix-socket transport and shared helpers for the example."""

from __future__ import annotations

import socket
import struct
import time
from pathlib import Path

from ratchetkit.packing import Constructor, ConstructorId
from ratchetkit.ratchet import (
    DoubleRatchet,
    DoubleRatchetMessage,
    RatchetMessage,
    TripleRatchet,
    TripleRatchetMessage,
)
from ratchetkit.session import Session

SOCKET = Path(__file__).resolve().parent / "ratchetkit.sock"

# Demo transport only: reject absurd frames before allocate/read.
# Does not authenticate the pipe (use TLS/Noise for untrusted networks).
MAX_FRAME_BYTES = 256 * 1024


class Link:
    """Length-prefixed byte pipe. Objects carry their own constructor id.

    Not a secure transport: length is cleartext and unauthenticated.
    ``MAX_FRAME_BYTES`` only bounds DoS from huge claimed sizes.
    """

    def __init__(
        self,
        conn: socket.socket,
        name: str,
        max_frame_bytes: int = MAX_FRAME_BYTES,
    ):
        self.conn = conn
        self.name = name
        self.max_frame_bytes = max_frame_bytes

    @classmethod
    def serve(cls, path: Path = SOCKET) -> tuple[Link, socket.socket]:
        if path.exists():
            path.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
        server.listen(1)
        print(f"[bob] listening on {path}")
        conn = server.accept()[0]
        return cls(conn, "bob"), server

    @classmethod
    def connect(cls, path: Path = SOCKET, attempts: int = 50) -> Link:
        for attempt in range(attempts):
            try:
                conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                conn.connect(str(path))
                print(f"[alice] connected to {path}")
                return cls(conn, "alice")
            except OSError:
                time.sleep(0.05)
        raise ConnectionError(f"could not connect to {path}")

    def close(self) -> None:
        self.conn.close()

    def send(self, data: bytes) -> None:
        if len(data) > self.max_frame_bytes:
            raise ValueError(
                f"frame too large: {len(data)} > {self.max_frame_bytes}"
            )
        self.conn.sendall(struct.pack(">I", len(data)) + data)

    def recv(self) -> bytes:
        header = self.read_exact(4)
        length = struct.unpack_from(">I", header, 0)[0]
        if length > self.max_frame_bytes:
            raise ValueError(
                f"[{self.name}] peer claimed frame {length} bytes "
                f"(max {self.max_frame_bytes})"
            )
        return self.read_exact(length) if length else b""

    def read_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("socket closed")
            buf.extend(chunk)
        return bytes(buf)

    def expect(self, constructor: ConstructorId) -> bytes:
        """Read one frame whose leading constructor matches ``constructor``."""
        data = self.recv()
        got, _ = Constructor.constructor_read(data, 0)
        if got is not constructor:
            raise RuntimeError(
                f"[{self.name}] expected {constructor.name}, got {got.name}"
            )
        return data


def fingerprint(data: bytes, n: int = 6) -> str:
    return data[:n].hex()


def describe_message(message: RatchetMessage) -> str:
    if isinstance(message, TripleRatchetMessage):
        ec = message.ec_message
        return (
            f"counter={ec.counter} "
            f"prev={ec.previous_counter} "
            f"ratchet={fingerprint(ec.ratchet_public)} "
            f"pqN={message.spqr_header.counter} "
            f"triple"
        )
    assert isinstance(message, DoubleRatchetMessage)
    return (
        f"counter={message.counter} "
        f"prev={message.previous_counter} "
        f"ratchet={fingerprint(message.ratchet_public)}"
    )


def describe_session(session: Session) -> str:
    ratchet = session.ratchet
    if isinstance(ratchet, TripleRatchet):
        ec = ratchet.ec
        send_index = (
            ec.sender_chain.chain_key.index
            if ec.sender_chain is not None
            else None
        )
        return (
            f"triple "
            f"send_index={send_index} "
            f"recv_chains={len(ec.receiver_chains)} "
            f"prev_counter={ec.previous_counter} "
            f"pq_epoch={ratchet.spqr.epoch}"
        )
    assert isinstance(ratchet, DoubleRatchet)
    send_index = (
        ratchet.sender_chain.chain_key.index
        if ratchet.sender_chain is not None
        else None
    )
    return (
        f"send_index={send_index} "
        f"recv_chains={len(ratchet.receiver_chains)} "
        f"prev_counter={ratchet.previous_counter}"
    )
