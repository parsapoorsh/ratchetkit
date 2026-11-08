"""Shared paths and logging helpers for the resume demo."""

from __future__ import annotations

from pathlib import Path

from ratchetkit.ratchet import (
    DoubleRatchet,
    DoubleRatchetMessage,
    RatchetMessage,
    TripleRatchet,
    TripleRatchetMessage,
)
from ratchetkit.session import Session
from ratchetkit.suite.triple import CryptoSuiteTripleRatchet

HERE = Path(__file__).resolve().parent
STATE_DIR = HERE / "state"
ALICE_SESSION = STATE_DIR / "alice.session"
BOB_SESSION = STATE_DIR / "bob.session"
MAILBOX_DIR = STATE_DIR / "mailbox"


def fingerprint(data: bytes, n: int = 6) -> str:
    return data[:n].hex()


def message_type_for(suite) -> type[RatchetMessage]:
    if isinstance(suite, CryptoSuiteTripleRatchet):
        return TripleRatchetMessage
    return DoubleRatchetMessage


def skipped_count(session: Session) -> int:
    """How many deferred message keys the session is holding."""
    ratchet = session.ratchet
    if isinstance(ratchet, TripleRatchet):
        return len(ratchet.ec.skipped.entries) + len(ratchet.spqr.skipped)
    assert isinstance(ratchet, DoubleRatchet)
    return len(ratchet.skipped.entries)


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
            f"pq_epoch={ratchet.spqr.epoch} "
            f"skipped={skipped_count(session)}"
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
        f"prev_counter={ratchet.previous_counter} "
        f"skipped={skipped_count(session)}"
    )


def reset_state_dir() -> None:
    """Wipe and recreate the on-disk demo state (sessions + mailbox)."""
    if STATE_DIR.exists():
        for path in STATE_DIR.rglob("*"):
            if path.is_file():
                path.unlink()
        for path in sorted(STATE_DIR.rglob("*"), reverse=True):
            if path.is_dir():
                path.rmdir()
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    MAILBOX_DIR.mkdir(parents=True, exist_ok=True)


def save_session(path: Path, session: Session) -> None:
    """Write a full Session blob. Treat the file as secret key material."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(session.to_bytes())
    print(f"      wrote {path.name}  ({path.stat().st_size}B)")


def load_session(path: Path) -> Session:
    session = Session.from_bytes(path.read_bytes())
    print(
        f"      loaded {path.name}  "
        f"({path.stat().st_size}B)  "
        f"({describe_session(session)})"
    )
    return session


def mailbox_put(name: str, data: bytes) -> Path:
    path = MAILBOX_DIR / name
    path.write_bytes(data)
    return path


def mailbox_get(name: str) -> bytes:
    return (MAILBOX_DIR / name).read_bytes()
