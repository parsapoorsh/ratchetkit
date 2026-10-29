#!/usr/bin/env python3
"""Phase 2: restore sessions from disk, out-of-order decrypt, keep chatting."""

from __future__ import annotations

from example.demo2.common import (
    ALICE_SESSION,
    BOB_SESSION,
    describe_message,
    describe_session,
    load_session,
    mailbox_get,
    message_type_for,
    save_session,
    skipped_count,
)
from example.demo2.suite_config import ACTIVE_SUITE


def main() -> int:
    if not ALICE_SESSION.exists() or not BOB_SESSION.exists():
        print(
            "[resume] missing session blobs — run phase_checkpoint first"
        )
        return 1

    suite = ACTIVE_SUITE()
    Message = message_type_for(suite)

    print(
        f"[resume] suite={type(suite).__name__}  "
        f"msg={Message.__name__}"
    )
    print("[resume] restore sessions (no new X3DH / PQXDH)")
    alice = load_session(ALICE_SESSION)
    bob = load_session(BOB_SESSION)

    # Deliver Alice's three stashed messages as m2, m0, m1.
    # Decrypting m2 first forces Bob to cache keys for counters 0 and 1.
    order = (2, 0, 1)
    expected = {
        0: b"m0-first",
        1: b"m1-middle",
        2: b"m2-last",
    }
    print(
        f"[resume] Bob drains mailbox out of order: {list(order)} "
        f"(skipped keys absorb the gap)"
    )
    for index in order:
        raw = mailbox_get(f"msg_{index}.bin")
        message = Message.from_bytes(raw)
        plain = bob.decrypt(message)
        if plain != expected[index]:
            print(
                f"[bob]   FAIL expected {expected[index]!r}, got {plain!r}"
            )
            return 1
        print(
            f"[bob]   <- {plain!r}  "
            f"{describe_message(message)}  "
            f"skipped={skipped_count(bob)}  "
            f"({describe_session(bob)})"
        )

    if skipped_count(bob) != 0:
        print(f"[bob]   FAIL expected skipped=0, got {skipped_count(bob)}")
        return 1

    # Conversation continues on the restored sessions.
    print("[resume] continue chat after restore + OOO drain")
    msg = alice.encrypt(b"still here after restart")
    plain = bob.decrypt(msg)
    print(
        f"[alice] -> {plain!r}  "
        f"{describe_message(msg)}  "
        f"({describe_session(alice)})"
    )
    if plain != b"still here after restart":
        print(f"[bob]   FAIL got {plain!r}")
        return 1

    reply = bob.encrypt(b"welcome back")
    plain = alice.decrypt(reply)
    print(
        f"[bob]   -> {plain!r}  "
        f"{describe_message(reply)}  "
        f"({describe_session(bob)})"
    )
    if plain != b"welcome back":
        print(f"[alice] FAIL got {plain!r}")
        return 1

    # Optional second checkpoint so a third process could pick up again.
    save_session(ALICE_SESSION, alice)
    save_session(BOB_SESSION, bob)
    print("[resume] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
