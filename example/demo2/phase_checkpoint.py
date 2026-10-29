#!/usr/bin/env python3
"""Phase 1: handshake, a short chat, checkpoint sessions, stash undelivered msgs."""

from __future__ import annotations

from example.demo2.common import (
    ALICE_SESSION,
    BOB_SESSION,
    describe_message,
    describe_session,
    fingerprint,
    mailbox_put,
    message_type_for,
    reset_state_dir,
    save_session,
)
from example.demo2.suite_config import ACTIVE_SUITE
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.session import Session
from ratchetkit.suite.triple import CryptoSuiteTripleRatchet


def main() -> int:
    reset_state_dir()
    suite = ACTIVE_SUITE()
    Message = message_type_for(suite)

    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(42, suite)
    if isinstance(suite, CryptoSuiteTripleRatchet):
        pq = suite.generate_pq_prekey(1, bob_id)
        bundle = suite.create_bundle(bob_id, spk, pq, opk)
    else:
        pq = None
        bundle = suite.create_bundle(bob_id, spk, opk)

    print(
        f"[checkpoint] suite={type(suite).__name__}  "
        f"msg={Message.__name__}"
    )
    print(
        f"[checkpoint] alice id={fingerprint(alice_id.signing.public.data)}  "
        f"bob id={fingerprint(bob_id.signing.public.data)}"
    )

    # --- handshake ---
    alice, initial = Session.initiate(alice_id, bundle)
    first = alice.encrypt(b"hello bob")
    bob, plain = Session.accept(
        bob_id,
        spk,
        initial,
        first,
        opk,
        our_pq_prekey=pq,
    )
    print(
        f"[bob]   accept <- {plain!r}  "
        f"{describe_message(first)}  "
        f"({describe_session(bob)})"
    )

    reply = bob.encrypt(b"ack:hello bob")
    plain = alice.decrypt(reply)
    print(
        f"[alice] <- {plain!r}  "
        f"{describe_message(reply)}  "
        f"({describe_session(alice)})"
    )

    # One more DH turn so both sides have live send chains before we freeze.
    mid = alice.encrypt(b"checkpoint soon")
    assert bob.decrypt(mid) == b"checkpoint soon"
    mid_reply = bob.encrypt(b"ready")
    assert alice.decrypt(mid_reply) == b"ready"
    print(
        f"[checkpoint] live chat ok  "
        f"alice=({describe_session(alice)})  "
        f"bob=({describe_session(bob)})"
    )

    # Alice encrypts three messages that will sit in the mailbox undelivered.
    # Bob has not seen them yet; after resume he will take them out of order.
    pending_plain = (b"m0-first", b"m1-middle", b"m2-last")
    print("[checkpoint] Alice encrypts 3 msgs into mailbox (Bob offline)")
    for index, plain in enumerate(pending_plain):
        message = alice.encrypt(plain)
        path = mailbox_put(f"msg_{index}.bin", message.to_bytes())
        print(
            f"[alice] -> {plain!r}  "
            f"{describe_message(message)}  "
            f"stashed {path.name}  "
            f"({describe_session(alice)})"
        )

    print("[checkpoint] persist full Session blobs (secret key material)")
    save_session(ALICE_SESSION, alice)
    save_session(BOB_SESSION, bob)
    print(
        "[checkpoint] done — process 'crash'; next phase restores from disk"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
