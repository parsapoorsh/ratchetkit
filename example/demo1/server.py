#!/usr/bin/env python3
"""Bob - publish a prekey bundle, accept X3DH, chat on the Double/Triple Ratchet."""

from __future__ import annotations

from example.common import (
    SOCKET,
    Link,
    describe_message,
    describe_session,
    fingerprint,
)
from example.suite_config import ACTIVE_SUITE
from ratchetkit.handshake.message import (
    InitialMessagePQXDH,
    InitialMessageX3DH,
)
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPqPreKey, SignedPreKey
from ratchetkit.ratchet.message import (
    DoubleRatchetMessage,
    TripleRatchetMessage,
)
from ratchetkit.suite.triple import CryptoSuiteTripleRatchet


def main() -> None:
    suite = ACTIVE_SUITE()
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob, suite)
    opk = OneTimePreKey.generate(42, suite)
    if isinstance(suite, CryptoSuiteTripleRatchet):
        Message = TripleRatchetMessage
        InitialMessage = InitialMessagePQXDH
        pq = SignedPqPreKey.generate(1, bob, suite, suite.pq_kem)
        bundle = suite.create_bundle(bob, spk, pq, opk)
    else:
        Message = DoubleRatchetMessage
        InitialMessage = InitialMessageX3DH
        pq = None
        bundle = suite.create_bundle(bob, spk, opk)
    print(
        f"[bob]   identity {fingerprint(bob.signing.public.data)}  "
        f"spk_id={spk.key_id}  opk_id={opk.key_id}  "
        f"({Message.__name__})"
    )

    link, server = Link.serve()
    try:
        # --- 1. hand Alice our prekey bundle ---
        link.send(bundle.to_bytes())
        print("[bob]   sent PreKeyBundle")

        # --- 2. handshake respond + first decrypt ---
        initial = InitialMessage.from_bytes(
            link.expect(InitialMessage.CONSTRUCTOR_ID),
        )
        first = Message.from_bytes(link.recv(), suite)
        session, plain = suite.accept(
            bob,
            spk,
            initial,
            first,
            opk,
            our_pq_prekey=pq,
        )
        print(
            f"[bob]   X3DH accept  "
            f"<- {plain!r}  "
            f"{describe_message(first)}  "
            f"({describe_session(session)})"
        )

        reply_plain = f"ack:{plain.decode()}".encode()
        reply = session.encrypt(reply_plain)
        link.send(reply.to_bytes())
        print(
            f"[bob]   -> {reply_plain!r}  "
            f"{describe_message(reply)}  "
            f"({describe_session(session)})"
        )

        # --- 3. Alice sent two in a row: counters 0 and 1, same chain ---
        message = Message.from_bytes(link.recv(), suite)
        plain = session.decrypt(message)
        print(
            f"[bob]   <- {plain!r}  "
            f"{describe_message(message)}  "
            f"({describe_session(session)})"
        )

        message = Message.from_bytes(link.recv(), suite)
        plain = session.decrypt(message)
        print(
            f"[bob]   <- {plain!r}  "
            f"{describe_message(message)}  "
            f"({describe_session(session)})"
        )

        reply_plain = b"yes, still here"
        reply = session.encrypt(reply_plain)
        link.send(reply.to_bytes())
        print(
            f"[bob]   -> {reply_plain!r}  "
            f"{describe_message(reply)}  "
            f"({describe_session(session)})"
        )

        # --- 4. one more round-trip (Alice bound this message with AD) ---
        message = Message.from_bytes(link.recv(), suite)
        ad = b"msg-id:thanks"
        plain = session.decrypt(message, associated_data=ad)
        print(
            f"[bob]   <- {plain!r}  ad={ad!r}  "
            f"{describe_message(message)}  "
            f"({describe_session(session)})"
        )

        reply_plain = f"ack:{plain.decode()}".encode()
        reply = session.encrypt(reply_plain)
        link.send(reply.to_bytes())
        print(
            f"[bob]   -> {reply_plain!r}  "
            f"{describe_message(reply)}  "
            f"({describe_session(session)})"
        )

        link.recv()
        link.send(b"")
        print("[bob]   done")
    finally:
        link.close()
        server.close()
        if SOCKET.exists():
            SOCKET.unlink()


if __name__ == "__main__":
    main()
