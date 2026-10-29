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
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.ratchet import (
    DoubleRatchetMessage,
    TripleRatchetMessage,
)
from ratchetkit.session import Session
from ratchetkit.suite.triple import CryptoSuiteTripleRatchet
from ratchetkit.handshake import InitialMessagePQXDH, InitialMessageX3DH


def main() -> None:
    suite = ACTIVE_SUITE()
    if isinstance(suite, CryptoSuiteTripleRatchet):
        Message = TripleRatchetMessage
    else:
        Message = DoubleRatchetMessage
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(42, suite)
    pq = (
        suite.generate_pq_prekey(1, bob)
        if isinstance(suite, CryptoSuiteTripleRatchet)
        else None
    )
    bundle = suite.create_bundle(bob, spk, pq, opk)
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
        if isinstance(suite, CryptoSuiteTripleRatchet):
            initial = InitialMessagePQXDH.from_bytes(
                link.expect(InitialMessagePQXDH.CONSTRUCTOR_ID),
            )
        else:
            initial = InitialMessageX3DH.from_bytes(
                link.expect(InitialMessageX3DH.CONSTRUCTOR_ID),
            )
        first = Message.from_bytes(link.expect(Message.CONSTRUCTOR_ID))
        session, plain = Session.accept(
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
        message = Message.from_bytes(link.expect(Message.CONSTRUCTOR_ID))
        plain = session.decrypt(message)
        print(
            f"[bob]   <- {plain!r}  "
            f"{describe_message(message)}  "
            f"({describe_session(session)})"
        )

        message = Message.from_bytes(link.expect(Message.CONSTRUCTOR_ID))
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
        message = Message.from_bytes(link.expect(Message.CONSTRUCTOR_ID))
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
