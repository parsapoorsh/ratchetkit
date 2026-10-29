"""Chunked ML-KEM SCKA tests."""

from ratchetkit.algorithms.kem.mlkem768 import Mlkem768
from ratchetkit.scka import ChunkCodec, ChunkedKemScka, ChunkFrame


def test_chunk_codec_roundtrip():
    codec = ChunkCodec(4)
    payload = b"abcdefghijklmnopqrstuvwxyz0123456789"
    parts = codec.split(payload)
    assert len(parts) == 4
    rebuilt = {i: part for i, part in enumerate(parts)}
    assert codec.join(rebuilt, len(payload)) == payload


def test_chunk_frame_roundtrip():
    frame = ChunkFrame(
        flags=ChunkFrame.FLAG_PAYLOAD,
        key_epoch=3,
        chunk_index=1,
        n_chunks=8,
        ack_count=2,
        payload_len=100,
        data=b"chunk-bytes",
    )
    restored = ChunkFrame.from_bytes(frame.to_bytes())
    assert restored.key_epoch == 3
    assert restored.chunk_index == 1
    assert restored.data == b"chunk-bytes"


def test_scka_bootstrap_and_exchange():
    kem = Mlkem768()
    alice = ChunkedKemScka.init_alice(kem, n_chunks=2)
    bob = ChunkedKemScka.init_bob(kem, n_chunks=2)

    secrets_a = []
    secrets_b = []

    def drip(sender, receiver, rounds=2):
        for _ in range(rounds):
            send = sender.send()
            if send.mix_key:
                if sender is alice:
                    secrets_a.append(send.mix_key)
                else:
                    secrets_b.append(send.mix_key)
            recv = receiver.receive(send.msg)
            if recv.mix_key:
                if receiver is alice:
                    secrets_a.append(recv.mix_key)
                else:
                    secrets_b.append(recv.mix_key)

    # Alice bootstraps public key (no shared secret yet).
    drip(alice, bob, 2)
    assert bob.their_public is not None
    assert not secrets_a and not secrets_b
    assert bob.is_cka_sender and not alice.is_cka_sender

    # Bob encapsulates: mix_key on first drip chunk (sender), receiver after both.
    send0 = bob.send()
    assert send0.mix_key is not None
    assert send0.mix_key.epoch == 1
    assert send0.chunks_sent == 1
    secrets_b.append(send0.mix_key)
    recv0 = alice.receive(send0.msg)
    assert recv0.mix_key is None
    assert alice.peer_ack == 0
    assert bob.peer_ack == 0

    send1 = bob.send()
    assert send1.mix_key is None
    assert send1.chunks_sent == 2
    recv1 = alice.receive(send1.msg)
    assert recv1.mix_key is not None
    assert recv1.mix_key.epoch == 1
    secrets_a.append(recv1.mix_key)

    assert len(secrets_a) == 1 and len(secrets_b) == 1
    assert secrets_a[0].key == secrets_b[0].key
    assert secrets_a[0].epoch == secrets_b[0].epoch == 1

    # Alice encapsulates → epoch 2 (sender mixes on first chunk).
    secrets_a.clear()
    secrets_b.clear()
    drip(alice, bob, 2)
    assert secrets_a[0].key == secrets_b[0].key
    assert secrets_a[0].epoch == 2
    # Sender mixed first; receiver after full reconstruction.
    assert secrets_a[0].epoch == 2


def test_scka_peer_ack_tracks_recv_chunks():
    kem = Mlkem768()
    alice = ChunkedKemScka.init_alice(kem, n_chunks=4)
    bob = ChunkedKemScka.init_bob(kem, n_chunks=4)

    # Bootstrap Alice's public key across 4 chunks.
    for _ in range(4):
        send = alice.send()
        bob.receive(send.msg)
    assert bob.is_cka_sender

    # Bob starts exchange; Alice acks after each chunk.
    send = bob.send()
    assert send.mix_key is not None
    alice.receive(send.msg)
    # Alice has 1 chunk of Bob's payload; her next ack-only / payload reports it.
    alice_reply = alice.send()  # not sender yet (Bob still dripping) → ack
    frame = ChunkFrame.from_bytes(alice_reply.msg)
    assert frame.ack_count == 1
    bob.receive(alice_reply.msg)
    assert bob.peer_ack == 1
