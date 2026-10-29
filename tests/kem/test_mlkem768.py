"""ML-KEM-768 smoke test."""

from ratchetkit.algorithms.kem.mlkem768 import Mlkem768


def test_mlkem768_encapsulate_roundtrip():
    kem = Mlkem768()
    pair = kem.generate_keypair()
    secret, ct = kem.encapsulate(pair.public)
    assert kem.decapsulate(pair, ct) == secret
