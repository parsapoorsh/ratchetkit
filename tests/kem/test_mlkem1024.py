"""ML-KEM-1024 smoke test."""

from ratchetkit.algorithms.kem.mlkem1024 import Mlkem1024


def test_mlkem1024_encapsulate_roundtrip():
    kem = Mlkem1024()
    pair = kem.generate_keypair()
    secret, ct = kem.encapsulate(pair.public)
    assert kem.decapsulate(pair, ct) == secret
