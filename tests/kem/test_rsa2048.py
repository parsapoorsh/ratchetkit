"""RSA-2048 KEM smoke test."""

from ratchetkit.algorithms.hash.sha256 import Sha256
from ratchetkit.algorithms.kem.rsa2048 import Rsa2048
from ratchetkit.algorithms.signing.rsa_pss import RsaPss2048


def test_rsa2048_encapsulate_roundtrip():
    kem = Rsa2048()
    pair = kem.generate_keypair()
    secret, ct = kem.encapsulate(pair.public)
    assert kem.decapsulate(pair, ct) == secret

    signer = RsaPss2048()
    signing = signer.generate_keypair()
    sig = signer.sign(signing, b"msg", Sha256)
    signer.verify(signing.public, b"msg", sig, Sha256)
