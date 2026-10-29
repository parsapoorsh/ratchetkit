"""RSA-4096 OAEP encapsulation."""
from __future__ import annotations


from ratchetkit.algorithms.kem.rsa_base import RsaKem
from ratchetkit.suite.algs import KeyExchangeAlg


class Rsa4096(RsaKem):
    algorithm = KeyExchangeAlg.RSA4096
    key_size = 4096
