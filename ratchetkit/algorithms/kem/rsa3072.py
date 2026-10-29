"""RSA-3072 OAEP encapsulation."""
from __future__ import annotations


from ratchetkit.algorithms.kem.rsa_base import RsaKem
from ratchetkit.suite.algs import KeyExchangeAlg


class Rsa3072(RsaKem):
    algorithm = KeyExchangeAlg.RSA3072
    key_size = 3072
