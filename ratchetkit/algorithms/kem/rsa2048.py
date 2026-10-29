"""RSA-2048 OAEP encapsulation."""
from __future__ import annotations


from ratchetkit.algorithms.kem.rsa_base import RsaKem
from ratchetkit.suite.algs import KeyExchangeAlg


class Rsa2048(RsaKem):
    algorithm = KeyExchangeAlg.RSA2048
    key_size = 2048
