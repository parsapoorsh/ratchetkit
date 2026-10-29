"""SECP521R1 ECDH."""
from __future__ import annotations


from cryptography.hazmat.primitives.asymmetric import ec

from ratchetkit.algorithms.kem.ec_base import EcKem
from ratchetkit.suite.algs import KeyExchangeAlg


class Secp521r1(EcKem):
    algorithm = KeyExchangeAlg.SECP521R1
    curve = ec.SECP521R1()
