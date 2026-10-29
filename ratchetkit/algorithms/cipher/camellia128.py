"""Camellia-128 cipher algorithm."""
from __future__ import annotations


try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import Camellia
except ImportError:  # pragma: no cover - older cryptography
    from cryptography.hazmat.primitives.ciphers.algorithms import Camellia

from ratchetkit.algorithms.cipher.base import CipherAlgorithm


class Camellia128(CipherAlgorithm):
    name = "camellia128"
    key_size = 16
    block_size = 16
    nonce_size = 16
    algorithm = Camellia
