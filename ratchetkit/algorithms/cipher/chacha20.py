"""ChaCha20 stream cipher algorithm."""
from __future__ import annotations


from cryptography.hazmat.primitives.ciphers import algorithms

from ratchetkit.algorithms.cipher.base import CipherAlgorithm


class ChaCha20(CipherAlgorithm):
    name = "chacha20"
    key_size = 32
    block_size = 1
    # cryptography ChaCha20 uses 16-byte nonce (4-byte counter + 12-byte nonce)
    nonce_size = 16
    algorithm = algorithms.ChaCha20
    is_stream = True
