from __future__ import annotations

from ratchetkit.suite.registry import cipher_backend
"""Symmetric cipher goldens (OpenSSL enc -* -ctr / chacha20) for every CipherAlg."""


import pytest
from cryptography.exceptions import UnsupportedAlgorithm

from ratchetkit.algorithms.cipher.aes128 import Aes128
from ratchetkit.algorithms.cipher.aes256 import Aes256
from ratchetkit.algorithms.cipher.camellia128 import Camellia128
from ratchetkit.algorithms.cipher.camellia256 import Camellia256
from ratchetkit.algorithms.cipher.chacha20 import ChaCha20
from ratchetkit.suite import CipherAlg

# OpenSSL enc name -> (CipherAlg, class, key field)
CIPHERS = {
    "aes-128-ctr": (CipherAlg.AES128, Aes128, "key128_hex"),
    "aes-256-ctr": (CipherAlg.AES256, Aes256, "key256_hex"),
    "camellia-128-ctr": (CipherAlg.CAMELLIA128, Camellia128, "key128_hex"),
    "camellia-256-ctr": (CipherAlg.CAMELLIA256, Camellia256, "key256_hex"),
    "chacha20": (CipherAlg.CHACHA20, ChaCha20, "key256_hex"),
}


def _run_or_skip(cls, key, iv, plaintext, expected_ct: bytes):
    try:
        ct = cls.encrypt(key, iv, plaintext)
    except UnsupportedAlgorithm as exc:
        pytest.skip(f"{cls.name}: {exc}")
    assert ct == expected_ct
    assert cls.decrypt(key, iv, ct) == plaintext


@pytest.mark.parametrize("openssl_name", list(CIPHERS))
def test_cipher_matches_openssl(goldens, openssl_name):
    c = goldens["cipher"]
    alg, cls, key_field = CIPHERS[openssl_name]
    key = bytes.fromhex(c[key_field])
    iv = bytes.fromhex(c["iv_hex"])
    plaintext = c["plaintext"].encode("ascii")
    expected = bytes.fromhex(c["ciphertext"][openssl_name])
    assert cipher_backend(alg) is cls
    assert cls.key_size == len(key)
    assert cls.iv_size() == len(iv)
    _run_or_skip(cls, key, iv, plaintext, expected)


def test_every_cipher_alg_is_covered():
    covered = {alg for alg, _, _ in CIPHERS.values()}
    assert covered == set(CipherAlg)
