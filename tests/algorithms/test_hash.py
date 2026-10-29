from __future__ import annotations

from ratchetkit.suite.registry import hash_backend
"""Hash + HMAC goldens (OpenSSL dgst) for every HashAlg."""


import pytest

from ratchetkit.algorithms.hash.blake2b import Blake2b
from ratchetkit.algorithms.hash.sha256 import Sha256
from ratchetkit.algorithms.hash.sha3256 import Sha3256
from ratchetkit.algorithms.hash.sha384 import Sha384
from ratchetkit.algorithms.hash.sha512 import Sha512
from ratchetkit.kdf import Kdf
from ratchetkit.suite import HashAlg

# OpenSSL dgst name -> (HashAlg, class)
HASHES = {
    "sha256": (HashAlg.SHA256, Sha256),
    "sha384": (HashAlg.SHA384, Sha384),
    "sha512": (HashAlg.SHA512, Sha512),
    "sha3-256": (HashAlg.SHA3_256, Sha3256),
    "blake2b512": (HashAlg.BLAKE2B, Blake2b),
}


@pytest.mark.parametrize("openssl_name", list(HASHES))
def test_hash_digest_matches_openssl(goldens, openssl_name):
    msg = goldens["hash_msg"].encode("ascii")
    alg, cls = HASHES[openssl_name]
    assert cls.new(msg).hexdigest() == goldens["hash"][openssl_name]
    assert hash_backend(alg) is cls
    assert cls.digest_size == len(bytes.fromhex(goldens["hash"][openssl_name]))


@pytest.mark.parametrize("openssl_name", list(HASHES))
def test_hmac_matches_openssl(goldens, openssl_name):
    key = bytes.fromhex(goldens["hmac_key_hex"])
    msg = goldens["hmac_msg"].encode("ascii")
    alg, _cls = HASHES[openssl_name]
    tag = Kdf(alg).hmac_digest(key, msg)
    assert tag.hex() == goldens["hmac"][openssl_name]


def test_every_hash_alg_is_covered():
    covered = {alg for alg, _ in HASHES.values()}
    assert covered == set(HashAlg)
