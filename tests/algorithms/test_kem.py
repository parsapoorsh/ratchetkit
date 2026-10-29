"""KEM / DH / signature goldens (OpenSSL genpkey / pkeyutl / dgst) for every KEX."""

from __future__ import annotations

import pytest

from ratchetkit.algorithms.hash.sha256 import Sha256
from ratchetkit.algorithms.kem.mlkem1024 import Mlkem1024
from ratchetkit.algorithms.kem.mlkem768 import Mlkem768
from ratchetkit.algorithms.kem.rsa2048 import Rsa2048
from ratchetkit.algorithms.kem.rsa3072 import Rsa3072
from ratchetkit.algorithms.kem.rsa4096 import Rsa4096
from ratchetkit.algorithms.kem.secp256r1 import Secp256r1
from ratchetkit.algorithms.kem.secp384r1 import Secp384r1
from ratchetkit.algorithms.kem.secp521r1 import Secp521r1
from ratchetkit.algorithms.kem.x25519 import X25519
from ratchetkit.algorithms.kem.x448 import X448
from ratchetkit.keys.keypair import PrivateKey, PublicKey, SigningPrivateKey, SigningPublicKey
from ratchetkit.suite import KeyExchangeAlg


def test_every_key_exchange_alg_is_covered():
    # Every enum member has a concrete backend class with a smoke path below.
    assert set(KeyExchangeAlg) == {
        KeyExchangeAlg.X25519,
        KeyExchangeAlg.X448,
        KeyExchangeAlg.SECP256R1,
        KeyExchangeAlg.SECP384R1,
        KeyExchangeAlg.SECP521R1,
        KeyExchangeAlg.RSA2048,
        KeyExchangeAlg.RSA3072,
        KeyExchangeAlg.RSA4096,
        KeyExchangeAlg.MLKEM768,
        KeyExchangeAlg.MLKEM1024,
    }


# ---------------------------------------------------------------------------
# X25519 + Ed25519 (OpenSSL genpkey X25519/ED25519 + pkeyutl -derive/-sign)
# ---------------------------------------------------------------------------


def test_x25519_dh_golden(goldens):
    g = goldens["kem"]["x25519"]
    kem = X25519()
    assert KeyExchangeAlg.X25519.impl is X25519
    alice = PrivateKey(bytes.fromhex(g["alice_private"]), kem.name)
    bob_pub = PublicKey(bytes.fromhex(g["bob_public"]), kem.name)
    bob = PrivateKey(bytes.fromhex(g["bob_private"]), kem.name)
    alice_pub = PublicKey(bytes.fromhex(g["alice_public"]), kem.name)
    ss = bytes.fromhex(g["shared_secret"])
    assert kem.dh(alice, bob_pub) == ss
    assert kem.dh(bob, alice_pub) == ss
    # decapsulate treats ciphertext as peer public
    assert kem.decapsulate(alice, bob_pub.data) == ss


def test_ed25519_sign_verify_golden(goldens):
    g = goldens["kem"]["ed25519"]
    kem = X25519()
    msg = g["message"].encode("ascii")
    sk = SigningPrivateKey(bytes.fromhex(g["private"]), kem.name)
    pk = SigningPublicKey(bytes.fromhex(g["public"]), kem.name)
    sig = bytes.fromhex(g["signature"])
    # Ed25519 is deterministic: our sign must match OpenSSL's signature.
    assert kem.sign(sk, msg, Sha256) == sig
    kem.verify(pk, msg, sig, Sha256)


# ---------------------------------------------------------------------------
# X448 + Ed448
# ---------------------------------------------------------------------------


def test_x448_dh_golden(goldens):
    g = goldens["kem"]["x448"]
    kem = X448()
    assert KeyExchangeAlg.X448.impl is X448
    alice = PrivateKey(bytes.fromhex(g["alice_private"]), kem.name)
    bob_pub = PublicKey(bytes.fromhex(g["bob_public"]), kem.name)
    bob = PrivateKey(bytes.fromhex(g["bob_private"]), kem.name)
    alice_pub = PublicKey(bytes.fromhex(g["alice_public"]), kem.name)
    ss = bytes.fromhex(g["shared_secret"])
    assert kem.dh(alice, bob_pub) == ss
    assert kem.dh(bob, alice_pub) == ss


def test_ed448_sign_verify_golden(goldens):
    g = goldens["kem"]["ed448"]
    kem = X448()
    msg = g["message"].encode("ascii")
    sk = SigningPrivateKey(bytes.fromhex(g["private"]), kem.name)
    pk = SigningPublicKey(bytes.fromhex(g["public"]), kem.name)
    sig = bytes.fromhex(g["signature"])
    assert kem.sign(sk, msg, Sha256) == sig
    kem.verify(pk, msg, sig, Sha256)


# ---------------------------------------------------------------------------
# NIST EC curves (OpenSSL genpkey EC + pkeyutl -derive + ECDSA)
# ---------------------------------------------------------------------------


EC_CASES = [
    ("secp256r1", Secp256r1, KeyExchangeAlg.SECP256R1),
    ("secp384r1", Secp384r1, KeyExchangeAlg.SECP384R1),
    ("secp521r1", Secp521r1, KeyExchangeAlg.SECP521R1),
]


@pytest.mark.parametrize("name,cls,alg", EC_CASES)
def test_ec_dh_and_ecdsa_golden(goldens, name, cls, alg):
    g = goldens["kem"][name]
    kem = cls()
    assert alg.impl is cls
    alice = PrivateKey(bytes.fromhex(g["alice_private"]), kem.name)
    bob_pub = PublicKey(bytes.fromhex(g["bob_public"]), kem.name)
    bob = PrivateKey(bytes.fromhex(g["bob_private"]), kem.name)
    alice_pub = PublicKey(bytes.fromhex(g["alice_public"]), kem.name)
    ss = bytes.fromhex(g["shared_secret"])
    assert kem.dh(alice, bob_pub) == ss
    assert kem.dh(bob, alice_pub) == ss

    msg = g["message"].encode("ascii")
    sk = SigningPrivateKey(bytes.fromhex(g["alice_private"]), kem.name)
    pk = SigningPublicKey(bytes.fromhex(g["alice_public"]), kem.name)
    # ECDSA is randomized: verify the OpenSSL signature, then round-trip ours.
    openssl_sig = bytes.fromhex(g["signature_sha256"])
    kem.verify(pk, msg, openssl_sig, Sha256)
    our_sig = kem.sign(sk, msg, Sha256)
    kem.verify(pk, msg, our_sig, Sha256)


# ---------------------------------------------------------------------------
# RSA-OAEP + RSA-PSS (OpenSSL genrsa / pkeyutl -encrypt / dgst -sign)
# ---------------------------------------------------------------------------


RSA_CASES = [
    ("rsa2048", Rsa2048, KeyExchangeAlg.RSA2048),
    ("rsa3072", Rsa3072, KeyExchangeAlg.RSA3072),
    ("rsa4096", Rsa4096, KeyExchangeAlg.RSA4096),
]


@pytest.mark.parametrize("name,cls,alg", RSA_CASES)
def test_rsa_oaep_and_pss_golden(goldens, name, cls, alg):
    g = goldens["kem"][name]
    kem = cls()
    assert alg.impl is cls
    priv = PrivateKey(bytes.fromhex(g["private_der"]), kem.name)
    pub = PublicKey(bytes.fromhex(g["public_der"]), kem.name)
    secret = bytes.fromhex(g["oaep_secret"])
    ct = bytes.fromhex(g["oaep_ciphertext"])
    assert kem.decapsulate(priv, ct) == secret

    # Live encapsulate/decapsulate still works with the golden key pair.
    live_secret, live_ct = kem.encapsulate(pub)
    assert kem.decapsulate(priv, live_ct) == live_secret

    msg = g["message"].encode("ascii")
    sk = SigningPrivateKey(bytes.fromhex(g["private_der"]), kem.name)
    pk = SigningPublicKey(bytes.fromhex(g["public_der"]), kem.name)
    # PSS salt is random: verify OpenSSL sig, then round-trip ours.
    openssl_sig = bytes.fromhex(g["pss_signature_sha256"])
    kem.verify(pk, msg, openssl_sig, Sha256)
    our_sig = kem.sign(sk, msg, Sha256)
    kem.verify(pk, msg, our_sig, Sha256)


# ---------------------------------------------------------------------------
# ML-KEM (OpenSSL genpkey ML-KEM-* + pkeyutl -encap; seed extracted from DER)
# ---------------------------------------------------------------------------


MLKEM_CASES = [
    ("ml_kem_768", Mlkem768, KeyExchangeAlg.MLKEM768),
    ("ml_kem_1024", Mlkem1024, KeyExchangeAlg.MLKEM1024),
]


@pytest.mark.parametrize("name,cls,alg", MLKEM_CASES)
def test_mlkem_decap_golden(goldens, name, cls, alg):
    g = goldens["kem"][name]
    kem = cls()
    assert alg.impl is cls
    priv = PrivateKey(bytes.fromhex(g["seed"]), kem.name)
    pub = PublicKey(bytes.fromhex(g["public"]), kem.name)
    ct = bytes.fromhex(g["ciphertext"])
    ss = bytes.fromhex(g["shared_secret"])
    assert kem.decapsulate(priv, ct) == ss
    # Public from seed must match the OpenSSL-derived public.
    pair_pub = kem.kem_private_cls.from_seed_bytes(priv.data).public_key().public_bytes_raw()
    assert pair_pub == pub.data
    # Live encapsulate against golden public still decaps with golden seed.
    live_ss, live_ct = kem.encapsulate(pub)
    assert kem.decapsulate(priv, live_ct) == live_ss


@pytest.mark.parametrize("name,cls,alg", MLKEM_CASES)
def test_mlkem_sign_verify_roundtrip(name, cls, alg):
    kem = cls()
    signing = kem.generate_signing_keypair()
    msg = b"ratchetkit-ml-dsa"
    sig = kem.sign(signing.private, msg, Sha256)
    kem.verify(signing.public, msg, sig, Sha256)
