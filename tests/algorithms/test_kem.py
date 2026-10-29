"""KEM / DH / signature goldens (OpenSSL) for every KEX and signing alg."""
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
from ratchetkit.algorithms.signing.ed25519 import Ed25519
from ratchetkit.algorithms.signing.ed448 import Ed448
from ratchetkit.algorithms.signing.ecdsa import (
    EcdsaSecp256r1,
    EcdsaSecp384r1,
    EcdsaSecp521r1,
)
from ratchetkit.algorithms.signing.rsa_pss import RsaPss2048, RsaPss3072, RsaPss4096
from ratchetkit.keys.keypair import KeyPair, PublicKey, SigningKeyPair, SigningPublicKey
from ratchetkit.suite import KeyExchangeAlg, SigningAlg
from ratchetkit.suite.registry import key_exchange_backend, signing_backend


def test_every_key_exchange_alg_is_covered():
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


def test_every_signing_alg_is_covered():
    assert set(SigningAlg) == {
        SigningAlg.ED25519,
        SigningAlg.ED448,
        SigningAlg.ECDSA_SECP256R1,
        SigningAlg.ECDSA_SECP384R1,
        SigningAlg.ECDSA_SECP521R1,
        SigningAlg.RSA_PSS_2048,
        SigningAlg.RSA_PSS_3072,
        SigningAlg.RSA_PSS_4096,
        SigningAlg.MLDSA65,
        SigningAlg.MLDSA87,
    }


def test_x25519_dh_golden(goldens):
    g = goldens["kem"]["x25519"]
    kem = X25519()
    assert key_exchange_backend(KeyExchangeAlg.X25519) is X25519
    alice = KeyPair(
        private=bytes.fromhex(g["alice_private"]),
        public=PublicKey(kem.derive_public(bytes.fromhex(g["alice_private"])), KeyExchangeAlg.X25519),
    )
    bob_pub = PublicKey(bytes.fromhex(g["bob_public"]), KeyExchangeAlg.X25519)
    bob = KeyPair(
        private=bytes.fromhex(g["bob_private"]),
        public=PublicKey(kem.derive_public(bytes.fromhex(g["bob_private"])), KeyExchangeAlg.X25519),
    )
    alice_pub = PublicKey(bytes.fromhex(g["alice_public"]), KeyExchangeAlg.X25519)
    ss = bytes.fromhex(g["shared_secret"])
    assert kem.dh(alice, bob_pub) == ss
    assert kem.dh(bob, alice_pub) == ss
    assert kem.decapsulate(alice, bob_pub.data) == ss
    assert alice.public.data == alice_pub.data


def test_ed25519_sign_verify_golden(goldens):
    g = goldens["kem"]["ed25519"]
    signer = Ed25519()
    msg = g["message"].encode("ascii")
    sk = SigningKeyPair(
        private=bytes.fromhex(g["private"]),
        public=SigningPublicKey(signer.derive_public(bytes.fromhex(g["private"])), SigningAlg.ED25519),
    )
    pk = SigningPublicKey(bytes.fromhex(g["public"]), SigningAlg.ED25519)
    sig = bytes.fromhex(g["signature"])
    assert signer.sign(sk, msg, Sha256) == sig
    signer.verify(pk, msg, sig, Sha256)
    assert sk.public.data == pk.data


def test_x448_dh_golden(goldens):
    g = goldens["kem"]["x448"]
    kem = X448()
    alice = KeyPair(
        private=bytes.fromhex(g["alice_private"]),
        public=PublicKey(kem.derive_public(bytes.fromhex(g["alice_private"])), KeyExchangeAlg.X448),
    )
    bob_pub = PublicKey(bytes.fromhex(g["bob_public"]), KeyExchangeAlg.X448)
    bob = KeyPair(
        private=bytes.fromhex(g["bob_private"]),
        public=PublicKey(kem.derive_public(bytes.fromhex(g["bob_private"])), KeyExchangeAlg.X448),
    )
    alice_pub = PublicKey(bytes.fromhex(g["alice_public"]), KeyExchangeAlg.X448)
    ss = bytes.fromhex(g["shared_secret"])
    assert kem.dh(alice, bob_pub) == ss
    assert kem.dh(bob, alice_pub) == ss


def test_ed448_sign_verify_golden(goldens):
    g = goldens["kem"]["ed448"]
    signer = Ed448()
    msg = g["message"].encode("ascii")
    sk = SigningKeyPair(
        private=bytes.fromhex(g["private"]),
        public=SigningPublicKey(signer.derive_public(bytes.fromhex(g["private"])), SigningAlg.ED448),
    )
    pk = SigningPublicKey(bytes.fromhex(g["public"]), SigningAlg.ED448)
    sig = bytes.fromhex(g["signature"])
    assert signer.sign(sk, msg, Sha256) == sig
    signer.verify(pk, msg, sig, Sha256)


EC_CASES = [
    ("secp256r1", Secp256r1, KeyExchangeAlg.SECP256R1, EcdsaSecp256r1, SigningAlg.ECDSA_SECP256R1),
    ("secp384r1", Secp384r1, KeyExchangeAlg.SECP384R1, EcdsaSecp384r1, SigningAlg.ECDSA_SECP384R1),
    ("secp521r1", Secp521r1, KeyExchangeAlg.SECP521R1, EcdsaSecp521r1, SigningAlg.ECDSA_SECP521R1),
]


@pytest.mark.parametrize("name,cls,alg,scls,salg", EC_CASES)
def test_ec_dh_and_ecdsa_golden(goldens, name, cls, alg, scls, salg):
    g = goldens["kem"][name]
    kem = cls()
    alice = KeyPair(
        private=bytes.fromhex(g["alice_private"]),
        public=PublicKey(kem.derive_public(bytes.fromhex(g["alice_private"])), alg),
    )
    bob_pub = PublicKey(bytes.fromhex(g["bob_public"]), alg)
    bob = KeyPair(
        private=bytes.fromhex(g["bob_private"]),
        public=PublicKey(kem.derive_public(bytes.fromhex(g["bob_private"])), alg),
    )
    alice_pub = PublicKey(bytes.fromhex(g["alice_public"]), alg)
    ss = bytes.fromhex(g["shared_secret"])
    assert kem.dh(alice, bob_pub) == ss
    assert kem.dh(bob, alice_pub) == ss

    msg = g["message"].encode("ascii")
    signer = scls()
    sk = SigningKeyPair(
        private=bytes.fromhex(g["alice_private"]),
        public=SigningPublicKey(signer.derive_public(bytes.fromhex(g["alice_private"])), salg),
    )
    pk = SigningPublicKey(bytes.fromhex(g["alice_public"]), salg)
    openssl_sig = bytes.fromhex(g["signature_sha256"])
    signer.verify(pk, msg, openssl_sig, Sha256)
    our_sig = signer.sign(sk, msg, Sha256)
    signer.verify(pk, msg, our_sig, Sha256)


RSA_CASES = [
    ("rsa2048", Rsa2048, KeyExchangeAlg.RSA2048, RsaPss2048, SigningAlg.RSA_PSS_2048),
    ("rsa3072", Rsa3072, KeyExchangeAlg.RSA3072, RsaPss3072, SigningAlg.RSA_PSS_3072),
    ("rsa4096", Rsa4096, KeyExchangeAlg.RSA4096, RsaPss4096, SigningAlg.RSA_PSS_4096),
]


@pytest.mark.parametrize("name,cls,alg,scls,salg", RSA_CASES)
def test_rsa_oaep_and_pss_golden(goldens, name, cls, alg, scls, salg):
    g = goldens["kem"][name]
    kem = cls()
    priv = KeyPair(
        private=bytes.fromhex(g["private_der"]),
        public=PublicKey(kem.derive_public(bytes.fromhex(g["private_der"])), alg),
    )
    pub = PublicKey(bytes.fromhex(g["public_der"]), alg)
    secret = bytes.fromhex(g["oaep_secret"])
    ct = bytes.fromhex(g["oaep_ciphertext"])
    assert kem.decapsulate(priv, ct) == secret
    live_secret, live_ct = kem.encapsulate(pub)
    assert kem.decapsulate(priv, live_ct) == live_secret

    msg = g["message"].encode("ascii")
    signer = scls()
    sk = SigningKeyPair(
        private=bytes.fromhex(g["private_der"]),
        public=SigningPublicKey(signer.derive_public(bytes.fromhex(g["private_der"])), salg),
    )
    pk = SigningPublicKey(bytes.fromhex(g["public_der"]), salg)
    openssl_sig = bytes.fromhex(g["pss_signature_sha256"])
    signer.verify(pk, msg, openssl_sig, Sha256)
    our_sig = signer.sign(sk, msg, Sha256)
    signer.verify(pk, msg, our_sig, Sha256)


MLKEM_CASES = [
    ("ml_kem_768", Mlkem768, KeyExchangeAlg.MLKEM768),
    ("ml_kem_1024", Mlkem1024, KeyExchangeAlg.MLKEM1024),
]


@pytest.mark.parametrize("name,cls,alg", MLKEM_CASES)
def test_mlkem_decap_golden(goldens, name, cls, alg):
    g = goldens["kem"][name]
    kem = cls()
    priv = KeyPair(
        private=bytes.fromhex(g["seed"]),
        public=PublicKey(kem.derive_public(bytes.fromhex(g["seed"])), alg),
    )
    pub = PublicKey(bytes.fromhex(g["public"]), alg)
    ct = bytes.fromhex(g["ciphertext"])
    ss = bytes.fromhex(g["shared_secret"])
    assert kem.decapsulate(priv, ct) == ss
    assert priv.public.data == pub.data
    live_ss, live_ct = kem.encapsulate(pub)
    assert kem.decapsulate(priv, live_ct) == live_ss


def test_signing_backends_roundtrip():
    for alg in SigningAlg:
        signer = signing_backend(alg)()
        pair = signer.generate_keypair()
        assert pair.public.algorithm is alg
        sig = signer.sign(pair, b"hello", Sha256)
        signer.verify(pair.public, b"hello", sig, Sha256)
