#!/usr/bin/env bash
# Regenerate tests/algorithms/openssl_goldens.json with OpenSSL 3.x.
# Requires: openssl, python3, xxd.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/tests/algorithms/openssl_goldens.json"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

printf '%s' 'abc' > msg_abc.bin
printf '%s' 'ratchetkit-mac' > msg_mac.bin
printf '%s' 'hello ratchetkit' > pt.bin
printf '%s' 'ratchetkit-sign' > sign_msg.bin

HMAC_KEY='0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'
KEY128="$(python3 -c 'print("11"*16)')"
KEY256="$(python3 -c 'print("11"*32)')"
IV128="$(python3 -c 'print("22"*16)')"
SECRET32="$(python3 -c 'print("33"*32)')"
python3 -c "open('secret32.bin','wb').write(bytes.fromhex('$SECRET32'))"

python3 - "$OUT" <<'PY'
import json, pathlib, subprocess, sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

out_path = pathlib.Path(sys.argv[1])
work = pathlib.Path(".")

def sh(*args):
    subprocess.check_call(args)

def dgst(alg, path):
    out = subprocess.check_output(["openssl", "dgst", f"-{alg}", "-hex", str(path)], text=True)
    return out.strip().split()[-1]

def hmac(alg, hexkey, path):
    out = subprocess.check_output(
        ["openssl", "dgst", f"-{alg}", "-mac", "HMAC", "-macopt", f"hexkey:{hexkey}", "-hex", str(path)],
        text=True,
    )
    return out.strip().split()[-1]

def enc(ciph, key_hex, iv_hex, inp):
    out = work / "ct.bin"
    sh("openssl", "enc", f"-{ciph}", "-K", key_hex, "-iv", iv_hex, "-nosalt", "-in", str(inp), "-out", str(out))
    return out.read_bytes().hex()

HMAC_KEY = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
KEY128 = "11" * 16
KEY256 = "11" * 32
IV128 = "22" * 16

gold = {
    "comment": "OpenSSL 3.x goldens for ratchetkit algorithms (scripts/gen_openssl_goldens.sh)",
    "hash_msg": "abc",
    "hmac_msg": "ratchetkit-mac",
    "hmac_key_hex": HMAC_KEY,
    "sign_message": "ratchetkit-sign",
    "hash": {},
    "hmac": {},
    "cipher": {
        "plaintext": "hello ratchetkit",
        "key128_hex": KEY128,
        "key256_hex": KEY256,
        "iv_hex": IV128,
        "ciphertext": {},
    },
    "kem": {},
}

for d in ("sha256", "sha384", "sha512", "sha3-256", "blake2b512"):
    gold["hash"][d] = dgst(d, work / "msg_abc.bin")
    gold["hmac"][d] = hmac(d, HMAC_KEY, work / "msg_mac.bin")

for ciph, key in (
    ("aes-128-ctr", KEY128),
    ("aes-256-ctr", KEY256),
    ("camellia-128-ctr", KEY128),
    ("camellia-256-ctr", KEY256),
    ("chacha20", KEY256),
):
    gold["cipher"]["ciphertext"][ciph] = enc(ciph, key, IV128, work / "pt.bin")

def raw_priv_pub(pem_path):
    key = serialization.load_pem_private_key(pem_path.read_bytes(), password=None)
    sk = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk.hex(), pk.hex()

# X25519 / Ed25519
sh("openssl", "genpkey", "-algorithm", "X25519", "-out", "x25519_a.pem")
sh("openssl", "genpkey", "-algorithm", "X25519", "-out", "x25519_b.pem")
sh("openssl", "pkey", "-in", "x25519_b.pem", "-pubout", "-out", "x25519_b.pub")
sh("openssl", "pkeyutl", "-derive", "-inkey", "x25519_a.pem", "-peerkey", "x25519_b.pub", "-out", "x25519_ss.bin")
a_sk, a_pk = raw_priv_pub(work / "x25519_a.pem")
b_sk, b_pk = raw_priv_pub(work / "x25519_b.pem")
gold["kem"]["x25519"] = {
    "alice_private": a_sk,
    "alice_public": a_pk,
    "bob_private": b_sk,
    "bob_public": b_pk,
    "shared_secret": (work / "x25519_ss.bin").read_bytes().hex(),
}
sh("openssl", "genpkey", "-algorithm", "ED25519", "-out", "ed25519.pem")
sh("openssl", "pkeyutl", "-sign", "-inkey", "ed25519.pem", "-rawin", "-in", "sign_msg.bin", "-out", "ed25519.sig")
ed_sk, ed_pk = raw_priv_pub(work / "ed25519.pem")
gold["kem"]["ed25519"] = {
    "private": ed_sk,
    "public": ed_pk,
    "message": "ratchetkit-sign",
    "signature": (work / "ed25519.sig").read_bytes().hex(),
}

# X448 / Ed448
sh("openssl", "genpkey", "-algorithm", "X448", "-out", "x448_a.pem")
sh("openssl", "genpkey", "-algorithm", "X448", "-out", "x448_b.pem")
sh("openssl", "pkey", "-in", "x448_b.pem", "-pubout", "-out", "x448_b.pub")
sh("openssl", "pkeyutl", "-derive", "-inkey", "x448_a.pem", "-peerkey", "x448_b.pub", "-out", "x448_ss.bin")
a_sk, a_pk = raw_priv_pub(work / "x448_a.pem")
b_sk, b_pk = raw_priv_pub(work / "x448_b.pem")
gold["kem"]["x448"] = {
    "alice_private": a_sk,
    "alice_public": a_pk,
    "bob_private": b_sk,
    "bob_public": b_pk,
    "shared_secret": (work / "x448_ss.bin").read_bytes().hex(),
}
sh("openssl", "genpkey", "-algorithm", "ED448", "-out", "ed448.pem")
sh("openssl", "pkeyutl", "-sign", "-inkey", "ed448.pem", "-rawin", "-in", "sign_msg.bin", "-out", "ed448.sig")
ed_sk, ed_pk = raw_priv_pub(work / "ed448.pem")
gold["kem"]["ed448"] = {
    "private": ed_sk,
    "public": ed_pk,
    "message": "ratchetkit-sign",
    "signature": (work / "ed448.sig").read_bytes().hex(),
}

# NIST EC
curve_map = {
    "prime256v1": "secp256r1",
    "secp384r1": "secp384r1",
    "secp521r1": "secp521r1",
}
for openssl_name, our_name in curve_map.items():
    sh("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{openssl_name}", "-out", f"ec_{openssl_name}_a.pem")
    sh("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{openssl_name}", "-out", f"ec_{openssl_name}_b.pem")
    sh("openssl", "pkey", "-in", f"ec_{openssl_name}_b.pem", "-pubout", "-out", f"ec_{openssl_name}_b.pub")
    sh("openssl", "pkeyutl", "-derive", "-inkey", f"ec_{openssl_name}_a.pem", "-peerkey", f"ec_{openssl_name}_b.pub", "-out", f"ec_{openssl_name}_ss.bin")
    a = serialization.load_pem_private_key((work / f"ec_{openssl_name}_a.pem").read_bytes(), password=None)
    b = serialization.load_pem_private_key((work / f"ec_{openssl_name}_b.pem").read_bytes(), password=None)
    bl = (a.curve.key_size + 7) // 8
    msg = b"ratchetkit-sign"
    sig = a.sign(msg, ec.ECDSA(hashes.SHA256()))
    gold["kem"][our_name] = {
        "alice_private": a.private_numbers().private_value.to_bytes(bl, "big").hex(),
        "alice_public": a.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex(),
        "bob_private": b.private_numbers().private_value.to_bytes(bl, "big").hex(),
        "bob_public": b.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex(),
        "shared_secret": (work / f"ec_{openssl_name}_ss.bin").read_bytes().hex(),
        "message": "ratchetkit-sign",
        "signature_sha256": sig.hex(),
    }

# RSA
for bits in (2048, 3072, 4096):
    sh("openssl", "genrsa", "-out", f"rsa{bits}.pem", str(bits))
    sh("openssl", "rsa", "-in", f"rsa{bits}.pem", "-outform", "DER", "-out", f"rsa{bits}_priv.der")
    sh("openssl", "rsa", "-in", f"rsa{bits}.pem", "-pubout", "-outform", "DER", "-out", f"rsa{bits}_pub.der")
    sh("openssl", "rsa", "-in", f"rsa{bits}.pem", "-pubout", "-out", f"rsa{bits}.pub")
    sh(
        "openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", f"rsa{bits}.pub",
        "-in", "secret32.bin", "-out", f"rsa{bits}.ct",
        "-pkeyopt", "rsa_padding_mode:oaep",
        "-pkeyopt", "rsa_oaep_md:sha256",
        "-pkeyopt", "rsa_mgf1_md:sha256",
    )
    sh(
        "openssl", "dgst", "-sha256",
        "-sigopt", "rsa_padding_mode:pss",
        "-sigopt", "rsa_pss_saltlen:max",
        "-sign", f"rsa{bits}.pem",
        "-out", f"rsa{bits}.sig",
        "sign_msg.bin",
    )
    gold["kem"][f"rsa{bits}"] = {
        "private_der": (work / f"rsa{bits}_priv.der").read_bytes().hex(),
        "public_der": (work / f"rsa{bits}_pub.der").read_bytes().hex(),
        "oaep_secret": "33" * 32,
        "oaep_ciphertext": (work / f"rsa{bits}.ct").read_bytes().hex(),
        "message": "ratchetkit-sign",
        "pss_signature_sha256": (work / f"rsa{bits}.sig").read_bytes().hex(),
    }

# ML-KEM
from cryptography.hazmat.primitives.asymmetric import mlkem as mlkem_mod

def extract_seed(der: bytes) -> bytes:
    idx = der.find(bytes([0x04, 0x40]))
    return der[idx + 2 : idx + 2 + 64]

def extract_pub_raw(pub_der: bytes, expected_len: int) -> bytes:
    i = 0
    while i < len(pub_der) - 4:
        if pub_der[i] == 0x03 and pub_der[i + 1] == 0x82:
            ln = int.from_bytes(pub_der[i + 2 : i + 4], "big")
            content = pub_der[i + 4 : i + 4 + ln]
            if content[0] == 0 and len(content) - 1 == expected_len:
                return content[1:]
        i += 1
    raise ValueError("public raw not found")

for alg, tag, priv_cls, pklen in (
    ("ML-KEM-768", "ml_kem_768", mlkem_mod.MLKEM768PrivateKey, 1184),
    ("ML-KEM-1024", "ml_kem_1024", mlkem_mod.MLKEM1024PrivateKey, 1568),
):
    sh("openssl", "genpkey", "-algorithm", alg, "-out", f"{tag}.pem")
    sh("openssl", "pkey", "-in", f"{tag}.pem", "-outform", "DER", "-out", f"{tag}_priv.der")
    sh("openssl", "pkey", "-in", f"{tag}.pem", "-pubout", "-outform", "DER", "-out", f"{tag}_pub.der")
    sh("openssl", "pkey", "-in", f"{tag}.pem", "-pubout", "-out", f"{tag}.pub")
    sh("openssl", "pkeyutl", "-encap", "-pubin", "-inkey", f"{tag}.pub", "-out", f"{tag}.ct", "-secret", f"{tag}.ss")
    seed = extract_seed((work / f"{tag}_priv.der").read_bytes())
    pub = extract_pub_raw((work / f"{tag}_pub.der").read_bytes(), pklen)
    assert priv_cls.from_seed_bytes(seed).public_key().public_bytes_raw() == pub
    gold["kem"][tag] = {
        "seed": seed.hex(),
        "public": pub.hex(),
        "ciphertext": (work / f"{tag}.ct").read_bytes().hex(),
        "shared_secret": (work / f"{tag}.ss").read_bytes().hex(),
        "comment": "seed+public extracted from OpenSSL genpkey/pkeyutl -encap DER",
    }

out_path.write_text(json.dumps(gold, indent=2) + "\n")
print(f"wrote {out_path} ({out_path.stat().st_size} bytes)")
PY
echo "done"
