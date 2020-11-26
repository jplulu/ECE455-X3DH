import secrets
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from key_generation import generate_key_pair


def diffie_hellman(priv_bytes, pub_bytes):
    return X25519PrivateKey.from_private_bytes(priv_bytes).exchange(X25519PublicKey.from_public_bytes(pub_bytes))


def key_derivation(KM, info_string):
    hash_function = hashes.SHA256()
    salt = b"\x00" * 32
    F = b"\xFF" * 32
    info = info_string.encode("ASCII", errors="strict")
    return HKDF(
        algorithm=hash_function,
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    ).derive(F + KM)


def key_agreement_initial(ik_a, ik_b, spk_b, spk_sig_b, opks_b=None, use_opk=True):
    # TODO: Need to verify signature (spk_sig_b) first

    EK_a_priv, EK_a_pub = generate_key_pair()
    DH1 = diffie_hellman(ik_a, spk_b)
    DH2 = diffie_hellman(EK_a_priv, ik_b)
    DH3 = diffie_hellman(EK_a_priv, spk_b)
    DH4 = b""

    opk = None
    if use_opk and len(opks_b) > 0:
        opk = secrets.choice(opks_b)
        DH4 = diffie_hellman(EK_a_priv, opk)

    info = "placeholder"
    SK = key_derivation(DH1 + DH2 + DH3 + DH4, info)

    # TODO: Calculate "associated data" (ad) here
    ad = b""

    return SK, ad, ik_a, EK_a_pub, opk, spk_b

