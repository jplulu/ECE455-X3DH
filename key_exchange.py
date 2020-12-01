import secrets
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from xeddsa.implementations import XEdDSA25519
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from key_generation import generate_key_pair
from models import ECPublicKey, OT_PKey

engine = create_engine('sqlite:///keybundle.db', echo=False)
Session = sessionmaker(bind=engine)
session = Session()


def publish_keys(opk_count):
    ik_priv, ik_pub = generate_key_pair()

    spk_priv, spk_pub = generate_key_pair()
    spk_sig = XEdDSA25519(mont_priv=ik_priv).sign(spk_pub)
    bundle = ECPublicKey(ik_pub, spk_pub, spk_sig)
    while opk_count > 0:
        key_priv, key_pub = generate_key_pair()
        bundle.opks.append(OT_PKey(key_pub))
        opk_count -= 1

    session.add(bundle)
    session.commit()


def diffie_hellman(priv_bytes, pub_bytes):
    return X25519PrivateKey.from_private_bytes(priv_bytes).exchange(X25519PublicKey.from_public_bytes(pub_bytes))


def key_derivation(KM):
    hash_function = hashes.SHA256()
    salt = b"\x00" * 32
    F = b"\xFF" * 32
    info = "placeholder".encode("ASCII", errors="strict")
    return HKDF(
        algorithm=hash_function,
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    ).derive(F + KM)


def key_agreement_active(ik_a, ik_b, spk_b, spk_sig_b, opks_b=None, use_opk=True):
    if not XEdDSA25519(mont_pub=ik_b).verify(
            spk_b,
            spk_sig_b
    ):
        return "The signature of this public bundle's spk could not be verified"

    EK_a_priv, EK_a_pub = generate_key_pair()
    DH1 = diffie_hellman(ik_a, spk_b)
    DH2 = diffie_hellman(EK_a_priv, ik_b)
    DH3 = diffie_hellman(EK_a_priv, spk_b)
    DH4 = b""

    opk = None
    if use_opk and len(opks_b) > 0:
        opk = secrets.choice(opks_b)
        DH4 = diffie_hellman(EK_a_priv, opk)

    SK = key_derivation(DH1 + DH2 + DH3 + DH4)

    # TODO: Calculate "associated data" (ad) here
    ad = ik_a + ik_b

    return SK, ad, ik_a, EK_a_pub, opk, spk_b


if __name__ == '__main__':
    publish_keys(5)
    bundle = session.query(ECPublicKey).filter(ECPublicKey.id == 1).first()
    print(bundle)
    print(bundle.opks)
