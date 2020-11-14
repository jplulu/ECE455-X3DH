from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.fernet import Fernet


def generate_key_pair():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return priv, pub

priv = X25519PrivateKey.generate()
peer_pub = X25519PrivateKey.generate().public_key()
shared = priv.exchange(peer_pub)
key = b64encode(shared)
f = Fernet(key)
token = f.encrypt(b"This is a secret")
print(token)
print(f.decrypt(token))

# priv, pub = generate_key_pair()
# print(priv, pub)
# print({
#     "priv": b64encode(priv).decode("ASCII"),
#     "pub": b64encode(pub).decode("ASCII")
# })
