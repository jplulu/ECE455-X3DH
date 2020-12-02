from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization


class KeyPair:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key

    @classmethod
    def generate_key_pair(cls) -> (bytes, bytes):
        """
        Generates a public/private key pair
        :return: the key pair
        """
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_key = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        return cls(private_key=private_key, public_key=public_key)

    def __repr__(self):
        return (
            "<KeyPair(private_key={}, public_key={})>".format(self.private_key, self.public_key)
        )