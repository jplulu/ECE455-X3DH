from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode





def diffie_hellman(priv_bytes: bytes, pub_bytes: bytes) -> bytes:
    """
    Performs a Diffie-Hellman operation on the two keys
    :param priv_bytes: bytes of the first key
    :param pub_bytes: bytes of the second key
    :return: exchange of the two keys
    """
    return X25519PrivateKey.from_private_bytes(priv_bytes).exchange(X25519PublicKey.from_public_bytes(pub_bytes))


def key_derivation(KM):
    """
    Derives the shared key
    :param KM:
    :return: the shared key
    """
    hash_function = hashes.SHA256()
    salt = b"\x00" * 32
    F = b"\xFF" * 32
    info = "placeholder".encode("ASCII", errors="strict")
    SK = HKDF(
        algorithm=hash_function,
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    ).derive(F + KM)
    return SK


def encrypt_message(message_str: str, key: bytes) -> bytes:
    """
    Encrypts the given string with the specified key
    :param message_str: the message as a string
    :param key: the encryption key
    :return: the encrypted message
    """
    key = b64encode(key)
    f = Fernet(key)
    message_bytes = f.encrypt(bytes(message_str, 'ascii'))
    return message_bytes


def decrypt_message(message_bytes: bytes, key: bytes) -> str:
    """
    Decrypts the given message with the specified key
    :param message_bytes: the message encrypted with the given key
    :param key: the decryption key
    :return: the decrypted message
    """
    key = b64encode(key)
    f = Fernet(key)
    message_str = f.decrypt(message_bytes).decode("ascii")
    return message_str


