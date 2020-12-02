import secrets

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from xeddsa.implementations import XEdDSA25519
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Local imports
from models import ECPublicKey, OT_PKey, Message
from util import generate_key_pair, diffie_hellman, key_derivation, decrypt_message, encrypt_message
from repository import PublicKeyRepository, OneTimeKeyRepository, MessageRepository


class User:
    def __init__(self):
        self.ik_priv = None
        self.ik_pub = None
        self.spk_priv = None
        self.spk_pub = None
        self.key_priv = None
        self.key_pub = None
        self.public_key_repository = PublicKeyRepository()
        self.one_time_repository = OneTimeKeyRepository()
        self.message_repository = MessageRepository()
        self.set_keys()  # Remove later

    def set_keys(self):
        """
        Sets the keys for a new user
        :return: None
        """
        self.ik_priv, self.ik_pub = generate_key_pair()
        self.spk_priv, self.spk_pub = generate_key_pair()
        self.key_priv, self.key_pub = generate_key_pair()

    def publish_keys(self, opk_count):
        """
        Publishes a bundle of public keys to the server
        :param opk_count: Number of One time pre-keys to create when the public key bundle is published
        :return: None
        """
        spk_sig = XEdDSA25519(mont_priv=self.ik_priv).sign(self.spk_pub)
        ec_public_key = ECPublicKey(self.ik_pub, self.spk_pub, spk_sig)
        while opk_count > 0:
            ot_pkey = OT_PKey(self.key_pub)
            ec_public_key.opks.append(ot_pkey)  # ???Add ot_pkey to bundle???
            opk_count -= 1

        # TEMPORARY FIX: set user.id to the id of the bundle
        # TODO: Authentication

        # Insert public keys into table
        self.public_key_repository.insert_public_key_bundle(ec_public_key=ec_public_key)

    def key_agreement_active(self, ec_public_key: ECPublicKey, opks_b=None, use_opk=True):
        """
        Generates a Shared Key, SK using the public key bundle
        :param ec_public_key: ECPublicKey for the desired receiver
        :param opks_b: list of One time pre-keys?
        :param use_opk: Use the pre-key
        :return: relevant data for first message
        """
        # Local vars
        ik_b = ec_public_key.ik
        spk_b = ec_public_key.spk
        spk_sig_b = ec_public_key.spk_sig

        # Verity the signature
        if not XEdDSA25519(mont_pub=ik_b).verify(
                spk_b,
                spk_sig_b
        ):
            print("The signature of this public bundle's spk could not be verified")
            return "The signature of this public bundle's spk could not be verified"

        EK_a_priv, EK_a_pub = generate_key_pair()
        DH1 = diffie_hellman(self.ik_pub, spk_b)
        DH2 = diffie_hellman(EK_a_pub, ik_b)
        DH3 = diffie_hellman(EK_a_pub, spk_b)
        DH4 = b""

        opk = None
        if use_opk and len(opks_b) > 0:
            opk = secrets.choice(opks_b)
            DH4 = diffie_hellman(EK_a_priv, opk.opk)

        # TODO: Need to delete opk after use

        SK = key_derivation(DH1 + DH2 + DH3 + DH4)

        # TODO: Calculate "associated data" (ad) here
        ad = self.ik_pub + ik_b

        return SK, ad, self.ik_pub, EK_a_pub, opk, spk_b

    def retrieve_key_bundle_for_handshake_by_id(self, id: int) -> ECPublicKey:
        """
        Gets the public key bundle for a user with the given id
        :param id: id for the public key bundle
        :return: the public key bundle for the given id
        """
        ec_public_key = self.public_key_repository.get_public_key_bundle_by_id(id=id)
        return ec_public_key


if __name__ == "__main__":

    # Receiver publishes keys to the server
    # receiver = User()
    # receiver.publish_keys(opk_count=1)

    # Sender gets the bundle and creates the shared key
    sender = User()
    bundle = sender.retrieve_key_bundle_for_handshake_by_id(23)  # param should be receiver.id
    SK, ad, ik_pub, EK_a_pub, opk, spk_b = sender.key_agreement_active(ec_public_key=bundle,
                                                                       opks_b=None,
                                                                       use_opk=False)

    enc = encrypt_message("NaM STFU WEEBS NaM", SK)
    print(enc)
    dec = decrypt_message(enc, SK)
    print(dec)